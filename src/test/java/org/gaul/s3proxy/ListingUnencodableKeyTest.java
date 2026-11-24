/*
 * Copyright 2014-2026 Andrew Gaul <andrew@gaul.org>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.gaul.s3proxy;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.StringReader;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import javax.xml.parsers.DocumentBuilderFactory;

import com.google.common.io.ByteSource;

import org.gaul.s3proxy.auth.AuthenticationType;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import software.amazon.awssdk.services.s3.model.BucketCannedACL;

/**
 * A key may hold any character and XML 1.0 cannot carry most control
 * characters.  The writer refuses one by throwing, after the status and half
 * of the listing have been sent, so a single object named U+0001 used to
 * leave every listing of its bucket a 200 whose body stopped inside the first
 * such Key.
 */
public final class ListingUnencodableKeyTest {
    // U+0001 sorts before nearly every other key, and the others cover what
    // else XML 1.0 excludes and what it must not be mistaken for.
    private static final String CONTROL_KEY = "\u0001";
    private static final String NONCHARACTER_KEY = "y\uffff";
    private static final String SUPPLEMENTARY_KEY = "smile-\ud83d\ude00";
    private static final List<String> KEYS = List.of(CONTROL_KEY, "a.txt",
            "b.txt", SUPPLEMENTARY_KEY, NONCHARACTER_KEY, "z.txt");
    private static final List<String> ESCAPED_KEYS = List.of("%01", "a.txt",
            "b.txt", "smile-%F0%9F%98%80", "y%EF%BF%BF", "z.txt");

    private BlobStore blobStore;
    private S3Proxy s3Proxy;
    private String containerName;
    private String baseUri;
    private final HttpClient httpClient = HttpClient.newHttpClient();

    @BeforeEach
    public void setUp() throws Exception {
        blobStore = TestUtils.createTransientBlobStore();
        containerName = TestUtils.createRandomContainerName();
        blobStore.createContainer(containerName);
        blobStore.setContainerAccess(containerName,
                BucketCannedACL.PUBLIC_READ);
        for (String key : KEYS) {
            TestUtils.putBlob(blobStore, containerName, key,
                    ByteSource.wrap(new byte[1]));
        }

        s3Proxy = S3Proxy.builder()
                .stopTimeout(0)
                .blobStore(blobStore)
                .awsAuthentication(AuthenticationType.AWS_V2_OR_V4,
                        "identity", "credential")
                .endpoint(URI.create("http://127.0.0.1:0"))
                .build();
        s3Proxy.start();
        while (!s3Proxy.getState().equals("STARTED")) {
            Thread.sleep(10);
        }
        baseUri = "http://127.0.0.1:" + s3Proxy.getPort() + "/";
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
    }

    /** ListObjects completes, naming the keys that sort after the odd one. */
    @Test
    public void testListObjectsIsWellFormed() throws Exception {
        assertListsEveryKey("");
    }

    @Test
    public void testListObjectsV2IsWellFormed() throws Exception {
        assertListsEveryKey("?list-type=2");
    }

    @Test
    public void testListObjectVersionsIsWellFormed() throws Exception {
        assertListsEveryKey("?versions");
    }

    @Test
    public void testListMultipartUploadsIsWellFormed() throws Exception {
        initiateUploads();
        assertThat(text(list("?uploads"), "Key")).containsExactly("\ufffd",
                "b.txt");
        assertThat(text(list("?uploads&encoding-type=url"), "Key"))
                .containsExactly("%01", "b.txt");
    }

    /** A client that needs such a key exactly asks for it escaped. */
    @Test
    public void testUrlEncodingKeepsTheKey() throws Exception {
        assertThat(text(list("?list-type=2&encoding-type=url"), "Key"))
                .containsExactlyElementsOf(ESCAPED_KEYS);
    }

    /**
     * A continuation token is not a key and encoding-type does not apply to
     * it, yet a store without tokens of its own hands out the last key of the
     * page.  It has to come back as it was issued: a token that lost a
     * character resumes somewhere else, skipping keys or serving a page again.
     */
    @Test
    public void testContinuationTokenSurvives() throws Exception {
        var keys = new ArrayList<String>();
        String query = "?list-type=2&encoding-type=url&max-keys=1";
        String token = null;
        do {
            assertThat(keys).hasSizeLessThan(KEYS.size());
            Document page = list(token == null ? query : query +
                    "&continuation-token=" +
                    URLEncoder.encode(token, StandardCharsets.UTF_8));
            keys.addAll(text(page, "Key"));
            List<String> next = text(page, "NextContinuationToken");
            token = next.isEmpty() ? null : next.get(0);
        } while (token != null);
        assertThat(keys).containsExactlyElementsOf(ESCAPED_KEYS);
    }

    @Test
    public void testMalformedContinuationTokenIsRefused() throws Exception {
        // "%zz" after the query is parsed, which no token decodes from
        HttpResponse<String> response = get(
                "?list-type=2&continuation-token=%25zz");
        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.body()).contains("<Code>InvalidArgument</Code>");
    }

    /**
     * A marker is a key, and the key a client sends back to get the next
     * page.  One that cannot be written as it is gets a refusal that names
     * the remedy, not a replacement that resumes the listing somewhere else:
     * after U+0001 that would skip the keys up to U+FFFD, and after U+FFFF it
     * would go back and serve the same page again.
     */
    @Test
    public void testUnencodableMarkerIsRefused() throws Exception {
        initiateUploads();
        for (String query : List.of("?max-keys=1", "?max-keys=1&marker=t",
                "?versions&max-keys=1", "?versions&max-keys=1&key-marker=t",
                "?uploads&max-uploads=1")) {
            HttpResponse<String> response = get(query);
            assertThat(response.statusCode()).as(query).isEqualTo(400);
            assertThat(response.body()).as(query)
                    .contains("<Code>InvalidArgument</Code>")
                    .contains("encoding-type=url");
        }
    }

    @Test
    public void testMarkerSurvives() throws Exception {
        var keys = new ArrayList<String>();
        String query = "?encoding-type=url&max-keys=1";
        String marker = null;
        do {
            assertThat(keys).hasSizeLessThan(KEYS.size());
            // NextMarker comes escaped as the keys do, which is also how
            // a query string spells it
            Document page = list(marker == null ? query : query +
                    "&marker=" + marker);
            keys.addAll(text(page, "Key"));
            List<String> next = text(page, "NextMarker");
            marker = next.isEmpty() ? null : next.get(0);
        } while (marker != null);
        assertThat(keys).containsExactlyElementsOf(ESCAPED_KEYS);
    }

    private void initiateUploads() {
        for (String key : List.of(CONTROL_KEY, "b.txt")) {
            blobStore.initiateMultipartUpload(
                    TestUtils.createRequest(containerName, key));
        }
    }

    private void assertListsEveryKey(String query) throws Exception {
        // What XML cannot carry is replaced and everything else is as stored.
        assertThat(text(list(query), "Key")).containsExactly("\ufffd", "a.txt",
                "b.txt", SUPPLEMENTARY_KEY, "y\ufffd", "z.txt");
    }

    private HttpResponse<String> get(String query) throws Exception {
        return httpClient.send(
                HttpRequest.newBuilder(URI.create(baseUri + containerName +
                        query)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }

    /** The listing, which has to be a complete document to parse at all. */
    private Document list(String query) throws Exception {
        HttpResponse<String> response = get(query);
        assertThat(response.statusCode()).isEqualTo(200);
        return DocumentBuilderFactory.newInstance().newDocumentBuilder()
                .parse(new InputSource(new StringReader(response.body())));
    }

    private static List<String> text(Document document, String tagName) {
        NodeList nodes = document.getElementsByTagName(tagName);
        var text = new ArrayList<String>();
        for (int i = 0; i < nodes.getLength(); i++) {
            text.add(nodes.item(i).getTextContent());
        }
        return text;
    }
}
