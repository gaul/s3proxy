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

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Random;

import com.google.common.io.ByteSource;

import org.gaul.s3proxy.auth.AuthenticationType;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.ObjectCannedACL;

/**
 * The parameters that replace response headers let the URL say what an object
 * contains, so S3 honours them only for a request it can attribute to a
 * caller.  Answering them on a read nobody signed would turn any object a
 * reader can fetch -- a public-read one, here -- into markup served from the
 * proxy's own origin.
 *
 * <p>{@link AwsSdkTest#testOverrideResponseHeader} covers the signed request,
 * which may use them, and {@link DefaultContentTypeTest} a proxy running
 * without authorization, where no request is anonymous because there is
 * nothing to authenticate against.
 */
public final class AnonymousResponseHeaderTest {
    private static final String BLOB_NAME = "public.json";
    private static final String CONTENT =
            "{\"note\": \"<script>alert(1)</script>\"}";

    private S3Proxy s3Proxy;
    private BlobStore blobStore;
    private String blobUri;
    private final HttpClient httpClient = HttpClient.newHttpClient();

    @BeforeEach
    public void setUp() throws Exception {
        blobStore = TestUtils.createTransientBlobStore();
        String containerName =
                "container-" + new Random().nextInt(Integer.MAX_VALUE);
        blobStore.createContainer(containerName);
        ByteSource payload = ByteSource.wrap(
                CONTENT.getBytes(StandardCharsets.UTF_8));
        blobStore.putBlob(TestUtils.putRequest(containerName, BLOB_NAME,
                payload).toBuilder()
                .contentType("application/json")
                .build(), payload.openStream());
        blobStore.setBlobAccess(containerName, BLOB_NAME,
                ObjectCannedACL.PUBLIC_READ);

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
        blobUri = "http://127.0.0.1:" + s3Proxy.getPort() + "/" +
                containerName + "/" + BLOB_NAME;
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
    }

    /** Reading a public object without asking for an override still works. */
    @Test
    public void testAnonymousReadKeepsStoredContentType() throws Exception {
        HttpResponse<String> response = get("");
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).isEqualTo(CONTENT);
        assertThat(response.headers().firstValue("Content-Type").orElseThrow())
                .isEqualTo("application/json");
    }

    /** Choosing the type the response claims needs a credential. */
    @Test
    public void testAnonymousContentTypeOverrideRefused() throws Exception {
        HttpResponse<String> response = get(
                "?response-content-type=text/html");
        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.body())
                .contains("<Code>InvalidRequest</Code>")
                .contains("anonymous GET requests");
    }

    @Test
    public void testAnonymousContentDispositionOverrideRefused()
            throws Exception {
        HttpResponse<String> response = get("?response-content-disposition=" +
                "attachment%3B%20filename%3Dinvoice.pdf");
        assertThat(response.statusCode()).isEqualTo(400);
    }

    /** The remaining four, which name headers of their own. */
    @Test
    public void testAnonymousOtherOverridesRefused() throws Exception {
        for (String parameter : List.of(
                "response-cache-control=no-cache",
                "response-content-encoding=gzip",
                "response-content-language=en",
                "response-expires=0")) {
            assertThat(get("?" + parameter).statusCode())
                    .as(parameter)
                    .isEqualTo(400);
        }
    }

    /** HEAD answers the same headers, and refuses the same parameters. */
    @Test
    public void testAnonymousHeadOverrideRefused() throws Exception {
        HttpResponse<Void> response = httpClient.send(
                HttpRequest.newBuilder(URI.create(blobUri +
                        "?response-content-type=text/html"))
                        .method("HEAD", HttpRequest.BodyPublishers.noBody())
                        .build(),
                HttpResponse.BodyHandlers.discarding());
        assertThat(response.statusCode()).isEqualTo(400);
    }

    private HttpResponse<String> get(String query) throws Exception {
        return httpClient.send(
                HttpRequest.newBuilder(URI.create(blobUri + query)).GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString());
    }
}
