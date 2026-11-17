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
import java.util.List;
import java.util.Random;

import org.gaul.s3proxy.auth.AuthenticationType;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Requests no SDK will build, sent as written.  Each leaves out something
 * the handler went on to read, and was answered 500 -- which says the
 * server failed, and which a client retries -- where the request was simply
 * wrong.
 */
public final class MalformedRequestTest {
    private static final String OWNER =
            "<Owner><ID>owner</ID></Owner>";
    private static final String OWNER_GRANT =
            "<Grant><Grantee xmlns:xsi=" +
            "\"http://www.w3.org/2001/XMLSchema-instance\"" +
            " xsi:type=\"CanonicalUser\"><ID>owner</ID></Grantee>" +
            "<Permission>FULL_CONTROL</Permission></Grant>";

    private S3Proxy s3Proxy;
    private String bucket;
    private String baseUri;
    private final HttpClient httpClient = HttpClient.newHttpClient();

    @BeforeEach
    public void setUp() throws Exception {
        BlobStore blobStore = TestUtils.createTransientBlobStore();
        bucket = "bucket-" + new Random().nextInt(Integer.MAX_VALUE);
        blobStore.createContainer(bucket);

        s3Proxy = S3Proxy.builder()
                .stopTimeout(0)
                .blobStore(blobStore)
                .awsAuthentication(AuthenticationType.NONE, null, null)
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

    /** An access control policy is complete or it is refused. */
    @Test
    public void testAclMissingAnElement() throws Exception {
        put(bucket + "/key", "content");
        for (String list : List.of(
                // no Owner
                "<AccessControlList>" + OWNER_GRANT + "</AccessControlList>",
                // an Owner of no ID
                "<Owner/><AccessControlList>" + OWNER_GRANT +
                        "</AccessControlList>",
                // a Grant of no Grantee
                OWNER + "<AccessControlList><Grant><Permission>READ" +
                        "</Permission></Grant></AccessControlList>",
                // a Grantee of no type
                OWNER + "<AccessControlList><Grant><Grantee><ID>owner</ID>" +
                        "</Grantee><Permission>READ</Permission></Grant>" +
                        "</AccessControlList>",
                // a Grant of no Permission
                OWNER + "<AccessControlList><Grant><Grantee xmlns:xsi=" +
                        "\"http://www.w3.org/2001/XMLSchema-instance\"" +
                        " xsi:type=\"CanonicalUser\"><ID>owner</ID>" +
                        "</Grantee></Grant></AccessControlList>")) {
            String policy = "<AccessControlPolicy>" + list +
                    "</AccessControlPolicy>";
            for (String target : List.of(bucket, bucket + "/key")) {
                var response = put(target + "?acl", policy);
                assertThat(response.statusCode()).as(policy).isEqualTo(400);
                assertThat(response.body()).contains("MalformedACLError");
            }
        }
    }

    /** The complete policy the ones above are cut down from is accepted. */
    @Test
    public void testAclComplete() throws Exception {
        String policy = "<AccessControlPolicy>" + OWNER +
                "<AccessControlList>" + OWNER_GRANT +
                "</AccessControlList></AccessControlPolicy>";
        assertThat(put(bucket + "?acl", policy).statusCode()).isEqualTo(200);
    }

    /** Creating or completing a multipart upload takes a key. */
    @Test
    public void testMultipartUploadWithoutAKey() throws Exception {
        for (String target : List.of(bucket + "?uploads",
                bucket + "/?uploads", bucket + "?uploadId=upload")) {
            var response = httpClient.send(
                    HttpRequest.newBuilder(URI.create(baseUri + target))
                            .POST(HttpRequest.BodyPublishers.noBody())
                            .build(),
                    HttpResponse.BodyHandlers.ofString());
            assertThat(response.statusCode()).as(target).isEqualTo(405);
            assertThat(response.body()).contains("MethodNotAllowed");
        }
    }

    /**
     * A date header that is not a date is no reason to refuse a write or a
     * read; a copy-source condition that is not one is refused by name.
     */
    @Test
    public void testDateHeaderThatIsNotADate() throws Exception {
        var put = httpClient.send(
                HttpRequest.newBuilder(URI.create(baseUri + bucket + "/key"))
                        .header("Expires", "0")
                        .PUT(HttpRequest.BodyPublishers.ofString("content"))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(put.statusCode()).isEqualTo(200);

        for (String header : List.of("If-Modified-Since",
                "If-Unmodified-Since")) {
            var get = httpClient.send(
                    HttpRequest.newBuilder(URI.create(baseUri + bucket +
                            "/key")).header(header, "yesterday").build(),
                    HttpResponse.BodyHandlers.ofString());
            assertThat(get.statusCode()).as(header).isEqualTo(200);
            assertThat(get.body()).isEqualTo("content");
        }

        var copy = httpClient.send(
                HttpRequest.newBuilder(URI.create(baseUri + bucket + "/copy"))
                        .header("x-amz-copy-source", bucket + "/key")
                        .header("x-amz-copy-source-if-unmodified-since",
                                "yesterday")
                        .PUT(HttpRequest.BodyPublishers.noBody())
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(copy.statusCode()).isEqualTo(400);
        assertThat(copy.body()).contains("InvalidArgument");
    }

    private HttpResponse<String> put(String pathAndQuery, String body)
            throws Exception {
        return httpClient.send(
                HttpRequest.newBuilder(URI.create(baseUri + pathAndQuery))
                        .PUT(HttpRequest.BodyPublishers.ofString(body))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
    }
}
