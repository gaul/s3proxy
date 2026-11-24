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

    /**
     * Few elements nest in a request and few namespaces are in scope.  The
     * parser looks a prefix up among all of those, so a body that declares
     * more is refused rather than read on.
     */
    @Test
    public void testXmlDeclarationsAndDepth() throws Exception {
        var declarations = new StringBuilder();
        for (int i = 0; i < 17; ++i) {
            declarations.append(" xmlns:p").append(i).append("=\"u\"");
        }
        for (String unknown : List.of(
                "<x" + declarations + "/>",
                "<x>".repeat(17) + "</x>".repeat(17))) {
            var response = put(bucket + "-new",
                    "<CreateBucketConfiguration>" + unknown +
                    "</CreateBucketConfiguration>");
            assertThat(response.statusCode()).as(unknown).isEqualTo(400);
            assertThat(response.body()).contains("MalformedXML");
        }
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

    /**
     * A copy source whose escapes are not UTF-8, or not escapes, is refused
     * as S3 refuses it.  Decoded leniently it named the object spelled with
     * U+FFFD instead, and copied that one where it existed.  Issue #201.
     */
    @Test
    public void testCopySourceThatDoesNotDecode() throws Exception {
        // what a lenient decoder makes of src%AE
        assertThat(put(bucket + "/src%EF%BF%BD", "content").statusCode())
                .isEqualTo(200);
        var initiate = httpClient.send(
                HttpRequest.newBuilder(URI.create(baseUri + bucket +
                        "/part-copy?uploads"))
                        .POST(HttpRequest.BodyPublishers.noBody()).build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(initiate.statusCode()).isEqualTo(200);
        String uploadId = initiate.body().replaceAll(
                "(?s).*<UploadId>(.*)</UploadId>.*", "$1");

        for (String source : List.of("/src%AE", "/src%C0%AF", "/src%ZZ",
                "/src%", "/src%A", "/src%EF%BF%BD?versionId=%AE")) {
            for (String target : List.of("/copy",
                    "/part-copy?partNumber=1&uploadId=" + uploadId)) {
                var copy = httpClient.send(
                        HttpRequest.newBuilder(URI.create(baseUri + bucket +
                                target))
                                .header("x-amz-copy-source", bucket + source)
                                .PUT(HttpRequest.BodyPublishers.noBody())
                                .build(),
                        HttpResponse.BodyHandlers.ofString());
                assertThat(copy.statusCode()).as("%s to %s", source, target)
                        .isEqualTo(400);
                assertThat(copy.body()).as("%s to %s", source, target)
                        .contains("InvalidArgument")
                        .contains("Invalid copy source encoding");
            }
        }

        // while a source that does decode is still found
        var copy = httpClient.send(
                HttpRequest.newBuilder(URI.create(baseUri + bucket + "/copy"))
                        .header("x-amz-copy-source",
                                bucket + "/src%EF%BF%BD")
                        .PUT(HttpRequest.BodyPublishers.noBody())
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(copy.statusCode()).isEqualTo(200);
        assertThat(get(bucket + "/copy", "bytes=0-").body())
                .isEqualTo("content");
    }

    /**
     * A Range that is not a range is ignored and the object served whole;
     * one that parses is served, or refused when it names no bytes.
     */
    @Test
    public void testRangeThatIsNotARange() throws Exception {
        put(bucket + "/key", "0123456789");
        for (String range : List.of("bytes=-", "bytes=a-b", "bytes=2-b",
                "bytes=--3", "bytes=2", "bytes=0-1,3-4", "lines=1-2")) {
            var get = get(bucket + "/key", range);
            assertThat(get.statusCode()).as(range).isEqualTo(200);
            assertThat(get.body()).as(range).isEqualTo("0123456789");
        }
        var partial = get(bucket + "/key", "bytes=2-4");
        assertThat(partial.statusCode()).isEqualTo(206);
        assertThat(partial.body()).isEqualTo("234");
        var toTheEnd = get(bucket + "/key",
                "bytes=8-99999999999999999999999999");
        assertThat(toTheEnd.statusCode()).isEqualTo(206);
        assertThat(toTheEnd.body()).isEqualTo("89");
        for (String range : List.of("bytes=5-2",
                "bytes=99999999999999999999999999-")) {
            var get = get(bucket + "/key", range);
            assertThat(get.statusCode()).as(range).isEqualTo(416);
            assertThat(get.body()).contains("InvalidRange");
        }
    }

    /**
     * A filesystem cannot hold both the object "a" and an object under
     * "a/".  Which of the two a write is, it is refused for what it is.
     */
    @Test
    public void testKeyAndKeyBeneathIt() throws Exception {
        assertThat(put(bucket + "/a", "content").statusCode()).isEqualTo(200);
        assertThat(put(bucket + "/c/d", "content").statusCode())
                .isEqualTo(200);
        for (String key : List.of("a/b", "a/b/c", "c")) {
            for (boolean conditional : new boolean[] {false, true}) {
                var request = HttpRequest.newBuilder(URI.create(baseUri +
                        bucket + "/" + key))
                        .PUT(HttpRequest.BodyPublishers.ofString("content"));
                if (conditional) {
                    request.header("If-None-Match", "*");
                }
                var response = httpClient.send(request.build(),
                        HttpResponse.BodyHandlers.ofString());
                assertThat(response.statusCode()).as("%s %s", key,
                        conditional).isEqualTo(400);
                assertThat(response.body()).contains("InvalidArgument");
            }
        }
        // a copy is a write like any other
        for (String key : List.of("a/b", "c")) {
            var copy = httpClient.send(
                    HttpRequest.newBuilder(URI.create(baseUri + bucket +
                            "/" + key))
                            .header("x-amz-copy-source", bucket + "/a")
                            .PUT(HttpRequest.BodyPublishers.noBody())
                            .build(),
                    HttpResponse.BodyHandlers.ofString());
            assertThat(copy.statusCode()).as(key).isEqualTo(400);
            assertThat(copy.body()).contains("InvalidArgument");
        }
        // and neither write disturbed what was there
        assertThat(get(bucket + "/a", "bytes=0-").body())
                .isEqualTo("content");
        assertThat(get(bucket + "/c/d", "bytes=0-").body())
                .isEqualTo("content");
    }

    /**
     * A key ending in a slash is kept as a directory, which holds metadata
     * and no content: content is refused rather than dropped, and the
     * marker is otherwise written like any object.
     */
    @Test
    public void testDirectoryMarker() throws Exception {
        String marker = baseUri + bucket + "/dir/";
        var withBody = put(bucket + "/dir/", "content");
        assertThat(withBody.statusCode()).isEqualTo(400);
        assertThat(withBody.body()).contains("InvalidArgument");

        assertThat(httpClient.send(HttpRequest.newBuilder(URI.create(marker))
                .header("x-amz-meta-first", "1")
                .PUT(HttpRequest.BodyPublishers.noBody()).build(),
                HttpResponse.BodyHandlers.ofString()).statusCode())
                .isEqualTo(200);
        // written again, it carries the metadata of the second write only
        assertThat(httpClient.send(HttpRequest.newBuilder(URI.create(marker))
                .header("x-amz-meta-second", "2")
                .PUT(HttpRequest.BodyPublishers.noBody()).build(),
                HttpResponse.BodyHandlers.ofString()).statusCode())
                .isEqualTo(200);
        var head = httpClient.send(HttpRequest.newBuilder(URI.create(marker))
                .method("HEAD", HttpRequest.BodyPublishers.noBody()).build(),
                HttpResponse.BodyHandlers.discarding());
        assertThat(head.statusCode()).isEqualTo(200);
        assertThat(head.headers().firstValue("x-amz-meta-second"))
                .hasValue("2");
        assertThat(head.headers().firstValue("x-amz-meta-first")).isEmpty();

        // and it is there, which a conditional create is refused for
        var conditional = httpClient.send(
                HttpRequest.newBuilder(URI.create(marker))
                        .header("If-None-Match", "*")
                        .PUT(HttpRequest.BodyPublishers.noBody()).build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(conditional.statusCode()).isEqualTo(412);
    }

    /** A multipart upload to a directory marker is refused at completion. */
    @Test
    public void testMultipartUploadToADirectoryMarker() throws Exception {
        String key = baseUri + bucket + "/dir/";
        var create = httpClient.send(
                HttpRequest.newBuilder(URI.create(key + "?uploads"))
                        .POST(HttpRequest.BodyPublishers.noBody()).build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(create.statusCode()).isEqualTo(200);
        String uploadId = create.body().replaceAll(
                "(?s).*<UploadId>(.*)</UploadId>.*", "$1");
        var part = httpClient.send(
                HttpRequest.newBuilder(URI.create(key +
                        "?partNumber=1&uploadId=" + uploadId))
                        .PUT(HttpRequest.BodyPublishers.ofString("content"))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(part.statusCode()).isEqualTo(200);
        String eTag = part.headers().firstValue("ETag").orElseThrow();
        var complete = httpClient.send(
                HttpRequest.newBuilder(URI.create(key + "?uploadId=" +
                        uploadId))
                        .POST(HttpRequest.BodyPublishers.ofString(
                                "<CompleteMultipartUpload><Part><PartNumber>" +
                                "1</PartNumber><ETag>" + eTag + "</ETag>" +
                                "</Part></CompleteMultipartUpload>"))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(complete.body()).contains("InvalidArgument");
    }

    /**
     * A doubled slash is an empty path segment, which a filesystem resolves
     * away: "a//b" is the file "a/b".  The store cannot keep it as a key
     * of its own, so it refuses it rather than write it over "a/b".
     */
    @Test
    public void testDoubledSlashKeyIsNotItsSingleSlashKey() throws Exception {
        assertThat(put(bucket + "/a/b", "single").statusCode())
                .isEqualTo(200);
        for (String key : List.of("a//b", "a///b", "a//")) {
            var response = put(bucket + "/" + key, "double");
            assertThat(response.statusCode()).as(key).isEqualTo(400);
            assertThat(response.body()).contains("InvalidArgument");
        }
        assertThat(get(bucket + "/a/b", "bytes=0-").body())
                .isEqualTo("single");
        // nor does a delete of the one remove the other
        var delete = httpClient.send(
                HttpRequest.newBuilder(URI.create(baseUri + bucket + "/a//b"))
                        .DELETE().build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(delete.statusCode()).isEqualTo(400);
        assertThat(get(bucket + "/a/b", "bytes=0-").body())
                .isEqualTo("single");
    }

    private HttpResponse<String> get(String path, String range)
            throws Exception {
        return httpClient.send(
                HttpRequest.newBuilder(URI.create(baseUri + path))
                        .header("Range", range).build(),
                HttpResponse.BodyHandlers.ofString());
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
