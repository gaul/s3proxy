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
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Properties;
import java.util.Random;

import org.gaul.s3proxy.auth.AuthenticationType;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.middleware.Middlewares;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * The checksum a completion request names for a part is a statement about
 * that part, and S3 refuses the completion when the part is another one,
 * as it does for the ETag.  The value used to be read for its presence
 * only: the parts were hashed again and the completion answered 200 with
 * the composite of what they really were, so whoever could upload a part
 * decided what was published under a completion that named other content.
 */
public final class MultipartPartChecksumTest {
    private static final byte[] UPLOADED =
            "uploaded".getBytes(StandardCharsets.UTF_8);
    private static final byte[] APPROVED =
            "approved".getBytes(StandardCharsets.UTF_8);

    private S3Proxy s3Proxy;
    private String baseUri;
    private String uploadId;
    private String eTag;
    private final HttpClient httpClient = HttpClient.newHttpClient();

    @AfterEach
    public void tearDown() throws Exception {
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
    }

    /** A part that is not the one named is refused, and nothing published. */
    @Test
    public void testWrongPartChecksumIsRefused() throws Exception {
        start(/*nullStore=*/ false);
        upload();

        HttpResponse<String> response = complete(digest(APPROVED));

        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.body()).contains("InvalidPart");
        assertThat(send(HttpRequest.newBuilder(URI.create(baseUri +
                "/object")).GET()).statusCode()).isEqualTo(404);

        // the upload is still there for a completion that names the part
        response = complete(digest(UPLOADED));

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).contains("<ChecksumSHA256>" +
                digest(Base64.getDecoder().decode(digest(UPLOADED))) +
                "-1</ChecksumSHA256>");
    }

    /** One that is no checksum at all is refused too. */
    @Test
    public void testMalformedPartChecksumIsRefused() throws Exception {
        start(/*nullStore=*/ false);
        upload();

        HttpResponse<String> response = complete("not base64");

        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.body()).contains("BadDigest");
    }

    /**
     * The null store keeps no part, and reads zeros back for one: nothing
     * the client names for a part it sent can be held to those.
     */
    @Test
    public void testNullStoreHoldsNoPartToItsChecksum() throws Exception {
        start(/*nullStore=*/ true);
        upload();

        assertThat(complete(digest(UPLOADED)).statusCode()).isEqualTo(200);
    }

    private void start(boolean nullStore) throws Exception {
        BlobStore blobStore = TestUtils.createTransientBlobStore();
        String container = "container-" + new Random().nextInt(
                Integer.MAX_VALUE);
        blobStore.createContainer(container);
        if (nullStore) {
            var properties = new Properties();
            properties.setProperty(S3ProxyConstants.PROPERTY_NULL_BLOBSTORE,
                    "true");
            blobStore = Middlewares.wrap(blobStore, properties, unused -> {
                throw new AssertionError("no second backend is configured");
            });
        }

        s3Proxy = S3Proxy.builder()
                .stopTimeout(0)
                .blobStore(blobStore)
                .awsAuthentication(AuthenticationType.NONE, "identity",
                        "credential")
                .endpoint(URI.create("http://127.0.0.1:0"))
                .build();
        s3Proxy.start();
        while (!s3Proxy.getState().equals("STARTED")) {
            Thread.sleep(10);
        }
        baseUri = "http://127.0.0.1:" + s3Proxy.getPort() + "/" + container;
    }

    /** Starts an upload of one part, {@link #UPLOADED}. */
    private void upload() throws Exception {
        var initiate = send(HttpRequest.newBuilder(
                URI.create(baseUri + "/object?uploads"))
                .header("Content-Type", "application/octet-stream")
                .header("x-amz-checksum-algorithm", "SHA256")
                .POST(HttpRequest.BodyPublishers.noBody()));
        assertThat(initiate.statusCode()).isEqualTo(200);
        uploadId = between(initiate.body(), "<UploadId>", "</UploadId>");

        var part = send(HttpRequest.newBuilder(URI.create(baseUri +
                "/object?partNumber=1&uploadId=" + uploadId))
                .header("Content-Type", "application/octet-stream")
                .PUT(HttpRequest.BodyPublishers.ofByteArray(UPLOADED)));
        assertThat(part.statusCode()).isEqualTo(200);
        eTag = part.headers().firstValue("ETag").orElseThrow();
    }

    /** Completes the upload, naming {@code checksum} for its part. */
    private HttpResponse<String> complete(String checksum) throws Exception {
        return send(HttpRequest.newBuilder(URI.create(baseUri +
                "/object?uploadId=" + uploadId))
                .header("Content-Type", "application/xml")
                .POST(HttpRequest.BodyPublishers.ofString(
                        "<CompleteMultipartUpload><Part>" +
                        "<PartNumber>1</PartNumber><ETag>" + eTag +
                        "</ETag><ChecksumSHA256>" + checksum +
                        "</ChecksumSHA256></Part>" +
                        "</CompleteMultipartUpload>")));
    }

    /** The base64 SHA-256 of {@code content}, as a client names it. */
    private static String digest(byte[] content) throws Exception {
        return Base64.getEncoder().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(content));
    }

    private static String between(String body, String open, String close) {
        int start = body.indexOf(open) + open.length();
        return body.substring(start, body.indexOf(close, start));
    }

    private HttpResponse<String> send(HttpRequest.Builder builder)
            throws Exception {
        return httpClient.send(builder.build(),
                HttpResponse.BodyHandlers.ofString());
    }
}
