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
import java.util.Base64;
import java.util.Random;

import org.gaul.s3proxy.auth.AuthenticationType;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.checksum.FlexChecksum;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * A flexible checksum may ride as an aws-chunked trailer rather than a
 * header, which is what an SDK sends by default and what minio-go sends for
 * "mc cp --checksum".  It is read only once the body it describes has gone
 * by: the bytes must still be checked against it, the value must still reach
 * the response and the stored object, and the frames it arrived in must not
 * reach the object.
 */
public final class TrailerChecksumTest {
    private static final byte[] CONTENT =
            "the body this describes\n".getBytes(StandardCharsets.UTF_8);

    private S3Proxy s3Proxy;
    private BlobStore blobStore;
    private String container;
    private String baseUri;
    private String checksum;
    private final HttpClient httpClient = HttpClient.newHttpClient();

    @BeforeEach
    public void setUp() throws Exception {
        blobStore = TestUtils.createTransientBlobStore();
        container = "container-" + new Random().nextInt(Integer.MAX_VALUE);
        blobStore.createContainer(container);

        var digest = FlexChecksum.CRC32C.newChecksum();
        digest.update(CONTENT, 0, CONTENT.length);
        checksum = Base64.getEncoder().encodeToString(
                digest.getChecksumBytes());

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

    @AfterEach
    public void tearDown() throws Exception {
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
    }

    /** The value reaches the response and the stored object, as on S3. */
    @Test
    public void testTrailerChecksumReportedAndStored() throws Exception {
        HttpResponse<String> response = put("object", checksum);

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.headers().firstValue("x-amz-checksum-crc32c"))
                .hasValue(checksum);

        var head = send(HttpRequest.newBuilder(URI.create(baseUri + "/object"))
                .header("x-amz-checksum-mode", "ENABLED")
                .method("HEAD", HttpRequest.BodyPublishers.noBody()));
        assertThat(head.headers().firstValue("x-amz-checksum-crc32c"))
                .hasValue(checksum);
    }

    /** The body arrives decoded, without the frames it was sent in. */
    @Test
    public void testChunkedBodyIsDecoded() throws Exception {
        assertThat(put("object", checksum).statusCode()).isEqualTo(200);

        var get = send(HttpRequest.newBuilder(
                URI.create(baseUri + "/object")).GET());
        assertThat(get.body()).isEqualTo(
                new String(CONTENT, StandardCharsets.UTF_8));
    }

    /**
     * A trailer that does not describe the bytes is refused, and refused
     * before the object lands rather than after.
     */
    @Test
    public void testWrongTrailerChecksumRejected() throws Exception {
        HttpResponse<String> response = put("object", "AAAAAA==");

        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.body()).contains("BadDigest");
        assertThat(blobStore.blobExists(container, "object")).isFalse();
    }

    /**
     * minio-go pads the trailer line with a newline of its own, which S3
     * accepts.
     */
    @Test
    public void testTrailerValueIsTrimmed() throws Exception {
        assertThat(put("object", checksum + "\n").statusCode()).isEqualTo(200);
    }

    /** Writes the body in one aws-chunked frame with the trailer given. */
    private HttpResponse<String> put(String key, String trailerValue)
            throws Exception {
        String body = Integer.toHexString(CONTENT.length) + "\r\n" +
                new String(CONTENT, StandardCharsets.UTF_8) + "\r\n0\r\n" +
                "x-amz-checksum-crc32c:" + trailerValue + "\r\n\r\n";
        return send(HttpRequest.newBuilder(URI.create(baseUri + "/" + key))
                .header("Content-Type", "application/octet-stream")
                .header("Content-Encoding", "aws-chunked")
                .header("x-amz-content-sha256",
                        "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
                .header("x-amz-decoded-content-length",
                        String.valueOf(CONTENT.length))
                .header("x-amz-trailer", "x-amz-checksum-crc32c")
                .PUT(HttpRequest.BodyPublishers.ofString(body)));
    }

    private HttpResponse<String> send(HttpRequest.Builder builder)
            throws Exception {
        return httpClient.send(builder.build(),
                HttpResponse.BodyHandlers.ofString());
    }
}
