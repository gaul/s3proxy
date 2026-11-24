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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Random;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import com.google.common.primitives.Bytes;

import org.gaul.s3proxy.auth.AuthenticationType;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.ForwardingBlobStore;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.gaul.s3proxy.checksum.FlexChecksum;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;

/**
 * A completion that asserts x-amz-checksum-* is checked against the content
 * of the parts, which the store then assembles by name.  A part uploaded
 * again between the two was published under the checksum computed from its
 * predecessor, so whoever signed that checksum onto a presigned completion
 * had approved one object and got another.  The completion now holds the
 * parts as they are, and the part that arrives meanwhile waits and finds the
 * upload gone.
 */
public final class MultipartCompletionPartSwapTest {
    /** S3 refuses a part under 5 MB unless it is the last one. */
    private static final byte[] APPROVED = new byte[5 * 1024 * 1024];
    private static final byte[] SUBSTITUTE = new byte[5 * 1024 * 1024];
    private static final byte[] LAST =
            "last part\n".getBytes(StandardCharsets.UTF_8);
    private static final String KEY = "object";

    static {
        new Random(0).nextBytes(APPROVED);
        new Random(1).nextBytes(SUBSTITUTE);
    }

    private final HttpClient httpClient = HttpClient.newHttpClient();
    private final CountDownLatch hashingLastPart = new CountDownLatch(1);
    private final CountDownLatch proceed = new CountDownLatch(1);
    private BlobStore blobStore;
    private String container;
    private S3Proxy s3Proxy;
    private String baseUri;

    @BeforeEach
    public void setUp() throws Exception {
        // Stops the completion where the attack needs it: the first part
        // has been hashed and the last one is about to be.
        blobStore = new ForwardingBlobStore(
                TestUtils.createTransientBlobStore()) {
            @Override
            public ResponseInputStream<GetObjectResponse> getMultipartPart(
                    MultipartUpload mpu, int partNumber) {
                if (partNumber == 2) {
                    hashingLastPart.countDown();
                    try {
                        proceed.await();
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        throw new RuntimeException(ie);
                    }
                }
                return super.getMultipartPart(mpu, partNumber);
            }
        };
        container = TestUtils.createRandomContainerName();
        blobStore.createContainer(container);

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
        proceed.countDown();
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
    }

    @Test
    public void testPartReplacedDuringCompletionIsNotPublished()
            throws Exception {
        var initiate = httpClient.send(HttpRequest.newBuilder(
                URI.create(baseUri + "/" + KEY + "?uploads"))
                .header("x-amz-checksum-algorithm", "SHA256")
                .POST(HttpRequest.BodyPublishers.noBody()).build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(initiate.statusCode()).isEqualTo(200);
        String uploadId = between(initiate.body(), "<UploadId>",
                "</UploadId>");

        var xml = new StringBuilder("<CompleteMultipartUpload>");
        byte[][] parts = {APPROVED, LAST};
        for (int i = 0; i < parts.length; i++) {
            var part = httpClient.send(uploadPart(uploadId, i + 1, parts[i]),
                    HttpResponse.BodyHandlers.ofString());
            assertThat(part.statusCode()).isEqualTo(200);
            xml.append("<Part><PartNumber>").append(i + 1)
                    .append("</PartNumber><ETag>")
                    .append(part.headers().firstValue("ETag").orElseThrow())
                    .append("</ETag><ChecksumSHA256>")
                    .append(digest(parts[i]))
                    .append("</ChecksumSHA256></Part>");
        }
        xml.append("</CompleteMultipartUpload>");

        var completing = httpClient.sendAsync(HttpRequest.newBuilder(
                URI.create(baseUri + "/" + KEY + "?uploadId=" + uploadId))
                .header("x-amz-checksum-sha256", composite(APPROVED, LAST))
                .POST(HttpRequest.BodyPublishers.ofString(xml.toString()))
                .build(), HttpResponse.BodyHandlers.ofString());
        assertThat(hashingLastPart.await(30, TimeUnit.SECONDS)).isTrue();

        var replacing = httpClient.sendAsync(
                uploadPart(uploadId, 1, SUBSTITUTE),
                HttpResponse.BodyHandlers.ofString());
        assertThatThrownBy(() -> replacing.get(500, TimeUnit.MILLISECONDS))
                .isInstanceOf(TimeoutException.class);
        proceed.countDown();

        var completed = completing.get(30, TimeUnit.SECONDS);
        assertThat(completed.statusCode()).isEqualTo(200);
        assertThat(completed.body()).contains(
                "<ChecksumSHA256>" + composite(APPROVED, LAST) +
                "</ChecksumSHA256>");
        var replaced = replacing.get(30, TimeUnit.SECONDS);
        assertThat(replaced.statusCode()).isEqualTo(404);
        assertThat(replaced.body()).contains("NoSuchUpload");

        var object = httpClient.send(HttpRequest.newBuilder(
                URI.create(baseUri + "/" + KEY)).build(),
                HttpResponse.BodyHandlers.ofByteArray());
        assertThat(object.statusCode()).isEqualTo(200);
        assertThat(object.body()).isEqualTo(Bytes.concat(APPROVED, LAST));
        // and the part that came too late is not left behind
        assertThat(blobStore.listMultipartUpload(new MultipartUpload(uploadId,
                CreateMultipartUploadRequest.builder()
                        .bucket(container).key(KEY).build()))).isEmpty();
    }

    private HttpRequest uploadPart(String uploadId, int partNumber,
            byte[] content) {
        return HttpRequest.newBuilder(URI.create(baseUri + "/" + KEY +
                "?partNumber=" + partNumber + "&uploadId=" + uploadId))
                .PUT(HttpRequest.BodyPublishers.ofByteArray(content))
                .build();
    }

    /** The base64 SHA-256 of one part. */
    private static String digest(byte[] content) {
        var checksum = FlexChecksum.SHA256.newChecksum();
        checksum.update(content, 0, content.length);
        return Base64.getEncoder().encodeToString(checksum.getChecksumBytes());
    }

    /** The SHA-256 of the parts' concatenated digests, S3's composite. */
    private static String composite(byte[]... parts) throws Exception {
        var digests = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            digests.write(Base64.getDecoder().decode(digest(part)));
        }
        return digest(digests.toByteArray()) + "-" + parts.length;
    }

    private static String between(String body, String open, String close) {
        int start = body.indexOf(open) + open.length();
        return body.substring(start, body.indexOf(close, start));
    }
}
