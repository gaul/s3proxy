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

import java.io.ByteArrayOutputStream;
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
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * An upload created with a checksum algorithm and no checksum type is a
 * composite one, and stays composite however the completion request spells
 * the value it asserts: S3 reads x-amz-checksum-* there only as the finished
 * object's checksum -- never as the request body's -- and takes the
 * composite with its "-&lt;partCount&gt;" suffix left off, which is how
 * minio-go spells it.  Reading a value of that shape as a full-object
 * checksum instead answered BadDigest to every such upload.
 */
public final class CompositeChecksumCompletionTest {
    /** S3 refuses a part under 5 MB unless it is the last one. */
    private static final byte[] PART_ONE = new byte[5 * 1024 * 1024];
    private static final byte[] PART_TWO =
            "second part\n".getBytes(StandardCharsets.UTF_8);

    static {
        new Random(0).nextBytes(PART_ONE);
    }

    private S3Proxy s3Proxy;
    private String baseUri;
    private final HttpClient httpClient = HttpClient.newHttpClient();

    @BeforeEach
    public void setUp() throws Exception {
        BlobStore blobStore = TestUtils.createTransientBlobStore();
        String container = "container-" + new Random().nextInt(
                Integer.MAX_VALUE);
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
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
    }

    /** The composite without its suffix is the value the object has. */
    @Test
    public void testCompletionAcceptsCompositeWithoutSuffix()
            throws Exception {
        HttpResponse<String> response = complete("object",
                composite(/*suffix=*/ false));

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).contains(
                "<ChecksumCRC32C>" + composite(/*suffix=*/ true) +
                "</ChecksumCRC32C>");
        assertThat(response.body()).contains(
                "<ChecksumType>COMPOSITE</ChecksumType>");
    }

    /** And with the suffix, which is how S3 itself spells it. */
    @Test
    public void testCompletionAcceptsCompositeWithSuffix() throws Exception {
        assertThat(complete("object", composite(/*suffix=*/ true))
                .statusCode()).isEqualTo(200);
    }

    /** A value that is neither is still refused. */
    @Test
    public void testCompletionRefusesOtherValue() throws Exception {
        HttpResponse<String> response = complete("object", "AAAAAA==");

        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.body()).contains("BadDigest");
    }

    /** Asserting nothing leaves the object with the checksum it has. */
    @Test
    public void testCompletionWithoutAssertion() throws Exception {
        HttpResponse<String> response = complete("object", null);

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).contains(
                "<ChecksumCRC32C>" + composite(/*suffix=*/ true) +
                "</ChecksumCRC32C>");
    }

    /**
     * Runs an upload of two parts through to completion, asserting {@code
     * assertedValue} on the completion request when it is not null.
     */
    private HttpResponse<String> complete(String key,
            @Nullable String assertedValue)
            throws Exception {
        var initiate = send(HttpRequest.newBuilder(
                URI.create(baseUri + "/" + key + "?uploads"))
                .header("Content-Type", "application/octet-stream")
                .header("x-amz-checksum-algorithm", "CRC32C")
                .POST(HttpRequest.BodyPublishers.noBody()));
        assertThat(initiate.statusCode()).isEqualTo(200);
        String uploadId = between(initiate.body(), "<UploadId>", "</UploadId>");

        var xml = new StringBuilder("<CompleteMultipartUpload>");
        byte[][] parts = {PART_ONE, PART_TWO};
        for (int i = 0; i < parts.length; i++) {
            int partNumber = i + 1;
            var part = send(HttpRequest.newBuilder(URI.create(baseUri + "/" +
                    key + "?partNumber=" + partNumber + "&uploadId=" +
                    uploadId))
                    .header("Content-Type", "application/octet-stream")
                    .header("x-amz-checksum-crc32c", digest(parts[i]))
                    .PUT(HttpRequest.BodyPublishers.ofByteArray(parts[i])));
            assertThat(part.statusCode()).isEqualTo(200);
            xml.append("<Part><PartNumber>").append(partNumber)
                    .append("</PartNumber><ETag>")
                    .append(part.headers().firstValue("ETag").orElseThrow())
                    .append("</ETag><ChecksumCRC32C>").append(digest(parts[i]))
                    .append("</ChecksumCRC32C></Part>");
        }
        xml.append("</CompleteMultipartUpload>");

        var builder = HttpRequest.newBuilder(URI.create(baseUri + "/" + key +
                "?uploadId=" + uploadId))
                .header("Content-Type", "application/xml")
                .POST(HttpRequest.BodyPublishers.ofString(xml.toString()));
        if (assertedValue != null) {
            builder.header("x-amz-checksum-crc32c", assertedValue);
        }
        return send(builder);
    }

    /** The base64 CRC32C of one part, as the client asserts it. */
    private static String digest(byte[] content) {
        var checksum = FlexChecksum.CRC32C.newChecksum();
        checksum.update(content, 0, content.length);
        return Base64.getEncoder().encodeToString(checksum.getChecksumBytes());
    }

    /** The CRC32C of the parts' concatenated digests, S3's composite. */
    private static String composite(boolean suffix) throws Exception {
        var digests = new ByteArrayOutputStream();
        for (byte[] part : new byte[][] {PART_ONE, PART_TWO}) {
            digests.write(Base64.getDecoder().decode(digest(part)));
        }
        var checksum = FlexChecksum.CRC32C.newChecksum();
        checksum.update(digests.toByteArray(), 0, digests.size());
        return Base64.getEncoder().encodeToString(
                checksum.getChecksumBytes()) + (suffix ? "-2" : "");
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
