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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.zip.CRC32;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.google.common.io.BaseEncoding;

import org.junit.jupiter.api.Test;

public final class ChunkedInputStreamTest {
    private static final int MAX_CHUNK_SIZE = 64 * 1024;
    private static final String EMPTY_SHA256 =
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    private static final String HMAC = "HmacSHA256";
    private static final String TIMESTAMP = "20260101T000000Z";
    private static final String SCOPE = "20260101/us-east-1/s3/aws4_request";
    private static final String SEED_SIGNATURE =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    @Test
    public void emptyStreamReturnsEof() throws IOException {
        byte[] body = unsignedChunked(new byte[0][]);
        try (var in = new ChunkedInputStream(new ByteArrayInputStream(body),
                MAX_CHUNK_SIZE)) {
            assertThat(in.read()).isEqualTo(-1);
        }
    }

    @Test
    public void singleUnsignedChunkRoundTrips() throws IOException {
        byte[] payload = "hello, chunked world".getBytes(StandardCharsets.UTF_8);
        byte[] body = unsignedChunked(new byte[][] {payload});
        try (var in = new ChunkedInputStream(new ByteArrayInputStream(body),
                MAX_CHUNK_SIZE)) {
            assertThat(in.readAllBytes()).isEqualTo(payload);
        }
    }

    @Test
    public void multipleUnsignedChunksRoundTrip() throws IOException {
        byte[] one = "first".getBytes(StandardCharsets.UTF_8);
        byte[] two = "second".getBytes(StandardCharsets.UTF_8);
        byte[] three = "third".getBytes(StandardCharsets.UTF_8);
        byte[] body = unsignedChunked(new byte[][] {one, two, three});
        try (var in = new ChunkedInputStream(new ByteArrayInputStream(body),
                MAX_CHUNK_SIZE)) {
            assertThat(in.readAllBytes()).isEqualTo(
                    "firstsecondthird".getBytes(StandardCharsets.UTF_8));
        }
    }

    @Test
    public void chunkLargerThanMaxIsRejected() {
        byte[] tooBig = new byte[16];
        byte[] body = unsignedChunked(new byte[][] {tooBig});
        try (var in = new ChunkedInputStream(new ByteArrayInputStream(body),
                /*maxChunkSize=*/ 8)) {
            assertThatThrownBy(in::readAllBytes)
                    .isInstanceOf(IOException.class)
                    .hasMessageContaining("chunk size exceeds maximum");
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }

    @Test
    public void signedChunksRoundTrip() throws Exception {
        byte[] signingKey = deriveSigningKey("test-secret");
        byte[] payload = "signed payload".getBytes(StandardCharsets.UTF_8);
        byte[] body = signedChunked(new byte[][] {payload}, signingKey);
        try (var in = new ChunkedInputStream(new ByteArrayInputStream(body),
                MAX_CHUNK_SIZE, SEED_SIGNATURE, signingKey, HMAC, TIMESTAMP,
                SCOPE)) {
            assertThat(in.readAllBytes()).isEqualTo(payload);
        }
    }

    @Test
    public void signedChunksWithWrongSignatureAreRejected() throws Exception {
        byte[] signingKey = deriveSigningKey("test-secret");
        byte[] payload = "signed payload".getBytes(StandardCharsets.UTF_8);
        byte[] body = signedChunked(new byte[][] {payload}, signingKey);
        // Flip a bit in the signature for the first chunk by corrupting one
        // hex character on the chunk-signature line.
        int sigIdx = indexOf(body,
                "chunk-signature=".getBytes(StandardCharsets.UTF_8)) +
                "chunk-signature=".length();
        body[sigIdx] = body[sigIdx] == '0' ? (byte) '1' : (byte) '0';

        try (var in = new ChunkedInputStream(new ByteArrayInputStream(body),
                MAX_CHUNK_SIZE, SEED_SIGNATURE, signingKey, HMAC, TIMESTAMP,
                SCOPE)) {
            assertThatThrownBy(in::readAllBytes)
                    .isInstanceOf(IOException.class)
                    .hasCauseInstanceOf(S3Exception.class)
                    .cause()
                    .extracting(c -> ((S3Exception) c).getError())
                    .isEqualTo(S3ErrorCode.SIGNATURE_DOES_NOT_MATCH);
        }
    }

    @Test
    public void unsignedChunkedTrailerAfterZeroChunkValidates()
            throws IOException {
        byte[] payload = "trailer-after-zero".getBytes(StandardCharsets.UTF_8);
        byte[] body = unsignedChunkedWithTrailer(payload,
                "x-amz-checksum-crc32", crc32Base64(payload));

        try (var in = new ChunkedInputStream(new ByteArrayInputStream(body),
                MAX_CHUNK_SIZE, "x-amz-checksum-crc32")) {
            assertThat(in.readAllBytes()).isEqualTo(payload);
        }
    }

    @Test
    public void unsignedChunkedTrailerAfterZeroChunkRejectsBadHash()
            throws IOException {
        byte[] payload = "trailer-after-zero".getBytes(StandardCharsets.UTF_8);
        byte[] body = unsignedChunkedWithTrailer(payload,
                "x-amz-checksum-crc32", "AAAAAA==");

        try (var in = new ChunkedInputStream(new ByteArrayInputStream(body),
                MAX_CHUNK_SIZE, "x-amz-checksum-crc32")) {
            assertThatThrownBy(in::readAllBytes)
                    .isInstanceOf(IOException.class)
                    .hasCauseInstanceOf(S3Exception.class)
                    .cause()
                    .extracting(c -> ((S3Exception) c).getError())
                    .isEqualTo(S3ErrorCode.BAD_DIGEST);
        }
    }

    @Test
    public void unsignedChunkedTrailerWithBadHashIsRejected() throws Exception {
        byte[] payload = "some payload".getBytes(StandardCharsets.UTF_8);
        // Build wire bytes: one chunk + trailer-line (with WRONG hash) +
        // zero-chunk.
        var out = new ByteArrayOutputStream();
        appendUnsignedChunk(out, payload);
        // Trailer line with deliberately wrong CRC32.
        out.write("x-amz-checksum-crc32:AAAAAA==\r\n"
                .getBytes(StandardCharsets.UTF_8));
        // The trailer parsing path sets currentLength=0 and returns -1;
        // no zero-chunk needed.

        try (var in = new ChunkedInputStream(new ByteArrayInputStream(
                out.toByteArray()), MAX_CHUNK_SIZE,
                "x-amz-checksum-crc32")) {
            assertThatThrownBy(in::readAllBytes)
                    .isInstanceOf(IOException.class)
                    .hasCauseInstanceOf(S3Exception.class)
                    .cause()
                    .extracting(c -> ((S3Exception) c).getError())
                    .isEqualTo(S3ErrorCode.BAD_DIGEST);
        }
    }

    @Test
    public void signedChunkedWithTrailerDecodesWithoutSigningKey()
            throws Exception {
        // STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER wire format: per-chunk
        // signatures plus a checksum trailer that follows the zero-length
        // chunk.  When the proxy runs with authorization=none it decodes this
        // body without a signing key, so it must still strip the chunk
        // framing instead of storing it verbatim.
        // Regression test for https://github.com/gaul/s3proxy/issues/922
        byte[] signingKey = deriveSigningKey("test-secret");
        byte[] payload = "fileContent-none".getBytes(StandardCharsets.UTF_8);

        var out = new ByteArrayOutputStream();
        String sig = chunkSignature(SEED_SIGNATURE, signingKey, payload);
        out.write((Integer.toHexString(payload.length) + ";chunk-signature=" +
                sig + "\r\n").getBytes(StandardCharsets.UTF_8));
        out.write(payload);
        out.write("\r\n".getBytes(StandardCharsets.UTF_8));
        String zeroSig = chunkSignature(sig, signingKey, new byte[0]);
        out.write(("0;chunk-signature=" + zeroSig + "\r\n")
                .getBytes(StandardCharsets.UTF_8));
        out.write(("x-amz-checksum-crc32:" + crc32Base64(payload) + "\r\n")
                .getBytes(StandardCharsets.UTF_8));
        out.write("\r\n".getBytes(StandardCharsets.UTF_8));

        try (var in = new ChunkedInputStream(new ByteArrayInputStream(
                out.toByteArray()), MAX_CHUNK_SIZE, "x-amz-checksum-crc32")) {
            assertThat(in.readAllBytes()).isEqualTo(payload);
        }
    }

    // --- helpers ---

    private static byte[] unsignedChunked(byte[][] chunks) {
        var out = new ByteArrayOutputStream();
        try {
            for (byte[] chunk : chunks) {
                appendUnsignedChunk(out, chunk);
            }
            // zero-length terminator
            out.write("0\r\n\r\n".getBytes(StandardCharsets.UTF_8));
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
        return out.toByteArray();
    }

    private static void appendUnsignedChunk(ByteArrayOutputStream out,
            byte[] chunk) throws IOException {
        out.write((Integer.toHexString(chunk.length) + "\r\n")
                .getBytes(StandardCharsets.UTF_8));
        out.write(chunk);
        out.write("\r\n".getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] signedChunked(byte[][] chunks, byte[] signingKey)
            throws Exception {
        return signedChunkedWithTrailer(chunks, signingKey, null, null);
    }

    private static byte[] signedChunkedWithTrailer(byte[][] chunks,
            byte[] signingKey, String trailerName, String trailerValue)
            throws Exception {
        var out = new ByteArrayOutputStream();
        String previousSignature = SEED_SIGNATURE;
        for (byte[] chunk : chunks) {
            String sig = chunkSignature(previousSignature, signingKey, chunk);
            out.write((Integer.toHexString(chunk.length) +
                    ";chunk-signature=" + sig + "\r\n")
                    .getBytes(StandardCharsets.UTF_8));
            out.write(chunk);
            out.write("\r\n".getBytes(StandardCharsets.UTF_8));
            previousSignature = sig;
        }
        if (trailerName != null) {
            out.write((trailerName + ":" + trailerValue + "\r\n")
                    .getBytes(StandardCharsets.UTF_8));
        }
        // zero-length terminator
        String zeroSig = chunkSignature(previousSignature, signingKey,
                new byte[0]);
        out.write(("0;chunk-signature=" + zeroSig + "\r\n\r\n")
                .getBytes(StandardCharsets.UTF_8));
        return out.toByteArray();
    }

    private static String chunkSignature(String previousSignature,
            byte[] signingKey, byte[] chunk) throws Exception {
        String chunkHash = sha256Hex(chunk);
        String stringToSign = "AWS4-HMAC-SHA256-PAYLOAD\n" +
                TIMESTAMP + "\n" +
                SCOPE + "\n" +
                previousSignature + "\n" +
                EMPTY_SHA256 + "\n" +
                chunkHash;
        Mac mac = Mac.getInstance(HMAC);
        mac.init(new SecretKeySpec(signingKey, HMAC));
        return BaseEncoding.base16().lowerCase().encode(
                mac.doFinal(stringToSign.getBytes(StandardCharsets.UTF_8)));
    }

    private static byte[] deriveSigningKey(String secret) throws Exception {
        byte[] dateKey = hmac(("AWS4" + secret).getBytes(StandardCharsets.UTF_8),
                "20260101");
        byte[] dateRegionKey = hmac(dateKey, "us-east-1");
        byte[] dateRegionServiceKey = hmac(dateRegionKey, "s3");
        return hmac(dateRegionServiceKey, "aws4_request");
    }

    private static byte[] hmac(byte[] key, String data) throws Exception {
        Mac mac = Mac.getInstance(HMAC);
        mac.init(new SecretKeySpec(key, HMAC));
        return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }

    private static String sha256Hex(byte[] bytes) throws Exception {
        return BaseEncoding.base16().lowerCase().encode(
                MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    /**
     * Build a single-chunk aws-chunked body with a trailer line that
     * follows the zero-length chunk -- the wire format AWS SDKs actually
     * emit for STREAMING-UNSIGNED-PAYLOAD-TRAILER.
     */
    private static byte[] unsignedChunkedWithTrailer(byte[] payload,
            String trailerName, String trailerValue) {
        var out = new ByteArrayOutputStream();
        try {
            appendUnsignedChunk(out, payload);
            // zero-length chunk
            out.write("0\r\n".getBytes(StandardCharsets.UTF_8));
            out.write((trailerName + ":" + trailerValue + "\r\n")
                    .getBytes(StandardCharsets.UTF_8));
            // empty terminator
            out.write("\r\n".getBytes(StandardCharsets.UTF_8));
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
        return out.toByteArray();
    }

    private static String crc32Base64(byte[] bytes) {
        var crc = new CRC32();
        crc.update(bytes);
        return Base64.getEncoder().encodeToString(
                ByteBuffer.allocate(4).putInt((int) crc.getValue()).array());
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }
}
