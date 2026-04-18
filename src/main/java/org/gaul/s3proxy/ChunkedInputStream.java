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

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.annotation.Nullable;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.google.common.hash.Hasher;
import com.google.common.hash.Hashing;
import com.google.common.io.BaseEncoding;
import com.google.common.io.ByteStreams;

/**
 * Parse an AWS v4 signature chunked stream.  Reference:
 * https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html
 */
final class ChunkedInputStream extends FilterInputStream {
    private static final int MAX_LINE_LENGTH = 4096;
    private static final String EMPTY_SHA256 =
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    private byte[] chunk;
    private int currentIndex;
    private int currentLength;
    private String currentSignature;
    private final int maxChunkSize;
    private final Hasher hasher;
    @Nullable private final byte[] signingKey;
    @Nullable private final String hmacAlgorithm;
    @Nullable private final String timestamp;
    @Nullable private final String scope;
    @Nullable private String previousSignature;

    ChunkedInputStream(InputStream is, int maxChunkSize) {
        super(is);
        this.maxChunkSize = maxChunkSize;
        hasher = null;
        signingKey = null;
        hmacAlgorithm = null;
        timestamp = null;
        scope = null;
    }

    @SuppressWarnings("deprecation")
    ChunkedInputStream(InputStream is, int maxChunkSize,
            @Nullable String trailer) {
        super(is);
        this.maxChunkSize = maxChunkSize;
        if ("x-amz-checksum-crc32".equals(trailer)) {
            hasher = Hashing.crc32().newHasher();
        } else if ("x-amz-checksum-crc32c".equals(trailer)) {
            hasher = Hashing.crc32c().newHasher();
        } else if ("x-amz-checksum-sha1".equals(trailer)) {
            hasher = Hashing.sha1().newHasher();
        } else if ("x-amz-checksum-sha256".equals(trailer)) {
            hasher = Hashing.sha256().newHasher();
        } else {
            // TODO: Guava does not support x-amz-checksum-crc64nvme
            hasher = null;
        }
        signingKey = null;
        hmacAlgorithm = null;
        timestamp = null;
        scope = null;
    }

    /**
     * Construct a chunked stream that verifies the per-chunk signature chain
     * used by STREAMING-AWS4-HMAC-SHA256-PAYLOAD.
     *
     * @param seedSignature the Authorization header signature (hex-encoded)
     * @param signingKey    the AWS SigV4 signing key
     * @param hmacAlgorithm HMAC algorithm name (e.g. "HmacSHA256")
     * @param timestamp     full ISO8601 request timestamp (x-amz-date)
     * @param scope         credential scope (date/region/service/aws4_request)
     */
    ChunkedInputStream(InputStream is, int maxChunkSize,
            String seedSignature, byte[] signingKey, String hmacAlgorithm,
            String timestamp, String scope) {
        super(is);
        this.maxChunkSize = maxChunkSize;
        this.hasher = null;
        this.signingKey = signingKey.clone();
        this.hmacAlgorithm = hmacAlgorithm;
        this.timestamp = timestamp;
        this.scope = scope;
        this.previousSignature = seedSignature;
    }

    @Override
    public int read() throws IOException {
        while (currentIndex == currentLength) {
            String line = readLine(in);
            if (line.equals("")) {
                return -1;
            }
            String[] parts = line.split(";", 2);
            if (parts[0].startsWith("x-amz-checksum-")) {
                String[] checksumParts = parts[0].split(":", 2);
                var expectedHash = checksumParts[1];
                var actualHash = switch (checksumParts[0]) {
                case "x-amz-checksum-crc32", "x-amz-checksum-crc32c" -> ByteBuffer.allocate(4).putInt(hasher.hash().asInt()).array(); // Use big-endian to match AWS
                case "x-amz-checksum-sha1", "x-amz-checksum-sha256" -> hasher.hash().asBytes();
                default -> throw new IllegalArgumentException("Unknown value: " + checksumParts[0]);
                };
                if (!expectedHash.equals(Base64.getEncoder().encodeToString(actualHash))) {
                    throw new IOException(new S3Exception(S3ErrorCode.BAD_DIGEST));
                }
                currentLength = 0;
            } else {
                currentLength = Integer.parseInt(parts[0], 16);
                if (currentLength < 0 || currentLength > maxChunkSize) {
                    throw new IOException(
                            "chunk size exceeds maximum: " + currentLength);
                }
            }
            if (parts.length > 1) {
                String sigPart = parts[1];
                int eq = sigPart.indexOf('=');
                currentSignature = eq >= 0 ? sigPart.substring(eq + 1) : sigPart;
            } else {
                currentSignature = null;
            }
            chunk = new byte[currentLength];
            currentIndex = 0;
            ByteStreams.readFully(in, chunk);
            if (hasher != null) {
                hasher.putBytes(chunk);
            }
            if (signingKey != null) {
                verifyChunkSignature(chunk, currentSignature);
            }
            if (currentLength == 0) {
                return -1;
            }
            // consume trailing \r\n
            readLine(in);
        }
        return chunk[currentIndex++] & 0xFF;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        int i;
        for (i = 0; i < len; ++i) {
            int ch = read();
            if (ch == -1) {
                break;
            }
            b[off + i] = (byte) ch;
        }
        if (i == 0) {
            return -1;
        }
        return i;
    }

    private void verifyChunkSignature(byte[] data, @Nullable String signature)
            throws IOException {
        if (signature == null) {
            throw new IOException(new S3Exception(
                    S3ErrorCode.SIGNATURE_DOES_NOT_MATCH));
        }
        String chunkHash;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            chunkHash = BaseEncoding.base16().lowerCase()
                    .encode(md.digest(data));
        } catch (NoSuchAlgorithmException e) {
            throw new IOException(e);
        }
        String stringToSign = "AWS4-HMAC-SHA256-PAYLOAD\n" +
                timestamp + "\n" +
                scope + "\n" +
                previousSignature + "\n" +
                EMPTY_SHA256 + "\n" +
                chunkHash;
        String expected;
        try {
            Mac mac = Mac.getInstance(hmacAlgorithm);
            mac.init(new SecretKeySpec(signingKey, hmacAlgorithm));
            expected = BaseEncoding.base16().lowerCase().encode(
                    mac.doFinal(stringToSign.getBytes(StandardCharsets.UTF_8)));
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            throw new IOException(e);
        }
        if (!constantTimeEquals(expected, signature)) {
            throw new IOException(new S3Exception(
                    S3ErrorCode.SIGNATURE_DOES_NOT_MATCH));
        }
        previousSignature = signature;
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a.length() != b.length()) {
            return false;
        }
        int diff = 0;
        for (int i = 0; i < a.length(); i++) {
            diff |= a.charAt(i) ^ b.charAt(i);
        }
        return diff == 0;
    }

    /**
     * Read a \r\n terminated line from an InputStream.
     *
     * @return line without the newline or empty String if InputStream is empty
     */
    private static String readLine(InputStream is) throws IOException {
        var builder = new StringBuilder();
        while (true) {
            int ch = is.read();
            if (ch == '\r') {
                ch = is.read();
                if (ch == '\n') {
                    break;
                } else {
                    throw new IOException("unexpected char after \\r: " + ch);
                }
            } else if (ch == -1) {
                if (builder.length() > 0) {
                    throw new IOException("unexpected end of stream");
                }
                break;
            }
            if (builder.length() >= MAX_LINE_LENGTH) {
                throw new IOException("chunk header too long");
            }
            builder.append((char) ch);
        }
        return builder.toString();
    }
}
