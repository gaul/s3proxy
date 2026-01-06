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
import java.util.Base64;

import javax.annotation.Nullable;

import com.google.common.hash.Hasher;
import com.google.common.hash.Hashing;
import com.google.common.io.ByteStreams;

/**
 * Parse an AWS v4 signature chunked stream.  Reference:
 * https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html
 */
final class ChunkedInputStream extends FilterInputStream {
    private byte[] chunk;
    private int currentIndex;
    private int currentLength;
    @edu.umd.cs.findbugs.annotations.SuppressFBWarnings(
            value = "URF_UNREAD_FIELD",
            justification = "https://github.com/gaul/s3proxy/issues/205")
    @SuppressWarnings("UnusedVariable")
    private String currentSignature;
    private final Hasher hasher;

    ChunkedInputStream(InputStream is) {
        super(is);
        hasher = null;
    }

    @SuppressWarnings("deprecation")
    ChunkedInputStream(InputStream is, @Nullable String trailer) {
        super(is);
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
            }
            if (parts.length > 1) {
                currentSignature = parts[1];
            }
            chunk = new byte[currentLength];
            currentIndex = 0;
            ByteStreams.readFully(in, chunk);
            if (hasher != null) {
                hasher.putBytes(chunk);
            }
            // TODO: check currentSignature
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
            builder.append((char) ch);
        }
        return builder.toString();
    }
}
