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

package org.gaul.s3proxy.checksum;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import org.gaul.s3proxy.S3ProxyException;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.checksums.DefaultChecksumAlgorithm;
import software.amazon.awssdk.checksums.SdkChecksum;

public final class ChecksumValidatingInputStreamTest {
    private static final byte[] BODY = "the body of the request".getBytes(
            StandardCharsets.UTF_8);

    /**
     * A body of no declared length, as chunked transfer encoding sends, is
     * judged where it ends and not after the first bytes of it.
     */
    @Test
    public void testUnknownLengthIsJudgedAtEndOfStream() throws Exception {
        try (var is = validating(BODY, checksumOf(BODY), -1)) {
            assertThat(readInPieces(is)).isEqualTo(BODY);
        }
    }

    @Test
    public void testUnknownLengthStillCatchesAMismatch() throws Exception {
        try (var is = validating(BODY, checksumOf(new byte[0]), -1)) {
            assertThatThrownBy(() -> readInPieces(is))
                    .isInstanceOf(IOException.class)
                    .hasCauseInstanceOf(S3ProxyException.class);
        }
    }

    /** A declared length is judged as its last byte is read. */
    @Test
    public void testKnownLengthIsJudgedAtTheLength() throws Exception {
        try (var is = validating(BODY, checksumOf(new byte[0]),
                BODY.length)) {
            var buffer = new byte[BODY.length];
            assertThatThrownBy(() -> is.read(buffer, 0, buffer.length))
                    .isInstanceOf(IOException.class);
        }
    }

    private static InputStream validating(byte[] body, byte[] expected,
            long contentLength) {
        return new ChecksumValidatingInputStream(
                new ByteArrayInputStream(body), newChecksum(), expected,
                contentLength);
    }

    private static byte[] readInPieces(InputStream is) throws IOException {
        var out = new java.io.ByteArrayOutputStream();
        var buffer = new byte[5];
        int count;
        while ((count = is.read(buffer, 0, buffer.length)) != -1) {
            out.write(buffer, 0, count);
        }
        return out.toByteArray();
    }

    private static byte[] checksumOf(byte[] body) {
        SdkChecksum checksum = newChecksum();
        checksum.update(body, 0, body.length);
        return checksum.getChecksumBytes();
    }

    private static SdkChecksum newChecksum() {
        return SdkChecksum.forAlgorithm(DefaultChecksumAlgorithm.CRC32);
    }
}
