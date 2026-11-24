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
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import org.gaul.s3proxy.S3ErrorCode;
import org.gaul.s3proxy.S3ProxyException;
import org.junit.jupiter.api.Test;

/**
 * A store told the length of a body may read that much and never ask for the
 * end of stream, so the body has to be judged by the time it has.
 */
public final class BodyLimitInputStreamTest {
    private static final byte[] BODY = "approved payload".getBytes(
            StandardCharsets.UTF_8);
    private static final byte[] FORGED = "EVIL EVIL EVIL!!".getBytes(
            StandardCharsets.UTF_8);
    private static final byte[] FORGED_AND_A_BYTE =
            "EVIL EVIL EVIL!!x".getBytes(StandardCharsets.UTF_8);

    @Test
    public void testExactBodyIsHandedOver() throws Exception {
        try (var is = new BodyLimitInputStream(
                new ByteArrayInputStream(BODY), BODY.length)) {
            assertThat(readExactly(is, BODY.length)).isEqualTo(BODY);
            assertThat(is.read()).isEqualTo(-1);
            assertThat(is.read(new byte[1], 0, 1)).isEqualTo(-1);
        }
    }

    @Test
    public void testLongerBodyIsRefusedWithinTheLength() throws Exception {
        try (var is = new BodyLimitInputStream(
                new ByteArrayInputStream(BODY), BODY.length - 1)) {
            assertThatThrownBy(() -> readExactly(is, BODY.length - 1))
                    .isInstanceOf(IOException.class)
                    .cause()
                    .isInstanceOfSatisfying(S3ProxyException.class,
                            e -> assertThat(e.getError()).isEqualTo(
                                    S3ErrorCode.INVALID_REQUEST));
        }
    }

    @Test
    public void testLongerBodyIsRefusedByteByByte() throws Exception {
        try (var is = new BodyLimitInputStream(
                new ByteArrayInputStream(BODY), 2)) {
            assertThat(is.read()).isEqualTo(BODY[0]);
            assertThatThrownBy(() -> is.read())
                    .isInstanceOf(IOException.class)
                    .hasCauseInstanceOf(S3ProxyException.class);
        }
    }

    /** A length of zero leaves the consumer no read to judge the body by. */
    @Test
    public void testLongerBodyIsRefusedWhenNoneWasDeclared() throws Exception {
        assertThatThrownBy(() -> new BodyLimitInputStream(
                new ByteArrayInputStream(BODY), 0))
                .isInstanceOf(IOException.class)
                .hasCauseInstanceOf(S3ProxyException.class);
        try (var is = new BodyLimitInputStream(
                new ByteArrayInputStream(new byte[0]), 0)) {
            assertThat(is.read()).isEqualTo(-1);
        }
    }

    /**
     * The hash a presigned URL pins is compared where the body the client
     * sent ends, which lies past the declared length when the body is
     * longer.
     */
    @Test
    public void testPinnedHashIsComparedWithinTheLength() throws Exception {
        try (var is = new BodyLimitInputStream(
                pinned(FORGED_AND_A_BYTE, FORGED_AND_A_BYTE.length),
                FORGED.length)) {
            assertThatThrownBy(() -> readExactly(is, FORGED.length))
                    .isInstanceOf(IOException.class)
                    .hasCauseInstanceOf(S3ProxyException.class);
        }
    }

    /** And only at the end of stream when the transfer is chunked. */
    @Test
    public void testPinnedHashIsComparedWithoutContentLength()
            throws Exception {
        try (var is = new BodyLimitInputStream(
                pinned(FORGED, -1), FORGED.length)) {
            assertThatThrownBy(() -> readExactly(is, FORGED.length))
                    .isInstanceOf(IOException.class)
                    .cause()
                    .isInstanceOfSatisfying(S3ProxyException.class,
                            e -> assertThat(e.getError()).isEqualTo(
                                    S3ErrorCode
                                            .X_AMZ_CONTENT_S_H_A_256_MISMATCH));
        }
    }

    @Test
    public void testTrailerIsComparedWithinTheLength() throws Exception {
        byte[] chunked = """
                3\r
                foo\r
                0\r
                x-amz-checksum-crc32:AAAAAA==\r
                \r
                """.getBytes(StandardCharsets.UTF_8);
        try (var is = new BodyLimitInputStream(new ChunkedInputStream(
                new ByteArrayInputStream(chunked), 1024,
                "x-amz-checksum-crc32"), 3)) {
            assertThatThrownBy(() -> readExactly(is, 3))
                    .isInstanceOf(IOException.class)
                    .cause()
                    .isInstanceOfSatisfying(S3ProxyException.class,
                            e -> assertThat(e.getError()).isEqualTo(
                                    S3ErrorCode.BAD_DIGEST));
        }
    }

    /** A body sent to a URL pinning BODY, wrapped as the handler wraps it. */
    private static InputStream pinned(byte[] sent, long contentLength) {
        var checksum = FlexChecksum.SHA256.newChecksum();
        checksum.update(BODY, 0, BODY.length);
        return new ChecksumValidatingInputStream(
                new ByteArrayInputStream(sent),
                FlexChecksum.SHA256.newChecksum(),
                checksum.getChecksumBytes(), contentLength,
                S3ErrorCode.X_AMZ_CONTENT_S_H_A_256_MISMATCH);
    }

    /**
     * Read as a store told the length does: that many bytes and not one read
     * more, which InputStream.readNBytes would make.
     */
    private static byte[] readExactly(InputStream is, int length)
            throws IOException {
        byte[] bytes = new byte[length];
        new DataInputStream(is).readFully(bytes);
        return bytes;
    }
}
