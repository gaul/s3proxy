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

import java.util.Random;

import com.google.common.hash.HashFunction;
import com.google.common.hash.Hashing;

import org.junit.jupiter.api.Test;

@SuppressWarnings("deprecation")
public final class CrcCombineTest {
    private static final long CRC32_POLYNOMIAL = 0xedb88320L;
    private static final long CRC32C_POLYNOMIAL = 0x82f63b78L;
    private static final long CRC64NVME_POLYNOMIAL = 0x9a6c9329ac4bc9b5L;

    @Test
    public void testCombineMatchesConcatenationCrc32() throws Exception {
        checkAgainstConcatenation(CRC32_POLYNOMIAL, 32,
                bytes -> Hashing.crc32().hashBytes(bytes).padToLong());
    }

    @Test
    public void testCombineMatchesConcatenationCrc32c() throws Exception {
        checkAgainstConcatenation(CRC32C_POLYNOMIAL, 32,
                bytes -> Hashing.crc32c().hashBytes(bytes).padToLong());
    }

    @Test
    public void testCombineMatchesConcatenationCrc64Nvme() throws Exception {
        HashFunction function = Crc64Nvme.INSTANCE;
        checkAgainstConcatenation(CRC64NVME_POLYNOMIAL, 64, bytes -> {
            // Crc64Nvme hashes straight to big-endian wire order
            long value = 0;
            for (byte b : function.hashBytes(bytes).asBytes()) {
                value = (value << Byte.SIZE) | (b & 0xffL);
            }
            return value;
        });
    }

    @Test
    public void testCombineWithEmptySecondRange() throws Exception {
        long crc = Hashing.crc32().hashBytes(
                "abc".getBytes(java.nio.charset.StandardCharsets.UTF_8))
                .padToLong();
        assertThat(CrcCombine.combine(crc, 0, /*lengthB=*/ 0,
                CRC32_POLYNOMIAL, 32)).isEqualTo(crc);
    }

    private interface Crc {
        long of(byte[] bytes);
    }

    /**
     * The property the full-object multipart checksum rests on: folding the
     * CRCs of two ranges yields the CRC the concatenation would have hashed
     * to directly.
     */
    private static void checkAgainstConcatenation(long polynomial, int width,
            Crc crc) throws Exception {
        var random = new Random(/*seed=*/ 42);
        for (int i = 0; i < 200; ++i) {
            var a = new byte[random.nextInt(512)];
            var b = new byte[random.nextInt(512)];
            random.nextBytes(a);
            random.nextBytes(b);
            var concatenated = new byte[a.length + b.length];
            System.arraycopy(a, 0, concatenated, 0, a.length);
            System.arraycopy(b, 0, concatenated, a.length, b.length);

            long mask = width == 32 ? 0xffffffffL : -1L;
            assertThat(CrcCombine.combine(crc.of(a), crc.of(b), b.length,
                    polynomial, width) & mask)
                    .as("lengths %d and %d", a.length, b.length)
                    .isEqualTo(crc.of(concatenated) & mask);
        }
    }
}
