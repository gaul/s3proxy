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

import java.nio.ByteBuffer;

import org.jspecify.annotations.Nullable;

import software.amazon.awssdk.checksums.SdkChecksum;

/**
 * CRC-64/NVME, which S3 exposes as x-amz-checksum-crc64nvme.  The SDK names
 * this algorithm but computes it only through the optional aws-crt module,
 * whose native libraries would dwarf the rest of the shaded jar, so supply
 * it here and let {@link SdkChecksum} carry every other algorithm.
 *
 * <p>CRC-64/NVME is the reflected form of polynomial 0xad93d23594c93659 with
 * all-ones initial and final values.  {@link #getChecksumBytes} answers in
 * the big-endian order S3 base64-encodes, as the SDK's own checksums do.
 */
final class Crc64Nvme implements SdkChecksum {
    /** Bit-reversed 0xad93d23594c93659. */
    private static final long POLYNOMIAL = 0x9a6c9329ac4bc9b5L;
    private static final long[] TABLE = new long[256];

    static {
        for (int i = 0; i < TABLE.length; ++i) {
            long crc = i;
            for (int bit = 0; bit < 8; ++bit) {
                crc = (crc & 1) != 0 ? (crc >>> 1) ^ POLYNOMIAL : crc >>> 1;
            }
            TABLE[i] = crc;
        }
    }

    private long crc = -1L;
    /** The value {@link #reset} returns to, once {@link #mark} names one. */
    private @Nullable Long marked;

    @Override
    public void update(int b) {
        crc = TABLE[(int) ((crc ^ b) & 0xff)] ^ (crc >>> 8);
    }

    @Override
    public void update(byte[] bytes, int off, int len) {
        for (int i = 0; i < len; ++i) {
            update(bytes[off + i]);
        }
    }

    @Override
    public long getValue() {
        return ~crc;
    }

    @Override
    public void reset() {
        crc = marked == null ? -1L : marked;
    }

    @Override
    public void mark(int readLimit) {
        marked = crc;
    }

    @Override
    public byte[] getChecksumBytes() {
        return ByteBuffer.allocate(Long.BYTES).putLong(getValue()).array();
    }
}
