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

/**
 * Combine the CRCs of two byte ranges into the CRC of their concatenation,
 * which is what lets a full-object multipart checksum be derived from the
 * per-part checksums without re-reading the parts.
 *
 * <p>This is zlib's {@code crc32_combine} generalized over the polynomial
 * width.  It holds for any reflected CRC whose initial and final values are
 * all ones -- the shape CRC-32, CRC-32C and CRC-64/NVME share -- and it
 * operates on the finished CRC values, since that conditioning cancels.
 *
 * <p>S3 allows a full-object checksum only for those three, and not for
 * SHA-1 or SHA-256, precisely because no such combination exists for a
 * cryptographic hash.
 */
final class CrcCombine {
    private CrcCombine() {
        throw new AssertionError("intentionally unimplemented");
    }

    /**
     * Returns crc(A || B) given crc(A), crc(B) and the length of B in bytes.
     *
     * @param polynomial the CRC's reflected polynomial
     * @param width the CRC width in bits, 32 or 64
     */
    static long combine(long crcA, long crcB, long lengthB, long polynomial,
            int width) {
        if (lengthB <= 0) {
            return crcA;
        }

        // operator for a single zero bit, then squared to reach one zero
        // byte, from which the operators for 2, 4, 8 ... bytes follow
        long[] odd = new long[width];
        long[] even = new long[width];
        odd[0] = polynomial;
        long row = 1;
        for (int n = 1; n < width; ++n) {
            odd[n] = row;
            row <<= 1;
        }
        square(even, odd);
        square(odd, even);

        // apply the operators for the set bits of lengthB, which shifts
        // crc(A) forward by exactly that many zero bytes
        long crc = crcA;
        long length = lengthB;
        while (true) {
            square(even, odd);
            if ((length & 1) != 0) {
                crc = times(even, crc);
            }
            length >>>= 1;
            if (length == 0) {
                break;
            }
            square(odd, even);
            if ((length & 1) != 0) {
                crc = times(odd, crc);
            }
            length >>>= 1;
            if (length == 0) {
                break;
            }
        }
        return crc ^ crcB;
    }

    /** Multiply the GF(2) vector by the matrix, i.e. XOR the selected rows. */
    private static long times(long[] matrix, long vector) {
        long sum = 0;
        long remaining = vector;
        for (int i = 0; remaining != 0; ++i) {
            if ((remaining & 1) != 0) {
                sum ^= matrix[i];
            }
            remaining >>>= 1;
        }
        return sum;
    }

    /** Square the GF(2) matrix, doubling the length it steps over. */
    private static void square(long[] result, long[] matrix) {
        for (int n = 0; n < matrix.length; ++n) {
            result[n] = times(matrix, matrix[n]);
        }
    }
}
