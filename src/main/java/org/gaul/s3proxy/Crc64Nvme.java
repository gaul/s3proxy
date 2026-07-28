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
import java.nio.charset.Charset;

import com.google.common.hash.Funnel;
import com.google.common.hash.HashCode;
import com.google.common.hash.HashFunction;
import com.google.common.hash.Hasher;

/**
 * CRC-64/NVME, which S3 exposes as x-amz-checksum-crc64nvme.  Guava has no
 * such hash and its adapter from java.util.zip.Checksum is package-private,
 * so implement the small part of HashFunction the flexible checksum code
 * uses.
 *
 * <p>CRC-64/NVME is the reflected form of polynomial 0xad93d23594c93659 with
 * all-ones initial and final values.  Unlike Guava's 32-bit CRCs, whose
 * HashCode holds the value little-endian and needs reversing for the wire,
 * {@link Hasher#hash} here returns the digest already in the big-endian form
 * S3 base64-encodes, so {@code FlexChecksum} treats it as raw bytes.
 */
final class Crc64Nvme implements HashFunction {
    static final Crc64Nvme INSTANCE = new Crc64Nvme();

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

    private Crc64Nvme() {
    }

    @Override
    public int bits() {
        return 64;
    }

    @Override
    public Hasher newHasher() {
        return new Crc64NvmeHasher();
    }

    @Override
    public Hasher newHasher(int expectedInputSize) {
        return newHasher();
    }

    @Override
    public HashCode hashInt(int input) {
        return newHasher().putInt(input).hash();
    }

    @Override
    public HashCode hashLong(long input) {
        return newHasher().putLong(input).hash();
    }

    @Override
    public HashCode hashBytes(byte[] input) {
        return newHasher().putBytes(input).hash();
    }

    @Override
    public HashCode hashBytes(byte[] input, int off, int len) {
        return newHasher().putBytes(input, off, len).hash();
    }

    @Override
    public HashCode hashBytes(ByteBuffer input) {
        return newHasher().putBytes(input).hash();
    }

    @Override
    public HashCode hashUnencodedChars(CharSequence input) {
        return newHasher().putUnencodedChars(input).hash();
    }

    @Override
    public HashCode hashString(CharSequence input, Charset charset) {
        return newHasher().putString(input, charset).hash();
    }

    @Override
    public <T> HashCode hashObject(T instance, Funnel<? super T> funnel) {
        return newHasher().putObject(instance, funnel).hash();
    }

    private static final class Crc64NvmeHasher implements Hasher {
        private long crc = -1L;

        @Override
        public Hasher putByte(byte b) {
            crc = TABLE[(int) ((crc ^ b) & 0xff)] ^ (crc >>> 8);
            return this;
        }

        @Override
        public Hasher putBytes(byte[] bytes) {
            return putBytes(bytes, 0, bytes.length);
        }

        @Override
        public Hasher putBytes(byte[] bytes, int off, int len) {
            for (int i = 0; i < len; ++i) {
                putByte(bytes[off + i]);
            }
            return this;
        }

        @Override
        public Hasher putBytes(ByteBuffer bytes) {
            while (bytes.hasRemaining()) {
                putByte(bytes.get());
            }
            return this;
        }

        @Override
        public Hasher putShort(short s) {
            putByte((byte) s);
            return putByte((byte) (s >>> 8));
        }

        @Override
        public Hasher putInt(int i) {
            for (int shift = 0; shift < Integer.SIZE; shift += 8) {
                putByte((byte) (i >>> shift));
            }
            return this;
        }

        @Override
        public Hasher putLong(long l) {
            for (int shift = 0; shift < Long.SIZE; shift += 8) {
                putByte((byte) (l >>> shift));
            }
            return this;
        }

        @Override
        public Hasher putFloat(float f) {
            return putInt(Float.floatToRawIntBits(f));
        }

        @Override
        public Hasher putDouble(double d) {
            return putLong(Double.doubleToRawLongBits(d));
        }

        @Override
        public Hasher putBoolean(boolean b) {
            return putByte(b ? (byte) 1 : (byte) 0);
        }

        @Override
        public Hasher putChar(char c) {
            putByte((byte) c);
            return putByte((byte) (c >>> 8));
        }

        @Override
        public Hasher putUnencodedChars(CharSequence charSequence) {
            for (int i = 0; i < charSequence.length(); ++i) {
                putChar(charSequence.charAt(i));
            }
            return this;
        }

        @Override
        public Hasher putString(CharSequence charSequence, Charset charset) {
            return putBytes(charSequence.toString().getBytes(charset));
        }

        @Override
        public <T> Hasher putObject(T instance, Funnel<? super T> funnel) {
            funnel.funnel(instance, this);
            return this;
        }

        @Override
        public HashCode hash() {
            return HashCode.fromBytes(
                    ByteBuffer.allocate(Long.BYTES).putLong(~crc).array());
        }
    }
}
