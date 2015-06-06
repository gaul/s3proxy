/*
 * Copyright 2014-2015 Andrew Gaul <andrew@gaul.org>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.gaul.s3proxy;

import java.io.IOException;
import java.io.InputStream;
import java.util.Random;

import com.google.common.io.ByteSource;

final class TestUtils {
    private TestUtils() {
        throw new AssertionError("intentionally unimplemented");
    }

    static ByteSource randomByteSource() {
        return randomByteSource(0);
    }

    static ByteSource randomByteSource(long seed) {
        return new RandomByteSource(seed);
    }

    private static class RandomByteSource extends ByteSource {
        private final long seed;

        RandomByteSource(long seed) {
            this.seed = seed;
        }

        @Override
        public InputStream openStream() {
            return new RandomInputStream(seed);
        }
    }

    private static class RandomInputStream extends InputStream {
        private final Random random;
        private boolean closed;

        RandomInputStream(long seed) {
            this.random = new Random(seed);
        }

        @Override
        public synchronized int read() throws IOException {
            if (closed) {
                throw new IOException("Stream already closed");
            }
            return (byte) random.nextInt();
        }

        @Override
        public synchronized int read(byte[] b) throws IOException {
            return read(b, 0, b.length);
        }

        @Override
        public synchronized int read(byte[] b, int off, int len)
                throws IOException {
            for (int i = 0; i < len; ++i) {
                b[off + i] = (byte) read();
            }
            return len;
        }

        @Override
        public void close() throws IOException {
            super.close();
            closed = true;
        }
    }
}
