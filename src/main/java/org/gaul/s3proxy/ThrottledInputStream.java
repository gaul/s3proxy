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

final class ThrottledInputStream extends FilterInputStream {
    private final Long speed;

    ThrottledInputStream(InputStream is, Long speed) {
        super(is);
        this.speed = speed;
    }

    @Override
    public int read() throws IOException {
        int b = super.read();
        if (b != -1) {
            simulateLatency(1);
        }
        return b;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        int n = super.read(b, off, len);
        if (n != -1) {
            simulateLatency(n);
        }
        return n;
    }

    private void simulateLatency(int size) {
        if (size == 0 || speed == null) {
            return;
        }
        try {
            Thread.sleep(size / speed, (int) (size % speed) * 1_000_000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
