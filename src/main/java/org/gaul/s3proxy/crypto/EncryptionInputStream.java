/*
 * Copyright 2014-2025 Andrew Gaul <andrew@gaul.org>
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

package org.gaul.s3proxy.crypto;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;

import javax.crypto.spec.IvParameterSpec;

public class EncryptionInputStream extends InputStream {

    private final int part;
    private final IvParameterSpec iv;
    private boolean hasPadding;
    private long size;
    private InputStream in;

    public EncryptionInputStream(InputStream in, int part,
        IvParameterSpec iv) {
        this.part = part;
        this.iv = iv;
        this.in = in;
    }

    // Padding (64 byte)
    // Delimiter (8 byte)
    // IV (16 byte)
    // Part (4 byte)
    // Size (8 byte)
    // Version (2 byte)
    // Reserved (26 byte)
    final void padding() throws IOException {
        if (in != null) {
            in.close();
        }

        if (!hasPadding) {
            ByteBuffer bb = ByteBuffer.allocate(Constants.PADDING_BLOCK_SIZE);
            bb.put(Constants.DELIMITER);
            bb.put(iv.getIV());
            bb.putInt(part);
            bb.putLong(size);
            bb.putShort(Constants.VERSION);

            in = new ByteArrayInputStream(bb.array());
            hasPadding = true;
        } else {
            in = null;
        }
    }

    @Override
    public final int available() throws IOException {
        if (in == null) {
            return 0; // no way to signal EOF from available()
        }
        return in.available();
    }

    @Override
    public final int read() throws IOException {
        while (in != null) {
            int c = in.read();
            if (c != -1) {
                size++;
                return c;
            }
            padding();
        }
        return -1;
    }

    @Override
    public final int read(byte[] b, int off, int len) throws IOException {
        if (in == null) {
            return -1;
        } else if (b == null) {
            throw new NullPointerException();
        } else if (off < 0 || len < 0 || len > b.length - off) {
            throw new IndexOutOfBoundsException();
        } else if (len == 0) {
            return 0;
        }
        do {
            int n = in.read(b, off, len);
            if (n > 0) {
                size = size + n;
                return n;
            }
            padding();
        } while (in != null);
        return -1;
    }

    @Override
    public final void close() throws IOException {
        IOException ioe = null;
        while (in != null) {
            try {
                in.close();
            } catch (IOException e) {
                if (ioe == null) {
                    ioe = e;
                } else {
                    ioe.addSuppressed(e);
                }
            }
            padding();
        }
        if (ioe != null) {
            throw ioe;
        }
    }
}
