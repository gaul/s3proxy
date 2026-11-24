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

package org.gaul.s3proxy.azureblob;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.Iterator;
import java.util.stream.Stream;

import reactor.core.publisher.Flux;

/**
 * The body of a download, read as the buffers of its one response arrive.
 * Only a few buffers are requested ahead of the reader, so a slow client
 * holds back the download rather than heap; closing the stream cancels
 * the download, which releases its connection.  A failure while the body
 * arrives is the reader's IOException.
 */
final class ByteBufferFluxInputStream extends InputStream {
    /** How many buffers are requested ahead of the reader. */
    private static final int PREFETCH = 4;

    private final Stream<ByteBuffer> buffers;
    private final Iterator<ByteBuffer> iterator;
    private ByteBuffer current = ByteBuffer.allocate(0);
    private boolean closed;

    ByteBufferFluxInputStream(Flux<ByteBuffer> body) {
        this.buffers = body.toStream(PREFETCH);
        this.iterator = buffers.iterator();
    }

    @Override
    public int read() throws IOException {
        if (!fill()) {
            return -1;
        }
        return current.get() & 0xff;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        if (len == 0) {
            return 0;
        }
        if (!fill()) {
            return -1;
        }
        int count = Math.min(len, current.remaining());
        current.get(b, off, count);
        return count;
    }

    @Override
    public int available() {
        return closed ? 0 : current.remaining();
    }

    /** Whether a byte is to be had, taking the next buffer if needed. */
    private boolean fill() throws IOException {
        if (closed) {
            throw new IOException("stream closed");
        }
        try {
            while (!current.hasRemaining()) {
                if (!iterator.hasNext()) {
                    return false;
                }
                current = iterator.next();
            }
            return true;
        } catch (RuntimeException re) {
            // Reactor delivers the download's failure through the iterator
            throw new IOException(re);
        }
    }

    @Override
    public void close() {
        if (!closed) {
            closed = true;
            buffers.close();
        }
    }
}
