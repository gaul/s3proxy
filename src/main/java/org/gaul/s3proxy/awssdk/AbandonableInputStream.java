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

package org.gaul.s3proxy.awssdk;

import java.io.FilterInputStream;
import java.io.IOException;

import org.jspecify.annotations.Nullable;

import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.core.exception.SdkException;

/**
 * An object read that its reader may give up on.  Closing the SDK's stream
 * before its end reads the remainder from the service, however long, so that
 * the connection can be reused.  Only a short remainder is worth that, e.g.,
 * the padding the encrypted blobstore leaves unread; past one this aborts the
 * response instead, which gives up the connection with it.
 */
final class AbandonableInputStream extends FilterInputStream {
    /** The most that close reads for the sake of keeping the connection. */
    private static final int DRAIN_LIMIT = 64 * 1024;

    // FilterInputStream declares in as nullable
    private final ResponseInputStream<?> response;
    private boolean atEnd;
    private boolean closed;

    AbandonableInputStream(ResponseInputStream<?> response) {
        super(response);
        this.response = response;
    }

    @Override
    public int read() throws IOException {
        int b = response.read();
        atEnd |= b == -1;
        return b;
    }

    @Override
    public int read(byte @Nullable [] b, int off, int len)
            throws IOException {
        int count = response.read(b, off, len);
        atEnd |= count == -1;
        return count;
    }

    @Override
    public void close() throws IOException {
        if (closed) {
            return;
        }
        closed = true;
        if (atEnd || drain()) {
            response.close();
        } else {
            response.abort();
        }
    }

    /** Whether the remainder was short enough to read to its end. */
    private boolean drain() {
        try {
            return response.readNBytes(DRAIN_LIMIT).length < DRAIN_LIMIT;
        } catch (IOException | SdkException e) {
            // a remainder that cannot be read is not worth waiting for
            return false;
        }
    }
}
