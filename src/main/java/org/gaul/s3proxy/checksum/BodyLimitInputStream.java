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

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.gaul.s3proxy.S3ErrorCode;
import org.gaul.s3proxy.S3ProxyException;

/**
 * Bound a body to the length its sender declared, then read the stream
 * through to its end.
 *
 * <p>A plain limit answers end of stream the moment the count runs out,
 * which for an aws-chunked body stops one read short of the terminator the
 * trailing headers follow: the checksum a client sends as a trailer is never
 * reached, so it is neither checked against the bytes that went by nor
 * recorded for the read side to answer with.  Reading one more time closes
 * that gap -- the underlying stream parses its terminator and any trailer on
 * the way to reporting the end -- and a stream that answers with a byte
 * instead sent more body than it declared, which is refused here rather than
 * stored as though the declaration had been true.
 */
public final class BodyLimitInputStream extends FilterInputStream {
    private long remaining;

    public BodyLimitInputStream(InputStream is, long limit) {
        super(is);
        this.remaining = limit;
    }

    @Override
    public int read() throws IOException {
        if (remaining == 0) {
            return finish();
        }
        int result = in.read();
        if (result != -1) {
            --remaining;
        }
        return result;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        if (remaining == 0) {
            return finish();
        }
        int result = in.read(b, off, (int) Math.min(len, remaining));
        if (result != -1) {
            remaining -= result;
        }
        return result;
    }

    @Override
    public int available() throws IOException {
        return (int) Math.min(in.available(), remaining);
    }

    /**
     * Read past the last declared byte so the stream underneath reaches its
     * end, which is where an aws-chunked trailer is read and checked.
     */
    private int finish() throws IOException {
        if (in.read() != -1) {
            throw new IOException(new S3ProxyException(
                    S3ErrorCode.INVALID_REQUEST,
                    "The request body is longer than the length it declared."));
        }
        return -1;
    }
}
