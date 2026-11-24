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
 * stored as though the declaration had been true.  A stream that ends before
 * the count runs out sent less, and is refused likewise.
 *
 * <p>That one more read is made here, by the read that takes the last
 * declared byte and before the byte is handed over, rather than left to the
 * consumer.  A store told the length may read that much and never ask for
 * the end of stream -- aws-s3 and azureblob do -- and would by then hold
 * every byte of a body that was longer than it declared, or that a stream
 * underneath refuses only at its own end: a trailer that does not match, or
 * the payload hash a presigned URL pins, which is compared where the body
 * the client sent ends and not where the part of it that was declared does.
 */
public final class BodyLimitInputStream extends FilterInputStream {
    // FilterInputStream declares in as nullable
    private final InputStream delegate;
    private long remaining;
    private boolean ended;

    public BodyLimitInputStream(InputStream is, long limit)
            throws IOException {
        super(is);
        this.delegate = is;
        this.remaining = limit;
        if (limit == 0) {
            // No declared byte for a read to take, so none to look for the
            // end along with: a store told the length is zero reads nothing.
            finish();
        }
    }

    @Override
    public int read() throws IOException {
        if (remaining == 0) {
            return finish();
        }
        int result = delegate.read();
        if (result == -1) {
            throw shorterThanDeclared();
        }
        --remaining;
        if (remaining == 0) {
            finish();
        }
        return result;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        if (remaining == 0) {
            return finish();
        }
        int result = delegate.read(b, off, (int) Math.min(len, remaining));
        if (result == -1) {
            throw shorterThanDeclared();
        }
        remaining -= result;
        if (remaining == 0) {
            finish();
        }
        return result;
    }

    /**
     * The stream ended with declared bytes still owed.  Passing the end
     * along would hand the store fewer bytes than the length it was told,
     * and it is left to each store whether that is an error or an object.
     */
    private IOException shorterThanDeclared() {
        return new IOException(new S3ProxyException(
                S3ErrorCode.INCOMPLETE_BODY,
                "The request body is shorter than the length it declared."));
    }

    @Override
    public int available() throws IOException {
        return (int) Math.min(delegate.available(), remaining);
    }

    /**
     * Read past the last declared byte so the stream underneath reaches its
     * end, which is where an aws-chunked trailer is read and checked.  The
     * end is looked for once: a consumer's own read past the last declared
     * byte, if it makes one, is answered from here.
     */
    private int finish() throws IOException {
        if (ended) {
            return -1;
        }
        if (delegate.read() != -1) {
            throw new IOException(new S3ProxyException(
                    S3ErrorCode.INVALID_REQUEST,
                    "The request body is longer than the length it declared."));
        }
        ended = true;
        return -1;
    }
}
