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
import java.util.Arrays;
import java.util.Base64;

import org.gaul.s3proxy.S3ErrorCode;
import org.gaul.s3proxy.S3ProxyException;
import org.jspecify.annotations.Nullable;

import software.amazon.awssdk.checksums.DefaultChecksumAlgorithm;
import software.amazon.awssdk.checksums.SdkChecksum;

/**
 * Validate an upload body against a precomputed AWS flexible checksum, sent
 * as a regular x-amz-checksum-* request header (as opposed to an aws-chunked
 * trailer, which {@link ChunkedInputStream} handles).  The checksum is
 * computed incrementally as the body is consumed and compared once the
 * declared content length is reached or end of stream is encountered,
 * whichever comes first -- a negative length is none, and leaves only the
 * end of stream; a mismatch throws {@link S3ProxyException} with
 * {@link S3ErrorCode#BAD_DIGEST}, or whichever code the caller names -- a
 * presigned URL pinning x-amz-content-sha256 reports its own.  Comparing at
 * the content-length boundary
 * rather than only at end of stream is necessary because some consumers read
 * exactly the declared number of bytes and never read the trailing -1.
 */
public final class ChecksumValidatingInputStream extends FilterInputStream {
    // FilterInputStream declares in as nullable
    private final InputStream delegate;
    private final SdkChecksum checksum;
    private final byte[] expected;
    private final long contentLength;
    private final S3ErrorCode errorCode;
    private long bytesRead;
    private boolean validated;

    public ChecksumValidatingInputStream(InputStream is, SdkChecksum checksum,
            byte[] expected, long contentLength) {
        this(is, checksum, expected, contentLength, S3ErrorCode.BAD_DIGEST);
    }

    public ChecksumValidatingInputStream(InputStream is, SdkChecksum checksum,
            byte[] expected, long contentLength, S3ErrorCode errorCode) {
        super(is);
        this.delegate = is;
        this.checksum = checksum;
        this.expected = expected.clone();
        this.contentLength = contentLength;
        this.errorCode = errorCode;
    }

    /**
     * Validate a body against its request's Content-MD5, base64 as on the
     * wire, or hand back {@code is} itself when the request carries none.
     * The handler leaves this comparison to the store, so a middleware that
     * changes the bytes on their way there -- and so has to drop the digest
     * from the request it hands on -- makes it here instead, over the bytes
     * the client sent.
     */
    public static InputStream forContentMD5(InputStream is,
            @Nullable String contentMD5, long contentLength) {
        if (contentMD5 == null) {
            return is;
        }
        return new ChecksumValidatingInputStream(is,
                SdkChecksum.forAlgorithm(DefaultChecksumAlgorithm.MD5),
                Base64.getDecoder().decode(contentMD5), contentLength);
    }

    @Override
    public int read() throws IOException {
        int b = delegate.read();
        if (b == -1) {
            validate();
        } else {
            checksum.update(b);
            ++bytesRead;
            if (lengthReached()) {
                validate();
            }
        }
        return b;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        int count = delegate.read(b, off, len);
        if (count == -1) {
            validate();
        } else if (count > 0) {
            // A read of no bytes -- InputStream.readNBytes asks for none
            // once its buffer is full -- may come after the declared length
            // was reached and the checksum finished, which then refuses an
            // update.
            checksum.update(b, off, count);
            bytesRead += count;
            if (lengthReached()) {
                validate();
            }
        }
        return count;
    }

    // The incremental hash assumes the body is consumed exactly once, so
    // forbid mark/reset rather than silently corrupting the digest.
    @Override
    public boolean markSupported() {
        return false;
    }

    /**
     * Whether the declared length has been read.  A body sent with chunked
     * transfer encoding declares none and is given as negative, which every
     * count has reached: the checksum was compared after the first read,
     * and a body that took more than one was refused for a mismatch it did
     * not have.  Such a body ends only at end of stream.
     */
    private boolean lengthReached() {
        return contentLength >= 0 && bytesRead >= contentLength;
    }

    private void validate() throws IOException {
        if (validated) {
            return;
        }
        validated = true;
        if (!Arrays.equals(expected, checksum.getChecksumBytes())) {
            throw new IOException(new S3ProxyException(errorCode));
        }
    }
}
