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
import java.util.Arrays;

import software.amazon.awssdk.checksums.SdkChecksum;

/**
 * Validate an upload body against a precomputed AWS flexible checksum, sent
 * as a regular x-amz-checksum-* request header (as opposed to an aws-chunked
 * trailer, which {@link ChunkedInputStream} handles).  The checksum is
 * computed incrementally as the body is consumed and compared once the
 * declared content length is reached or end of stream is encountered,
 * whichever comes first; a mismatch throws {@link S3ProxyException} with
 * {@link S3ErrorCode#BAD_DIGEST}, or whichever code the caller names -- a
 * presigned URL pinning x-amz-content-sha256 reports its own.  Comparing at
 * the content-length boundary
 * rather than only at end of stream is necessary because some consumers read
 * exactly the declared number of bytes and never read the trailing -1.
 */
final class ChecksumValidatingInputStream extends FilterInputStream {
    private final SdkChecksum checksum;
    private final byte[] expected;
    private final long contentLength;
    private final S3ErrorCode errorCode;
    private long bytesRead;
    private boolean validated;

    ChecksumValidatingInputStream(InputStream is, SdkChecksum checksum,
            byte[] expected, long contentLength) {
        this(is, checksum, expected, contentLength, S3ErrorCode.BAD_DIGEST);
    }

    ChecksumValidatingInputStream(InputStream is, SdkChecksum checksum,
            byte[] expected, long contentLength, S3ErrorCode errorCode) {
        super(is);
        this.checksum = checksum;
        this.expected = expected.clone();
        this.contentLength = contentLength;
        this.errorCode = errorCode;
    }

    @Override
    public int read() throws IOException {
        int b = in.read();
        if (b == -1) {
            validate();
        } else {
            checksum.update(b);
            ++bytesRead;
            if (bytesRead >= contentLength) {
                validate();
            }
        }
        return b;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        int count = in.read(b, off, len);
        if (count == -1) {
            validate();
        } else {
            checksum.update(b, off, count);
            bytesRead += count;
            if (bytesRead >= contentLength) {
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
