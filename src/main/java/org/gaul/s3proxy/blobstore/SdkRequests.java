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

package org.gaul.s3proxy.blobstore;

import java.util.List;

import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.jspecify.annotations.Nullable;

import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.CompletedMultipartUpload;
import software.amazon.awssdk.services.s3.model.CompletedPart;
import software.amazon.awssdk.services.s3.model.ObjectCannedACL;

/**
 * Helpers for the SDK request types the {@link BlobStore} SPI consumes.
 * Requests carry the Range header verbatim, e.g. bytes=0-9; backends that
 * emulate ranges parse it with {@link #parseRange}.
 */
public final class SdkRequests {

    private SdkRequests() {
        throw new AssertionError("intentionally not implemented");
    }

    /**
     * One bytes= range.  A suffix range bytes=-N is (null, N); an open
     * range bytes=A- is (A, null).
     */
    public record ByteRange(@Nullable Long first, @Nullable Long last) {
    }

    /** Formats a closed range request header. */
    public static String range(long first, long last) {
        return "bytes=" + first + "-" + last;
    }

    /**
     * A request's canned ACL normalized to the two states the SPI
     * supports: PUBLIC_READ, or PRIVATE for anything else including none.
     */
    public static ObjectCannedACL aclOrPrivate(
            @Nullable ObjectCannedACL acl) {
        return acl == ObjectCannedACL.PUBLIC_READ ? acl :
                ObjectCannedACL.PRIVATE;
    }

    /** An unconditional completion request asserting {@code parts}. */
    public static CompleteMultipartUploadRequest completeRequest(
            MultipartUpload mpu, List<CompletedPart> parts) {
        return CompleteMultipartUploadRequest.builder()
                .bucket(mpu.containerName())
                .key(mpu.blobName())
                .uploadId(mpu.id())
                .multipartUpload(CompletedMultipartUpload.builder()
                        .parts(parts)
                        .build())
                .build();
    }

    /**
     * Parses a request's Range header, or returns null when there is none.
     * Throws the 416 InvalidRange shape on a range no backend can serve:
     * bad syntax, multiple ranges, or negative offsets.
     */
    @Nullable
    public static ByteRange parseRange(@Nullable String range) {
        if (range == null) {
            return null;
        }
        if (!range.startsWith("bytes=")) {
            throw S3Exceptions.fromStatusCode(416);
        }
        String spec = range.substring("bytes=".length());
        if (spec.indexOf(',') != -1 || spec.indexOf('-') == -1) {
            throw S3Exceptions.fromStatusCode(416);
        }
        String[] firstLast = spec.split("-", 2);
        try {
            Long first = firstLast[0].isEmpty() ? null :
                    Long.parseLong(firstLast[0]);
            Long last = firstLast[1].isEmpty() ? null :
                    Long.parseLong(firstLast[1]);
            if ((first == null && last == null) ||
                    (first != null && first < 0) ||
                    (last != null && last < 0)) {
                throw S3Exceptions.fromStatusCode(416);
            }
            return new ByteRange(first, last);
        } catch (NumberFormatException nfe) {
            throw S3Exceptions.fromStatusCode(416, nfe);
        }
    }
}
