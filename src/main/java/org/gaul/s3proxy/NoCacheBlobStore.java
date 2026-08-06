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

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.ForwardingBlobStore;
import org.jspecify.annotations.Nullable;

import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;

/**
 * BlobStore which drops ETag or date-based cache options from object requests.
 * This is useful as the backends do not fully support the proxying of HTTP
 * 304 responses.
 */
final class NoCacheBlobStore extends ForwardingBlobStore {

    private NoCacheBlobStore(BlobStore blobStore) {
        super(blobStore);
    }

    public static BlobStore newNoCacheBlobStore(BlobStore blobStore) {
        return new NoCacheBlobStore(blobStore);
    }

    @Override
    @Nullable
    public ResponseInputStream<GetObjectResponse> getBlob(
            GetObjectRequest request) {
        return super.getBlob(resetCacheHeaders(request));
    }

    static GetObjectRequest resetCacheHeaders(GetObjectRequest request) {
        if (request.ifMatch() != null || request.ifNoneMatch() != null ||
                request.ifModifiedSince() != null ||
                request.ifUnmodifiedSince() != null) {
            return request.toBuilder()
                    .ifMatch(null)
                    .ifNoneMatch(null)
                    .ifModifiedSince(null)
                    .ifUnmodifiedSince(null)
                    .build();
        }
        return request;
    }

}
