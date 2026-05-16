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
import org.gaul.s3proxy.blobstore.domain.Blob;
import org.gaul.s3proxy.blobstore.options.GetOptions;

/**
 * BlobStore which drops ETag or date-based cache options from object requests.
 * This is useful as jclouds does not fully support the proxying of HTTP 304 responses.
 */
final class NoCacheBlobStore extends ForwardingBlobStore {

    private NoCacheBlobStore(BlobStore blobStore) {
        super(blobStore);
    }

    public static BlobStore newNoCacheBlobStore(BlobStore blobStore) {
        return new NoCacheBlobStore(blobStore);
    }

    @Override
    public Blob getBlob(String containerName, String name) {
        return getBlob(containerName, name, GetOptions.NONE);
    }

    @Override
    public Blob getBlob(String containerName, String name, GetOptions getOptions) {
        return super.getBlob(containerName, name, resetCacheHeaders(getOptions));
    }

    static GetOptions resetCacheHeaders(GetOptions options) {
        if (options.ifMatch() != null || options.ifNoneMatch() != null ||
            options.ifModifiedSince() != null ||  options.ifUnmodifiedSince() != null) {
              // as there is no exposed method to reset just the cache headers, a copy is used
            var builder = GetOptions.builder();
            for (String range : options.ranges()) {
                String[] ranges = range.split("-", 2);
                if (ranges[0].isEmpty()) {
                    builder.tail(Long.parseLong(ranges[1]));
                } else if (ranges[1].isEmpty()) {
                    builder.startAt(Long.parseLong(ranges[0]));
                } else {
                    builder.range(Long.parseLong(ranges[0]),
                            Long.parseLong(ranges[1]));
                }
            }
            return builder.build();
        }
        return options;
    }

}
