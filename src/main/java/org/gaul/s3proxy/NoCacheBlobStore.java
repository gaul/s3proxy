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

package org.gaul.s3proxy;

import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.domain.Blob;
import org.jclouds.blobstore.options.GetOptions;
import org.jclouds.blobstore.util.ForwardingBlobStore;

/**
 * BlobStore which drops eTag or date based cache options from object requests.
 * This is useful as the JClouds library does not fully support the proxying of HTTP 304 responses.
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
        return getBlob(containerName, name, new GetOptions());
    }

    @Override
    public Blob getBlob(String containerName, String name, GetOptions getOptions) {
        return super.getBlob(containerName, name, resetCacheHeaders(getOptions));
    }

    static GetOptions resetCacheHeaders(GetOptions options) {
        if (options.getIfMatch() != null || options.getIfNoneMatch() != null ||
            options.getIfModifiedSince() != null ||  options.getIfUnmodifiedSince() != null) {
              // as there is no exposed method to reset just the cache headers, a copy is used
            GetOptions optionsNoCache = new GetOptions();
            for (String range : options.getRanges()) {
                String[] ranges = range.split("-", 2);
                if (ranges[0].isEmpty()) {
                    optionsNoCache.tail(Long.parseLong(ranges[1]));
                } else if (ranges[1].isEmpty()) {
                    optionsNoCache.startAt(Long.parseLong(ranges[0]));
                } else {
                    optionsNoCache.range(Long.parseLong(ranges[0]), Long.parseLong(ranges[1]));
                }
            }
            return optionsNoCache;
        }
        return options;
    }

}
