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

import java.util.Set;

final class Quirks {
    /** Blobstores which do not support blob-level access control. */
    static final Set<String> NO_BLOB_ACCESS_CONTROL = Set.of(
            "azureblob-sdk",
            "google-cloud-storage-sdk"
    );

    /** Blobstores which do not support the Cache-Control header. */
    static final Set<String> NO_CACHE_CONTROL_SUPPORT = Set.of(
            "google-cloud-storage-sdk"
    );

    /** Blobstores which do not support the Content-Disposition header. */
    static final Set<String> NO_CONTENT_DISPOSITION = Set.of();

    /** Blobstores which do not support the Content-Encoding header. */
    static final Set<String> NO_CONTENT_ENCODING = Set.of(
            "google-cloud-storage-sdk"
    );

    /** Blobstores which do not support the Content-Language header. */
    static final Set<String> NO_CONTENT_LANGUAGE = Set.of();

    static final Set<String> NO_EXPIRES = Set.of(
            "azureblob-sdk"
    );

    /** Blobstores which do not allow listing zero keys. */
    static final Set<String> NO_LIST_ZERO_KEYS = Set.of(
            "azureblob-sdk"
    );

    /**
     * S3 stores object metadata during initiate multipart while others
     * require it during complete multipart.  Emulate the former in the latter
     * by storing and retrieving a stub object.
     *
     * Note: azureblob-sdk also uses stubs for multipart uploads but handles
     * this internally in AzureBlobStore rather than in S3ProxyHandler.
     */
    static final Set<String> MULTIPART_REQUIRES_STUB = Set.of(
            "filesystem-nio2",
            "transient-nio2"
    );

    /** Blobstores with opaque ETags. */
    static final Set<String> OPAQUE_ETAG = Set.of(
            "azureblob-sdk",
            "google-cloud-storage-sdk"
    );

    /** Blobstores with opaque markers. */
    static final Set<String> OPAQUE_MARKERS = Set.of(
            "azureblob-sdk",
            "google-cloud-storage-sdk"
    );

    private Quirks() {
        throw new AssertionError("Intentionally unimplemented");
    }
}
