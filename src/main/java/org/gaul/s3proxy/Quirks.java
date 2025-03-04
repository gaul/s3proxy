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

import java.util.Set;

final class Quirks {
    /** Blobstores which do not support blob-level access control. */
    static final Set<String> NO_BLOB_ACCESS_CONTROL = Set.of(
            "azureblob",
            "azureblob-sdk",
            "b2",
            "rackspace-cloudfiles-uk",
            "rackspace-cloudfiles-us",
            "openstack-swift"
    );

    /** Blobstores which do not support the Cache-Control header. */
    static final Set<String> NO_CACHE_CONTROL_SUPPORT = Set.of(
            "atmos",
            "b2",
            "google-cloud-storage",
            "rackspace-cloudfiles-uk",
            "rackspace-cloudfiles-us",
            "openstack-swift"
    );

    /** Blobstores which do not support the Cache-Control header. */
    static final Set<String> NO_CONTENT_DISPOSITION = Set.of(
            "b2"
    );

    /** Blobstores which do not support the Content-Encoding header. */
    static final Set<String> NO_CONTENT_ENCODING = Set.of(
            "b2",
            "google-cloud-storage"
    );

    /** Blobstores which do not support the Content-Language header. */
    static final Set<String> NO_CONTENT_LANGUAGE = Set.of(
            "b2",
            "rackspace-cloudfiles-uk",
            "rackspace-cloudfiles-us",
            "openstack-swift"
    );

    /** Blobstores which do not support the If-None-Match header during copy. */
    static final Set<String> NO_COPY_IF_NONE_MATCH = Set.of(
            "openstack-swift",
            "rackspace-cloudfiles-uk",
            "rackspace-cloudfiles-us"
    );

    static final Set<String> NO_EXPIRES = Set.of(
            "azureblob",
            "azureblob-sdk"
    );

    static final Set<String> NO_LIST_MULTIPART_UPLOADS = Set.of(
            "atmos",
            "filesystem",
            "google-cloud-storage",
            "openstack-swift",
            "rackspace-cloudfiles-uk",
            "rackspace-cloudfiles-us",
            "transient"
    );

    /** Blobstores which do not allow listing zero keys. */
    static final Set<String> NO_LIST_ZERO_KEYS = Set.of(
            "atmos",
            "azureblob",
            "azureblob-sdk"
    );

    /**
     * S3 stores object metadata during initiate multipart while others
     * require it during complete multipart.  Emulate the former in the latter
     * by storing and retrieving a stub object.
     */
    static final Set<String> MULTIPART_REQUIRES_STUB = Set.of(
            "azureblob",
            "azureblob-sdk",
            "filesystem",
            "filesystem-nio2",
            "google-cloud-storage",
            "openstack-swift",
            "transient",
            "transient-nio2"
    );

    /** Blobstores with opaque ETags. */
    static final Set<String> OPAQUE_ETAG = Set.of(
            "azureblob",
            "azureblob-sdk",
            "b2",
            "google-cloud-storage"
    );

    /** Blobstores with opaque markers. */
    static final Set<String> OPAQUE_MARKERS = Set.of(
            "azureblob",
            "azureblob-sdk",
            // S3 marker means one past this token while B2 means this token
            "b2",
            "google-cloud-storage"
    );

    private Quirks() {
        throw new AssertionError("Intentionally unimplemented");
    }
}
