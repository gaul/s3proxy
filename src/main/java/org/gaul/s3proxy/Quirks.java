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

public final class Quirks {
    /** Blobstores which do not support blob-level access control. */
    public static final Set<String> NO_BLOB_ACCESS_CONTROL = Set.of(
            "azureblob",
            "openstack-swift"
    );

    /** Blobstores which do not support the Cache-Control header. */
    public static final Set<String> NO_CACHE_CONTROL_SUPPORT = Set.of(
            "google-cloud-storage",
            "openstack-swift",
            "sftp"
    );

    /** Blobstores which do not support the Content-Encoding header. */
    public static final Set<String> NO_CONTENT_ENCODING = Set.of(
            "google-cloud-storage",
            "sftp"
    );

    /** Blobstores which do not support the Content-Language header. */
    public static final Set<String> NO_CONTENT_LANGUAGE = Set.of(
            "openstack-swift",
            "sftp"
    );

    /**
     * Blobstores which store only the object bytes.  SFTP servers offer no
     * portable user extended attributes, so everything the nio2 stores keep
     * in xattrs -- content metadata, user metadata, ETags, checksums,
     * storage class, and directory-marker identity -- does not survive the
     * write, and reads report defaults instead.
     */
    public static final Set<String> NO_PERSISTED_METADATA = Set.of(
            "sftp"
    );

    /**
     * The stores built on AbstractNio2BlobStore.  They share path and
     * listing semantics -- directory markers, the reserved "/" key,
     * relative-path rejection -- which the nio2-specific tests pin on
     * every member.
     */
    public static final Set<String> NIO2_BACKENDS = Set.of(
            "filesystem",
            "sftp",
            "transient"
    );

    /**
     * S3 stores object metadata during initiate multipart while others
     * require it during complete multipart.  Emulate the former in the latter
     * by storing and retrieving a stub object.
     *
     * Note: azureblob also uses stubs for multipart uploads but handles
     * this internally in AzureBlobStore rather than in S3ProxyHandler.
     */
    public static final Set<String> MULTIPART_REQUIRES_STUB = Set.of(
            "filesystem",
            "sftp",
            "transient"
    );

    /**
     * Blobstores that evaluate If-None-Match as they write the blob, so
     * S3Proxy must not check the condition itself beforehand.  If-Match is not
     * among them: it needs a compare-and-swap the filesystem cannot offer.
     */
    public static final Set<String> NATIVE_IF_NONE_MATCH = Set.of(
            "filesystem",
            "transient"
    );

    /**
     * Blobstores whose completeMultipartUpload evaluates the conditional
     * headers itself.  This is not the same set as for a plain put: GCS
     * compose can only require that the target be absent, and Swift's
     * manifest PUT only honours If-None-Match: *, so neither can answer a
     * condition naming an ETag.
     */
    public static final Set<String> NATIVE_CONDITIONAL_COMPLETE = Set.of(
            "aws-s3",
            "azureblob",
            "filesystem",
            "transient"
    );

    /** Blobstores with opaque ETags. */
    public static final Set<String> OPAQUE_ETAG = Set.of(
            "azureblob",
            "google-cloud-storage"
    );

    /**
     * Blobstores whose list marker is a token they issue rather than a key,
     * so that a caller paging with the last key it was given needs the
     * frontend to substitute the marker that produced it.
     */
    public static final Set<String> OPAQUE_MARKERS = Set.of(
            "azureblob"
    );

    /**
     * Blobstores that cannot grant anonymous writes: Azure public access is
     * read-only by definition and Swift write ACLs cannot name a referrer.
     * Both refuse public-read-write rather than grant half of it.
     */
    public static final Set<String> NO_PUBLIC_WRITE_ACCESS = Set.of(
            "azureblob",
            "openstack-swift"
    );

    private Quirks() {
        throw new AssertionError("Intentionally unimplemented");
    }
}
