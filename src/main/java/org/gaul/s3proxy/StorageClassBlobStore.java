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
import org.gaul.s3proxy.blobstore.domain.BlobMetadata;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.gaul.s3proxy.blobstore.domain.StorageClass;
import org.gaul.s3proxy.blobstore.options.PutOptions;

/**
 * This class implements a middleware to set the storage class when creating
 * objects.  The class is configured via:
 *
 *   s3proxy.storage-class-blobstore = VALUE
 *
 * VALUE can be any S3 storage class name, e.g., STANDARD, STANDARD_IA,
 * GLACIER_IR, DEEP_ARCHIVE. This mapping is best effort especially for
 * non-S3 object stores.
 */
public final class StorageClassBlobStore extends ForwardingBlobStore {
    private final StorageClass storageClass;

    private StorageClassBlobStore(BlobStore delegate,
            String storageClassString) {
        super(delegate);
        StorageClass parsed;
        try {
            parsed = StorageClass.valueOf(storageClassString.toUpperCase());
        } catch (IllegalArgumentException iae) {
            parsed = StorageClass.STANDARD;
        }
        this.storageClass = parsed;
    }

    static StorageClassBlobStore newStorageClassBlobStore(BlobStore blobStore,
            String storageClass) {
        return new StorageClassBlobStore(blobStore, storageClass);
    }

    public StorageClass getStorageClass() {
        return storageClass;
    }

    @Override
    public String putBlob(String containerName, Blob blob) {
        var newBlob = replaceStorageClass(blob);
        return delegate().putBlob(containerName, newBlob);
    }

    @Override
    public String putBlob(String containerName, Blob blob,
            PutOptions options) {
        var newBlob = replaceStorageClass(blob);
        return delegate().putBlob(containerName, newBlob, options);
    }

    @Override
    public MultipartUpload initiateMultipartUpload(
            String container, BlobMetadata blobMetadata, PutOptions options) {
        var newBlobMetadata = replaceStorageClass(blobMetadata);
        return delegate().initiateMultipartUpload(container, newBlobMetadata,
                options);
    }

    private Blob replaceStorageClass(Blob blob) {
        var blobMeta = blob.getMetadata();
        var contentMeta = blob.getMetadata().getContentMetadata();
        var builder = Blob.builder(blobMeta.name())
                .storageClass(storageClass)
                .userMetadata(blobMeta.userMetadata())
                .payload(blob.getPayload())
                .cacheControl(contentMeta.cacheControl())
                .contentDisposition(contentMeta.contentDisposition())
                .contentEncoding(contentMeta.contentEncoding())
                .contentLanguage(contentMeta.contentLanguage())
                .contentMD5(contentMeta.contentMD5())
                .contentType(contentMeta.contentType())
                .expires(contentMeta.expires());
        Long contentLength = contentMeta.contentLength();
        if (contentLength != null) {
            builder.contentLength(contentLength);
        }
        return builder.build();
    }

    private BlobMetadata replaceStorageClass(BlobMetadata meta) {
        return meta.toBuilder().storageClass(storageClass).build();
    }

    // TODO: copyBlob
}
