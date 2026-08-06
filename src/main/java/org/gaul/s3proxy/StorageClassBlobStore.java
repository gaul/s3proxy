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

import java.io.InputStream;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.ForwardingBlobStore;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;

import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.awssdk.services.s3.model.StorageClass;

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
    public PutObjectResponse putBlob(PutObjectRequest request,
            InputStream payload) {
        return delegate().putBlob(request.toBuilder()
                .storageClass(storageClass)
                .build(), payload);
    }

    @Override
    public MultipartUpload initiateMultipartUpload(
            CreateMultipartUploadRequest request) {
        return delegate().initiateMultipartUpload(request.toBuilder()
                .storageClass(storageClass)
                .build());
    }

    // TODO: copyBlob
}
