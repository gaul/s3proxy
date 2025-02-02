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
import org.jclouds.blobstore.domain.BlobMetadata;
import org.jclouds.blobstore.domain.MultipartUpload;
import org.jclouds.blobstore.domain.Tier;
import org.jclouds.blobstore.domain.internal.BlobMetadataImpl;
import org.jclouds.blobstore.options.PutOptions;
import org.jclouds.blobstore.util.ForwardingBlobStore;
import org.jclouds.s3.domain.ObjectMetadata.StorageClass;

/**
 * This class implements a middleware to set the storage tier when creating
 * objects.  The class is configured via:
 *
 *   s3proxy.storage-class-blobstore = VALUE
 *
 * VALUE can be anything from org.jclouds.s3.domain.StorageClass, e.g.,
 * STANDARD, STANDARD_IA, GLACIER_IR, DEEP_ARCHIVE.  Some values do not
 * translate exactly due to jclouds limitations, e.g., REDUCED_REDUNDANCY maps
 * to STANDARD.  This mapping is best effort especially for non-S3 object
 * stores.
 */
public final class StorageClassBlobStore extends ForwardingBlobStore {
    private final Tier tier;

    private StorageClassBlobStore(BlobStore delegate,
            String storageClassString) {
        super(delegate);
        StorageClass storageClass;
        try {
            storageClass = StorageClass.valueOf(
                    storageClassString.toUpperCase());
        } catch (IllegalArgumentException iae) {
            storageClass = StorageClass.STANDARD;
        }
        this.tier = storageClass.toTier();
    }

    static StorageClassBlobStore newStorageClassBlobStore(BlobStore blobStore,
            String storageClass) {
        return new StorageClassBlobStore(blobStore, storageClass);
    }

    public Tier getTier() {
        return tier;
    }

    @Override
    public String putBlob(String containerName, Blob blob) {
        var newBlob = replaceTier(containerName, blob);
        return delegate().putBlob(containerName, newBlob);
    }

    @Override
    public String putBlob(String containerName, Blob blob,
            PutOptions options) {
        var newBlob = replaceTier(containerName, blob);
        return delegate().putBlob(containerName, newBlob, options);
    }

    @Override
    public MultipartUpload initiateMultipartUpload(
            String container, BlobMetadata blobMetadata, PutOptions options) {
        var newBlobMetadata = replaceTier(blobMetadata);
        return delegate().initiateMultipartUpload(container, newBlobMetadata,
                options);
    }

    private Blob replaceTier(String containerName, Blob blob) {
        var blobMeta = blob.getMetadata();
        var contentMeta = blob.getMetadata().getContentMetadata();
        return blobBuilder(containerName)
                .name(blobMeta.getName())
                .type(blobMeta.getType())
                .tier(tier)
                .userMetadata(blobMeta.getUserMetadata())
                .payload(blob.getPayload())
                .cacheControl(contentMeta.getCacheControl())
                .contentDisposition(contentMeta.getContentDisposition())
                .contentEncoding(contentMeta.getContentEncoding())
                .contentLanguage(contentMeta.getContentLanguage())
                .contentType(contentMeta.getContentType())
                .build();
    }

    private BlobMetadata replaceTier(BlobMetadata meta) {
        return new BlobMetadataImpl(meta.getProviderId(), meta.getName(),
                meta.getLocation(), meta.getUri(), meta.getETag(),
                meta.getCreationDate(), meta.getLastModified(),
                meta.getUserMetadata(), meta.getPublicUri(),
                meta.getContainer(), meta.getContentMetadata(), meta.getSize(),
                tier);
    }

    // TODO: copyBlob
}
