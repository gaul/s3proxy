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

import java.util.List;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.ForwardingBlobStore;
import org.gaul.s3proxy.blobstore.Payload;
import org.gaul.s3proxy.blobstore.domain.Blob;
import org.gaul.s3proxy.blobstore.domain.BlobAccess;
import org.gaul.s3proxy.blobstore.domain.BlobMetadata;
import org.gaul.s3proxy.blobstore.domain.ContainerAccess;
import org.gaul.s3proxy.blobstore.domain.MultipartPart;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.gaul.s3proxy.blobstore.options.CopyOptions;
import org.gaul.s3proxy.blobstore.options.CreateContainerOptions;
import org.gaul.s3proxy.blobstore.options.ListContainerOptions;
import org.gaul.s3proxy.blobstore.options.PutOptions;

/** This class is a BlobStore wrapper which prevents mutating operations. */
final class ReadOnlyBlobStore extends ForwardingBlobStore {
    private ReadOnlyBlobStore(BlobStore blobStore) {
        super(blobStore);
    }

    static BlobStore newReadOnlyBlobStore(BlobStore blobStore) {
        return new ReadOnlyBlobStore(blobStore);
    }

    @Override
    public boolean createContainer(String container,
            CreateContainerOptions options) {
        throw new UnsupportedOperationException("read-only BlobStore");
    }

    @Override
    public void setContainerAccess(String container,
            ContainerAccess containerAccess) {
        throw new UnsupportedOperationException("read-only BlobStore");
    }

    @Override
    public void clearContainer(String container) {
        throw new UnsupportedOperationException("read-only BlobStore");
    }

    @Override
    public void clearContainer(String container, ListContainerOptions options) {
        throw new UnsupportedOperationException("read-only BlobStore");
    }

    @Override
    public void deleteContainer(String container) {
        throw new UnsupportedOperationException("read-only BlobStore");
    }

    @Override
    public boolean deleteContainerIfEmpty(String container) {
        throw new UnsupportedOperationException("read-only BlobStore");
    }

    @Override
    public String putBlob(String containerName, Blob blob) {
        throw new UnsupportedOperationException("read-only BlobStore");
    }

    @Override
    public String putBlob(final String containerName, Blob blob,
            final PutOptions options) {
        throw new UnsupportedOperationException("read-only BlobStore");
    }

    @Override
    public void removeBlob(final String containerName, final String blobName) {
        throw new UnsupportedOperationException("read-only BlobStore");
    }

    @Override
    public void removeBlobs(final String containerName,
            final Iterable<String> blobNames) {
        throw new UnsupportedOperationException("read-only BlobStore");
    }

    @Override
    public void setBlobAccess(String container, String name,
            BlobAccess access) {
        throw new UnsupportedOperationException("read-only BlobStore");
    }

    @Override
    public String copyBlob(final String fromContainer, final String fromName,
            final String toContainer, final String toName,
            final CopyOptions options) {
        throw new UnsupportedOperationException("read-only BlobStore");
    }

    @Override
    public MultipartUpload initiateMultipartUpload(String container,
            BlobMetadata blobMetadata, PutOptions options) {
        throw new UnsupportedOperationException("read-only BlobStore");
    }

    @Override
    public void abortMultipartUpload(MultipartUpload mpu) {
        throw new UnsupportedOperationException("read-only BlobStore");
    }

    @Override
    public String completeMultipartUpload(final MultipartUpload mpu,
            final List<MultipartPart> parts) {
        throw new UnsupportedOperationException("read-only BlobStore");
    }

    @Override
    public MultipartPart uploadMultipartPart(MultipartUpload mpu,
            int partNumber, Payload payload) {
        throw new UnsupportedOperationException("read-only BlobStore");
    }
}
