/*
 * Copyright 2009-2025 The Apache Software Foundation
 * Copyright 2026 Andrew Gaul <andrew@gaul.org>
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

package org.gaul.s3proxy.blobstore;

import java.util.List;
import java.util.Objects;

import com.google.common.collect.ForwardingObject;

import org.gaul.s3proxy.blobstore.domain.Blob;
import org.gaul.s3proxy.blobstore.domain.BlobAccess;
import org.gaul.s3proxy.blobstore.domain.BlobMetadata;
import org.gaul.s3proxy.blobstore.domain.ContainerAccess;
import org.gaul.s3proxy.blobstore.domain.MultipartPart;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.gaul.s3proxy.blobstore.domain.PageSet;
import org.gaul.s3proxy.blobstore.domain.StorageMetadata;
import org.gaul.s3proxy.blobstore.options.CopyOptions;
import org.gaul.s3proxy.blobstore.options.CreateContainerOptions;
import org.gaul.s3proxy.blobstore.options.GetOptions;
import org.gaul.s3proxy.blobstore.options.ListContainerOptions;
import org.gaul.s3proxy.blobstore.options.PutOptions;

public abstract class ForwardingBlobStore extends ForwardingObject
        implements BlobStore {
    private final BlobStore blobStore;

    public ForwardingBlobStore(BlobStore blobStore) {
        this.blobStore = Objects.requireNonNull(blobStore);
    }

    @Override
    public BlobStore delegate() {
        return blobStore;
    }

    @Override
    public PageSet<? extends StorageMetadata> list() {
        return delegate().list();
    }

    @Override
    public PageSet<? extends StorageMetadata> list(String container) {
        return delegate().list(container);
    }

    @Override
    public PageSet<? extends StorageMetadata> list(String container,
            ListContainerOptions options) {
        return delegate().list(container, options);
    }

    @Override
    public boolean containerExists(String container) {
        return delegate().containerExists(container);
    }

    @Override
    public boolean createContainer(String container) {
        return delegate().createContainer(container);
    }

    @Override
    public boolean createContainer(String container,
            CreateContainerOptions createContainerOptions) {
        return delegate().createContainer(container, createContainerOptions);
    }

    @Override
    public ContainerAccess getContainerAccess(String container) {
        return delegate().getContainerAccess(container);
    }

    @Override
    public void setContainerAccess(String container, ContainerAccess
            containerAccess) {
        delegate().setContainerAccess(container, containerAccess);
    }

    @Override
    public void clearContainer(String container) {
        delegate().clearContainer(container);
    }

    @Override
    public void clearContainer(String container, ListContainerOptions options) {
        delegate().clearContainer(container, options);
    }

    @Override
    public void deleteContainer(String container) {
        delegate().deleteContainer(container);
    }

    @Override
    public boolean deleteContainerIfEmpty(String container) {
        return delegate().deleteContainerIfEmpty(container);
    }

    @Override
    public boolean blobExists(String container, String name) {
        return delegate().blobExists(container, name);
    }

    @Override
    public String putBlob(String containerName, Blob blob) {
        return delegate().putBlob(containerName, blob);
    }

    @Override
    public String putBlob(String containerName, Blob blob,
            PutOptions putOptions) {
        return delegate().putBlob(containerName, blob, putOptions);
    }

    @Override
    public String copyBlob(String fromContainer, String fromName,
            String toContainer, String toName, CopyOptions options) {
        return delegate().copyBlob(fromContainer, fromName, toContainer,
                toName, options);
    }

    @Override
    public BlobMetadata blobMetadata(String container, String name) {
        return delegate().blobMetadata(container, name);
    }

    @Override
    public Blob getBlob(String containerName, String blobName) {
        return delegate().getBlob(containerName, blobName);
    }

    @Override
    public Blob getBlob(String containerName, String blobName,
            GetOptions getOptions) {
        return delegate().getBlob(containerName, blobName, getOptions);
    }

    @Override
    public void removeBlob(String container, String name) {
        delegate().removeBlob(container, name);
    }

    @Override
    public void removeBlobs(String container, Iterable<String> iterable) {
        delegate().removeBlobs(container, iterable);
    }

    @Override
    public BlobAccess getBlobAccess(String container, String name) {
        return delegate().getBlobAccess(container, name);
    }

    @Override
    public void setBlobAccess(String container, String name,
            BlobAccess access) {
        delegate().setBlobAccess(container, name, access);
    }

    @Override
    public MultipartUpload initiateMultipartUpload(String container,
            BlobMetadata blobMetadata, PutOptions options) {
        return delegate().initiateMultipartUpload(container, blobMetadata,
                options);
    }

    @Override
    public void abortMultipartUpload(MultipartUpload mpu) {
        delegate().abortMultipartUpload(mpu);
    }

    @Override
    public String completeMultipartUpload(MultipartUpload mpu,
            List<MultipartPart> parts) {
        return delegate().completeMultipartUpload(mpu, parts);
    }

    @Override
    public MultipartPart uploadMultipartPart(MultipartUpload mpu,
            int partNumber, Payload payload) {
        return delegate().uploadMultipartPart(mpu, partNumber, payload);
    }

    @Override
    public List<MultipartPart> listMultipartUpload(MultipartUpload mpu) {
        return delegate().listMultipartUpload(mpu);
    }

    @Override
    public List<MultipartUpload> listMultipartUploads(String container) {
        return delegate().listMultipartUploads(container);
    }

    @Override
    public long getMinimumMultipartPartSize() {
        return delegate().getMinimumMultipartPartSize();
    }

    @Override
    public long getMaximumMultipartPartSize() {
        return delegate().getMaximumMultipartPartSize();
    }
}
