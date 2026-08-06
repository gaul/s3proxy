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

import java.io.InputStream;
import java.util.List;
import java.util.Objects;

import com.google.common.collect.ForwardingObject;
import com.google.common.hash.HashCode;

import org.gaul.s3proxy.blobstore.domain.BlobAccess;
import org.gaul.s3proxy.blobstore.domain.ContainerAccess;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.gaul.s3proxy.blobstore.options.CreateContainerOptions;
import org.gaul.s3proxy.blobstore.options.ListContainerOptions;
import org.gaul.s3proxy.blobstore.options.ListVersionsOptions;
import org.jspecify.annotations.Nullable;

import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.services.s3.model.BucketVersioningStatus;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.CopyObjectRequest;
import software.amazon.awssdk.services.s3.model.CopyObjectResponse;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.DeleteObjectResponse;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.HeadObjectRequest;
import software.amazon.awssdk.services.s3.model.HeadObjectResponse;
import software.amazon.awssdk.services.s3.model.ListBucketsResponse;
import software.amazon.awssdk.services.s3.model.ListObjectVersionsResponse;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Response;
import software.amazon.awssdk.services.s3.model.Part;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.awssdk.services.s3.model.UploadPartResponse;

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
    public void close() {
        delegate().close();
    }

    @Override
    public ListBucketsResponse list() {
        return delegate().list();
    }

    @Override
    public ListObjectsV2Response list(String container,
            ListContainerOptions options) {
        return delegate().list(container, options);
    }

    @Override
    public boolean containerExists(String container) {
        return delegate().containerExists(container);
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
    public PutObjectResponse putBlob(PutObjectRequest request,
            InputStream payload) {
        return delegate().putBlob(request, payload);
    }

    @Override
    public CopyObjectResponse copyBlob(CopyObjectRequest request) {
        return delegate().copyBlob(request);
    }

    @Override
    @Nullable
    public HeadObjectResponse blobMetadata(HeadObjectRequest request) {
        return delegate().blobMetadata(request);
    }

    @Override
    @Nullable
    public ResponseInputStream<GetObjectResponse> getBlob(
            GetObjectRequest request) {
        return delegate().getBlob(request);
    }

    @Override
    public void removeBlob(String container, String name) {
        delegate().removeBlob(container, name);
    }

    @Override
    public DeleteObjectResponse removeBlob(String container, String name,
            @Nullable String versionId) {
        return delegate().removeBlob(container, name, versionId);
    }

    @Override
    public boolean supportsVersioning() {
        return delegate().supportsVersioning();
    }

    @Override
    @Nullable
    public BucketVersioningStatus getContainerVersioning(String container) {
        return delegate().getContainerVersioning(container);
    }

    @Override
    public void setContainerVersioning(String container,
            BucketVersioningStatus status) {
        delegate().setContainerVersioning(container, status);
    }

    @Override
    public ListObjectVersionsResponse listVersions(String container,
            ListVersionsOptions options) {
        return delegate().listVersions(container, options);
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
    public MultipartUpload initiateMultipartUpload(
            CreateMultipartUploadRequest request) {
        return delegate().initiateMultipartUpload(request);
    }

    @Override
    public void abortMultipartUpload(MultipartUpload mpu) {
        delegate().abortMultipartUpload(mpu);
    }

    @Override
    public CompleteMultipartUploadResponse completeMultipartUpload(
            MultipartUpload mpu, CompleteMultipartUploadRequest request) {
        return delegate().completeMultipartUpload(mpu, request);
    }

    @Override
    public UploadPartResponse uploadMultipartPart(MultipartUpload mpu,
            int partNumber, InputStream is, long contentLength,
            @Nullable HashCode contentMD5) {
        return delegate().uploadMultipartPart(mpu, partNumber, is,
                contentLength, contentMD5);
    }

    @Override
    public List<Part> listMultipartUpload(MultipartUpload mpu) {
        return delegate().listMultipartUpload(mpu);
    }

    @Override
    public List<software.amazon.awssdk.services.s3.model.MultipartUpload>
            listMultipartUploads(String container) {
        return delegate().listMultipartUploads(container);
    }

    @Override
    public long getMinimumMultipartPartSize() {
        return delegate().getMinimumMultipartPartSize();
    }
}
