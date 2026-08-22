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

import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.jspecify.annotations.Nullable;

import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.services.s3.model.BucketCannedACL;
import software.amazon.awssdk.services.s3.model.BucketVersioningStatus;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.CopyObjectRequest;
import software.amazon.awssdk.services.s3.model.CopyObjectResponse;
import software.amazon.awssdk.services.s3.model.CreateBucketRequest;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.DeleteObjectResponse;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.HeadObjectRequest;
import software.amazon.awssdk.services.s3.model.HeadObjectResponse;
import software.amazon.awssdk.services.s3.model.ListBucketsResponse;
import software.amazon.awssdk.services.s3.model.ListObjectVersionsRequest;
import software.amazon.awssdk.services.s3.model.ListObjectVersionsResponse;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Response;
import software.amazon.awssdk.services.s3.model.ObjectCannedACL;
import software.amazon.awssdk.services.s3.model.Part;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.awssdk.services.s3.model.ServerSideEncryptionConfiguration;
import software.amazon.awssdk.services.s3.model.UploadPartRequest;
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
    public ListObjectsV2Response list(ListObjectsV2Request request) {
        return delegate().list(request);
    }

    @Override
    public boolean containerExists(String container) {
        return delegate().containerExists(container);
    }

    @Override
    public boolean createContainer(CreateBucketRequest request) {
        return delegate().createContainer(request);
    }

    @Override
    public BucketCannedACL getContainerAccess(String container) {
        return delegate().getContainerAccess(container);
    }

    @Override
    public void setContainerAccess(String container, BucketCannedACL
            containerAccess) {
        delegate().setContainerAccess(container, containerAccess);
    }

    @Override
    public void clearContainer(ListObjectsV2Request request) {
        delegate().clearContainer(request);
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
    public DeleteObjectResponse removeBlob(DeleteObjectRequest request) {
        return delegate().removeBlob(request);
    }

    @Override
    public boolean supportsVersioning() {
        return delegate().supportsVersioning();
    }

    @Override
    public boolean supportsServerSideEncryption() {
        return delegate().supportsServerSideEncryption();
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
    public ListObjectVersionsResponse listVersions(
            ListObjectVersionsRequest request) {
        return delegate().listVersions(request);
    }

    @Override
    public boolean supportsBucketEncryption() {
        return delegate().supportsBucketEncryption();
    }

    @Override
    public ServerSideEncryptionConfiguration getContainerEncryption(
            String container) {
        return delegate().getContainerEncryption(container);
    }

    @Override
    public void setContainerEncryption(String container,
            ServerSideEncryptionConfiguration configuration) {
        delegate().setContainerEncryption(container, configuration);
    }

    @Override
    public void deleteContainerEncryption(String container) {
        delegate().deleteContainerEncryption(container);
    }

    @Override
    public ObjectCannedACL getBlobAccess(String container, String name) {
        return delegate().getBlobAccess(container, name);
    }

    @Override
    public ObjectCannedACL getBlobAccess(String container, String name,
            @Nullable String versionId) {
        return delegate().getBlobAccess(container, name, versionId);
    }

    @Override
    public void setBlobAccess(String container, String name,
            ObjectCannedACL access) {
        delegate().setBlobAccess(container, name, access);
    }

    @Override
    public void setBlobAccess(String container, String name,
            ObjectCannedACL access, @Nullable String versionId) {
        delegate().setBlobAccess(container, name, access, versionId);
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
            UploadPartRequest request, InputStream is) {
        return delegate().uploadMultipartPart(mpu, request, is);
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
