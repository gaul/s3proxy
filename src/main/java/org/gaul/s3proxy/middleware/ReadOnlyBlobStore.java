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

package org.gaul.s3proxy.middleware;

import java.io.InputStream;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.ForwardingBlobStore;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.jspecify.annotations.Nullable;

import software.amazon.awssdk.services.s3.model.BucketCannedACL;
import software.amazon.awssdk.services.s3.model.BucketVersioningStatus;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.CopyObjectRequest;
import software.amazon.awssdk.services.s3.model.CopyObjectResponse;
import software.amazon.awssdk.services.s3.model.CreateBucketRequest;
import software.amazon.awssdk.services.s3.model.CreateBucketResponse;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.DeleteObjectResponse;
import software.amazon.awssdk.services.s3.model.DeleteObjectsRequest;
import software.amazon.awssdk.services.s3.model.DeleteObjectsResponse;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.ObjectCannedACL;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.awssdk.services.s3.model.ServerSideEncryptionConfiguration;
import software.amazon.awssdk.services.s3.model.UploadPartRequest;
import software.amazon.awssdk.services.s3.model.UploadPartResponse;

/** This class is a BlobStore wrapper which prevents mutating operations. */
final class ReadOnlyBlobStore extends ForwardingBlobStore {
    private ReadOnlyBlobStore(BlobStore blobStore) {
        super(blobStore);
    }

    static BlobStore newReadOnlyBlobStore(BlobStore blobStore) {
        return new ReadOnlyBlobStore(blobStore);
    }

    @Override
    public CreateBucketResponse createContainer(CreateBucketRequest request) {
        throw new UnsupportedOperationException("read-only BlobStore");
    }

    @Override
    public void setContainerAccess(String container,
            BucketCannedACL containerAccess) {
        throw new UnsupportedOperationException("read-only BlobStore");
    }

    @Override
    public void clearContainer(ListObjectsV2Request request) {
        throw new UnsupportedOperationException("read-only BlobStore");
    }

    @Override
    public void deleteContainer(String container) {
        throw new UnsupportedOperationException("read-only BlobStore");
    }

    @Override
    public void deleteBucket(String container) {
        throw new UnsupportedOperationException("read-only BlobStore");
    }

    @Override
    public PutObjectResponse putBlob(PutObjectRequest request,
            InputStream payload) {
        throw new UnsupportedOperationException("read-only BlobStore");
    }

    @Override
    public DeleteObjectResponse removeBlob(final DeleteObjectRequest request) {
        throw new UnsupportedOperationException("read-only BlobStore");
    }

    @Override
    public DeleteObjectsResponse removeBlobs(DeleteObjectsRequest request) {
        throw new UnsupportedOperationException("read-only BlobStore");
    }

    @Override
    public void setContainerVersioning(final String containerName,
            final BucketVersioningStatus status) {
        throw new UnsupportedOperationException("read-only BlobStore");
    }

    @Override
    public void setContainerEncryption(final String containerName,
            final ServerSideEncryptionConfiguration configuration) {
        throw new UnsupportedOperationException("read-only BlobStore");
    }

    @Override
    public void deleteContainerEncryption(final String containerName) {
        throw new UnsupportedOperationException("read-only BlobStore");
    }

    @Override
    public void setBlobAccess(String container, String name,
            ObjectCannedACL access) {
        throw new UnsupportedOperationException("read-only BlobStore");
    }

    @Override
    public void setBlobAccess(String container, String name,
            ObjectCannedACL access, @Nullable String versionId) {
        throw new UnsupportedOperationException("read-only BlobStore");
    }

    @Override
    public CopyObjectResponse copyBlob(CopyObjectRequest request) {
        throw new UnsupportedOperationException("read-only BlobStore");
    }

    @Override
    public MultipartUpload initiateMultipartUpload(
            CreateMultipartUploadRequest request) {
        throw new UnsupportedOperationException("read-only BlobStore");
    }

    @Override
    public void abortMultipartUpload(MultipartUpload mpu) {
        throw new UnsupportedOperationException("read-only BlobStore");
    }

    @Override
    public CompleteMultipartUploadResponse completeMultipartUpload(final MultipartUpload mpu,
            final CompleteMultipartUploadRequest request) {
        throw new UnsupportedOperationException("read-only BlobStore");
    }

    @Override
    public UploadPartResponse uploadMultipartPart(MultipartUpload mpu,
            UploadPartRequest request, InputStream is) {
        throw new UnsupportedOperationException("read-only BlobStore");
    }
}
