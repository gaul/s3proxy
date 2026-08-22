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
import java.util.List;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;

import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.services.s3.model.BucketCannedACL;
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
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Response;
import software.amazon.awssdk.services.s3.model.ObjectCannedACL;
import software.amazon.awssdk.services.s3.model.Part;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.awssdk.services.s3.model.UploadPartRequest;
import software.amazon.awssdk.services.s3.model.UploadPartResponse;

/**
 * A store whose every operation is unsupported.  Tests of the interface's
 * default methods extend it, overriding only what the default under test
 * touches -- implementing BlobStore directly rather than extending
 * ForwardingBlobStore, which would measure a delegate's implementation
 * instead of the default.
 */
abstract class AbstractUnsupportedBlobStore implements BlobStore {
    @Override
    public ListBucketsResponse list() {
        throw new UnsupportedOperationException();
    }

    @Override
    public ListObjectsV2Response list(ListObjectsV2Request request) {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean containerExists(String container) {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean createContainer(CreateBucketRequest request) {
        throw new UnsupportedOperationException();
    }

    @Override
    public BucketCannedACL getContainerAccess(String container) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void setContainerAccess(String container,
            BucketCannedACL access) {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean deleteContainerIfEmpty(String container) {
        throw new UnsupportedOperationException();
    }

    @Override
    public PutObjectResponse putBlob(PutObjectRequest request,
            InputStream payload) {
        throw new UnsupportedOperationException();
    }

    @Override
    public CopyObjectResponse copyBlob(CopyObjectRequest request) {
        throw new UnsupportedOperationException();
    }

    @Override
    public HeadObjectResponse blobMetadata(HeadObjectRequest request) {
        throw new UnsupportedOperationException();
    }

    @Override
    public ResponseInputStream<GetObjectResponse> getBlob(
            GetObjectRequest request) {
        throw new UnsupportedOperationException();
    }

    @Override
    public DeleteObjectResponse removeBlob(DeleteObjectRequest request) {
        throw new UnsupportedOperationException();
    }

    @Override
    public ObjectCannedACL getBlobAccess(String container, String name) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void setBlobAccess(String container, String name,
            ObjectCannedACL access) {
        throw new UnsupportedOperationException();
    }

    @Override
    public MultipartUpload initiateMultipartUpload(
            CreateMultipartUploadRequest request) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void abortMultipartUpload(MultipartUpload mpu) {
        throw new UnsupportedOperationException();
    }

    @Override
    public CompleteMultipartUploadResponse completeMultipartUpload(
            MultipartUpload mpu,
            CompleteMultipartUploadRequest request) {
        throw new UnsupportedOperationException();
    }

    @Override
    public UploadPartResponse uploadMultipartPart(MultipartUpload mpu,
            UploadPartRequest request, InputStream payload) {
        throw new UnsupportedOperationException();
    }

    @Override
    public List<Part> listMultipartUpload(MultipartUpload mpu) {
        throw new UnsupportedOperationException();
    }

    @Override
    public List<software.amazon.awssdk.services.s3.model.MultipartUpload>
            listMultipartUploads(String container) {
        throw new UnsupportedOperationException();
    }

    @Override
    public long getMinimumMultipartPartSize() {
        throw new UnsupportedOperationException();
    }
}
