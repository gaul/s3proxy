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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicLong;

import com.google.common.hash.HashCode;
import com.google.common.hash.Hashing;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.S3Exceptions;
import org.gaul.s3proxy.blobstore.SdkResponses;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.jspecify.annotations.Nullable;

import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.services.s3.model.BucketCannedACL;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.CopyObjectRequest;
import software.amazon.awssdk.services.s3.model.CopyObjectResponse;
import software.amazon.awssdk.services.s3.model.CopyObjectResult;
import software.amazon.awssdk.services.s3.model.CreateBucketRequest;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.HeadObjectRequest;
import software.amazon.awssdk.services.s3.model.HeadObjectResponse;
import software.amazon.awssdk.services.s3.model.ListBucketsResponse;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Response;
import software.amazon.awssdk.services.s3.model.NoSuchUploadException;
import software.amazon.awssdk.services.s3.model.ObjectCannedACL;
import software.amazon.awssdk.services.s3.model.Part;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.awssdk.services.s3.model.UploadPartResponse;

/**
 * A minimal in-memory BlobStore treating server-side encryption the way S3
 * does -- applies AES256 when a request names nothing, honors whatever it
 * names, and reports the outcome on every response -- standing in for the
 * aws-s3-sdk backend so the frontend's forwarding and reporting can be
 * exercised end to end without one.  The write requests seen are kept for
 * asserting what was forwarded.  Only the paths the encryption tests walk
 * are implemented.
 */
final class InMemorySseBlobStore implements BlobStore {
    private final SortedMap<String, SortedMap<String, StoredBlob>> containers =
            new TreeMap<>();
    private final SortedMap<String, Upload> uploads = new TreeMap<>();
    private final AtomicLong uploadCounter = new AtomicLong();
    private @Nullable PutObjectRequest lastPutRequest;
    private @Nullable CopyObjectRequest lastCopyRequest;
    private @Nullable CreateMultipartUploadRequest lastCreateRequest;

    /** The encryption an object rests under, as S3 would report it. */
    private record Encryption(String algorithm, @Nullable String kmsKeyId,
            @Nullable String kmsContext, @Nullable Boolean bucketKeyEnabled) {
        /** What a write request's fields come to rest as: the S3 default
         * when it names nothing. */
        static Encryption forRequest(@Nullable String algorithm,
                @Nullable String kmsKeyId, @Nullable String kmsContext,
                @Nullable Boolean bucketKeyEnabled) {
            return algorithm == null ?
                    new Encryption("AES256", null, null, null) :
                    new Encryption(algorithm, kmsKeyId, kmsContext,
                            bucketKeyEnabled);
        }
    }

    @SuppressWarnings("ArrayRecordComponent")
    private record StoredBlob(byte[] content, String eTag,
            Instant lastModified, Encryption encryption) {
    }

    @SuppressWarnings("ArrayRecordComponent")
    private record StoredPart(byte[] content, String eTag) {
    }

    private record Upload(CreateMultipartUploadRequest request,
            Encryption encryption, SortedMap<Integer, StoredPart> parts) {
    }

    synchronized @Nullable PutObjectRequest lastPutRequest() {
        return lastPutRequest;
    }

    synchronized @Nullable CopyObjectRequest lastCopyRequest() {
        return lastCopyRequest;
    }

    synchronized @Nullable CreateMultipartUploadRequest lastCreateRequest() {
        return lastCreateRequest;
    }

    private SortedMap<String, StoredBlob> getContainer(String containerName) {
        var container = containers.get(containerName);
        if (container == null) {
            throw S3Exceptions.noSuchBucket(containerName, "");
        }
        return container;
    }

    private Upload getUpload(String id) {
        var upload = uploads.get(id);
        if (upload == null) {
            throw NoSuchUploadException.builder()
                    .message("no such upload " + id)
                    .statusCode(404)
                    .build();
        }
        return upload;
    }

    @SuppressWarnings("deprecation")
    private static String eTagOf(byte[] content) {
        return Hashing.md5().hashBytes(content).toString();
    }

    @Override
    public ListBucketsResponse list() {
        throw new UnsupportedOperationException("listing not supported");
    }

    @Override
    public ListObjectsV2Response list(ListObjectsV2Request request) {
        throw new UnsupportedOperationException("listing not supported");
    }

    @Override
    public synchronized boolean containerExists(String containerName) {
        return containers.containsKey(containerName);
    }

    @Override
    public synchronized boolean createContainer(CreateBucketRequest request) {
        return containers.putIfAbsent(request.bucket(),
                new TreeMap<>()) == null;
    }

    @Override
    public BucketCannedACL getContainerAccess(String containerName) {
        return BucketCannedACL.PRIVATE;
    }

    @Override
    public void setContainerAccess(String containerName,
            BucketCannedACL access) {
    }

    @Override
    public synchronized boolean deleteContainerIfEmpty(String containerName) {
        var container = getContainer(containerName);
        if (!container.isEmpty()) {
            return false;
        }
        containers.remove(containerName);
        return true;
    }

    @Override
    public synchronized boolean blobExists(String containerName, String key) {
        return getContainer(containerName).containsKey(key);
    }

    /**
     * True so that completeMultipartUpload runs synchronously, as it does
     * on the aws-s3 store, whose completion response carries the
     * encryption headers this store exists to exercise.
     */
    @Override
    public boolean supportsVersioning() {
        return true;
    }

    @Override
    public boolean supportsServerSideEncryption() {
        return true;
    }

    @Override
    public synchronized PutObjectResponse putBlob(PutObjectRequest request,
            InputStream payload) {
        lastPutRequest = request;
        var container = getContainer(request.bucket());
        byte[] content = readPayload(payload);
        var encryption = Encryption.forRequest(
                request.serverSideEncryptionAsString(), request.ssekmsKeyId(),
                request.ssekmsEncryptionContext(), request.bucketKeyEnabled());
        var blob = new StoredBlob(content, eTagOf(content), Instant.now(),
                encryption);
        container.put(request.key(), blob);
        return PutObjectResponse.builder()
                .eTag(blob.eTag())
                .serverSideEncryption(encryption.algorithm())
                .ssekmsKeyId(encryption.kmsKeyId())
                .ssekmsEncryptionContext(encryption.kmsContext())
                .bucketKeyEnabled(encryption.bucketKeyEnabled())
                .build();
    }

    @Override
    public synchronized CopyObjectResponse copyBlob(CopyObjectRequest request) {
        lastCopyRequest = request;
        var source = getContainer(request.sourceBucket())
                .get(request.sourceKey());
        if (source == null) {
            throw S3Exceptions.noSuchKey(request.sourceBucket(),
                    request.sourceKey(), "while copying");
        }
        var encryption = Encryption.forRequest(
                request.serverSideEncryptionAsString(), request.ssekmsKeyId(),
                request.ssekmsEncryptionContext(), request.bucketKeyEnabled());
        var dest = new StoredBlob(source.content(), source.eTag(),
                Instant.now(), encryption);
        getContainer(request.destinationBucket())
                .put(request.destinationKey(), dest);
        return CopyObjectResponse.builder()
                .copyObjectResult(CopyObjectResult.builder()
                        .eTag(dest.eTag())
                        .lastModified(dest.lastModified())
                        .build())
                .serverSideEncryption(encryption.algorithm())
                .ssekmsKeyId(encryption.kmsKeyId())
                .ssekmsEncryptionContext(encryption.kmsContext())
                .bucketKeyEnabled(encryption.bucketKeyEnabled())
                .build();
    }

    @Override
    @Nullable
    public synchronized HeadObjectResponse blobMetadata(
            HeadObjectRequest request) {
        var blob = getContainer(request.bucket()).get(request.key());
        if (blob == null) {
            return null;
        }
        return HeadObjectResponse.builder()
                .eTag(blob.eTag())
                .contentLength((long) blob.content().length)
                .lastModified(blob.lastModified())
                .serverSideEncryption(blob.encryption().algorithm())
                .ssekmsKeyId(blob.encryption().kmsKeyId())
                .bucketKeyEnabled(blob.encryption().bucketKeyEnabled())
                .build();
    }

    @Override
    @Nullable
    public synchronized ResponseInputStream<GetObjectResponse> getBlob(
            GetObjectRequest request) {
        var blob = getContainer(request.bucket()).get(request.key());
        if (blob == null) {
            return null;
        }
        return SdkResponses.getResponse(GetObjectResponse.builder()
                        .eTag(blob.eTag())
                        .contentLength((long) blob.content().length)
                        .lastModified(blob.lastModified())
                        .serverSideEncryption(blob.encryption().algorithm())
                        .ssekmsKeyId(blob.encryption().kmsKeyId())
                        .bucketKeyEnabled(blob.encryption().bucketKeyEnabled())
                        .build(),
                new ByteArrayInputStream(blob.content()));
    }

    @Override
    public synchronized void removeBlob(String containerName, String key) {
        getContainer(containerName).remove(key);
    }

    @Override
    public ObjectCannedACL getBlobAccess(String containerName, String key) {
        return ObjectCannedACL.PRIVATE;
    }

    @Override
    public void setBlobAccess(String containerName, String key,
            ObjectCannedACL access) {
    }

    @Override
    public synchronized MultipartUpload initiateMultipartUpload(
            CreateMultipartUploadRequest request) {
        lastCreateRequest = request;
        getContainer(request.bucket());
        var encryption = Encryption.forRequest(
                request.serverSideEncryptionAsString(), request.ssekmsKeyId(),
                request.ssekmsEncryptionContext(), request.bucketKeyEnabled());
        String id = "upload-" + uploadCounter.incrementAndGet();
        uploads.put(id, new Upload(request, encryption, new TreeMap<>()));
        return new MultipartUpload(id, request,
                CreateMultipartUploadResponse.builder()
                        .bucket(request.bucket())
                        .key(request.key())
                        .uploadId(id)
                        .serverSideEncryption(encryption.algorithm())
                        .ssekmsKeyId(encryption.kmsKeyId())
                        .ssekmsEncryptionContext(encryption.kmsContext())
                        .bucketKeyEnabled(encryption.bucketKeyEnabled())
                        .build());
    }

    @Override
    public synchronized void abortMultipartUpload(MultipartUpload mpu) {
        uploads.remove(mpu.id());
    }

    @Override
    public synchronized CompleteMultipartUploadResponse
            completeMultipartUpload(MultipartUpload mpu,
                    CompleteMultipartUploadRequest request) {
        var upload = getUpload(mpu.id());
        var out = new ByteArrayOutputStream();
        for (var part : upload.parts().values()) {
            out.writeBytes(part.content());
        }
        byte[] content = out.toByteArray();
        var blob = new StoredBlob(content, eTagOf(content), Instant.now(),
                upload.encryption());
        getContainer(upload.request().bucket())
                .put(upload.request().key(), blob);
        uploads.remove(mpu.id());
        return CompleteMultipartUploadResponse.builder()
                .bucket(upload.request().bucket())
                .key(upload.request().key())
                .eTag(blob.eTag())
                .serverSideEncryption(upload.encryption().algorithm())
                .ssekmsKeyId(upload.encryption().kmsKeyId())
                .bucketKeyEnabled(upload.encryption().bucketKeyEnabled())
                .build();
    }

    @Override
    public synchronized UploadPartResponse uploadMultipartPart(
            MultipartUpload mpu, int partNumber, InputStream is,
            long contentLength, @Nullable HashCode contentMD5) {
        var upload = getUpload(mpu.id());
        byte[] content = readPayload(is);
        var part = new StoredPart(content, eTagOf(content));
        upload.parts().put(partNumber, part);
        return UploadPartResponse.builder()
                .eTag(part.eTag())
                .serverSideEncryption(upload.encryption().algorithm())
                .ssekmsKeyId(upload.encryption().kmsKeyId())
                .bucketKeyEnabled(upload.encryption().bucketKeyEnabled())
                .build();
    }

    @Override
    public synchronized List<Part> listMultipartUpload(MultipartUpload mpu) {
        var upload = getUpload(mpu.id());
        var parts = new ArrayList<Part>();
        for (var entry : upload.parts().entrySet()) {
            parts.add(SdkResponses.part(entry.getKey(),
                    (long) entry.getValue().content().length,
                    entry.getValue().eTag(), new Date()));
        }
        return parts;
    }

    @Override
    public List<software.amazon.awssdk.services.s3.model.MultipartUpload>
            listMultipartUploads(String containerName) {
        throw new UnsupportedOperationException("listing not supported");
    }

    @Override
    public long getMinimumMultipartPartSize() {
        return 1;
    }

    private static byte[] readPayload(InputStream payload) {
        try (var is = payload) {
            return is.readAllBytes();
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }
}
