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

package org.gaul.s3proxy.awssdk;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.Comparator;
import java.util.List;

import com.google.common.base.Supplier;
import com.google.common.collect.ImmutableList;
import com.google.common.hash.HashCode;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.Credentials;
import org.gaul.s3proxy.blobstore.S3Exceptions;
import org.gaul.s3proxy.blobstore.SdkResponses;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.jspecify.annotations.Nullable;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.core.checksums.RequestChecksumCalculation;
import software.amazon.awssdk.core.checksums.ResponseChecksumValidation;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.retries.DefaultRetryStrategy;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3ClientBuilder;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.model.AbortMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.BucketCannedACL;
import software.amazon.awssdk.services.s3.model.BucketVersioningStatus;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.CompletedMultipartUpload;
import software.amazon.awssdk.services.s3.model.CompletedPart;
import software.amazon.awssdk.services.s3.model.CopyObjectRequest;
import software.amazon.awssdk.services.s3.model.CopyObjectResponse;
import software.amazon.awssdk.services.s3.model.CreateBucketConfiguration;
import software.amazon.awssdk.services.s3.model.CreateBucketRequest;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.DeleteBucketRequest;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.DeleteObjectResponse;
import software.amazon.awssdk.services.s3.model.DeleteObjectsRequest;
import software.amazon.awssdk.services.s3.model.DeleteObjectsResponse;
import software.amazon.awssdk.services.s3.model.GetBucketAclRequest;
import software.amazon.awssdk.services.s3.model.GetBucketVersioningRequest;
import software.amazon.awssdk.services.s3.model.GetObjectAclRequest;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.Grant;
import software.amazon.awssdk.services.s3.model.HeadBucketRequest;
import software.amazon.awssdk.services.s3.model.HeadObjectRequest;
import software.amazon.awssdk.services.s3.model.HeadObjectResponse;
import software.amazon.awssdk.services.s3.model.ListBucketsResponse;
import software.amazon.awssdk.services.s3.model.ListMultipartUploadsRequest;
import software.amazon.awssdk.services.s3.model.ListObjectVersionsRequest;
import software.amazon.awssdk.services.s3.model.ListObjectVersionsResponse;
import software.amazon.awssdk.services.s3.model.ListObjectsRequest;
import software.amazon.awssdk.services.s3.model.ListObjectsResponse;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Response;
import software.amazon.awssdk.services.s3.model.ListPartsRequest;
import software.amazon.awssdk.services.s3.model.NoSuchBucketException;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.s3.model.ObjectCannedACL;
import software.amazon.awssdk.services.s3.model.Part;
import software.amazon.awssdk.services.s3.model.Permission;
import software.amazon.awssdk.services.s3.model.PutBucketAclRequest;
import software.amazon.awssdk.services.s3.model.PutBucketVersioningRequest;
import software.amazon.awssdk.services.s3.model.PutObjectAclRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.services.s3.model.Type;
import software.amazon.awssdk.services.s3.model.UploadPartCopyRequest;
import software.amazon.awssdk.services.s3.model.UploadPartCopyResponse;
import software.amazon.awssdk.services.s3.model.UploadPartRequest;
import software.amazon.awssdk.services.s3.model.UploadPartResponse;
import software.amazon.awssdk.services.s3.model.VersioningConfiguration;

public final class AwsS3SdkBlobStore implements BlobStore {
    private static final String DELETE_MARKER_HEADER = "x-amz-delete-marker";
    private static final String VERSION_ID_HEADER = "x-amz-version-id";

    private final S3Client s3Client;
    private final String endpoint;
    private final boolean useNativeConditionalWrites;
    private final boolean stripETagQuotes;
    private final Region awsRegion;

    public AwsS3SdkBlobStore(
            Supplier<Credentials> creds,
            String endpointUrl,
            String region,
            String conditionalWrites,
            String chunkedEncodingEnabled,
            String stripETagQuotes) {
        this.endpoint = endpointUrl;
        this.awsRegion = Region.of(region);
        this.useNativeConditionalWrites = !"emulated".equalsIgnoreCase(
                conditionalWrites);
        this.stripETagQuotes = Boolean.parseBoolean(stripETagQuotes);
        var cred = creds.get();

        S3ClientBuilder builder = S3Client.builder();

        builder.serviceConfiguration(S3Configuration.builder()
                .chunkedEncodingEnabled(Boolean.valueOf(chunkedEncodingEnabled))
                .build());

        // Disable checksum calculation to avoid reading the stream twice.
        // This allows streaming non-resettable InputStreams to S3-compatible
        // backends that don't support aws-chunked encoding.
        builder.requestChecksumCalculation(RequestChecksumCalculation.WHEN_REQUIRED);
        builder.responseChecksumValidation(ResponseChecksumValidation.WHEN_REQUIRED);

        // Disable SDK retries so a non-resettable payload stream that errors
        // mid-upload (e.g. a ChecksumValidatingInputStream rejecting a body)
        // is not re-read -- a retry would fail to reset the consumed stream
        // and mask the original error.  The S3 client retries the whole
        // operation instead.  Mirrors the no-retry AzureBlobStore client.
        builder.overrideConfiguration(o -> o.retryStrategy(
                DefaultRetryStrategy.doNotRetry()));

        if (cred.identity() != null && !cred.identity().isEmpty() &&
                cred.credential() != null && !cred.credential().isEmpty()) {
            builder.credentialsProvider(StaticCredentialsProvider.create(
                    AwsBasicCredentials.create(cred.identity(),
                            cred.credential())));
        } else {
            builder.credentialsProvider(
                    DefaultCredentialsProvider.builder().build());
        }

        if (endpoint != null && !endpoint.isEmpty()) {
            URI endpointUri = URI.create(endpoint);
            builder.endpointOverride(endpointUri);

            // Use path-style for non-AWS endpoints (Hetzner, MinIO, etc.)
            String host = endpointUri.getHost();
            if (host != null && !host.endsWith(".amazonaws.com")) {
                builder.forcePathStyle(true);
            }
        }

        builder.region(this.awsRegion);

        this.s3Client = builder.build();
    }

    // Releases the SDK client's connection pool and background threads when
    // the BlobStore is closed.
    @Override
    public void close() {
        s3Client.close();
    }

    @Override
    public ListBucketsResponse list() {
        try {
            return s3Client.listBuckets();
        } catch (S3Exception e) {
            throw propagate(e, null, null);
        }
    }

    @Override
    public ListObjectsV2Response list(ListObjectsV2Request request) {
        if (request.maxKeys() != null && request.maxKeys() == 0) {
            return SdkResponses.objectsPage(List.of(), List.of(), null);
        }
        try {
            return s3Client.listObjectsV2(request);
        } catch (S3Exception e) {
            throw propagate(e, request.bucket(), null);
        }
    }

    @Override
    public ListObjectsResponse listV1(ListObjectsRequest request) {
        if (request.maxKeys() != null && request.maxKeys() == 0) {
            return ListObjectsResponse.builder().isTruncated(false).build();
        }
        try {
            return s3Client.listObjects(request);
        } catch (S3Exception e) {
            throw propagate(e, request.bucket(), null);
        }
    }

    @Override
    public boolean containerExists(String container) {
        try {
            s3Client.headBucket(HeadBucketRequest.builder()
                    .bucket(container)
                    .build());
            return true;
        } catch (NoSuchBucketException e) {
            return false;
        } catch (S3Exception e) {
            if (e.statusCode() == 404) {
                return false;
            }
            throw propagate(e, container, null);
        }
    }

    @Override
    public boolean createContainer(CreateBucketRequest request) {
        try {
            if (!Region.US_EAST_1.equals(awsRegion) &&
                    request.createBucketConfiguration() == null) {
                request = request.toBuilder()
                        .createBucketConfiguration(
                                CreateBucketConfiguration.builder()
                                        .locationConstraint(awsRegion.id())
                                        .build())
                        .build();
            }
            s3Client.createBucket(request);
            return true;
        } catch (S3Exception e) {
            if ("BucketAlreadyOwnedByYou".equals(S3Exceptions.errorCode(e))) {
                // Idempotent success - bucket exists and caller owns it
                return false;
            }
            throw propagate(e, request.bucket(), null);
        }
    }

    @Override
    public void deleteContainer(String container) {
        try {
            clearContainer(ListObjectsV2Request.builder()
                    .bucket(container)
                    .build());
            s3Client.deleteBucket(DeleteBucketRequest.builder()
                    .bucket(container)
                    .build());
        } catch (NoSuchBucketException e) {
            // Already deleted, ignore
        } catch (S3Exception e) {
            throw propagate(e, container, null);
        }
    }

    @Override
    public boolean deleteContainerIfEmpty(String container) {
        try {
            var response = s3Client.listObjectsV2(ListObjectsV2Request.builder()
                    .bucket(container)
                    .maxKeys(1)
                    .build());
            if (!response.contents().isEmpty()) {
                return false;
            }
            s3Client.deleteBucket(DeleteBucketRequest.builder()
                    .bucket(container)
                    .build());
            return true;
        } catch (NoSuchBucketException e) {
            return true;
        } catch (S3Exception e) {
            if (e.statusCode() == 409) {
                // Bucket not empty
                return false;
            }
            throw e;
        }
    }

    @Override
    public boolean blobExists(String container, String key) {
        try {
            s3Client.headObject(HeadObjectRequest.builder()
                    .bucket(container)
                    .key(key)
                    .build());
            return true;
        } catch (NoSuchKeyException e) {
            return false;
        } catch (S3Exception e) {
            if (e.statusCode() == 404) {
                return false;
            }
            throw e;
        }
    }

    @Override
    public ResponseInputStream<GetObjectResponse> getBlob(
            GetObjectRequest request) {
        if (request.ifMatch() != null || request.ifNoneMatch() != null) {
            request = request.toBuilder()
                    .ifMatch(maybeStripETagQuotes(request.ifMatch()))
                    .ifNoneMatch(maybeStripETagQuotes(request.ifNoneMatch()))
                    .build();
        }
        try {
            return s3Client.getObject(request);
        } catch (S3Exception e) {
            // 304, 405 on a delete marker read, NoSuchVersion and the rest
            // pass through verbatim; the response headers, e.g. ETag and
            // x-amz-delete-marker, ride on the exception.
            throw propagate(e, request.bucket(), request.key());
        }
    }

    @Override
    public PutObjectResponse putBlob(PutObjectRequest request,
            InputStream payload) {
        String container = request.bucket();
        String key = request.key();
        String ifMatch = request.ifMatch();
        String ifNoneMatch = request.ifNoneMatch();

        boolean hasConditionalHeaders = ifMatch != null || ifNoneMatch != null;
        if (hasConditionalHeaders && !useNativeConditionalWrites) {
            validateConditionalPut(container, key, ifMatch, ifNoneMatch);
            request = request.toBuilder()
                    .ifMatch(null)
                    .ifNoneMatch(null)
                    .build();
        } else if (hasConditionalHeaders) {
            request = request.toBuilder()
                    .ifMatch(maybeStripETagQuotes(ifMatch))
                    .ifNoneMatch(maybeStripETagQuotes(ifNoneMatch))
                    .build();
        }

        try (InputStream is = payload) {
            Long contentLength = request.contentLength();
            if (contentLength == null) {
                // Mimic S3 behavior: Reject unknown length instead of crashing memory
                throw new IllegalArgumentException("Content-Length is required for S3 putBlob");
            }
            return s3Client.putObject(request,
                    RequestBody.fromInputStream(is, contentLength));
        } catch (IOException e) {
            throw new RuntimeException("Failed to read blob payload", e);
        } catch (S3Exception e) {
            throw propagate(e, container, key);
        }
    }

    @Override
    public CopyObjectResponse copyBlob(CopyObjectRequest request) {
        try {
            return s3Client.copyObject(request);
        } catch (S3Exception e) {
            throw propagate(e, request.sourceBucket(), request.sourceKey());
        }
    }

    @Override
    public void removeBlob(String container, String key) {
        try {
            removeBlob(container, key, /*versionId=*/ null);
        } catch (NoSuchBucketException e) {
            // Ignore - delete is idempotent
        }
    }

    @Override
    public DeleteObjectResponse removeBlob(String container, String key,
            @Nullable String versionId) {
        var requestBuilder = DeleteObjectRequest.builder()
                .bucket(container)
                .key(key);
        if (versionId != null) {
            requestBuilder.versionId(versionId);
        }
        try {
            return s3Client.deleteObject(requestBuilder.build());
        } catch (NoSuchKeyException e) {
            // Delete is idempotent; an absent key is not an error.
            return DeleteObjectResponse.builder().build();
        } catch (NoSuchBucketException e) {
            throw e;
        } catch (S3Exception e) {
            if (e.statusCode() == 404 && versionId == null) {
                return DeleteObjectResponse.builder().build();
            }
            throw propagate(e, container, key);
        }
    }

    @Override
    public DeleteObjectResponse removeBlob(DeleteObjectRequest request) {
        // The service judges the conditions, so its answer -- including a
        // 404 for an absent key, unlike the idempotent forms above --
        // relays verbatim.
        try {
            return s3Client.deleteObject(request);
        } catch (S3Exception e) {
            throw propagate(e, request.bucket(), request.key());
        }
    }

    /**
     * Passes the batch through as the DeleteObjects it already is: S3 answers
     * a thousand keys in one round trip, and its answer carries the per-key
     * Deleted and Error entries the frontend reports, delete markers and all.
     * The interface default would spend a round trip per key against a
     * service that is not local.
     */
    @Override
    public DeleteObjectsResponse removeBlobs(DeleteObjectsRequest request) {
        return s3Client.deleteObjects(request);
    }

    @Override
    @Nullable
    public HeadObjectResponse blobMetadata(HeadObjectRequest request) {
        try {
            return s3Client.headObject(request);
        } catch (NoSuchKeyException e) {
            return nullOrDeleteMarker(request.bucket(), request.key(), e);
        } catch (NoSuchBucketException e) {
            throw e;
        } catch (S3Exception e) {
            if (e.statusCode() == 404) {
                return nullOrDeleteMarker(request.bucket(), request.key(), e);
            }
            // 405 on a delete marker read passes through verbatim with
            // x-amz-delete-marker riding on the exception's headers.
            throw e;
        }
    }

    @Override
    public BucketCannedACL getContainerAccess(String container) {
        try {
            var response = s3Client.getBucketAcl(GetBucketAclRequest.builder()
                    .bucket(container)
                    .build());
            if (hasAllUsersGrant(response.grants(), Permission.WRITE)) {
                return BucketCannedACL.PUBLIC_READ_WRITE;
            }
            return hasAllUsersGrant(response.grants(), Permission.READ) ?
                    BucketCannedACL.PUBLIC_READ : BucketCannedACL.PRIVATE;
        } catch (NoSuchBucketException e) {
            throw e;
        } catch (S3Exception e) {
            if (e.statusCode() == 404) {
                throw propagate(e, container, null);
            }
            return BucketCannedACL.PRIVATE;
        }
    }

    @Override
    public void setContainerAccess(String container, BucketCannedACL access) {
        try {
            s3Client.putBucketAcl(PutBucketAclRequest.builder()
                    .bucket(container)
                    .acl(access)
                    .build());
        } catch (S3Exception e) {
            throw propagate(e, container, null);
        }
    }

    @Override
    public boolean supportsVersioning() {
        return true;
    }

    @Override
    @Nullable
    public BucketVersioningStatus getContainerVersioning(String container) {
        try {
            var response = s3Client.getBucketVersioning(
                    GetBucketVersioningRequest.builder()
                            .bucket(container)
                            .build());
            return response.status();
        } catch (S3Exception e) {
            throw propagate(e, container, null);
        }
    }

    @Override
    public void setContainerVersioning(String container,
            BucketVersioningStatus status) {
        try {
            s3Client.putBucketVersioning(PutBucketVersioningRequest.builder()
                    .bucket(container)
                    .versioningConfiguration(VersioningConfiguration.builder()
                            .status(status)
                            .build())
                    .build());
        } catch (S3Exception e) {
            throw propagate(e, container, null);
        }
    }

    @Override
    public ListObjectVersionsResponse listVersions(
            ListObjectVersionsRequest request) {
        try {
            return s3Client.listObjectVersions(request);
        } catch (S3Exception e) {
            throw propagate(e, request.bucket(), null);
        }
    }

    @Override
    public ObjectCannedACL getBlobAccess(String container, String key) {
        return getBlobAccess(container, key, /*versionId=*/ null);
    }

    @Override
    public ObjectCannedACL getBlobAccess(String container, String key,
            @Nullable String versionId) {
        try {
            var response = s3Client.getObjectAcl(GetObjectAclRequest.builder()
                    .bucket(container)
                    .key(key)
                    .versionId(versionId)
                    .build());
            return hasAllUsersGrant(response.grants(), Permission.READ) ?
                    ObjectCannedACL.PUBLIC_READ : ObjectCannedACL.PRIVATE;
        } catch (S3Exception e) {
            if (e.statusCode() == 404) {
                throw translateAclNotFound(container, key, e);
            }
            throw e;
        }
    }

    private static boolean hasAllUsersGrant(List<Grant> grants,
            Permission permission) {
        for (Grant grant : grants) {
            if (grant.permission() == permission ||
                    grant.permission() == Permission.FULL_CONTROL) {
                if (grant.grantee().type() == Type.GROUP &&
                        "http://acs.amazonaws.com/groups/global/AllUsers".equals(grant.grantee().uri())) {
                    return true;
                }
            }
        }
        return false;
    }

    private RuntimeException translateAclNotFound(String container, String key,
            S3Exception e) {
        String errorCode = S3Exceptions.errorCode(e);
        if ("NoSuchBucket".equals(errorCode) || key == null) {
            return e instanceof NoSuchBucketException ? e :
                    S3Exceptions.noSuchBucket(container, e.getMessage());
        }
        return e instanceof NoSuchKeyException ? e :
                S3Exceptions.noSuchKey(container, key, e.getMessage());
    }

    @Override
    public void setBlobAccess(String container, String key,
            ObjectCannedACL access) {
        setBlobAccess(container, key, access, /*versionId=*/ null);
    }

    @Override
    public void setBlobAccess(String container, String key,
            ObjectCannedACL access, @Nullable String versionId) {
        try {
            s3Client.putObjectAcl(PutObjectAclRequest.builder()
                    .bucket(container)
                    .key(key)
                    .acl(access)
                    .versionId(versionId)
                    .build());
        } catch (S3Exception e) {
            throw propagate(e, container, key);
        }
    }

    @Override
    public MultipartUpload initiateMultipartUpload(
            CreateMultipartUploadRequest request) {
        try {
            var response = s3Client.createMultipartUpload(request);
            return new MultipartUpload(response.uploadId(), request);
        } catch (S3Exception e) {
            throw propagate(e, request.bucket(), request.key());
        }
    }

    @Override
    public void abortMultipartUpload(MultipartUpload mpu) {
        try {
            s3Client.abortMultipartUpload(AbortMultipartUploadRequest.builder()
                    .bucket(mpu.containerName())
                    .key(mpu.blobName())
                    .uploadId(mpu.id())
                    .build());
        } catch (S3Exception e) {
            // an unknown upload id surfaces as NoSuchUploadException, which
            // the frontend remaps to NoSuchUpload
            throw propagate(e, mpu.containerName(), mpu.blobName());
        }
    }

    @Override
    public CompleteMultipartUploadResponse completeMultipartUpload(
            MultipartUpload mpu, CompleteMultipartUploadRequest request) {
        var completedParts = sortAndValidateParts(
                request.multipartUpload() == null ? List.of() :
                        request.multipartUpload().parts());

        try {
            return s3Client.completeMultipartUpload(request.toBuilder()
                    .multipartUpload(CompletedMultipartUpload.builder()
                            .parts(completedParts)
                            .build())
                    .build());
        } catch (S3Exception e) {
            throw propagate(e, request.bucket(), request.key());
        }
    }

    @Override
    public UploadPartResponse uploadMultipartPart(MultipartUpload mpu,
            int partNumber, InputStream is, long contentLength,
            @Nullable HashCode contentMD5) {
        try (is) {
            return s3Client.uploadPart(UploadPartRequest.builder()
                    .bucket(mpu.containerName())
                    .key(mpu.blobName())
                    .uploadId(mpu.id())
                    .partNumber(partNumber)
                    .build(),
                    RequestBody.fromInputStream(is, contentLength));
        } catch (IOException e) {
            throw new RuntimeException("Failed to upload part", e);
        } catch (S3Exception e) {
            throw propagate(e, mpu.containerName(), mpu.blobName());
        }
    }

    @Override
    public boolean supportsCopyMultipartPart() {
        return true;
    }

    @Override
    public UploadPartCopyResponse copyMultipartPart(MultipartUpload mpu,
            UploadPartCopyRequest request) {
        try {
            return s3Client.uploadPartCopy(request);
        } catch (S3Exception e) {
            throw propagate(e, request.sourceBucket(), request.sourceKey());
        }
    }

    @Override
    public List<Part> listMultipartUpload(MultipartUpload mpu) {
        try {
            var parts = ImmutableList.<Part>builder();
            Integer partNumberMarker = null;

            do {
                var response = s3Client.listParts(ListPartsRequest.builder()
                        .bucket(mpu.containerName())
                        .key(mpu.blobName())
                        .uploadId(mpu.id())
                        .partNumberMarker(partNumberMarker)
                        .build());

                parts.addAll(response.parts());

                partNumberMarker = response.isTruncated() ?
                        response.nextPartNumberMarker() : null;
            } while (partNumberMarker != null);

            return parts.build();
        } catch (S3Exception e) {
            if (e.statusCode() == 404) {
                return List.of();
            }
            throw propagate(e, mpu.containerName(), mpu.blobName());
        }
    }

    @Override
    public List<software.amazon.awssdk.services.s3.model.MultipartUpload>
            listMultipartUploads(String container) {
        try {
            var builder = ImmutableList.<software.amazon.awssdk.services.s3
                    .model.MultipartUpload>builder();
            String keyMarker = null;
            String uploadIdMarker = null;

            do {
                var response = s3Client.listMultipartUploads(
                        ListMultipartUploadsRequest.builder()
                                .bucket(container)
                                .keyMarker(keyMarker)
                                .uploadIdMarker(uploadIdMarker)
                                .build());

                builder.addAll(response.uploads());

                if (response.isTruncated()) {
                    keyMarker = response.nextKeyMarker();
                    uploadIdMarker = response.nextUploadIdMarker();
                } else {
                    keyMarker = null;
                }
            } while (keyMarker != null);

            return builder.build();
        } catch (S3Exception e) {
            throw propagate(e, container, null);
        }
    }

    @Override
    public long getMinimumMultipartPartSize() {
        // S3 minimum part size is 5MB (except for last part)
        return 5L * 1024 * 1024;
    }

    private static List<CompletedPart> sortAndValidateParts(
            List<CompletedPart> parts) {
        if (parts == null || parts.isEmpty()) {
            throw new IllegalArgumentException(
                    "At least one multipart part is required");
        }
        var sortedParts = parts.stream()
                .sorted(Comparator.comparingInt(CompletedPart::partNumber))
                .toList();
        int previousPartNumber = 0;
        for (CompletedPart part : sortedParts) {
            int partNumber = part.partNumber();
            if (partNumber <= 0) {
                throw new IllegalArgumentException(
                        "Part numbers must be positive integers");
            }
            if (partNumber < previousPartNumber) {
                throw new IllegalArgumentException(
                        "Parts must be provided in ascending PartNumber order");
            }
            previousPartNumber = partNumber;
        }
        return sortedParts;
    }

    /**
     * Answers the blobMetadata contract for a 404: an absent object is
     * null, while a delete marker or missing version still throws.
     */
    @Nullable
    private static HeadObjectResponse nullOrDeleteMarker(String container,
            String key, S3Exception e) {
        if ("NoSuchVersion".equals(S3Exceptions.errorCode(e))) {
            throw e;
        }
        var details = e.awsErrorDetails();
        if (details == null) {
            return null;
        }
        var http = details.sdkHttpResponse();
        boolean marker = http.firstMatchingHeader(DELETE_MARKER_HEADER)
                .map(Boolean::parseBoolean).orElse(false);
        if (!marker) {
            return null;
        }
        if (S3Exceptions.errorCode(e) != null) {
            // verbatim; the marker headers ride on the exception
            throw e;
        }
        // A bodyless HEAD 404 names no error code; synthesize NoSuchKey
        // keeping the marker headers.
        throw S3Exceptions.noSuchKeyDeleteMarker(container, key,
                http.firstMatchingHeader(VERSION_ID_HEADER).orElse("null"),
                e.getMessage());
    }

    /**
     * Rethrows e verbatim when it names an S3 error code, so the upstream
     * code, message and headers reach the client as sent.  A bodyless 404,
     * e.g. from a HEAD, gets a synthesized NoSuchKey or NoSuchBucket so
     * the frontend still renders an error document.
     */
    private static RuntimeException propagate(S3Exception e,
            @Nullable String container, @Nullable String key) {
        if (container != null && e.statusCode() == 404 &&
                S3Exceptions.errorCode(e) == null) {
            return key != null ?
                    S3Exceptions.noSuchKey(container, key, e.getMessage()) :
                    S3Exceptions.noSuchBucket(container, e.getMessage());
        }
        return e;
    }

    /**
     * Ensures the ETag is surrounded by quotes if not already.
     */
    private static String maybeQuoteETag(String eTag) {
        if (!eTag.startsWith("\"") && !eTag.endsWith("\"")) {
            eTag = "\"" + eTag + "\"";
        }
        return eTag;
    }

    /**
     * Strips surrounding quotes from ETag if stripETagQuotes is enabled.
     * Required for backends with Ceph Reef bug.
     * See: https://tracker.ceph.com/issues/68712
     * TODO: Can be removed after 2027-01-01 - by then every provider should
     * have migrated to a newer Ceph version (including Hetzner).
     */
    private String maybeStripETagQuotes(String eTag) {
        if (!stripETagQuotes || eTag == null) {
            return eTag;
        }
        if (eTag.length() >= 2 && eTag.startsWith("\"") && eTag.endsWith("\"")) {
            return eTag.substring(1, eTag.length() - 1);
        }
        return eTag;
    }

    /**
     * Compares two ETags, ignoring surrounding quotes.
     */
    private static boolean equalsIgnoringSurroundingQuotes(
            String s1, String s2) {
        if (s1.length() >= 2 && s1.startsWith("\"") && s1.endsWith("\"")) {
            s1 = s1.substring(1, s1.length() - 1);
        }
        if (s2.length() >= 2 && s2.startsWith("\"") && s2.endsWith("\"")) {
            s2 = s2.substring(1, s2.length() - 1);
        }
        return s1.equals(s2);
    }

    private S3Exception preconditionFailed() {
        return S3Exceptions.fromStatusCode(412);
    }

    private NoSuchKeyException keyNotFound(String container, String key) {
        return S3Exceptions.noSuchKey(container, key,
                "Object does not exist for If-Match condition");
    }

    /**
     * For S3-compatible backends that don't support If-Match/If-None-Match
     * headers natively.
     */
    private void validateConditionalPut(String container, String blobName,
            @Nullable String ifMatch, @Nullable String ifNoneMatch) {
        HeadObjectResponse metadata = blobMetadata(container, blobName);

        if (ifMatch != null) {
            validateIfMatch(container, blobName, ifMatch, metadata);
        }

        if (ifNoneMatch != null) {
            validateIfNoneMatch(ifNoneMatch, metadata);
        }
    }

    private void validateIfMatch(String container, String blobName,
            String ifMatch, @Nullable HeadObjectResponse metadata) {
        if ("*".equals(ifMatch)) {
            if (metadata == null) {
                throw preconditionFailed();
            }
            return;
        }

        if (metadata == null) {
            throw keyNotFound(container, blobName);
        }

        String currentETag = metadata.eTag();
        if (currentETag == null ||
                !equalsIgnoringSurroundingQuotes(ifMatch,
                    maybeQuoteETag(currentETag))) {
            throw preconditionFailed();
        }
    }

    private void validateIfNoneMatch(String ifNoneMatch,
            @Nullable HeadObjectResponse metadata) {
        if ("*".equals(ifNoneMatch)) {
            if (metadata != null) {
                throw preconditionFailed();
            }
            return;
        }

        if (metadata == null) {
            return;
        }

        String currentETag = metadata.eTag();
        if (currentETag != null &&
                equalsIgnoringSurroundingQuotes(ifNoneMatch,
                    maybeQuoteETag(currentETag))) {
            throw preconditionFailed();
        }
    }
}
