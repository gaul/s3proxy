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
import java.time.Instant;
import java.util.Base64;
import java.util.Comparator;
import java.util.Date;
import java.util.List;

import com.google.common.base.Supplier;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Streams;
import com.google.common.hash.HashCode;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.ContentMetadata;
import org.gaul.s3proxy.blobstore.Credentials;
import org.gaul.s3proxy.blobstore.S3Exceptions;
import org.gaul.s3proxy.blobstore.SdkResponses;
import org.gaul.s3proxy.blobstore.domain.Blob;
import org.gaul.s3proxy.blobstore.domain.BlobAccess;
import org.gaul.s3proxy.blobstore.domain.BlobMetadata;
import org.gaul.s3proxy.blobstore.domain.ContainerAccess;
import org.gaul.s3proxy.blobstore.domain.MultipartPart;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.gaul.s3proxy.blobstore.options.CopyOptions;
import org.gaul.s3proxy.blobstore.options.CreateContainerOptions;
import org.gaul.s3proxy.blobstore.options.GetOptions;
import org.gaul.s3proxy.blobstore.options.ListContainerOptions;
import org.gaul.s3proxy.blobstore.options.ListVersionsOptions;
import org.gaul.s3proxy.blobstore.options.PutOptions;
import org.jspecify.annotations.Nullable;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
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
import software.amazon.awssdk.services.s3.model.GetBucketAclRequest;
import software.amazon.awssdk.services.s3.model.GetBucketVersioningRequest;
import software.amazon.awssdk.services.s3.model.GetObjectAclRequest;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.Grant;
import software.amazon.awssdk.services.s3.model.HeadBucketRequest;
import software.amazon.awssdk.services.s3.model.HeadObjectRequest;
import software.amazon.awssdk.services.s3.model.HeadObjectResponse;
import software.amazon.awssdk.services.s3.model.ListBucketsResponse;
import software.amazon.awssdk.services.s3.model.ListMultipartUploadsRequest;
import software.amazon.awssdk.services.s3.model.ListObjectVersionsRequest;
import software.amazon.awssdk.services.s3.model.ListObjectVersionsResponse;
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
import software.amazon.awssdk.services.s3.model.StorageClass;
import software.amazon.awssdk.services.s3.model.Type;
import software.amazon.awssdk.services.s3.model.UploadPartCopyRequest;
import software.amazon.awssdk.services.s3.model.UploadPartRequest;
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
    public ListObjectsV2Response list(String container,
            ListContainerOptions options) {
        var requestBuilder = ListObjectsV2Request.builder()
                .bucket(container);

        if (options.prefix() != null) {
            requestBuilder.prefix(options.prefix());
        }
        if (options.delimiter() != null) {
            requestBuilder.delimiter(options.delimiter());
        }
        if (options.marker() != null) {
            requestBuilder.startAfter(options.marker());
        }
        int maxKeys = options.maxResults() != null ?
                options.maxResults() : 1000;
        if (maxKeys == 0) {
            return SdkResponses.objectsPage(List.of(), List.of(), null);
        }
        requestBuilder.maxKeys(maxKeys);

        try {
            var response = s3Client.listObjectsV2(requestBuilder.build());

            // The marker convention names the last key of the page rather
            // than passing the service's opaque continuation token through,
            // since the frontend round-trips markers as start-after.
            String nextMarker = null;
            if (response.isTruncated()) {
                if (!response.contents().isEmpty()) {
                    nextMarker = Streams.findLast(response.contents().stream())
                            .orElseThrow().key();
                } else if (!response.commonPrefixes().isEmpty()) {
                    nextMarker = Streams.findLast(
                            response.commonPrefixes().stream())
                            .orElseThrow().prefix();
                }
            }

            return SdkResponses.objectsPage(response.contents(),
                    response.commonPrefixes(), nextMarker);
        } catch (S3Exception e) {
            throw propagate(e, container, null);
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
    public boolean createContainer(String container,
            CreateContainerOptions options) {
        if (options == null) {
            options = CreateContainerOptions.NONE;
        }
        try {
            var requestBuilder = CreateBucketRequest.builder()
                    .bucket(container);
            if (!Region.US_EAST_1.equals(awsRegion)) {
                requestBuilder.createBucketConfiguration(
                        CreateBucketConfiguration.builder()
                                .locationConstraint(awsRegion.id())
                                .build());
            }
            if (options.publicRead()) {
                requestBuilder.acl(BucketCannedACL.PUBLIC_READ);
            }
            s3Client.createBucket(requestBuilder.build());
            return true;
        } catch (S3Exception e) {
            if ("BucketAlreadyOwnedByYou".equals(S3Exceptions.errorCode(e))) {
                // Idempotent success - bucket exists and caller owns it
                return false;
            }
            throw propagate(e, container, null);
        }
    }

    @Override
    public void deleteContainer(String container) {
        try {
            clearContainer(container,
                    ListContainerOptions.NONE);
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
    public Blob getBlob(String container, String key, GetOptions options) {
        var requestBuilder = GetObjectRequest.builder()
                .bucket(container)
                .key(key);

        if (options.versionId() != null) {
            requestBuilder.versionId(options.versionId());
        }

        if (!options.ranges().isEmpty()) {
            String rangeSpec = options.ranges().get(0);
            requestBuilder.range("bytes=" + rangeSpec);
        }

        if (options.ifMatch() != null) {
            requestBuilder.ifMatch(maybeStripETagQuotes(options.ifMatch()));
        }
        if (options.ifNoneMatch() != null) {
            requestBuilder.ifNoneMatch(
                    maybeStripETagQuotes(options.ifNoneMatch()));
        }
        if (options.ifModifiedSince() != null) {
            requestBuilder.ifModifiedSince(
                    options.ifModifiedSince().toInstant());
        }
        if (options.ifUnmodifiedSince() != null) {
            requestBuilder.ifUnmodifiedSince(
                    options.ifUnmodifiedSince().toInstant());
        }

        try {
            var responseStream = s3Client.getObject(requestBuilder.build());
            var response = responseStream.response();

            // The SDK deprecated expires() in favor of expiresString() but
            // the blobstore API models Expires as a Date, so use the SDK's
            // parsed value.
            @SuppressWarnings("deprecation")
            var expires = response.expires() == null ?
                    null : Date.from(response.expires());
            var builder = Blob.builder(key)
                    .userMetadata(response.metadata())
                    .payload(responseStream)
                    .cacheControl(response.cacheControl())
                    .contentDisposition(response.contentDisposition())
                    .contentEncoding(response.contentEncoding())
                    .contentLanguage(response.contentLanguage())
                    .contentLength(response.contentLength())
                    .contentType(response.contentType())
                    .expires(expires);

            if (response.contentRange() != null) {
                builder.contentRange(response.contentRange());
            }

            builder.eTag(response.eTag());
            if (response.lastModified() != null) {
                builder.lastModified(Date.from(response.lastModified()));
            }
            // Carry the storage class so GET reports x-amz-storage-class
            // consistently with HEAD (blobMetadata) instead of defaulting to
            // STANDARD for GLACIER/IA objects.
            builder.storageClass(orStandard(response.storageClassAsString()));

            builder.versionId(response.versionId());

            return builder.build();
        } catch (S3Exception e) {
            // 304, 405 on a delete marker read, NoSuchVersion and the rest
            // pass through verbatim; the response headers, e.g. ETag and
            // x-amz-delete-marker, ride on the exception.
            throw propagate(e, container, key);
        }
    }

    @Override
    public PutObjectResponse putBlob(String container, Blob blob,
            PutOptions options) {
        var contentMetadata = blob.getMetadata().contentMetadata();
        var requestBuilder = PutObjectRequest.builder()
                .bucket(container)
                .key(blob.getMetadata().name());

        if (contentMetadata.cacheControl() != null) {
            requestBuilder.cacheControl(contentMetadata.cacheControl());
        }
        if (contentMetadata.contentDisposition() != null) {
            requestBuilder.contentDisposition(
                    contentMetadata.contentDisposition());
        }
        if (contentMetadata.contentEncoding() != null) {
            requestBuilder.contentEncoding(contentMetadata.contentEncoding());
        }
        if (contentMetadata.contentLanguage() != null) {
            requestBuilder.contentLanguage(contentMetadata.contentLanguage());
        }
        HashCode md5 = contentMetadata.contentMD5();
        if (md5 != null) {
            requestBuilder.contentMD5(Base64.getEncoder().encodeToString(
                    md5.asBytes()));
        }
        if (contentMetadata.contentType() != null) {
            requestBuilder.contentType(contentMetadata.contentType());
        }
        if (contentMetadata.expires() != null) {
            requestBuilder.expires(contentMetadata.expires().toInstant());
        }

        var userMetadata = blob.getMetadata().userMetadata();
        if (userMetadata != null && !userMetadata.isEmpty()) {
            requestBuilder.metadata(userMetadata);
        }

        BlobAccess requestedAccess = options != null ? options.blobAccess() : null;
        if (requestedAccess == BlobAccess.PUBLIC_READ) {
            requestBuilder.acl(ObjectCannedACL.PUBLIC_READ);
        }

        if (blob.getMetadata().storageClass() != null &&
                blob.getMetadata().storageClass() != StorageClass.STANDARD) {
            requestBuilder.storageClass(
                    blob.getMetadata().storageClass());
        }

        String ifMatch = options != null ? options.ifMatch() : null;
        String ifNoneMatch = options != null ? options.ifNoneMatch() : null;

        boolean hasConditionalHeaders = ifMatch != null || ifNoneMatch != null;
        if (hasConditionalHeaders && !useNativeConditionalWrites) {
            validateConditionalPut(container, blob.getMetadata().name(),
                    ifMatch, ifNoneMatch);
            ifMatch = null;
            ifNoneMatch = null;
        }

        if (ifMatch != null) {
            requestBuilder.ifMatch(maybeStripETagQuotes(ifMatch));
        }
        if (ifNoneMatch != null) {
            requestBuilder.ifNoneMatch(maybeStripETagQuotes(ifNoneMatch));
        }

        try (InputStream is = blob.getPayload()) {
            Long contentLength = contentMetadata.contentLength();
            if (contentLength == null) {
                // Mimic S3 behavior: Reject unknown length instead of crashing memory
                throw new IllegalArgumentException("Content-Length is required for S3 putBlob");
            } else {
                return s3Client.putObject(requestBuilder.build(),
                        RequestBody.fromInputStream(is, contentLength));
            }
        } catch (IOException e) {
            throw new RuntimeException("Failed to read blob payload", e);
        } catch (S3Exception e) {
            throw propagate(e, container, blob.getMetadata().name());
        }
    }

    @Override
    public CopyObjectResponse copyBlob(String fromContainer, String fromName,
            String toContainer, String toName, CopyOptions options) {
        var requestBuilder = CopyObjectRequest.builder()
                .sourceBucket(fromContainer)
                .sourceKey(fromName)
                .destinationBucket(toContainer)
                .destinationKey(toName);

        if (options.sourceVersionId() != null) {
            requestBuilder.sourceVersionId(options.sourceVersionId());
        }

        var contentMetadata = options.contentMetadata();
        if (contentMetadata != null) {
            if (contentMetadata.cacheControl() != null) {
                requestBuilder.cacheControl(contentMetadata.cacheControl());
            }
            if (contentMetadata.contentDisposition() != null) {
                requestBuilder.contentDisposition(
                        contentMetadata.contentDisposition());
            }
            if (contentMetadata.contentEncoding() != null) {
                requestBuilder.contentEncoding(
                        contentMetadata.contentEncoding());
            }
            if (contentMetadata.contentLanguage() != null) {
                requestBuilder.contentLanguage(
                        contentMetadata.contentLanguage());
            }
            if (contentMetadata.contentType() != null) {
                requestBuilder.contentType(contentMetadata.contentType());
            }
            requestBuilder.metadataDirective("REPLACE");
        }

        var userMetadata = options.userMetadata();
        if (userMetadata != null) {
            requestBuilder.metadata(userMetadata);
            requestBuilder.metadataDirective("REPLACE");
        }

        String ifMatch = options.ifMatch();
        if (ifMatch != null) {
            requestBuilder.copySourceIfMatch(ifMatch);
        }
        String ifNoneMatch = options.ifNoneMatch();
        if (ifNoneMatch != null) {
            requestBuilder.copySourceIfNoneMatch(ifNoneMatch);
        }
        Date ifModifiedSince = options.ifModifiedSince();
        if (ifModifiedSince != null) {
            requestBuilder.copySourceIfModifiedSince(
                    ifModifiedSince.toInstant());
        }
        Date ifUnmodifiedSince = options.ifUnmodifiedSince();
        if (ifUnmodifiedSince != null) {
            requestBuilder.copySourceIfUnmodifiedSince(
                    ifUnmodifiedSince.toInstant());
        }

        if (options.blobAccess() == BlobAccess.PUBLIC_READ) {
            requestBuilder.acl(ObjectCannedACL.PUBLIC_READ);
        }

        try {
            return s3Client.copyObject(requestBuilder.build());
        } catch (S3Exception e) {
            throw propagate(e, fromContainer, fromName);
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
    @Nullable
    public BlobMetadata blobMetadata(String container, String key) {
        return blobMetadata(container, key, /*versionId=*/ null);
    }

    @Override
    @Nullable
    public BlobMetadata blobMetadata(String container, String key,
            @Nullable String versionId) {
        var requestBuilder = HeadObjectRequest.builder()
                .bucket(container)
                .key(key);
        if (versionId != null) {
            requestBuilder.versionId(versionId);
        }
        try {
            HeadObjectResponse response = s3Client.headObject(
                    requestBuilder.build());

            return new BlobMetadata(key,
                    response.metadata(), response.eTag(),
                    toDate(response.lastModified()),
                    orStandard(response.storageClassAsString()),
                    container,
                    toContentMetadata(response),
                    response.versionId());
        } catch (NoSuchKeyException e) {
            return nullOrDeleteMarker(container, key, e);
        } catch (NoSuchBucketException e) {
            throw e;
        } catch (S3Exception e) {
            if (e.statusCode() == 404) {
                return nullOrDeleteMarker(container, key, e);
            }
            // 405 on a delete marker read passes through verbatim with
            // x-amz-delete-marker riding on the exception's headers.
            throw e;
        }
    }

    @Override
    public ContainerAccess getContainerAccess(String container) {
        try {
            var response = s3Client.getBucketAcl(GetBucketAclRequest.builder()
                    .bucket(container)
                    .build());
            boolean isPublic = hasPublicRead(response.grants());
            return isPublic ?
                    ContainerAccess.PUBLIC_READ : ContainerAccess.PRIVATE;
        } catch (NoSuchBucketException e) {
            throw e;
        } catch (S3Exception e) {
            if (e.statusCode() == 404) {
                throw propagate(e, container, null);
            }
            return ContainerAccess.PRIVATE;
        }
    }

    @Override
    public void setContainerAccess(String container, ContainerAccess access) {
        BucketCannedACL acl = access == ContainerAccess.PUBLIC_READ ?
                BucketCannedACL.PUBLIC_READ : BucketCannedACL.PRIVATE;
        try {
            s3Client.putBucketAcl(PutBucketAclRequest.builder()
                    .bucket(container)
                    .acl(acl)
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
    public ListObjectVersionsResponse listVersions(String container,
            ListVersionsOptions options) {
        var requestBuilder = ListObjectVersionsRequest.builder()
                .bucket(container);
        if (options.prefix() != null) {
            requestBuilder.prefix(options.prefix());
        }
        if (options.delimiter() != null) {
            requestBuilder.delimiter(options.delimiter());
        }
        if (options.keyMarker() != null) {
            requestBuilder.keyMarker(options.keyMarker());
        }
        if (options.versionIdMarker() != null) {
            requestBuilder.versionIdMarker(options.versionIdMarker());
        }
        if (options.maxResults() != null) {
            requestBuilder.maxKeys(options.maxResults());
        }

        try {
            return s3Client.listObjectVersions(requestBuilder.build());
        } catch (S3Exception e) {
            throw propagate(e, container, null);
        }
    }

    @Override
    public BlobAccess getBlobAccess(String container, String key) {
        try {
            var response = s3Client.getObjectAcl(GetObjectAclRequest.builder()
                    .bucket(container)
                    .key(key)
                    .build());
            return hasPublicRead(response.grants()) ?
                    BlobAccess.PUBLIC_READ : BlobAccess.PRIVATE;
        } catch (S3Exception e) {
            if (e.statusCode() == 404) {
                throw translateAclNotFound(container, key, e);
            }
            throw e;
        }
    }

    private static boolean hasPublicRead(List<Grant> grants) {
        for (Grant grant : grants) {
            if (grant.permission() == Permission.READ || grant.permission() == Permission.FULL_CONTROL) {
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
    public void setBlobAccess(String container, String key, BlobAccess access) {
        ObjectCannedACL acl = access == BlobAccess.PUBLIC_READ ?
                ObjectCannedACL.PUBLIC_READ : ObjectCannedACL.PRIVATE;
        try {
            s3Client.putObjectAcl(PutObjectAclRequest.builder()
                    .bucket(container)
                    .key(key)
                    .acl(acl)
                    .build());
        } catch (S3Exception e) {
            throw propagate(e, container, key);
        }
    }

    @Override
    public MultipartUpload initiateMultipartUpload(String container,
            BlobMetadata blobMetadata, PutOptions options) {
        var requestBuilder = CreateMultipartUploadRequest.builder()
                .bucket(container)
                .key(blobMetadata.name());

        var contentMetadata = blobMetadata.contentMetadata();
        if (contentMetadata != null) {
            if (contentMetadata.cacheControl() != null) {
                requestBuilder.cacheControl(contentMetadata.cacheControl());
            }
            if (contentMetadata.contentDisposition() != null) {
                requestBuilder.contentDisposition(
                        contentMetadata.contentDisposition());
            }
            if (contentMetadata.contentEncoding() != null) {
                requestBuilder.contentEncoding(
                        contentMetadata.contentEncoding());
            }
            if (contentMetadata.contentLanguage() != null) {
                requestBuilder.contentLanguage(
                        contentMetadata.contentLanguage());
            }
            if (contentMetadata.contentType() != null) {
                requestBuilder.contentType(contentMetadata.contentType());
            }
        }

        var userMetadata = blobMetadata.userMetadata();
        if (userMetadata != null && !userMetadata.isEmpty()) {
            requestBuilder.metadata(userMetadata);
        }

        if (options != null && options.blobAccess() == BlobAccess.PUBLIC_READ) {
            requestBuilder.acl(ObjectCannedACL.PUBLIC_READ);
        }

        if (blobMetadata.storageClass() != null &&
                blobMetadata.storageClass() != StorageClass.STANDARD) {
            requestBuilder.storageClass(
                    blobMetadata.storageClass());
        }

        try {
            var response = s3Client.createMultipartUpload(
                    requestBuilder.build());
            return new MultipartUpload(container, blobMetadata.name(),
                    response.uploadId(), blobMetadata, options);
        } catch (S3Exception e) {
            throw propagate(e, container, blobMetadata.name());
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
    public CompleteMultipartUploadResponse completeMultipartUpload(MultipartUpload mpu,
            List<MultipartPart> parts) {
        var sortedParts = sortAndValidateParts(parts);
        var completedParts = sortedParts.stream()
                .map(part -> CompletedPart.builder()
                        .partNumber(part.partNumber())
                        .eTag(part.partETag())
                        .build())
                .toList();

        var requestBuilder = CompleteMultipartUploadRequest.builder()
                .bucket(mpu.containerName())
                .key(mpu.blobName())
                .uploadId(mpu.id())
                .multipartUpload(CompletedMultipartUpload.builder()
                        .parts(completedParts)
                        .build());

        var putOptions = mpu.putOptions();
        if (putOptions != null) {
            // S3 resolves the condition as it publishes the object, so it
            // holds even against a writer racing this completion
            requestBuilder.ifMatch(putOptions.ifMatch());
            requestBuilder.ifNoneMatch(putOptions.ifNoneMatch());
        }

        try {
            return s3Client.completeMultipartUpload(
                    requestBuilder.build());
        } catch (S3Exception e) {
            throw propagate(e, mpu.containerName(), mpu.blobName());
        }
    }

    @Override
    public MultipartPart uploadMultipartPart(MultipartUpload mpu,
            int partNumber, InputStream is, long contentLength,
            @Nullable HashCode contentMD5) {
        try (is) {
            var response = s3Client.uploadPart(UploadPartRequest.builder()
                    .bucket(mpu.containerName())
                    .key(mpu.blobName())
                    .uploadId(mpu.id())
                    .partNumber(partNumber)
                    .build(),
                    RequestBody.fromInputStream(is, contentLength));

            return new MultipartPart(partNumber, contentLength,
                    response.eTag(), null);
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
    public MultipartPart copyMultipartPart(MultipartUpload mpu,
            int partNumber, String sourceContainer, String sourceName,
            @Nullable String sourceVersionId,
            @Nullable String copySourceRange, @Nullable String ifMatch,
            @Nullable String ifNoneMatch, @Nullable Date ifModifiedSince,
            @Nullable Date ifUnmodifiedSince) {
        var builder = UploadPartCopyRequest.builder()
                .sourceBucket(sourceContainer)
                .sourceKey(sourceName)
                .destinationBucket(mpu.containerName())
                .destinationKey(mpu.blobName())
                .uploadId(mpu.id())
                .partNumber(partNumber);
        if (sourceVersionId != null) {
            builder.sourceVersionId(sourceVersionId);
        }
        if (copySourceRange != null) {
            builder.copySourceRange(copySourceRange);
        }
        if (ifMatch != null) {
            builder.copySourceIfMatch(ifMatch);
        }
        if (ifNoneMatch != null) {
            builder.copySourceIfNoneMatch(ifNoneMatch);
        }
        if (ifModifiedSince != null) {
            builder.copySourceIfModifiedSince(ifModifiedSince.toInstant());
        }
        if (ifUnmodifiedSince != null) {
            builder.copySourceIfUnmodifiedSince(ifUnmodifiedSince.toInstant());
        }
        try {
            var response = s3Client.uploadPartCopy(builder.build());
            var result = response.copyPartResult();
            return new MultipartPart(partNumber, /*partSize=*/ -1,
                    result.eTag(), Date.from(result.lastModified()),
                    response.copySourceVersionId());
        } catch (S3Exception e) {
            throw propagate(e, sourceContainer, sourceName);
        }
    }

    @Override
    public List<MultipartPart> listMultipartUpload(MultipartUpload mpu) {
        try {
            var parts = ImmutableList.<MultipartPart>builder();
            Integer partNumberMarker = null;

            do {
                var response = s3Client.listParts(ListPartsRequest.builder()
                        .bucket(mpu.containerName())
                        .key(mpu.blobName())
                        .uploadId(mpu.id())
                        .partNumberMarker(partNumberMarker)
                        .build());

                for (Part part : response.parts()) {
                    parts.add(new MultipartPart(part.partNumber(),
                            part.size(),
                            part.eTag(),
                            toDate(part.lastModified())));
                }

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
    public List<MultipartUpload> listMultipartUploads(String container) {
        try {
            var builder = ImmutableList.<MultipartUpload>builder();
            String keyMarker = null;
            String uploadIdMarker = null;

            do {
                var response = s3Client.listMultipartUploads(
                        ListMultipartUploadsRequest.builder()
                                .bucket(container)
                                .keyMarker(keyMarker)
                                .uploadIdMarker(uploadIdMarker)
                                .build());

                for (var upload : response.uploads()) {
                    builder.add(new MultipartUpload(container,
                            upload.key(),
                            upload.uploadId(),
                            null, null));
                }

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

    private static List<MultipartPart> sortAndValidateParts(
            List<MultipartPart> parts) {
        if (parts == null || parts.isEmpty()) {
            throw new IllegalArgumentException(
                    "At least one multipart part is required");
        }
        var sortedParts = parts.stream()
                .sorted(Comparator.comparingInt(MultipartPart::partNumber))
                .toList();
        int previousPartNumber = 0;
        for (MultipartPart part : sortedParts) {
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

    @Nullable
    private static Date toDate(@Nullable Instant instant) {
        if (instant == null) {
            return null;
        }
        return Date.from(instant);
    }

    /**
     * The listed or reported storage class, defaulting an absent or novel
     * one to STANDARD as the S3 listing schema does.
     */
    private static StorageClass orStandard(@Nullable String storageClass) {
        if (storageClass == null) {
            return StorageClass.STANDARD;
        }
        StorageClass parsed = StorageClass.fromValue(storageClass);
        return parsed == StorageClass.UNKNOWN_TO_SDK_VERSION ?
                StorageClass.STANDARD : parsed;
    }

    private static org.gaul.s3proxy.blobstore.ContentMetadata toContentMetadata(
            HeadObjectResponse response) {
        // The SDK deprecated expires() in favor of expiresString() but the
        // blobstore API models Expires as a Date, so use the SDK's parsed
        // value.
        @SuppressWarnings("deprecation")
        var expires = response.expires() == null ?
                null : Date.from(response.expires());
        return org.gaul.s3proxy.blobstore.ContentMetadata.builder()
                .cacheControl(response.cacheControl())
                .contentDisposition(response.contentDisposition())
                .contentEncoding(response.contentEncoding())
                .contentLanguage(response.contentLanguage())
                .contentLength(response.contentLength())
                .contentType(response.contentType())
                .expires(expires)
                .build();
    }

    /**
     * Answers the blobMetadata contract for a 404: an absent object is
     * null, while a delete marker or missing version still throws.
     */
    @Nullable
    private static BlobMetadata nullOrDeleteMarker(String container,
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
        BlobMetadata metadata = blobMetadata(container, blobName);

        if (ifMatch != null) {
            validateIfMatch(container, blobName, ifMatch, metadata);
        }

        if (ifNoneMatch != null) {
            validateIfNoneMatch(ifNoneMatch, metadata);
        }
    }

    private void validateIfMatch(String container, String blobName,
            String ifMatch, @Nullable BlobMetadata metadata) {
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
            @Nullable BlobMetadata metadata) {
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
