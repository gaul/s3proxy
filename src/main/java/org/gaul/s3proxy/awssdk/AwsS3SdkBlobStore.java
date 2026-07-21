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
import java.util.Map;
import java.util.Set;

import com.google.common.base.Supplier;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Streams;
import com.google.common.hash.HashCode;
import com.google.common.net.HttpHeaders;

import org.gaul.s3proxy.blobstore.BaseBlobStore;
import org.gaul.s3proxy.blobstore.BucketAlreadyExistsException;
import org.gaul.s3proxy.blobstore.ContainerNotFoundException;
import org.gaul.s3proxy.blobstore.ContentMetadata;
import org.gaul.s3proxy.blobstore.Credentials;
import org.gaul.s3proxy.blobstore.HttpResponse;
import org.gaul.s3proxy.blobstore.HttpResponseException;
import org.gaul.s3proxy.blobstore.KeyNotFoundException;
import org.gaul.s3proxy.blobstore.Payload;
import org.gaul.s3proxy.blobstore.domain.Blob;
import org.gaul.s3proxy.blobstore.domain.BlobAccess;
import org.gaul.s3proxy.blobstore.domain.BlobMetadata;
import org.gaul.s3proxy.blobstore.domain.ContainerAccess;
import org.gaul.s3proxy.blobstore.domain.ContainerMetadata;
import org.gaul.s3proxy.blobstore.domain.MultipartPart;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.gaul.s3proxy.blobstore.domain.PageSet;
import org.gaul.s3proxy.blobstore.domain.StorageClass;
import org.gaul.s3proxy.blobstore.domain.StorageMetadata;
import org.gaul.s3proxy.blobstore.domain.StorageType;
import org.gaul.s3proxy.blobstore.options.CopyOptions;
import org.gaul.s3proxy.blobstore.options.CreateContainerOptions;
import org.gaul.s3proxy.blobstore.options.GetOptions;
import org.gaul.s3proxy.blobstore.options.ListContainerOptions;
import org.gaul.s3proxy.blobstore.options.PutOptions;
import org.jspecify.annotations.Nullable;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.awscore.exception.AwsErrorDetails;
import software.amazon.awssdk.core.checksums.RequestChecksumCalculation;
import software.amazon.awssdk.core.checksums.ResponseChecksumValidation;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.retries.DefaultRetryStrategy;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3ClientBuilder;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.model.AbortMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.Bucket;
import software.amazon.awssdk.services.s3.model.BucketCannedACL;
import software.amazon.awssdk.services.s3.model.CommonPrefix;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.CompletedMultipartUpload;
import software.amazon.awssdk.services.s3.model.CompletedPart;
import software.amazon.awssdk.services.s3.model.CopyObjectRequest;
import software.amazon.awssdk.services.s3.model.CreateBucketConfiguration;
import software.amazon.awssdk.services.s3.model.CreateBucketRequest;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.DeleteBucketRequest;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.GetBucketAclRequest;
import software.amazon.awssdk.services.s3.model.GetObjectAclRequest;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.Grant;
import software.amazon.awssdk.services.s3.model.HeadBucketRequest;
import software.amazon.awssdk.services.s3.model.HeadObjectRequest;
import software.amazon.awssdk.services.s3.model.HeadObjectResponse;
import software.amazon.awssdk.services.s3.model.ListMultipartUploadsRequest;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.ListPartsRequest;
import software.amazon.awssdk.services.s3.model.NoSuchBucketException;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.s3.model.ObjectCannedACL;
import software.amazon.awssdk.services.s3.model.Part;
import software.amazon.awssdk.services.s3.model.Permission;
import software.amazon.awssdk.services.s3.model.PutBucketAclRequest;
import software.amazon.awssdk.services.s3.model.PutObjectAclRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.services.s3.model.S3Object;
import software.amazon.awssdk.services.s3.model.Type;
import software.amazon.awssdk.services.s3.model.UploadPartRequest;

public final class AwsS3SdkBlobStore extends BaseBlobStore {
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
            builder.credentialsProvider(DefaultCredentialsProvider.create());
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
    public PageSet<? extends StorageMetadata> list() {
        try {
            var set = ImmutableSet.<StorageMetadata>builder();
            for (Bucket bucket : s3Client.listBuckets().buckets()) {
                set.add(new ContainerMetadata(bucket.name(), Map.of(),
                        /*eTag=*/ null, toDate(bucket.creationDate()),
                        toDate(bucket.creationDate()),
                        /*size=*/ null, StorageClass.STANDARD));
            }
            return new PageSet<StorageMetadata>(set.build(), null);
        } catch (S3Exception e) {
            throw translate(e, null, null);
        }
    }

    @Override
    public PageSet<? extends StorageMetadata> list(String container,
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
            return new PageSet<StorageMetadata>(Set.of(), null);
        }
        requestBuilder.maxKeys(maxKeys);

        try {
            var response = s3Client.listObjectsV2(requestBuilder.build());

            var set = ImmutableSet.<StorageMetadata>builder();
            String nextMarker = null;

            for (S3Object obj : response.contents()) {
                set.add(new BlobMetadata(StorageType.BLOB, obj.key(),
                        Map.of(), obj.eTag(), toDate(obj.lastModified()),
                        toDate(obj.lastModified()),
                        fromAwsObjectStorageClass(obj.storageClass()),
                        /*container=*/ null,
                        ContentMetadata.builder()
                                .contentLength(obj.size())
                                .build()));
            }

            for (CommonPrefix prefix : response.commonPrefixes()) {
                set.add(new BlobMetadata(StorageType.RELATIVE_PATH,
                        prefix.prefix(), Map.of(), /*eTag=*/ null,
                        /*creationDate=*/ null, /*lastModified=*/ null,
                        StorageClass.STANDARD, /*container=*/ null,
                        ContentMetadata.builder().build()));
            }

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

            return new PageSet<StorageMetadata>(set.build(), nextMarker);
        } catch (NoSuchBucketException e) {
            throw new ContainerNotFoundException(container, e.getMessage());
        } catch (S3Exception e) {
            throw translate(e, container, null);
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
            throw translate(e, container, null);
        }
    }

    @Override
    public boolean createContainer(String container) {
        return createContainer(container, CreateContainerOptions.NONE);
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
            s3Client.createBucket(requestBuilder.build());
            if (options.publicRead()) {
                setContainerAccess(container, ContainerAccess.PUBLIC_READ);
            }
            return true;
        } catch (S3Exception e) {
            if (e.statusCode() == 409) {
                String errorCode = e.awsErrorDetails() != null ?
                        e.awsErrorDetails().errorCode() :
                        null;
                if ("BucketAlreadyOwnedByYou".equals(errorCode)) {
                    // Idempotent success - bucket exists and caller owns it
                    return false;
                }
                if ("BucketAlreadyExists".equals(errorCode)) {
                    // Bucket exists but is owned by someone else
                    throw new BucketAlreadyExistsException(
                            "Bucket already exists: " + container, e);
                }
            }
            throw translate(e, container, null);
        }
    }

    @Override
    public void deleteContainer(String container) {
        try {
            clearContainer(container);
            s3Client.deleteBucket(DeleteBucketRequest.builder()
                    .bucket(container)
                    .build());
        } catch (NoSuchBucketException | ContainerNotFoundException e) {
            // Already deleted, ignore
        } catch (S3Exception e) {
            throw translate(e, container, null);
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

            var builder = Blob.builder(key)
                    .userMetadata(response.metadata())
                    .payload(responseStream)
                    .cacheControl(response.cacheControl())
                    .contentDisposition(response.contentDisposition())
                    .contentEncoding(response.contentEncoding())
                    .contentLanguage(response.contentLanguage())
                    .contentLength(response.contentLength())
                    .contentType(response.contentType())
                    .expires(response.expires() != null ?
                            Date.from(response.expires()) : null);

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
            builder.storageClass(fromAwsStorageClass(response.storageClass()));

            return builder.build();
        } catch (NoSuchKeyException e) {
            throw new KeyNotFoundException(container, key, e.getMessage());
        } catch (NoSuchBucketException e) {
            throw new ContainerNotFoundException(container, e.getMessage());
        } catch (S3Exception e) {
            if (e.statusCode() == 304) {
                String eTag = e.awsErrorDetails().sdkHttpResponse()
                        .firstMatchingHeader(HttpHeaders.ETAG).orElse(null);
                throw new HttpResponseException(
                        new HttpResponse(304, eTag), e);
            }
            throw translate(e, container, key);
        }
    }

    @Override
    public String putBlob(String container, Blob blob) {
        return putBlob(container, blob, PutOptions.NONE);
    }

    @Override
    public String putBlob(String container, Blob blob, PutOptions options) {
        var contentMetadata = blob.getMetadata().getContentMetadata();
        var requestBuilder = PutObjectRequest.builder()
                .bucket(container)
                .key(blob.getMetadata().getName());

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

        var userMetadata = blob.getMetadata().getUserMetadata();
        if (userMetadata != null && !userMetadata.isEmpty()) {
            requestBuilder.metadata(userMetadata);
        }

        BlobAccess requestedAccess = options != null ? options.blobAccess() : null;
        if (requestedAccess == BlobAccess.PUBLIC_READ) {
            requestBuilder.acl(ObjectCannedACL.PUBLIC_READ);
        }

        if (blob.getMetadata().getStorageClass() != null &&
                blob.getMetadata().getStorageClass() != StorageClass.STANDARD) {
            requestBuilder.storageClass(
                    toAwsStorageClass(blob.getMetadata().getStorageClass()));
        }

        String ifMatch = options != null ? options.ifMatch() : null;
        String ifNoneMatch = options != null ? options.ifNoneMatch() : null;

        boolean hasConditionalHeaders = ifMatch != null || ifNoneMatch != null;
        if (hasConditionalHeaders && !useNativeConditionalWrites) {
            validateConditionalPut(container, blob.getMetadata().getName(),
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

        try (InputStream is = blob.getPayload().openStream()) {
            Long contentLength = contentMetadata.contentLength();
            if (contentLength == null) {
                // Mimic S3 behavior: Reject unknown length instead of crashing memory
                throw new IllegalArgumentException("Content-Length is required for S3 putBlob");
            } else {
                var response = s3Client.putObject(requestBuilder.build(),
                        RequestBody.fromInputStream(is, contentLength));
                return response.eTag();
            }
        } catch (IOException e) {
            throw new RuntimeException("Failed to read blob payload", e);
        } catch (S3Exception e) {
            throw translate(e, container, blob.getMetadata().getName());
        }
    }

    @Override
    public String copyBlob(String fromContainer, String fromName,
            String toContainer, String toName, CopyOptions options) {
        var requestBuilder = CopyObjectRequest.builder()
                .sourceBucket(fromContainer)
                .sourceKey(fromName)
                .destinationBucket(toContainer)
                .destinationKey(toName);

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

        try {
            var response = s3Client.copyObject(requestBuilder.build());
            return response.copyObjectResult().eTag();
        } catch (NoSuchKeyException e) {
            throw new KeyNotFoundException(fromContainer, fromName,
                    e.getMessage());
        } catch (NoSuchBucketException e) {
            throw new ContainerNotFoundException(fromContainer, e.getMessage());
        } catch (S3Exception e) {
            throw translate(e, fromContainer, fromName);
        }
    }

    @Override
    public void removeBlob(String container, String key) {
        try {
            s3Client.deleteObject(DeleteObjectRequest.builder()
                    .bucket(container)
                    .key(key)
                    .build());
        } catch (NoSuchKeyException | NoSuchBucketException e) {
            // Ignore - delete is idempotent
        } catch (S3Exception e) {
            if (e.statusCode() != 404) {
                throw e;
            }
        }
    }

    @Override
    public BlobMetadata blobMetadata(String container, String key) {
        try {
            HeadObjectResponse response = s3Client.headObject(
                    HeadObjectRequest.builder()
                            .bucket(container)
                            .key(key)
                            .build());

            return new BlobMetadata(StorageType.BLOB, key,
                    response.metadata(), response.eTag(),
                    toDate(response.lastModified()),
                    toDate(response.lastModified()),
                    fromAwsStorageClass(response.storageClass()),
                    container,
                    toContentMetadata(response));
        } catch (NoSuchKeyException e) {
            return null;
        } catch (NoSuchBucketException e) {
            throw new ContainerNotFoundException(container, e.getMessage());
        } catch (S3Exception e) {
            if (e.statusCode() == 404) {
                return null;
            }
            throw translate(e, container, key);
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
            throw new ContainerNotFoundException(container, e.getMessage());
        } catch (S3Exception e) {
            if (e.statusCode() == 404) {
                throw new ContainerNotFoundException(container, e.getMessage());
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
        } catch (NoSuchBucketException e) {
            throw new ContainerNotFoundException(container, e.getMessage());
        } catch (S3Exception e) {
            throw translate(e, container, null);
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
        } catch (NoSuchKeyException e) {
            throw new KeyNotFoundException(container, key, e.getMessage());
        } catch (NoSuchBucketException e) {
            throw new ContainerNotFoundException(container, e.getMessage());
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
        AwsErrorDetails details = e.awsErrorDetails();
        String errorCode = details != null ? details.errorCode() : null;
        if ("NoSuchKey".equals(errorCode) || "NotFound".equals(errorCode)) {
            return new KeyNotFoundException(container, key, e.getMessage());
        }
        if ("NoSuchBucket".equals(errorCode)) {
            return new ContainerNotFoundException(container, e.getMessage());
        }
        if (key != null) {
            return new KeyNotFoundException(container, key, e.getMessage());
        }
        return new ContainerNotFoundException(container, e.getMessage());
    }

    private void applyMultipartAclIfNeeded(MultipartUpload mpu) {
        if (mpu == null) {
            return;
        }
        PutOptions putOptions = mpu.putOptions();
        if (putOptions != null && putOptions.blobAccess() == BlobAccess.PUBLIC_READ) {
            setBlobAccess(mpu.containerName(), mpu.blobName(), BlobAccess.PUBLIC_READ);
        }
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
        } catch (NoSuchKeyException e) {
            throw new KeyNotFoundException(container, key, e.getMessage());
        } catch (NoSuchBucketException e) {
            throw new ContainerNotFoundException(container, e.getMessage());
        } catch (S3Exception e) {
            throw translate(e, container, key);
        }
    }

    @Override
    public MultipartUpload initiateMultipartUpload(String container,
            BlobMetadata blobMetadata, PutOptions options) {
        var requestBuilder = CreateMultipartUploadRequest.builder()
                .bucket(container)
                .key(blobMetadata.getName());

        var contentMetadata = blobMetadata.getContentMetadata();
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

        var userMetadata = blobMetadata.getUserMetadata();
        if (userMetadata != null && !userMetadata.isEmpty()) {
            requestBuilder.metadata(userMetadata);
        }

        if (options != null && options.blobAccess() == BlobAccess.PUBLIC_READ) {
            requestBuilder.acl(ObjectCannedACL.PUBLIC_READ);
        }

        if (blobMetadata.getStorageClass() != null &&
                blobMetadata.getStorageClass() != StorageClass.STANDARD) {
            requestBuilder.storageClass(
                    toAwsStorageClass(blobMetadata.getStorageClass()));
        }

        try {
            var response = s3Client.createMultipartUpload(
                    requestBuilder.build());
            return new MultipartUpload(container, blobMetadata.getName(),
                    response.uploadId(), blobMetadata, options);
        } catch (NoSuchBucketException e) {
            throw new ContainerNotFoundException(container, e.getMessage());
        } catch (S3Exception e) {
            throw translate(e, container, blobMetadata.getName());
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
        } catch (NoSuchKeyException e) {
            throw new KeyNotFoundException(mpu.containerName(), mpu.blobName(),
                    "Multipart upload not found: " + mpu.id());
        } catch (S3Exception e) {
            if (e.statusCode() == 404) {
                throw new KeyNotFoundException(mpu.containerName(),
                        mpu.blobName(),
                        "Multipart upload not found: " + mpu.id());
            }
            throw e;
        }
    }

    @Override
    public String completeMultipartUpload(MultipartUpload mpu,
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

        try {
            var response = s3Client.completeMultipartUpload(
                    requestBuilder.build());
            applyMultipartAclIfNeeded(mpu);
            return response.eTag();
        } catch (S3Exception e) {
            throw translate(e, mpu.containerName(), mpu.blobName());
        }
    }

    @Override
    public MultipartPart uploadMultipartPart(MultipartUpload mpu,
            int partNumber, Payload payload) {
        Long contentLength = payload.getContentMetadata().contentLength();
        if (contentLength == null) {
            throw new IllegalArgumentException("Content-Length is required");
        }

        try (InputStream is = payload.openStream()) {
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
            throw translate(e, mpu.containerName(), mpu.blobName());
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
            throw translate(e, mpu.containerName(), mpu.blobName());
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
        } catch (NoSuchBucketException e) {
            throw new ContainerNotFoundException(container, e.getMessage());
        } catch (S3Exception e) {
            throw translate(e, container, null);
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

    private static Date toDate(@Nullable Instant instant) {
        if (instant == null) {
            return null;
        }
        return Date.from(instant);
    }

    private static software.amazon.awssdk.services.s3.model.StorageClass
            toAwsStorageClass(StorageClass storageClass) {
        return software.amazon.awssdk.services.s3.model.StorageClass.valueOf(
                storageClass.name());
    }

    private static StorageClass fromAwsStorageClass(
            software.amazon.awssdk.services.s3.model.@Nullable StorageClass
                    storageClass) {
        if (storageClass == null) {
            return StorageClass.STANDARD;
        }
        try {
            return StorageClass.valueOf(storageClass.name());
        } catch (IllegalArgumentException e) {
            return StorageClass.STANDARD;
        }
    }

    private static StorageClass fromAwsObjectStorageClass(
            software.amazon.awssdk.services.s3.model.@Nullable
                    ObjectStorageClass storageClass) {
        if (storageClass == null) {
            return StorageClass.STANDARD;
        }
        try {
            return StorageClass.valueOf(storageClass.name());
        } catch (IllegalArgumentException e) {
            return StorageClass.STANDARD;
        }
    }

    private static org.gaul.s3proxy.blobstore.ContentMetadata toContentMetadata(
            HeadObjectResponse response) {
        return org.gaul.s3proxy.blobstore.ContentMetadata.builder()
                .cacheControl(response.cacheControl())
                .contentDisposition(response.contentDisposition())
                .contentEncoding(response.contentEncoding())
                .contentLanguage(response.contentLanguage())
                .contentLength(response.contentLength())
                .contentType(response.contentType())
                .expires(response.expires() != null ?
                        Date.from(response.expires()) : null)
                .build();
    }

    private RuntimeException translate(S3Exception e,
            @Nullable String container, @Nullable String key) {
        if (container != null && e.statusCode() == 404) {
            String errorCode = e.awsErrorDetails().errorCode();
            if ("NoSuchBucket".equals(errorCode)) {
                return new ContainerNotFoundException(container, e.getMessage());
            } else if ("NoSuchKey".equals(errorCode)) {
                if (key == null) {
                    return new ContainerNotFoundException(container, e.getMessage());
                }
                return new KeyNotFoundException(container, key, e.getMessage());
            }
            if (key != null) {
                return new KeyNotFoundException(container, key, e.getMessage());
            } else {
                return new ContainerNotFoundException(container, e.getMessage());
            }
        }
        String eTag = e.statusCode() == 304 ?
                e.awsErrorDetails().sdkHttpResponse()
                        .firstMatchingHeader(HttpHeaders.ETAG).orElse(null) :
                null;
        return new HttpResponseException(
                new HttpResponse(e.statusCode(), eTag), e);
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

    private HttpResponseException preconditionFailed() {
        return new HttpResponseException(new HttpResponse(412));
    }

    private KeyNotFoundException keyNotFound(String container, String key) {
        return new KeyNotFoundException(container, key,
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

        String currentETag = metadata.getETag();
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

        String currentETag = metadata.getETag();
        if (currentETag != null &&
                equalsIgnoringSurroundingQuotes(ifNoneMatch,
                    maybeQuoteETag(currentETag))) {
            throw preconditionFailed();
        }
    }
}
