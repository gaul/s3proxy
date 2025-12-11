/*
 * Copyright 2014-2025 Andrew Gaul <andrew@gaul.org>
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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import javax.annotation.Nullable;

import com.google.common.base.Supplier;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Iterables;
import com.google.common.io.BaseEncoding;
import com.google.common.net.HttpHeaders;

import jakarta.inject.Inject;
import jakarta.inject.Named;
import jakarta.inject.Singleton;

import org.gaul.s3proxy.PutOptions2;
import org.jclouds.blobstore.BlobStoreContext;
import org.jclouds.blobstore.ContainerNotFoundException;
import org.jclouds.blobstore.KeyNotFoundException;
import org.jclouds.blobstore.domain.Blob;
import org.jclouds.blobstore.domain.BlobAccess;
import org.jclouds.blobstore.domain.BlobMetadata;
import org.jclouds.blobstore.domain.ContainerAccess;
import org.jclouds.blobstore.domain.MultipartPart;
import org.jclouds.blobstore.domain.MultipartUpload;
import org.jclouds.blobstore.domain.PageSet;
import org.jclouds.blobstore.domain.StorageMetadata;
import org.jclouds.blobstore.domain.StorageType;
import org.jclouds.blobstore.domain.Tier;
import org.jclouds.blobstore.domain.internal.BlobBuilderImpl;
import org.jclouds.blobstore.domain.internal.BlobMetadataImpl;
import org.jclouds.blobstore.domain.internal.PageSetImpl;
import org.jclouds.blobstore.domain.internal.StorageMetadataImpl;
import org.jclouds.blobstore.internal.BaseBlobStore;
import org.jclouds.blobstore.options.CopyOptions;
import org.jclouds.blobstore.options.CreateContainerOptions;
import org.jclouds.blobstore.options.GetOptions;
import org.jclouds.blobstore.options.ListContainerOptions;
import org.jclouds.blobstore.options.PutOptions;
import org.jclouds.blobstore.util.BlobUtils;
import org.jclouds.collect.Memoized;
import org.jclouds.domain.Credentials;
import org.jclouds.domain.Location;
import org.jclouds.http.HttpCommand;
import org.jclouds.http.HttpRequest;
import org.jclouds.http.HttpResponse;
import org.jclouds.http.HttpResponseException;
import org.jclouds.io.ContentMetadataBuilder;
import org.jclouds.io.Payload;
import org.jclouds.io.PayloadSlicer;
import org.jclouds.providers.ProviderMetadata;
import org.jclouds.rest.AuthorizationException;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.awscore.exception.AwsErrorDetails;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3ClientBuilder;
import software.amazon.awssdk.services.s3.model.AbortMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.Bucket;
import software.amazon.awssdk.services.s3.model.BucketCannedACL;
import software.amazon.awssdk.services.s3.model.CommonPrefix;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.CompletedMultipartUpload;
import software.amazon.awssdk.services.s3.model.CompletedPart;
import software.amazon.awssdk.services.s3.model.CopyObjectRequest;
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
import software.amazon.awssdk.services.s3.model.StorageClass;
import software.amazon.awssdk.services.s3.model.Type;
import software.amazon.awssdk.services.s3.model.UploadPartRequest;

@Singleton
public final class AwsS3SdkBlobStore extends BaseBlobStore {
    /**
     * Tri-state for conditional writes support detection:
     * - null: not yet detected
     * - true: backend supports native conditional writes
     * - false: backend does not support, emulation required
     */
    private final AtomicReference<Boolean> conditionalWritesSupported =
            new AtomicReference<>(null);

    private final S3Client s3Client;
    private final String endpoint;

    @Inject
    AwsS3SdkBlobStore(BlobStoreContext context, BlobUtils blobUtils,
            Supplier<Location> defaultLocation,
            @Memoized Supplier<Set<? extends Location>> locations,
            PayloadSlicer slicer,
            @org.jclouds.location.Provider Supplier<Credentials> creds,
            ProviderMetadata provider,
            @Named(AwsS3SdkApiMetadata.REGION) String region) {
        super(context, blobUtils, defaultLocation, locations, slicer);
        this.endpoint = provider.getEndpoint();
        var cred = creds.get();

        S3ClientBuilder builder = S3Client.builder();

        // Configure credentials
        if (cred.identity != null && !cred.identity.isEmpty() &&
                cred.credential != null && !cred.credential.isEmpty()) {
            builder.credentialsProvider(StaticCredentialsProvider.create(
                    AwsBasicCredentials.create(cred.identity, cred.credential)));
        }

        // Configure endpoint and path-style access for non-AWS endpoints
        if (endpoint != null && !endpoint.isEmpty()) {
            URI endpointUri = URI.create(endpoint);
            builder.endpointOverride(endpointUri);

            // Use path-style for non-AWS endpoints (Hetzner, MinIO, etc.)
            String host = endpointUri.getHost();
            if (host != null && !host.endsWith(".amazonaws.com")) {
                builder.forcePathStyle(true);
            }
        }

        // Configure region from property or default to us-east-1
        builder.region(Region.of(region));

        this.s3Client = builder.build();
    }

    @Override
    public PageSet<? extends StorageMetadata> list() {
        var set = ImmutableSet.<StorageMetadata>builder();
        for (Bucket bucket : s3Client.listBuckets().buckets()) {
            set.add(new StorageMetadataImpl(StorageType.CONTAINER, /*id=*/ null,
                    bucket.name(), /*location=*/ null, /*uri=*/ null,
                    /*eTag=*/ null,
                    toDate(bucket.creationDate()),
                    toDate(bucket.creationDate()),
                    Map.of(), /*size=*/ null,
                    Tier.STANDARD));
        }
        return new PageSetImpl<StorageMetadata>(set.build(), null);
    }

    @Override
    public PageSet<? extends StorageMetadata> list(String container,
            ListContainerOptions options) {
        var requestBuilder = ListObjectsV2Request.builder()
                .bucket(container);

        if (options.getPrefix() != null) {
            requestBuilder.prefix(options.getPrefix());
        }
        if (options.getDelimiter() != null) {
            requestBuilder.delimiter(options.getDelimiter());
        }
        if (options.getMarker() != null) {
            requestBuilder.startAfter(options.getMarker());
        }
        int maxKeys = options.getMaxResults() != null ?
                options.getMaxResults() : 1000;
        if (maxKeys == 0) {
            return new PageSetImpl<StorageMetadata>(ImmutableSet.of(), null);
        }
        requestBuilder.maxKeys(maxKeys);

        try {
            var response = s3Client.listObjectsV2(requestBuilder.build());

            var set = ImmutableSet.<StorageMetadata>builder();
            String nextMarker = null;

            // Add objects
            for (S3Object obj : response.contents()) {
                set.add(new StorageMetadataImpl(StorageType.BLOB,
                        /*id=*/ null, obj.key(), /*location=*/ null,
                        /*uri=*/ null, obj.eTag(),
                        toDate(obj.lastModified()),
                        toDate(obj.lastModified()),
                        Map.of(),
                        obj.size(),
                        toTier(obj.storageClass())));
            }

            // Add common prefixes (directories)
            for (CommonPrefix prefix : response.commonPrefixes()) {
                try {
                    set.add(new StorageMetadataImpl(StorageType.RELATIVE_PATH,
                            /*id=*/ null, prefix.prefix(), /*location=*/ null,
                            /*uri=*/ null, /*eTag=*/ null,
                            /*creationDate=*/ null,
                            /*lastModified=*/ null,
                            Map.of(),
                            /*size=*/ 0L,
                            Tier.STANDARD));
                } catch (Exception e) {
                    System.err.println("Error creating StorageMetadataImpl for prefix: " + prefix.prefix());
                    e.printStackTrace();
                    throw e;
                }
            }

            if (response.isTruncated()) {
                if (!response.contents().isEmpty()) {
                    nextMarker = Iterables.getLast(response.contents()).key();
                } else if (!response.commonPrefixes().isEmpty()) {
                    nextMarker = Iterables.getLast(response.commonPrefixes()).prefix();
                }
            }

            // Workaround for LocalStack/Backend reporting truncated when result count < maxKeys
            if (set.build().size() < maxKeys) {
                nextMarker = null;
            }

            return new PageSetImpl<StorageMetadata>(set.build(), nextMarker);
        } catch (NoSuchBucketException e) {
            throw new ContainerNotFoundException(container, e.getMessage());
        } catch (S3Exception e) {
            translateAndRethrowException(e, container, null);
            throw e;
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
            throw e;
        }
    }

    @Override
    public boolean createContainerInLocation(Location location,
            String container) {
        return createContainerInLocation(location, container,
                new CreateContainerOptions());
    }

    @Override
    public boolean createContainerInLocation(Location location,
            String container, CreateContainerOptions options) {
        if (options == null) {
            options = new CreateContainerOptions();
        }
        try {
            s3Client.createBucket(CreateBucketRequest.builder()
                    .bucket(container)
                    .build());
            if (options.isPublicRead()) {
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
                    throw new AuthorizationException(
                            "Bucket already exists: " + container, e);
                }
                // Other 409s (OperationAborted, InvalidBucketState, etc.)
                // fall through to translateAndRethrowException
            }
            translateAndRethrowException(e, container, null);
            throw e;
        }
    }

    @Override
    public void deleteContainer(String container) {
        try {
            // First, delete all objects in the container
            clearContainer(container);
            // Then delete the bucket
            s3Client.deleteBucket(DeleteBucketRequest.builder()
                    .bucket(container)
                    .build());
        } catch (NoSuchBucketException e) {
            // Already deleted, ignore
        } catch (S3Exception e) {
            translateAndRethrowException(e, container, null);
            throw e;
        }
    }

    @Override
    public boolean deleteContainerIfEmpty(String container) {
        try {
            // Check if empty first
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

        // Handle range requests
        if (!options.getRanges().isEmpty()) {
            String rangeSpec = options.getRanges().get(0);
            requestBuilder.range("bytes=" + rangeSpec);
        }

        // Handle conditional gets
        if (options.getIfMatch() != null) {
            requestBuilder.ifMatch(options.getIfMatch());
        }
        if (options.getIfNoneMatch() != null) {
            requestBuilder.ifNoneMatch(options.getIfNoneMatch());
        }
        if (options.getIfModifiedSince() != null) {
            requestBuilder.ifModifiedSince(
                    options.getIfModifiedSince().toInstant());
        }
        if (options.getIfUnmodifiedSince() != null) {
            requestBuilder.ifUnmodifiedSince(
                    options.getIfUnmodifiedSince().toInstant());
        }

        try {
            var responseStream = s3Client.getObject(requestBuilder.build());
            var response = responseStream.response();

            var blob = new BlobBuilderImpl()
                    .name(key)
                    .userMetadata(response.metadata())
                    .payload(responseStream)
                    .cacheControl(response.cacheControl())
                    .contentDisposition(response.contentDisposition())
                    .contentEncoding(response.contentEncoding())
                    .contentLanguage(response.contentLanguage())
                    .contentLength(response.contentLength())
                    .contentType(response.contentType())
                    .expires(response.expires() != null ?
                            Date.from(response.expires()) : null)
                    .build();

            // Add Content-Range header for range requests
            if (response.contentRange() != null) {
                blob.getAllHeaders().put(HttpHeaders.CONTENT_RANGE,
                        response.contentRange());
            }

            var metadata = blob.getMetadata();
            metadata.setETag(response.eTag());
            if (response.lastModified() != null) {
                metadata.setLastModified(Date.from(response.lastModified()));
            }
            metadata.setSize(response.contentLength());

            return blob;
        } catch (NoSuchKeyException e) {
            throw new KeyNotFoundException(container, key, e.getMessage());
        } catch (NoSuchBucketException e) {
            throw new ContainerNotFoundException(container, e.getMessage());
        } catch (S3Exception e) {
            // 304 Not Modified - condition not met for If-None-Match
            if (e.statusCode() == 304) {
                var request = HttpRequest.builder()
                        .method("GET")
                        .endpoint(endpoint)
                        .build();
                var responseBuilder = HttpResponse.builder()
                        .statusCode(304);

                // Try to get ETag from exception headers
                var etagOptional = e.awsErrorDetails().sdkHttpResponse().firstMatchingHeader("ETag");
                if (etagOptional.isPresent()) {
                    responseBuilder.addHeader(HttpHeaders.ETAG, etagOptional.get());
                } else {
                    // Fallback: ETag missing in 304 response (LocalStack issue?), fetch it via HeadObject
                    try {
                        HeadObjectResponse head = s3Client.headObject(HeadObjectRequest.builder()
                                .bucket(container)
                                .key(key)
                                .build());
                        if (head.eTag() != null) {
                            responseBuilder.addHeader(HttpHeaders.ETAG, head.eTag());
                        }
                    } catch (Exception ignored) {
                        // Ignore if head fails, we can't do much
                        System.err.println("Failed to fetch fallback ETag for 304: " + ignored.getMessage());
                    }
                }

                throw new HttpResponseException(
                        new HttpCommand(request), responseBuilder.build(), e);
            }
            translateAndRethrowException(e, container, key);
            throw e;
        }
    }

    @Override
    public String putBlob(String container, Blob blob) {
        return putBlob(container, blob, new PutOptions());
    }

    @Override
    public String putBlob(String container, Blob blob, PutOptions options) {
        var contentMetadata = blob.getMetadata().getContentMetadata();
        var requestBuilder = PutObjectRequest.builder()
                .bucket(container)
                .key(blob.getMetadata().getName());

        // Set content metadata
        if (contentMetadata.getCacheControl() != null) {
            requestBuilder.cacheControl(contentMetadata.getCacheControl());
        }
        if (contentMetadata.getContentDisposition() != null) {
            requestBuilder.contentDisposition(
                    contentMetadata.getContentDisposition());
        }
        if (contentMetadata.getContentEncoding() != null) {
            requestBuilder.contentEncoding(contentMetadata.getContentEncoding());
        }
        if (contentMetadata.getContentLanguage() != null) {
            requestBuilder.contentLanguage(contentMetadata.getContentLanguage());
        }
        if (contentMetadata.getContentMD5() != null) {
            requestBuilder.contentMD5(BaseEncoding.base64().encode(
                    contentMetadata.getContentMD5()));
        }
        if (contentMetadata.getContentType() != null) {
            requestBuilder.contentType(contentMetadata.getContentType());
        }
        if (contentMetadata.getExpires() != null) {
            requestBuilder.expires(contentMetadata.getExpires().toInstant());
        }

        // Set user metadata
        var userMetadata = blob.getMetadata().getUserMetadata();
        if (userMetadata != null && !userMetadata.isEmpty()) {
            requestBuilder.metadata(userMetadata);
        }

        BlobAccess requestedAccess = options != null ? options.getBlobAccess() : null;
        if (requestedAccess == BlobAccess.PUBLIC_READ) {
            requestBuilder.acl(ObjectCannedACL.PUBLIC_READ);
        }

        // Set storage class/tier
        if (blob.getMetadata().getTier() != null &&
                blob.getMetadata().getTier() != Tier.STANDARD) {
            requestBuilder.storageClass(
                    toStorageClass(blob.getMetadata().getTier()));
        }

        // Handle conditional puts (If-Match/If-None-Match)
        if (options instanceof PutOptions2) {
            var putOptions2 = (PutOptions2) options;
            if (putOptions2.getIfMatch() != null) {
                requestBuilder.ifMatch(putOptions2.getIfMatch());
            }
            if (putOptions2.getIfNoneMatch() != null) {
                requestBuilder.ifNoneMatch(putOptions2.getIfNoneMatch());
            }
        }

        try (InputStream is = blob.getPayload().openStream()) {
            Long contentLength = contentMetadata.getContentLength();
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
            translateAndRethrowException(e, container,
                    blob.getMetadata().getName());
            throw e;
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
            if (contentMetadata.getCacheControl() != null) {
                requestBuilder.cacheControl(contentMetadata.getCacheControl());
            }
            if (contentMetadata.getContentDisposition() != null) {
                requestBuilder.contentDisposition(
                        contentMetadata.getContentDisposition());
            }
            if (contentMetadata.getContentEncoding() != null) {
                requestBuilder.contentEncoding(
                        contentMetadata.getContentEncoding());
            }
            if (contentMetadata.getContentLanguage() != null) {
                requestBuilder.contentLanguage(
                        contentMetadata.getContentLanguage());
            }
            if (contentMetadata.getContentType() != null) {
                requestBuilder.contentType(contentMetadata.getContentType());
            }
            // Mark that we want to replace metadata
            requestBuilder.metadataDirective("REPLACE");
        }

        var userMetadata = options.userMetadata();
        if (userMetadata != null) {
            requestBuilder.metadata(userMetadata);
            requestBuilder.metadataDirective("REPLACE");
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
            translateAndRethrowException(e, fromContainer, fromName);
            throw e;
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

            return new BlobMetadataImpl(/*id=*/ null, key, /*location=*/ null,
                    /*uri=*/ null, response.eTag(),
                    toDate(response.lastModified()),
                    toDate(response.lastModified()),
                    response.metadata(), /*publicUri=*/ null, container,
                    toContentMetadata(response),
                    response.contentLength(),
                    toTier(response.storageClass()));
        } catch (NoSuchKeyException e) {
            return null;
        } catch (NoSuchBucketException e) {
            throw new ContainerNotFoundException(container, e.getMessage());
        } catch (S3Exception e) {
            if (e.statusCode() == 404) {
                return null;
            }
            translateAndRethrowException(e, container, key);
            throw e;
        }
    }

    @Override
    protected boolean deleteAndVerifyContainerGone(String container) {
        try {
            s3Client.deleteBucket(DeleteBucketRequest.builder()
                    .bucket(container)
                    .build());
            return true;
        } catch (NoSuchBucketException e) {
            return true;
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
        s3Client.putBucketAcl(PutBucketAclRequest.builder()
                .bucket(container)
                .acl(acl)
                .build());
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
        if (putOptions != null && putOptions.getBlobAccess() == BlobAccess.PUBLIC_READ) {
            setBlobAccess(mpu.containerName(), mpu.blobName(), BlobAccess.PUBLIC_READ);
        }
    }

    @Override
    public void setBlobAccess(String container, String key, BlobAccess access) {
        ObjectCannedACL acl = access == BlobAccess.PUBLIC_READ ?
                ObjectCannedACL.PUBLIC_READ : ObjectCannedACL.PRIVATE;
        s3Client.putObjectAcl(PutObjectAclRequest.builder()
                .bucket(container)
                .key(key)
                .acl(acl)
                .build());
    }

    // Multipart upload operations

    @Override
    public MultipartUpload initiateMultipartUpload(String container,
            BlobMetadata blobMetadata, PutOptions options) {
        var requestBuilder = CreateMultipartUploadRequest.builder()
                .bucket(container)
                .key(blobMetadata.getName());

        var contentMetadata = blobMetadata.getContentMetadata();
        if (contentMetadata != null) {
            if (contentMetadata.getCacheControl() != null) {
                requestBuilder.cacheControl(contentMetadata.getCacheControl());
            }
            if (contentMetadata.getContentDisposition() != null) {
                requestBuilder.contentDisposition(
                        contentMetadata.getContentDisposition());
            }
            if (contentMetadata.getContentEncoding() != null) {
                requestBuilder.contentEncoding(
                        contentMetadata.getContentEncoding());
            }
            if (contentMetadata.getContentLanguage() != null) {
                requestBuilder.contentLanguage(
                        contentMetadata.getContentLanguage());
            }
            if (contentMetadata.getContentType() != null) {
                requestBuilder.contentType(contentMetadata.getContentType());
            }
        }

        var userMetadata = blobMetadata.getUserMetadata();
        if (userMetadata != null && !userMetadata.isEmpty()) {
            requestBuilder.metadata(userMetadata);
        }

        if (options != null && options.getBlobAccess() == BlobAccess.PUBLIC_READ) {
            requestBuilder.acl(ObjectCannedACL.PUBLIC_READ);
        }

        if (blobMetadata.getTier() != null &&
                blobMetadata.getTier() != Tier.STANDARD) {
            requestBuilder.storageClass(
                    toStorageClass(blobMetadata.getTier()));
        }

        try {
            var response = s3Client.createMultipartUpload(
                    requestBuilder.build());
            return MultipartUpload.create(container, blobMetadata.getName(),
                    response.uploadId(), blobMetadata, options);
        } catch (NoSuchBucketException e) {
            throw new ContainerNotFoundException(container, e.getMessage());
        } catch (S3Exception e) {
            translateAndRethrowException(e, container, blobMetadata.getName());
            throw e;
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
            translateAndRethrowException(e, mpu.containerName(), mpu.blobName());
            throw e;
        }
    }

    @Override
    public MultipartPart uploadMultipartPart(MultipartUpload mpu,
            int partNumber, Payload payload) {
        Long contentLength = payload.getContentMetadata().getContentLength();
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

            return MultipartPart.create(partNumber, contentLength,
                    response.eTag(), null);
        } catch (IOException e) {
            throw new RuntimeException("Failed to upload part", e);
        } catch (S3Exception e) {
            translateAndRethrowException(e, mpu.containerName(), mpu.blobName());
            throw e;
        }
    }

    @Override
    public List<MultipartPart> listMultipartUpload(MultipartUpload mpu) {
        try {
            var response = s3Client.listParts(ListPartsRequest.builder()
                    .bucket(mpu.containerName())
                    .key(mpu.blobName())
                    .uploadId(mpu.id())
                    .build());

            var parts = ImmutableList.<MultipartPart>builder();
            for (Part part : response.parts()) {
                parts.add(MultipartPart.create(part.partNumber(),
                        part.size(),
                        part.eTag(),
                        toDate(part.lastModified())));
            }
            return parts.build();
        } catch (S3Exception e) {
            if (e.statusCode() == 404) {
                return ImmutableList.of();
            }
            throw e;
        }
    }

    @Override
    public List<MultipartUpload> listMultipartUploads(String container) {
        try {
            var response = s3Client.listMultipartUploads(
                    ListMultipartUploadsRequest.builder()
                            .bucket(container)
                            .build());

            var builder = ImmutableList.<MultipartUpload>builder();
            for (var upload : response.uploads()) {
                builder.add(MultipartUpload.create(container,
                        upload.key(),
                        upload.uploadId(),
                        null, null));
            }
            return builder.build();
        } catch (NoSuchBucketException e) {
            throw new ContainerNotFoundException(container, e.getMessage());
        } catch (S3Exception e) {
            translateAndRethrowException(e, container, null);
            throw e;
        }
    }

    @Override
    public long getMinimumMultipartPartSize() {
        // S3 minimum part size is 5MB (except for last part)
        return 5L * 1024 * 1024;
    }

    @Override
    public long getMaximumMultipartPartSize() {
        // S3 maximum part size is 5GB
        return 5L * 1024 * 1024 * 1024;
    }

    @Override
    public int getMaximumNumberOfParts() {
        return 10000;
    }

    @Override
    public InputStream streamBlob(String container, String name) {
        throw new UnsupportedOperationException("not yet implemented");
    }

    // Helper methods

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

    private static StorageClass toStorageClass(Tier tier) {
        return switch (tier) {
        case ARCHIVE -> StorageClass.GLACIER;
        case COLD -> StorageClass.GLACIER_IR;
        case COOL, INFREQUENT -> StorageClass.STANDARD_IA;
        case STANDARD -> StorageClass.STANDARD;
        };
    }

    private static Tier toTier(@Nullable StorageClass storageClass) {
        if (storageClass == null) {
            return Tier.STANDARD;
        }
        return switch (storageClass) {
        case GLACIER, DEEP_ARCHIVE -> Tier.ARCHIVE;
        case GLACIER_IR -> Tier.COLD;
        case STANDARD_IA, ONEZONE_IA -> Tier.INFREQUENT;
        default -> Tier.STANDARD;
        };
    }

    private static Tier toTier(
            @Nullable software.amazon.awssdk.services.s3.model.ObjectStorageClass
                storageClass) {
        if (storageClass == null) {
            return Tier.STANDARD;
        }
        return switch (storageClass) {
        case GLACIER, DEEP_ARCHIVE -> Tier.ARCHIVE;
        case GLACIER_IR -> Tier.COLD;
        case STANDARD_IA, ONEZONE_IA -> Tier.INFREQUENT;
        default -> Tier.STANDARD;
        };
    }

    private static org.jclouds.io.ContentMetadata toContentMetadata(
            HeadObjectResponse response) {
        var builder = ContentMetadataBuilder.create();
        if (response.cacheControl() != null) {
            builder.cacheControl(response.cacheControl());
        }
        if (response.contentDisposition() != null) {
            builder.contentDisposition(response.contentDisposition());
        }
        if (response.contentEncoding() != null) {
            builder.contentEncoding(response.contentEncoding());
        }
        if (response.contentLanguage() != null) {
            builder.contentLanguage(response.contentLanguage());
        }
        if (response.contentLength() != null) {
            builder.contentLength(response.contentLength());
        }
        if (response.contentType() != null) {
            builder.contentType(response.contentType());
        }
        if (response.expires() != null) {
            builder.expires(Date.from(response.expires()));
        }
        return builder.build();
    }

    /**
     * Translate S3Exception to a jclouds exception. Throws if
     * translated otherwise returns.
     */
    private void translateAndRethrowException(S3Exception e,
            String container, @Nullable String key) {
        if (e.statusCode() == 501) {
            System.err.println("Caught 501 Not Implemented from AWS SDK");
            System.err.println("Message: " + e.getMessage());
            System.err.println("Error Code: " + e.awsErrorDetails().errorCode());
            System.err.println("Service Name: " + e.awsErrorDetails().serviceName());
        }
        if (e.statusCode() == 404) {
            String errorCode = e.awsErrorDetails().errorCode();
            if ("NoSuchBucket".equals(errorCode)) {
                throw new ContainerNotFoundException(container, e.getMessage());
            } else if ("NoSuchKey".equals(errorCode)) {
                if (key == null) {
                    // Should not happen for key-less operations but fallback
                    throw new ContainerNotFoundException(container, e.getMessage());
                }
                throw new KeyNotFoundException(container, key, e.getMessage());
            }
            // Fallback for other 404s
            if (key != null) {
                throw new KeyNotFoundException(container, key, e.getMessage());
            } else {
                throw new ContainerNotFoundException(container, e.getMessage());
            }
        }
        var request = HttpRequest.builder()
                .method("GET")
                .endpoint(endpoint)
                .build();
        var responseBuilder = HttpResponse.builder()
                .statusCode(e.statusCode())
                .message(e.getMessage());

        if (e.statusCode() == 304) {
            // S3Exception headers are in the response
            e.awsErrorDetails().sdkHttpResponse().firstMatchingHeader(HttpHeaders.ETAG)
                    .ifPresent(etag -> responseBuilder.addHeader(HttpHeaders.ETAG, etag));
        }

        throw new HttpResponseException(
                new HttpCommand(request), responseBuilder.build(), e);
    }
}
