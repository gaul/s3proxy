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

import static com.google.common.base.Preconditions.checkArgument;
import static java.util.Objects.requireNonNull;

import java.io.InputStream;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;

import org.gaul.s3proxy.S3ProxyConstants;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.ForwardingBlobStore;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.jspecify.annotations.Nullable;

import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.services.s3.model.BucketCannedACL;
import software.amazon.awssdk.services.s3.model.CommonPrefix;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.CopyObjectRequest;
import software.amazon.awssdk.services.s3.model.CopyObjectResponse;
import software.amazon.awssdk.services.s3.model.CreateBucketRequest;
import software.amazon.awssdk.services.s3.model.CreateBucketResponse;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.DeleteBucketEncryptionRequest;
import software.amazon.awssdk.services.s3.model.DeleteBucketEncryptionResponse;
import software.amazon.awssdk.services.s3.model.DeleteBucketOwnershipControlsRequest;
import software.amazon.awssdk.services.s3.model.DeleteBucketOwnershipControlsResponse;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.DeleteObjectResponse;
import software.amazon.awssdk.services.s3.model.DeletePublicAccessBlockRequest;
import software.amazon.awssdk.services.s3.model.DeletePublicAccessBlockResponse;
import software.amazon.awssdk.services.s3.model.GetObjectAclRequest;
import software.amazon.awssdk.services.s3.model.GetObjectAclResponse;
import software.amazon.awssdk.services.s3.model.GetObjectLegalHoldRequest;
import software.amazon.awssdk.services.s3.model.GetObjectLegalHoldResponse;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.GetObjectRetentionRequest;
import software.amazon.awssdk.services.s3.model.GetObjectRetentionResponse;
import software.amazon.awssdk.services.s3.model.HeadObjectRequest;
import software.amazon.awssdk.services.s3.model.HeadObjectResponse;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Response;
import software.amazon.awssdk.services.s3.model.ObjectCannedACL;
import software.amazon.awssdk.services.s3.model.Part;
import software.amazon.awssdk.services.s3.model.PutBucketEncryptionRequest;
import software.amazon.awssdk.services.s3.model.PutBucketEncryptionResponse;
import software.amazon.awssdk.services.s3.model.PutBucketOwnershipControlsRequest;
import software.amazon.awssdk.services.s3.model.PutBucketOwnershipControlsResponse;
import software.amazon.awssdk.services.s3.model.PutObjectLegalHoldRequest;
import software.amazon.awssdk.services.s3.model.PutObjectLegalHoldResponse;
import software.amazon.awssdk.services.s3.model.PutObjectLockConfigurationRequest;
import software.amazon.awssdk.services.s3.model.PutObjectLockConfigurationResponse;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.awssdk.services.s3.model.PutObjectRetentionRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRetentionResponse;
import software.amazon.awssdk.services.s3.model.PutPublicAccessBlockRequest;
import software.amazon.awssdk.services.s3.model.PutPublicAccessBlockResponse;
import software.amazon.awssdk.services.s3.model.S3Object;
import software.amazon.awssdk.services.s3.model.UploadPartCopyRequest;
import software.amazon.awssdk.services.s3.model.UploadPartCopyResponse;
import software.amazon.awssdk.services.s3.model.UploadPartRequest;
import software.amazon.awssdk.services.s3.model.UploadPartResponse;

/**
 * Middleware that scopes a virtual bucket to a fixed backend prefix.
 */
public final class PrefixBlobStore extends ForwardingBlobStore {
    private final Map<String, String> prefixes;

    private PrefixBlobStore(BlobStore delegate, Map<String, String> prefixes) {
        super(delegate);
        // Keyed by the lower-case spelling of the bucket.  A backend need
        // not tell TENANT from tenant -- a filesystem store on a
        // case-insensitive volume opens one directory for both -- and a
        // spelling with no prefix passes through to all of the bucket.
        Map<String, String> lowerCase = new HashMap<>();
        for (var entry : requireNonNull(prefixes).entrySet()) {
            checkArgument(lowerCase.put(
                    entry.getKey().toLowerCase(Locale.ROOT),
                    entry.getValue()) == null,
                    "Multiple prefixes configured for bucket %s",
                    entry.getKey());
        }
        this.prefixes = Map.copyOf(lowerCase);
    }

    static BlobStore newPrefixBlobStore(BlobStore delegate,
            Map<String, String> prefixes) {
        return new PrefixBlobStore(delegate, prefixes);
    }

    public static Map<String, String> parsePrefixes(Properties properties) {
        Map<String, String> prefixMap = new HashMap<>();
        for (String key : properties.stringPropertyNames()) {
            if (!key.startsWith(S3ProxyConstants.PROPERTY_PREFIX_BLOBSTORE + ".")) {
                continue;
            }
            String bucket = key.substring(
                    S3ProxyConstants.PROPERTY_PREFIX_BLOBSTORE.length() + 1);
            String prefix = properties.getProperty(key);
            checkArgument(!Strings.isNullOrEmpty(bucket),
                    "Prefix property %s must specify a bucket", key);
            checkArgument(!Strings.isNullOrEmpty(prefix),
                    "Prefix for bucket %s must not be empty", bucket);
            checkArgument(prefixMap.put(bucket, prefix) == null,
                    "Multiple prefixes configured for bucket %s", bucket);
        }
        return Map.copyOf(prefixMap);
    }

    private boolean hasPrefix(String container) {
        return getPrefix(container) != null;
    }

    @Nullable
    private String getPrefix(String container) {
        return this.prefixes.get(container.toLowerCase(Locale.ROOT));
    }

    private String addPrefix(String container, String name) {
        if (!hasPrefix(container) || Strings.isNullOrEmpty(name)) {
            return name;
        }
        // Always, whatever the name looks like.  Leaving a name that
        // already began with the prefix as it was stored the keys "x" and
        // "<prefix>x" as one object, each overwriting and deleting the
        // other, and dropping a leading slash did the same to "x" and "/x".
        return requireNonNull(getPrefix(container)) + name;
    }

    private String trimPrefix(String container, String name) {
        if (!hasPrefix(container) || Strings.isNullOrEmpty(name)) {
            return name;
        }
        String prefix = requireNonNull(getPrefix(container));
        if (name.startsWith(prefix)) {
            return name.substring(prefix.length());
        }
        return name;
    }

    private MultipartUpload toDelegateMultipartUpload(MultipartUpload upload) {
        if (!hasPrefix(upload.containerName())) {
            return upload;
        }
        return new MultipartUpload(upload.id(),
                upload.request().toBuilder()
                        .key(addPrefix(upload.containerName(),
                                upload.blobName()))
                        .build());
    }

    private MultipartUpload toClientMultipartUpload(MultipartUpload upload) {
        if (!hasPrefix(upload.containerName())) {
            return upload;
        }
        return new MultipartUpload(upload.id(),
                upload.request().toBuilder()
                        .key(trimPrefix(upload.containerName(),
                                upload.blobName()))
                        .build(),
                upload.response());
    }

    private ListObjectsV2Request applyPrefix(String container,
            ListObjectsV2Request request) {
        if (!hasPrefix(container)) {
            return request;
        }
        var builder = request.toBuilder();
        String basePrefix = getPrefix(container);
        String requestedPrefix = request.prefix();

        if (Strings.isNullOrEmpty(requestedPrefix)) {
            builder.prefix(basePrefix);
        } else {
            builder.prefix(addPrefix(container, requestedPrefix));
        }

        // start-after is a key and takes the prefix like any other.  The
        // continuation token is not: it is whatever the backend handed out
        // and expects back unaltered -- an opaque marker on aws-s3,
        // azureblob and google-cloud-storage, which a prefix in front of
        // made into a token the backend had never issued.
        if (!Strings.isNullOrEmpty(request.startAfter())) {
            builder.startAfter(addPrefix(container, request.startAfter()));
        }

        return builder.build();
    }

    private ListObjectsV2Response trimListing(String container,
            ListObjectsV2Response listing) {
        if (!hasPrefix(container)) {
            return listing;
        }
        var contents = ImmutableList.<S3Object>builder();
        for (S3Object object : listing.contents()) {
            contents.add(object.toBuilder()
                    .key(trimPrefix(container, object.key()))
                    .build());
        }
        var prefixes = ImmutableList.<CommonPrefix>builder();
        for (CommonPrefix prefix : listing.commonPrefixes()) {
            prefixes.add(CommonPrefix.builder()
                    .prefix(trimPrefix(container, prefix.prefix()))
                    .build());
        }
        return listing.toBuilder()
                .contents(contents.build())
                .commonPrefixes(prefixes.build())
                .build();
    }

    // A prefixed bucket is one part of a backend bucket, and the ACL and
    // the default encryption are the backend bucket's: they cover every
    // other prefix in it as well.  Passing a change through let the client
    // of one prefix open all of them to anonymous callers, so a prefixed
    // bucket keeps what the backend bucket has.

    @Override
    public CreateBucketResponse createContainer(CreateBucketRequest request) {
        BucketCannedACL acl = request.acl();
        if (hasPrefix(request.bucket()) && acl != null &&
                acl != BucketCannedACL.PRIVATE) {
            throw new UnsupportedOperationException("prefixed bucket");
        }
        return super.createContainer(request);
    }

    @Override
    public void setContainerAccess(String container,
            BucketCannedACL containerAccess) {
        if (!hasPrefix(container)) {
            super.setContainerAccess(container, containerAccess);
            return;
        }
        // Some clients restate the ACL a bucket already has; that changes
        // nothing for anyone and needs no refusal.
        if (getContainerAccess(container) != containerAccess) {
            throw new UnsupportedOperationException("prefixed bucket");
        }
    }

    @Override
    public PutBucketEncryptionResponse putBucketEncryption(
            PutBucketEncryptionRequest request) {
        refusePrefixed(request.bucket());
        return super.putBucketEncryption(request);
    }

    @Override
    public PutBucketOwnershipControlsResponse putBucketOwnershipControls(
            PutBucketOwnershipControlsRequest request) {
        refusePrefixed(request.bucket());
        return super.putBucketOwnershipControls(request);
    }

    @Override
    public DeleteBucketOwnershipControlsResponse deleteBucketOwnershipControls(
            DeleteBucketOwnershipControlsRequest request) {
        refusePrefixed(request.bucket());
        return super.deleteBucketOwnershipControls(request);
    }

    @Override
    public PutPublicAccessBlockResponse putPublicAccessBlock(
            PutPublicAccessBlockRequest request) {
        refusePrefixed(request.bucket());
        return super.putPublicAccessBlock(request);
    }

    @Override
    public DeletePublicAccessBlockResponse deletePublicAccessBlock(
            DeletePublicAccessBlockRequest request) {
        refusePrefixed(request.bucket());
        return super.deletePublicAccessBlock(request);
    }

    @Override
    public PutObjectLockConfigurationResponse putObjectLockConfiguration(
            PutObjectLockConfigurationRequest request) {
        refusePrefixed(request.bucket());
        return super.putObjectLockConfiguration(request);
    }

    /**
     * Deleting the bucket deletes the backend bucket, which the other
     * prefixes live in too: emptied of its own objects, one prefix's client
     * took the bucket from under every other, whose writes then answered
     * NoSuchBucket.  As with the ACL, the backend bucket is not a prefix's
     * to delete.
     */
    @Override
    public void deleteBucket(String container) {
        refusePrefixed(container);
        super.deleteBucket(container);
    }

    private void refusePrefixed(String container) {
        if (hasPrefix(container)) {
            throw new UnsupportedOperationException("prefixed bucket");
        }
    }

    // Object lock is kept per object, so a prefixed bucket names its
    // objects under the prefix here as everywhere else.  Forwarded as they
    // were, these read and set the retention of whatever object of the
    // backend bucket had the unprefixed name: another prefix's.

    @Override
    public GetObjectRetentionResponse getObjectRetention(
            GetObjectRetentionRequest request) {
        return super.getObjectRetention(request.toBuilder()
                .key(addPrefix(request.bucket(), request.key()))
                .build());
    }

    @Override
    public PutObjectRetentionResponse putObjectRetention(
            PutObjectRetentionRequest request) {
        return super.putObjectRetention(request.toBuilder()
                .key(addPrefix(request.bucket(), request.key()))
                .build());
    }

    @Override
    public GetObjectLegalHoldResponse getObjectLegalHold(
            GetObjectLegalHoldRequest request) {
        return super.getObjectLegalHold(request.toBuilder()
                .key(addPrefix(request.bucket(), request.key()))
                .build());
    }

    @Override
    public PutObjectLegalHoldResponse putObjectLegalHold(
            PutObjectLegalHoldRequest request) {
        return super.putObjectLegalHold(request.toBuilder()
                .key(addPrefix(request.bucket(), request.key()))
                .build());
    }

    @Override
    public DeleteBucketEncryptionResponse deleteBucketEncryption(
            DeleteBucketEncryptionRequest request) {
        if (hasPrefix(request.bucket())) {
            throw new UnsupportedOperationException("prefixed bucket");
        }
        return super.deleteBucketEncryption(request);
    }

    @Override
    public boolean blobExists(String container, String name) {
        return super.blobExists(container, addPrefix(container, name));
    }

    @Override
    public HeadObjectResponse blobMetadata(HeadObjectRequest request) {
        return super.blobMetadata(request.toBuilder()
                .key(addPrefix(request.bucket(), request.key()))
                .build());
    }

    @Override
    public ResponseInputStream<GetObjectResponse> getBlob(
            GetObjectRequest request) {
        return super.getBlob(request.toBuilder()
                .key(addPrefix(request.bucket(), request.key()))
                .build());
    }

    @Override
    public PutObjectResponse putBlob(PutObjectRequest request,
            InputStream payload) {
        return super.putBlob(request.toBuilder()
                .key(addPrefix(request.bucket(), request.key()))
                .build(), payload);
    }

    @Override
    public DeleteObjectResponse removeBlob(DeleteObjectRequest request) {
        return super.removeBlob(request.toBuilder()
                .key(addPrefix(request.bucket(), request.key()))
                .build());
    }

    @Override
    public ObjectCannedACL getBlobAccess(String container, String name) {
        return super.getBlobAccess(container, addPrefix(container, name));
    }

    @Override
    public GetObjectAclResponse getBlobAcl(GetObjectAclRequest request) {
        return super.getBlobAcl(request.toBuilder()
                .key(addPrefix(request.bucket(), request.key()))
                .build());
    }

    @Override
    public void setBlobAccess(String container, String name,
            ObjectCannedACL access) {
        super.setBlobAccess(container, addPrefix(container, name), access);
    }

    @Override
    public boolean recordChecksumMetadata(String container, String name,
            String eTag, String metadataKey, String value) {
        return super.recordChecksumMetadata(container,
                addPrefix(container, name), eTag, metadataKey, value);
    }

    @Override
    public CopyObjectResponse copyBlob(CopyObjectRequest request) {
        return super.copyBlob(request.toBuilder()
                .sourceKey(addPrefix(request.sourceBucket(),
                        request.sourceKey()))
                .destinationKey(addPrefix(request.destinationBucket(),
                        request.destinationKey()))
                .build());
    }

    @Override
    public ListObjectsV2Response list(ListObjectsV2Request request) {
        String container = request.bucket();
        if (!hasPrefix(container)) {
            return super.list(request);
        }
        var effective = applyPrefix(container, request);
        return trimListing(container, super.list(effective));
    }

    @Override
    public void clearContainer(ListObjectsV2Request request) {
        String container = request.bucket();
        if (!hasPrefix(container)) {
            super.clearContainer(request);
            return;
        }
        super.clearContainer(applyPrefix(container, request));
    }

    /**
     * Removes what this store shows of the bucket: the objects under its
     * prefix.  Forwarded as it was, this emptied the whole backend bucket,
     * taking every object outside the prefix with it.  The backend bucket
     * stays, emptied or not: other prefixes live in it, and see deleteBucket.
     */
    @Override
    public void deleteContainer(String container) {
        if (!hasPrefix(container)) {
            super.deleteContainer(container);
            return;
        }
        if (!containerExists(container)) {
            // already gone, which deleting succeeds on
            return;
        }
        clearContainer(ListObjectsV2Request.builder()
                .bucket(container)
                .build());
    }

    @Override
    public MultipartUpload initiateMultipartUpload(
            CreateMultipartUploadRequest request) {
        MultipartUpload upload = super.initiateMultipartUpload(
                request.toBuilder()
                        .key(addPrefix(request.bucket(), request.key()))
                        .build());
        return toClientMultipartUpload(upload);
    }

    @Override
    public void abortMultipartUpload(MultipartUpload mpu) {
        super.abortMultipartUpload(toDelegateMultipartUpload(mpu));
    }

    @Override
    public CompleteMultipartUploadResponse completeMultipartUpload(MultipartUpload mpu,
            CompleteMultipartUploadRequest request) {
        return super.completeMultipartUpload(toDelegateMultipartUpload(mpu),
                request.toBuilder()
                        .key(addPrefix(request.bucket(), request.key()))
                        .build());
    }

    @Override
    public UploadPartResponse uploadMultipartPart(MultipartUpload mpu,
            UploadPartRequest request, InputStream is) {
        return super.uploadMultipartPart(
                toDelegateMultipartUpload(mpu), request, is);
    }

    /**
     * The prefix renames keys and nothing else, so a part the backend can
     * copy on its own it can still copy once both keys carry their prefix.
     * Keeping the interface's refusal instead would send every part down to
     * S3Proxy and back up again.  Whether the backend copies at all stays
     * its own answer, which is what keeps a wrapper that rewrites what it
     * stores from having a backend copy slip past it.
     */
    @Override
    public boolean supportsCopyMultipartPart() {
        return delegate().supportsCopyMultipartPart();
    }

    @Override
    public UploadPartCopyResponse copyMultipartPart(MultipartUpload mpu,
            UploadPartCopyRequest request) {
        return delegate().copyMultipartPart(toDelegateMultipartUpload(mpu),
                request.toBuilder()
                        .sourceKey(addPrefix(request.sourceBucket(),
                                request.sourceKey()))
                        .destinationKey(addPrefix(
                                request.destinationBucket(),
                                request.destinationKey()))
                        .build());
    }

    @Override
    public List<Part> listMultipartUpload(MultipartUpload mpu) {
        return super.listMultipartUpload(toDelegateMultipartUpload(mpu));
    }

    @Override
    public List<software.amazon.awssdk.services.s3.model.MultipartUpload>
            listMultipartUploads(String container) {
        var uploads = super.listMultipartUploads(container);
        if (!hasPrefix(container)) {
            return uploads;
        }
        var builder = ImmutableList.<software.amazon.awssdk.services.s3
                .model.MultipartUpload>builder();
        String prefix = requireNonNull(getPrefix(container));
        for (var upload : uploads) {
            // An upload to a key outside the prefix is not in this bucket,
            // as an object there is not: listing it showed a caller keys
            // and upload IDs from the rest of the backend bucket.
            if (!upload.key().startsWith(prefix)) {
                continue;
            }
            builder.add(upload.toBuilder()
                    .key(trimPrefix(container, upload.key()))
                    .build());
        }
        return builder.build();
    }
    // Disable versioning: the prefix rewrite does not extend to the
    // versioned operations.
    @Override
    public boolean supportsVersioning() {
        return false;
    }

}
