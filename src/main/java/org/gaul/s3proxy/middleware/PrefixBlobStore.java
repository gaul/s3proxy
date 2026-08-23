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
import software.amazon.awssdk.services.s3.model.CommonPrefix;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.CopyObjectRequest;
import software.amazon.awssdk.services.s3.model.CopyObjectResponse;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.DeleteObjectResponse;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.HeadObjectRequest;
import software.amazon.awssdk.services.s3.model.HeadObjectResponse;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Response;
import software.amazon.awssdk.services.s3.model.ObjectCannedACL;
import software.amazon.awssdk.services.s3.model.Part;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.awssdk.services.s3.model.S3Object;
import software.amazon.awssdk.services.s3.model.UploadPartRequest;
import software.amazon.awssdk.services.s3.model.UploadPartResponse;

/**
 * Middleware that scopes a virtual bucket to a fixed backend prefix.
 */
public final class PrefixBlobStore extends ForwardingBlobStore {
    private final Map<String, String> prefixes;

    private PrefixBlobStore(BlobStore delegate, Map<String, String> prefixes) {
        super(delegate);
        this.prefixes = Map.copyOf(requireNonNull(prefixes));
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
        return this.prefixes.containsKey(container);
    }

    @Nullable
    private String getPrefix(String container) {
        return this.prefixes.get(container);
    }

    private String addPrefix(String container, String name) {
        if (!hasPrefix(container) || Strings.isNullOrEmpty(name)) {
            return name;
        }
        String prefix = requireNonNull(getPrefix(container));
        if (name.startsWith(prefix)) {
            return name;
        }
        if (prefix.endsWith("/") && name.startsWith("/")) {
            return prefix + name.substring(1);
        }
        return prefix + name;
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
        if (upload == null || !hasPrefix(upload.containerName())) {
            return upload;
        }
        return new MultipartUpload(upload.id(),
                upload.request().toBuilder()
                        .key(addPrefix(upload.containerName(),
                                upload.blobName()))
                        .build());
    }

    private MultipartUpload toClientMultipartUpload(MultipartUpload upload) {
        if (upload == null || !hasPrefix(upload.containerName())) {
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
        String requestedMarker = request.continuationToken() != null ?
                request.continuationToken() : request.startAfter();

        if (Strings.isNullOrEmpty(requestedPrefix)) {
            builder.prefix(basePrefix);
        } else {
            builder.prefix(addPrefix(container, requestedPrefix));
        }

        if (!Strings.isNullOrEmpty(requestedMarker)) {
            builder.continuationToken(
                    addPrefix(container, requestedMarker));
            builder.startAfter(null);
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
        String nextMarker = listing.nextContinuationToken();
        if (nextMarker != null) {
            nextMarker = trimPrefix(container, nextMarker);
        }
        return listing.toBuilder()
                .contents(contents.build())
                .commonPrefixes(prefixes.build())
                .nextContinuationToken(nextMarker)
                .build();
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
    public void setBlobAccess(String container, String name,
            ObjectCannedACL access) {
        super.setBlobAccess(container, addPrefix(container, name), access);
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
        for (var upload : uploads) {
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
