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

package org.gaul.s3proxy.gcloudsdk;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.channels.Channels;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import com.google.auth.oauth2.GoogleCredentials;
import com.google.auth.oauth2.ServiceAccountCredentials;
import com.google.cloud.NoCredentials;
import com.google.cloud.ReadChannel;
import com.google.cloud.storage.Acl;
import com.google.cloud.storage.Blob;
import com.google.cloud.storage.BlobId;
import com.google.cloud.storage.BlobInfo;
import com.google.cloud.storage.Bucket;
import com.google.cloud.storage.BucketInfo;
import com.google.cloud.storage.Storage;
import com.google.cloud.storage.Storage.BlobField;
import com.google.cloud.storage.Storage.BlobGetOption;
import com.google.cloud.storage.Storage.BlobListOption;
import com.google.cloud.storage.Storage.BlobWriteOption;
import com.google.cloud.storage.Storage.BucketField;
import com.google.cloud.storage.Storage.BucketGetOption;
import com.google.cloud.storage.Storage.ComposeRequest;
import com.google.cloud.storage.Storage.CopyRequest;
import com.google.cloud.storage.StorageException;
import com.google.cloud.storage.StorageOptions;
import com.google.common.base.Supplier;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.hash.HashFunction;
import com.google.common.hash.Hashing;
import com.google.common.hash.HashingInputStream;
import com.google.common.io.BaseEncoding;
import com.google.common.net.HttpHeaders;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import org.gaul.s3proxy.PutOptions2;
import org.jclouds.blobstore.BlobStoreContext;
import org.jclouds.blobstore.ContainerNotFoundException;
import org.jclouds.blobstore.KeyNotFoundException;
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
import org.jclouds.io.ContentMetadata;
import org.jclouds.io.ContentMetadataBuilder;
import org.jclouds.io.PayloadSlicer;
import org.jclouds.providers.ProviderMetadata;
import org.jspecify.annotations.Nullable;

@Singleton
public final class GCloudBlobStore extends BaseBlobStore {
    private static final String STUB_BLOB_PREFIX = ".s3proxy/stubs/";
    private static final String TARGET_BLOB_NAME_KEY =
            "s3proxy_target_blob_name";
    private static final HashFunction MD5 = Hashing.md5();
    // GCS compose supports up to 32 source objects
    private static final int MAX_COMPOSE_PARTS = 32;

    private final Storage storage;

    @Inject
    GCloudBlobStore(BlobStoreContext context, BlobUtils blobUtils,
            Supplier<Location> defaultLocation,
            @Memoized Supplier<Set<? extends Location>> locations,
            PayloadSlicer slicer,
            @org.jclouds.location.Provider Supplier<Credentials> creds,
            ProviderMetadata provider) {
        super(context, blobUtils, defaultLocation, locations, slicer);
        var cred = creds.get();
        var storageBuilder = StorageOptions.newBuilder();
        if (cred.identity != null && !cred.identity.isEmpty()) {
            storageBuilder.setProjectId(cred.identity);
        }
        if (cred.credential != null && !cred.credential.isEmpty()) {
            try {
                var credentials = ServiceAccountCredentials.fromStream(
                        new ByteArrayInputStream(
                                cred.credential.getBytes(StandardCharsets.UTF_8)));
                storageBuilder.setCredentials(credentials);
            } catch (IOException ioe) {
                // Fall back to application default credentials
                try {
                    storageBuilder.setCredentials(
                            GoogleCredentials.getApplicationDefault());
                } catch (IOException ioe2) {
                    throw new RuntimeException(
                            "Failed to initialize GCS credentials", ioe2);
                }
            }
        } else {
            // No credentials provided — use NoCredentials for emulator
            storageBuilder.setCredentials(NoCredentials.getInstance());
        }
        var endpoint = provider.getEndpoint();
        if (endpoint != null && !endpoint.isEmpty() &&
                !endpoint.equals("https://storage.googleapis.com")) {
            storageBuilder.setHost(endpoint);
        }
        storage = storageBuilder.build().getService();
    }

    @Override
    public PageSet<? extends StorageMetadata> list() {
        var set = ImmutableSet.<StorageMetadata>builder();
        for (Bucket bucket : storage.list().iterateAll()) {
            set.add(new StorageMetadataImpl(StorageType.CONTAINER,
                    /*id=*/ null, bucket.getName(), /*location=*/ null,
                    /*uri=*/ null, /*eTag=*/ null,
                    toDate(bucket.getCreateTimeOffsetDateTime()),
                    toDate(bucket.getUpdateTimeOffsetDateTime()),
                    Map.of(), /*size=*/ null, Tier.STANDARD));
        }
        return new PageSetImpl<StorageMetadata>(set.build(), null);
    }

    @Override
    public PageSet<? extends StorageMetadata> list(String container,
            ListContainerOptions options) {
        var gcsOptions = new java.util.ArrayList<BlobListOption>();
        if (options.getPrefix() != null) {
            gcsOptions.add(BlobListOption.prefix(options.getPrefix()));
        }
        if (options.getMaxResults() != null) {
            gcsOptions.add(BlobListOption.pageSize(
                    options.getMaxResults()));
        }
        String marker = options.getMarker();
        if (options.getDelimiter() != null) {
            gcsOptions.add(BlobListOption.delimiter(options.getDelimiter()));
        }

        com.google.api.gax.paging.Page<Blob> page;
        try {
            page = storage.list(container,
                    gcsOptions.toArray(new BlobListOption[0]));
        } catch (StorageException se) {
            translateAndRethrowException(se, container, null);
            throw se;
        }

        var set = ImmutableSet.<StorageMetadata>builder();
        Integer maxResults = options.getMaxResults();
        int count = 0;
        boolean hasMore = false;
        String lastName = null;
        for (Blob blob : page.iterateAll()) {
            // Skip blobs at or before the marker (S3 marker is exclusive)
            if (marker != null && blob.getName().compareTo(marker) <= 0) {
                continue;
            }
            if (maxResults != null && count >= maxResults) {
                hasMore = true;
                break;
            }
            if (blob.isDirectory()) {
                set.add(new StorageMetadataImpl(StorageType.RELATIVE_PATH,
                        /*id=*/ null, blob.getName(), /*location=*/ null,
                        /*uri=*/ null, /*eTag=*/ null,
                        /*creationDate=*/ null, /*lastModified=*/ null,
                        Map.of(), /*size=*/ null, Tier.STANDARD));
            } else {
                set.add(new StorageMetadataImpl(StorageType.BLOB,
                        /*id=*/ null, blob.getName(), /*location=*/ null,
                        /*uri=*/ null, blob.getEtag(),
                        toDate(blob.getCreateTimeOffsetDateTime()),
                        toDate(blob.getUpdateTimeOffsetDateTime()),
                        Map.of(), blob.getSize(),
                        toTier(blob.getStorageClass())));
            }
            lastName = blob.getName();
            count++;
        }

        // Synthesize a next marker if we truncated results
        String nextMarker = hasMore ? lastName : null;
        return new PageSetImpl<StorageMetadata>(set.build(), nextMarker);
    }

    @Override
    public boolean containerExists(String container) {
        return storage.get(container,
                BucketGetOption.fields(BucketField.NAME)) != null;
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
        try {
            var bucketInfo = BucketInfo.newBuilder(container).build();
            storage.create(bucketInfo);
            if (options.isPublicRead()) {
                try {
                    storage.createAcl(container,
                            Acl.of(Acl.User.ofAllUsers(), Acl.Role.READER));
                } catch (StorageException se2) {
                    // ACL operations not supported (e.g., emulator)
                }
            }
            return true;
        } catch (StorageException se) {
            if (se.getCode() == 409) {
                return false;
            }
            throw se;
        }
    }

    @Override
    public void deleteContainer(String container) {
        try {
            // Delete all blobs first since GCS requires empty bucket
            var page = storage.list(container);
            for (Blob blob : page.iterateAll()) {
                storage.delete(blob.getBlobId());
            }
            storage.delete(container);
        } catch (StorageException se) {
            if (se.getCode() != 404) {
                throw se;
            }
        }
    }

    @Override
    public boolean deleteContainerIfEmpty(String container) {
        var page = storage.list(container,
                BlobListOption.pageSize(1));
        if (page.getValues().iterator().hasNext()) {
            return false;
        }
        try {
            storage.delete(container);
            return true;
        } catch (StorageException se) {
            if (se.getCode() == 404) {
                return true;
            }
            throw se;
        }
    }

    @Override
    public boolean blobExists(String container, String key) {
        return storage.get(BlobId.of(container, key),
                BlobGetOption.fields(BlobField.NAME)) != null;
    }

    @Override
    public org.jclouds.blobstore.domain.Blob getBlob(String container,
            String key, GetOptions options) {
        var gcsOptions = new java.util.ArrayList<BlobGetOption>();

        Blob gcsBlob;
        try {
            gcsBlob = storage.get(BlobId.of(container, key),
                    gcsOptions.toArray(new BlobGetOption[0]));
        } catch (StorageException se) {
            translateAndRethrowException(se, container, key);
            throw se;
        }
        if (gcsBlob == null) {
            throw new KeyNotFoundException(container, key, "");
        }

        Long rangeOffset = null;
        Long rangeEnd = null;
        boolean trailingRange = false;
        if (!options.getRanges().isEmpty()) {
            var ranges = options.getRanges().get(0).split("-", 2);
            if (ranges[0].isEmpty()) {
                // trailing range: last N bytes
                long trailing = Long.parseLong(ranges[1]);
                long blobSz = gcsBlob.getSize();
                rangeOffset = Math.max(0, blobSz - trailing);
                rangeEnd = blobSz - 1;
                trailingRange = true;
            } else if (ranges[1].isEmpty()) {
                rangeOffset = Long.parseLong(ranges[0]);
            } else {
                rangeOffset = Long.parseLong(ranges[0]);
                rangeEnd = Long.parseLong(ranges[1]);
            }
        }

        InputStream is;
        long contentLength;
        long blobSize = gcsBlob.getSize();
        try {
            if (rangeOffset != null) {
                ReadChannel reader = gcsBlob.reader();
                reader.seek(rangeOffset);
                if (rangeEnd != null) {
                    reader.limit(rangeEnd + 1);
                    contentLength = rangeEnd - rangeOffset + 1;
                } else {
                    contentLength = blobSize - rangeOffset;
                }
                is = Channels.newInputStream(reader);
            } else {
                ReadChannel reader = gcsBlob.reader();
                is = Channels.newInputStream(reader);
                contentLength = blobSize;
            }
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }

        var metadata = gcsBlob.getMetadata();
        var blob = new BlobBuilderImpl()
                .name(key)
                .userMetadata(metadata != null ? metadata : Map.of())
                .payload(is)
                .cacheControl(gcsBlob.getCacheControl())
                .contentDisposition(gcsBlob.getContentDisposition())
                .contentEncoding(gcsBlob.getContentEncoding())
                .contentLanguage(gcsBlob.getContentLanguage())
                .contentLength(contentLength)
                .contentType(gcsBlob.getContentType())
                .build();
        if (rangeOffset != null) {
            long end = rangeEnd != null ? rangeEnd :
                    blobSize - 1;
            blob.getAllHeaders().put(HttpHeaders.CONTENT_RANGE,
                    "bytes " + rangeOffset + "-" + end + "/" + blobSize);
        }
        var blobMeta = blob.getMetadata();
        blobMeta.setETag(gcsBlob.getEtag());
        blobMeta.setSize(blobSize);
        blobMeta.setTier(toTier(gcsBlob.getStorageClass()));
        blobMeta.setCreationDate(
                toDate(gcsBlob.getCreateTimeOffsetDateTime()));
        blobMeta.setLastModified(
                toDate(gcsBlob.getUpdateTimeOffsetDateTime()));
        return blob;
    }

    @Override
    public String putBlob(String container,
            org.jclouds.blobstore.domain.Blob blob) {
        return putBlob(container, blob, new PutOptions());
    }

    @Override
    public String putBlob(String container,
            org.jclouds.blobstore.domain.Blob blob, PutOptions options) {
        var contentMetadata = blob.getMetadata().getContentMetadata();
        var blobInfo = BlobInfo.newBuilder(
                BlobId.of(container, blob.getMetadata().getName()));
        blobInfo.setContentType(contentMetadata.getContentType());
        blobInfo.setContentDisposition(
                contentMetadata.getContentDisposition());
        blobInfo.setContentEncoding(contentMetadata.getContentEncoding());
        blobInfo.setContentLanguage(contentMetadata.getContentLanguage());
        blobInfo.setCacheControl(contentMetadata.getCacheControl());
        var hash = contentMetadata.getContentMD5AsHashCode();
        if (hash != null) {
            blobInfo.setMd5(hash.toString());
        }
        if (blob.getMetadata().getUserMetadata() != null) {
            blobInfo.setMetadata(blob.getMetadata().getUserMetadata());
        }
        if (blob.getMetadata().getTier() != null &&
                blob.getMetadata().getTier() != Tier.STANDARD) {
            blobInfo.setStorageClass(
                    toStorageClass(blob.getMetadata().getTier()));
        }

        var writeOptions = new java.util.ArrayList<BlobWriteOption>();
        if (options instanceof PutOptions2 putOptions2) {
            String ifMatch = putOptions2.getIfMatch();
            String ifNoneMatch = putOptions2.getIfNoneMatch();
            if (ifNoneMatch != null && ifNoneMatch.equals("*")) {
                writeOptions.add(BlobWriteOption.doesNotExist());
            } else if (ifMatch != null) {
                writeOptions.add(
                        BlobWriteOption.generationMatch(
                                getGeneration(container,
                                        blob.getMetadata().getName(),
                                        ifMatch)));
            }
        }

        try (var is = blob.getPayload().openStream()) {
            Blob gcsBlob = storage.createFrom(blobInfo.build(), is,
                    writeOptions.toArray(new BlobWriteOption[0]));
            return gcsBlob.getEtag();
        } catch (StorageException se) {
            translateAndRethrowException(se, container, null);
            throw se;
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }

    @Override
    public String copyBlob(String fromContainer, String fromName,
            String toContainer, String toName, CopyOptions options) {
        var source = BlobId.of(fromContainer, fromName);
        var targetBuilder = BlobInfo.newBuilder(
                BlobId.of(toContainer, toName));

        var contentMetadata = options.contentMetadata();
        if (contentMetadata != null) {
            if (contentMetadata.getCacheControl() != null) {
                targetBuilder.setCacheControl(
                        contentMetadata.getCacheControl());
            }
            if (contentMetadata.getContentDisposition() != null) {
                targetBuilder.setContentDisposition(
                        contentMetadata.getContentDisposition());
            }
            if (contentMetadata.getContentEncoding() != null) {
                targetBuilder.setContentEncoding(
                        contentMetadata.getContentEncoding());
            }
            if (contentMetadata.getContentLanguage() != null) {
                targetBuilder.setContentLanguage(
                        contentMetadata.getContentLanguage());
            }
            if (contentMetadata.getContentType() != null) {
                targetBuilder.setContentType(
                        contentMetadata.getContentType());
            }
        }
        var userMetadata = options.userMetadata();
        if (userMetadata != null) {
            targetBuilder.setMetadata(userMetadata);
        }

        try {
            var copyRequest = CopyRequest.newBuilder()
                    .setSource(source)
                    .setTarget(targetBuilder.build())
                    .build();
            var result = storage.copy(copyRequest);
            return result.getResult().getEtag();
        } catch (StorageException se) {
            translateAndRethrowException(se, fromContainer, fromName);
            throw se;
        }
    }

    @Override
    public void removeBlob(String container, String key) {
        try {
            storage.delete(BlobId.of(container, key));
        } catch (StorageException se) {
            if (se.getCode() != 404) {
                throw se;
            }
        }
    }

    @Override
    public BlobMetadata blobMetadata(String container, String key) {
        Blob gcsBlob;
        try {
            gcsBlob = storage.get(BlobId.of(container, key));
        } catch (StorageException se) {
            if (se.getCode() == 404) {
                return null;
            }
            translateAndRethrowException(se, container, null);
            throw se;
        }
        if (gcsBlob == null) {
            return null;
        }
        Long size = gcsBlob.getSize();
        return new BlobMetadataImpl(/*id=*/ null, key, /*location=*/ null,
                /*uri=*/ null, gcsBlob.getEtag(),
                toDate(gcsBlob.getCreateTimeOffsetDateTime()),
                toDate(gcsBlob.getUpdateTimeOffsetDateTime()),
                gcsBlob.getMetadata() != null ?
                        gcsBlob.getMetadata() : Map.of(),
                /*publicUri=*/ null, container,
                toContentMetadata(gcsBlob),
                size != null ? size : 0L,
                toTier(gcsBlob.getStorageClass()));
    }

    @Override
    protected boolean deleteAndVerifyContainerGone(String container) {
        try {
            storage.delete(container);
        } catch (StorageException se) {
            if (se.getCode() == 404) {
                return true;
            }
            throw se;
        }
        return true;
    }

    @Override
    public ContainerAccess getContainerAccess(String container) {
        var bucket = storage.get(container);
        if (bucket == null) {
            throw new ContainerNotFoundException(container, "");
        }
        try {
            var acls = bucket.listAcls();
            for (var acl : acls) {
                if (acl.getEntity().equals(Acl.User.ofAllUsers())) {
                    return ContainerAccess.PUBLIC_READ;
                }
            }
        } catch (StorageException se) {
            // ACL operations not supported (e.g., emulator)
        }
        return ContainerAccess.PRIVATE;
    }

    @Override
    public void setContainerAccess(String container,
            ContainerAccess access) {
        try {
            if (access == ContainerAccess.PUBLIC_READ) {
                storage.createAcl(container,
                        Acl.of(Acl.User.ofAllUsers(), Acl.Role.READER));
            } else {
                storage.deleteAcl(container, Acl.User.ofAllUsers());
            }
        } catch (StorageException se) {
            // ACL operations not supported (e.g., emulator)
        }
    }

    @Override
    public BlobAccess getBlobAccess(String container, String key) {
        return BlobAccess.PRIVATE;
    }

    @Override
    public void setBlobAccess(String container, String key,
            BlobAccess access) {
        throw new UnsupportedOperationException(
                "unsupported in Google Cloud Storage");
    }

    @Override
    public MultipartUpload initiateMultipartUpload(String container,
            BlobMetadata blobMetadata, PutOptions options) {
        if (!containerExists(container)) {
            throw new ContainerNotFoundException(container, "");
        }

        String uploadKey = STUB_BLOB_PREFIX + UUID.randomUUID().toString();
        String targetBlobName = blobMetadata.getName();

        // Store stub blob with metadata for later use during complete
        var stubMetadata = new HashMap<String, String>();
        stubMetadata.put(TARGET_BLOB_NAME_KEY, targetBlobName);

        var contentMetadata = blobMetadata.getContentMetadata();
        if (contentMetadata != null) {
            if (contentMetadata.getContentType() != null) {
                stubMetadata.put("s3proxy_content_type",
                        contentMetadata.getContentType());
            }
            if (contentMetadata.getContentDisposition() != null) {
                stubMetadata.put("s3proxy_content_disposition",
                        contentMetadata.getContentDisposition());
            }
            if (contentMetadata.getContentEncoding() != null) {
                stubMetadata.put("s3proxy_content_encoding",
                        contentMetadata.getContentEncoding());
            }
            if (contentMetadata.getContentLanguage() != null) {
                stubMetadata.put("s3proxy_content_language",
                        contentMetadata.getContentLanguage());
            }
            if (contentMetadata.getCacheControl() != null) {
                stubMetadata.put("s3proxy_cache_control",
                        contentMetadata.getCacheControl());
            }
        }

        var userMetadata = blobMetadata.getUserMetadata();
        if (userMetadata != null) {
            for (var entry : userMetadata.entrySet()) {
                stubMetadata.put("s3proxy_user_" + entry.getKey(),
                        entry.getValue());
            }
        }

        if (blobMetadata.getTier() != null &&
                blobMetadata.getTier() != Tier.STANDARD) {
            stubMetadata.put("s3proxy_tier",
                    blobMetadata.getTier().name());
        }

        var stubInfo = BlobInfo.newBuilder(
                BlobId.of(container, uploadKey))
                .setMetadata(stubMetadata)
                .build();
        storage.create(stubInfo, new byte[0]);

        return MultipartUpload.create(container, targetBlobName,
                uploadKey, blobMetadata, options);
    }

    @Override
    public void abortMultipartUpload(MultipartUpload mpu) {
        String uploadKey = mpu.id();

        if (!uploadKey.startsWith(STUB_BLOB_PREFIX)) {
            throw new KeyNotFoundException(mpu.containerName(), uploadKey,
                    "Multipart upload not found: " + uploadKey);
        }

        String nonce = uploadKey.substring(STUB_BLOB_PREFIX.length());

        // Delete part blobs
        var page = storage.list(mpu.containerName(),
                BlobListOption.prefix(STUB_BLOB_PREFIX + nonce + "/"));
        for (Blob blob : page.iterateAll()) {
            storage.delete(blob.getBlobId());
        }

        // Delete stub
        if (!storage.delete(BlobId.of(mpu.containerName(), uploadKey))) {
            throw new KeyNotFoundException(mpu.containerName(), uploadKey,
                    "Multipart upload not found: " + uploadKey);
        }
    }

    @Override
    public String completeMultipartUpload(MultipartUpload mpu,
            List<MultipartPart> parts) {
        String uploadKey = mpu.id();
        String nonce = uploadKey.substring(STUB_BLOB_PREFIX.length());

        Blob stubBlob = storage.get(
                BlobId.of(mpu.containerName(), uploadKey));
        if (stubBlob == null) {
            throw new IllegalArgumentException(
                    "Upload not found: uploadId=" + uploadKey);
        }

        var stubMetadata = stubBlob.getMetadata();
        String targetBlobName = stubMetadata.get(TARGET_BLOB_NAME_KEY);
        if (targetBlobName == null) {
            throw new IllegalArgumentException(
                    "Stub blob missing target name: uploadId=" + uploadKey);
        }

        if (parts == null || parts.isEmpty()) {
            throw new IllegalArgumentException("Parts list cannot be empty");
        }

        int previousPartNumber = 0;
        for (var part : parts) {
            if (part.partNumber() <= previousPartNumber) {
                throw new IllegalArgumentException(
                        "Parts must be in strictly ascending order");
            }
            previousPartNumber = part.partNumber();
        }

        // Build target blob info from stub metadata
        var targetBuilder = BlobInfo.newBuilder(
                BlobId.of(mpu.containerName(), targetBlobName));
        if (stubMetadata.containsKey("s3proxy_content_type")) {
            targetBuilder.setContentType(
                    stubMetadata.get("s3proxy_content_type"));
        }
        if (stubMetadata.containsKey("s3proxy_content_disposition")) {
            targetBuilder.setContentDisposition(
                    stubMetadata.get("s3proxy_content_disposition"));
        }
        if (stubMetadata.containsKey("s3proxy_content_encoding")) {
            targetBuilder.setContentEncoding(
                    stubMetadata.get("s3proxy_content_encoding"));
        }
        if (stubMetadata.containsKey("s3proxy_content_language")) {
            targetBuilder.setContentLanguage(
                    stubMetadata.get("s3proxy_content_language"));
        }
        if (stubMetadata.containsKey("s3proxy_cache_control")) {
            targetBuilder.setCacheControl(
                    stubMetadata.get("s3proxy_cache_control"));
        }
        if (stubMetadata.containsKey("s3proxy_tier")) {
            targetBuilder.setStorageClass(toStorageClass(
                    Tier.valueOf(stubMetadata.get("s3proxy_tier"))));
        }

        // Restore user metadata
        var userMetadata = new HashMap<String, String>();
        for (var entry : stubMetadata.entrySet()) {
            if (entry.getKey().startsWith("s3proxy_user_")) {
                userMetadata.put(
                        entry.getKey().substring("s3proxy_user_".length()),
                        entry.getValue());
            }
        }
        if (!userMetadata.isEmpty()) {
            targetBuilder.setMetadata(userMetadata);
        }

        // If single part, just copy it to the target
        if (parts.size() == 1) {
            String partBlobName = makePartBlobName(nonce,
                    parts.get(0).partNumber());
            var source = BlobId.of(mpu.containerName(), partBlobName);
            var copyRequest = CopyRequest.newBuilder()
                    .setSource(source)
                    .setTarget(targetBuilder.build())
                    .build();
            var result = storage.copy(copyRequest);
            // Clean up
            storage.delete(source);
            storage.delete(BlobId.of(mpu.containerName(), uploadKey));
            return result.getResult().getEtag();
        }

        // GCS compose supports up to 32 parts.
        // For more parts, compose recursively.
        var sourceBlobIds = new java.util.ArrayList<BlobId>();
        for (var part : parts) {
            String partBlobName = makePartBlobName(nonce, part.partNumber());
            sourceBlobIds.add(BlobId.of(mpu.containerName(), partBlobName));
        }

        String eTag = composeRecursive(mpu.containerName(),
                targetBuilder.build(), sourceBlobIds, nonce);

        // Clean up part blobs and stub
        for (var blobId : sourceBlobIds) {
            storage.delete(blobId);
        }
        // Clean up any intermediate compose blobs
        var intermediatePage = storage.list(mpu.containerName(),
                BlobListOption.prefix(
                        STUB_BLOB_PREFIX + nonce + "/compose_"));
        for (Blob blob : intermediatePage.iterateAll()) {
            storage.delete(blob.getBlobId());
        }
        storage.delete(BlobId.of(mpu.containerName(), uploadKey));

        return eTag;
    }

    /**
     * Recursively compose blobs to handle more than 32 parts.
     * GCS compose supports max 32 sources, so for N > 32 parts we
     * compose in groups of 32, then compose those results.
     */
    private String composeRecursive(String container, BlobInfo target,
            List<BlobId> sources, String nonce) {
        if (sources.size() <= MAX_COMPOSE_PARTS) {
            var composeBuilder = ComposeRequest.newBuilder();
            composeBuilder.setTarget(target);
            for (var source : sources) {
                composeBuilder.addSource(source.getName());
            }
            var result = storage.compose(composeBuilder.build());
            return result.getEtag();
        }

        // Compose in groups of MAX_COMPOSE_PARTS
        var intermediateIds = new java.util.ArrayList<BlobId>();
        int groupIndex = 0;
        for (int i = 0; i < sources.size();
                i += MAX_COMPOSE_PARTS) {
            int end = Math.min(i + MAX_COMPOSE_PARTS, sources.size());
            var group = sources.subList(i, end);
            String intermediateName = STUB_BLOB_PREFIX + nonce +
                    "/compose_" + groupIndex;
            var intermediateInfo = BlobInfo.newBuilder(
                    BlobId.of(container, intermediateName)).build();

            var composeBuilder = ComposeRequest.newBuilder();
            composeBuilder.setTarget(intermediateInfo);
            for (var source : group) {
                composeBuilder.addSource(source.getName());
            }
            storage.compose(composeBuilder.build());

            intermediateIds.add(BlobId.of(container, intermediateName));
            groupIndex++;
        }

        // Recursively compose intermediates
        return composeRecursive(container, target, intermediateIds,
                nonce);
    }

    @Override
    public MultipartPart uploadMultipartPart(MultipartUpload mpu,
            int partNumber, org.jclouds.io.Payload payload) {
        if (partNumber < 1 || partNumber > 10_000) {
            throw new IllegalArgumentException(
                    "Part number must be between 1 and 10,000, got: " +
                    partNumber);
        }

        Long contentLength = payload.getContentMetadata()
                .getContentLength();
        if (contentLength == null) {
            throw new IllegalArgumentException(
                    "Content-Length is required");
        }

        String uploadKey = mpu.id();
        String nonce = uploadKey.substring(STUB_BLOB_PREFIX.length());
        String partBlobName = makePartBlobName(nonce, partNumber);

        byte[] md5Hash;
        try (var is = payload.openStream();
             var his = new HashingInputStream(MD5, is)) {
            var partInfo = BlobInfo.newBuilder(
                    BlobId.of(mpu.containerName(), partBlobName)).build();
            storage.createFrom(partInfo, his);

            md5Hash = his.hash().asBytes();

            var providedMd5 = payload.getContentMetadata()
                    .getContentMD5AsHashCode();
            if (providedMd5 != null) {
                if (!MessageDigest.isEqual(md5Hash,
                        providedMd5.asBytes())) {
                    // Clean up the uploaded part
                    storage.delete(BlobId.of(mpu.containerName(),
                            partBlobName));
                    throw new IllegalArgumentException(
                            "Content-MD5 mismatch");
                }
            }
        } catch (StorageException se) {
            translateAndRethrowException(se, mpu.containerName(),
                    mpu.blobName());
            throw new RuntimeException((
                    "Failed to upload part %d for blob '%s' in " +
                    "container '%s': %s").formatted(
                    partNumber, mpu.blobName(), mpu.containerName(),
                    se.getMessage()), se);
        } catch (IOException ioe) {
            throw new RuntimeException((
                    "Failed to upload part %d for blob '%s' in " +
                    "container '%s': %s").formatted(
                    partNumber, mpu.blobName(), mpu.containerName(),
                    ioe.getMessage()), ioe);
        }

        String eTag = BaseEncoding.base16().lowerCase().encode(md5Hash);
        return MultipartPart.create(partNumber, contentLength, eTag, null);
    }

    @Override
    public List<MultipartPart> listMultipartUpload(MultipartUpload mpu) {
        String uploadKey = mpu.id();
        String nonce = uploadKey.substring(STUB_BLOB_PREFIX.length());
        String prefix = STUB_BLOB_PREFIX + nonce + "/part_";

        var parts = ImmutableList.<MultipartPart>builder();
        var page = storage.list(mpu.containerName(),
                BlobListOption.prefix(prefix));
        for (Blob blob : page.iterateAll()) {
            String name = blob.getName();
            String partNumberStr = name.substring(
                    name.lastIndexOf('_') + 1);
            int partNumber;
            try {
                partNumber = Integer.parseInt(partNumberStr);
            } catch (NumberFormatException e) {
                continue;
            }
            parts.add(MultipartPart.create(partNumber, blob.getSize(),
                    "", null));
        }
        return parts.build();
    }

    @Override
    public List<MultipartUpload> listMultipartUploads(String container) {
        var builder = ImmutableList.<MultipartUpload>builder();
        var page = storage.list(container,
                BlobListOption.prefix(STUB_BLOB_PREFIX));
        for (Blob blob : page.iterateAll()) {
            String name = blob.getName();
            // Only look at stub blobs, not part blobs
            if (name.contains("/part_") || name.contains("/compose_")) {
                continue;
            }
            var metadata = blob.getMetadata();
            if (metadata == null ||
                    !metadata.containsKey(TARGET_BLOB_NAME_KEY)) {
                continue;
            }
            String targetBlobName = metadata.get(TARGET_BLOB_NAME_KEY);
            builder.add(MultipartUpload.create(container, targetBlobName,
                    name, null, null));
        }
        return builder.build();
    }

    @Override
    public long getMinimumMultipartPartSize() {
        // GCS minimum part is 5 MB except for last part
        return 5L * 1024 * 1024;
    }

    @Override
    public long getMaximumMultipartPartSize() {
        return 5L * 1024 * 1024 * 1024;
    }

    @Override
    public int getMaximumNumberOfParts() {
        // With recursive compose we can handle many more than 32
        return 10_000;
    }

    @Override
    public InputStream streamBlob(String container, String name) {
        throw new UnsupportedOperationException("not yet implemented");
    }

    private static String makePartBlobName(String nonce, int partNumber) {
        return STUB_BLOB_PREFIX + nonce +
                "/part_%05d".formatted(partNumber);
    }

    /**
     * Get blob generation for conditional writes.  GCS uses generations
     * rather than ETags for conditional operations.
     */
    private long getGeneration(String container, String name,
            String eTag) {
        Blob blob = storage.get(BlobId.of(container, name));
        if (blob == null) {
            throw new KeyNotFoundException(container, name, "");
        }
        // If the ETag doesn't match, the precondition fails
        if (!eTag.equals("*") && !eTag.equals(blob.getEtag())) {
            var request = HttpRequest.builder()
                    .method("PUT")
                    .endpoint("https://storage.googleapis.com")
                    .build();
            var response = HttpResponse.builder()
                    .statusCode(412)
                    .build();
            throw new HttpResponseException(
                    new HttpCommand(request), response);
        }
        return blob.getGeneration();
    }

    private static Date toDate(
            java.time.@Nullable OffsetDateTime offsetDateTime) {
        if (offsetDateTime == null) {
            return null;
        }
        return new Date(offsetDateTime.toInstant().toEpochMilli());
    }

    private static com.google.cloud.storage.StorageClass toStorageClass(
            Tier tier) {
        if (tier == Tier.ARCHIVE) {
            return com.google.cloud.storage.StorageClass.ARCHIVE;
        } else if (tier == Tier.COLD) {
            return com.google.cloud.storage.StorageClass.COLDLINE;
        } else if (tier == Tier.COOL || tier == Tier.INFREQUENT) {
            return com.google.cloud.storage.StorageClass.NEARLINE;
        } else {
            return com.google.cloud.storage.StorageClass.STANDARD;
        }
    }

    private static Tier toTier(
            com.google.cloud.storage.@Nullable StorageClass storageClass) {
        if (storageClass == null) {
            return Tier.STANDARD;
        } else if (storageClass.equals(
                com.google.cloud.storage.StorageClass.ARCHIVE)) {
            return Tier.ARCHIVE;
        } else if (storageClass.equals(
                com.google.cloud.storage.StorageClass.COLDLINE)) {
            return Tier.COLD;
        } else if (storageClass.equals(
                com.google.cloud.storage.StorageClass.NEARLINE)) {
            return Tier.COOL;
        } else {
            return Tier.STANDARD;
        }
    }

    private static ContentMetadata toContentMetadata(Blob blob) {
        return ContentMetadataBuilder.create()
                .cacheControl(blob.getCacheControl())
                .contentDisposition(blob.getContentDisposition())
                .contentEncoding(blob.getContentEncoding())
                .contentLanguage(blob.getContentLanguage())
                .contentLength(blob.getSize())
                .contentType(blob.getContentType())
                .build();
    }

    /**
     * Translate StorageException to jclouds exceptions.
     */
    private static void translateAndRethrowException(StorageException se,
            String container, @Nullable String key) {
        switch (se.getCode()) {
        case 404:
            if (key != null) {
                var keyEx = new KeyNotFoundException(container, key, "");
                keyEx.initCause(se);
                throw keyEx;
            } else {
                var containerEx = new ContainerNotFoundException(
                        container, "");
                containerEx.initCause(se);
                throw containerEx;
            }
        case 412:
            var request = HttpRequest.builder()
                    .method("GET")
                    .endpoint("https://storage.googleapis.com")
                    .build();
            var response = HttpResponse.builder()
                    .statusCode(412)
                    .build();
            throw new HttpResponseException(
                    new HttpCommand(request), response, se);
        default:
            break;
        }
    }
}
