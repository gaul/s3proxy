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
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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
import com.google.cloud.storage.Storage.BlobSourceOption;
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

import org.gaul.s3proxy.blobstore.BaseBlobStore;
import org.gaul.s3proxy.blobstore.ContainerNotFoundException;
import org.gaul.s3proxy.blobstore.ContentMetadata;
import org.gaul.s3proxy.blobstore.Credentials;
import org.gaul.s3proxy.blobstore.HttpResponse;
import org.gaul.s3proxy.blobstore.HttpResponseException;
import org.gaul.s3proxy.blobstore.KeyNotFoundException;
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

public final class GCloudBlobStore extends BaseBlobStore {
    private static final String STUB_BLOB_PREFIX = ".s3proxy/stubs/";
    private static final String TARGET_BLOB_NAME_KEY =
            "s3proxy_target_blob_name";
    private static final HashFunction MD5 = Hashing.md5();
    // GCS compose supports up to 32 source objects
    private static final int MAX_COMPOSE_PARTS = 32;

    private final Storage storage;

    public GCloudBlobStore(
            Supplier<Credentials> creds,
            String endpointUrl) {
        var cred = creds.get();
        var storageBuilder = StorageOptions.newBuilder();
        if (cred.identity() != null && !cred.identity().isEmpty()) {
            storageBuilder.setProjectId(cred.identity());
        }
        if (cred.credential() != null && !cred.credential().isEmpty()) {
            try {
                var credentials = ServiceAccountCredentials.fromStream(
                        new ByteArrayInputStream(
                                cred.credential().getBytes(
                                        StandardCharsets.UTF_8)));
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
        var endpoint = endpointUrl;
        if (endpoint != null && !endpoint.isEmpty() &&
                !endpoint.equals("https://storage.googleapis.com")) {
            storageBuilder.setHost(endpoint);
        }
        storage = storageBuilder.build().getService();
    }

    // Releases the SDK client's transport channels and background threads when
    // the BlobStore is closed.
    @Override
    public void close() {
        try {
            storage.close();
        } catch (Exception e) {
            // Best effort: releasing the client on shutdown must not fail the
            // caller.
        }
    }

    @Override
    public PageSet<? extends StorageMetadata> list() {
        var set = ImmutableSet.<StorageMetadata>builder();
        for (Bucket bucket : storage.list().iterateAll()) {
            set.add(new ContainerMetadata(bucket.getName(), Map.of(),
                    /*eTag=*/ null,
                    toDate(bucket.getCreateTimeOffsetDateTime()),
                    toDate(bucket.getUpdateTimeOffsetDateTime()),
                    /*size=*/ null, StorageClass.STANDARD));
        }
        return new PageSet<StorageMetadata>(set.build(), null);
    }

    @Override
    public PageSet<? extends StorageMetadata> list(String container,
            ListContainerOptions options) {
        var gcsOptions = new java.util.ArrayList<BlobListOption>();
        if (options.prefix() != null) {
            gcsOptions.add(BlobListOption.prefix(options.prefix()));
        }
        if (options.maxResults() != null) {
            gcsOptions.add(BlobListOption.pageSize(
                    options.maxResults()));
        }
        String marker = options.marker();
        if (marker != null) {
            // Begin the server-side scan at the marker rather than paging from
            // the start of the bucket, which would make listing a bucket of N
            // objects cost O(N^2).  GCS startOffset is inclusive while the S3
            // marker is exclusive, so the loop below still skips the single
            // entry equal to the marker; results are otherwise identical.
            gcsOptions.add(BlobListOption.startOffset(marker));
        }
        if (options.delimiter() != null) {
            gcsOptions.add(BlobListOption.delimiter(options.delimiter()));
        }

        com.google.api.gax.paging.Page<Blob> page;
        try {
            page = storage.list(container,
                    gcsOptions.toArray(new BlobListOption[0]));
        } catch (StorageException se) {
            throw translate(se, container, null);
        }

        var set = ImmutableSet.<StorageMetadata>builder();
        Integer maxResults = options.maxResults();
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
                set.add(new BlobMetadata(StorageType.RELATIVE_PATH,
                        blob.getName(), Map.of(), /*eTag=*/ null,
                        /*creationDate=*/ null, /*lastModified=*/ null,
                        StorageClass.STANDARD,
                        /*container=*/ null,
                        ContentMetadata.builder().build()));
            } else {
                set.add(new BlobMetadata(StorageType.BLOB,
                        blob.getName(), Map.of(), blob.getEtag(),
                        toDate(blob.getCreateTimeOffsetDateTime()),
                        toDate(blob.getUpdateTimeOffsetDateTime()),
                        fromGcsStorageClass(blob.getStorageClass()),
                        /*container=*/ null,
                        ContentMetadata.builder()
                                .contentLength(blob.getSize())
                                .build()));
            }
            lastName = blob.getName();
            count++;
        }

        // Synthesize a next marker if we truncated results
        String nextMarker = hasMore ? lastName : null;
        return new PageSet<StorageMetadata>(set.build(), nextMarker);
    }

    @Override
    public boolean containerExists(String container) {
        return storage.get(container,
                BucketGetOption.fields(BucketField.NAME)) != null;
    }

    @Override
    public boolean createContainer(String container) {
        return createContainer(container, CreateContainerOptions.NONE);
    }

    @Override
    public boolean createContainer(String container,
            CreateContainerOptions options) {
        try {
            var bucketInfo = BucketInfo.newBuilder(container).build();
            storage.create(bucketInfo);
            if (options.publicRead()) {
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
    public org.gaul.s3proxy.blobstore.domain.Blob getBlob(String container,
            String key, GetOptions options) {
        var gcsOptions = new java.util.ArrayList<BlobGetOption>();

        Blob gcsBlob;
        try {
            gcsBlob = storage.get(BlobId.of(container, key),
                    gcsOptions.toArray(new BlobGetOption[0]));
        } catch (StorageException se) {
            throw translate(se, container, key);
        }
        if (gcsBlob == null) {
            // The SDK collapses a missing bucket and a missing object both to
            // null; distinguish them so the frontend emits NoSuchBucket vs
            // NoSuchKey.
            if (storage.get(container) == null) {
                throw new ContainerNotFoundException(container, "");
            }
            throw new KeyNotFoundException(container, key, "");
        }

        // Enforce conditional-GET preconditions before streaming.  jclouds
        // backends report every conditional-header failure as 412; the
        // frontend (S3ProxyHandlerJetty) remaps GET/HEAD If-None-Match and
        // If-Modified-Since misses to 304 Not Modified.
        String eTag = gcsBlob.getEtag();
        Date lastModified = toDate(gcsBlob.getUpdateTimeOffsetDateTime());
        enforceConditionalGet(options, eTag, lastModified);

        long blobSize = gcsBlob.getSize();
        Long rangeOffset = null;
        Long rangeEnd = null;
        if (!options.ranges().isEmpty()) {
            var ranges = options.ranges().get(0).split("-", 2);
            if (ranges[0].isEmpty()) {
                // trailing range: last N bytes
                long trailing = Long.parseLong(ranges[1]);
                rangeOffset = Math.max(0, blobSize - trailing);
                rangeEnd = blobSize - 1;
            } else if (ranges[1].isEmpty()) {
                rangeOffset = Long.parseLong(ranges[0]);
            } else {
                rangeOffset = Long.parseLong(ranges[0]);
                rangeEnd = Long.parseLong(ranges[1]);
            }
            // A range starting at or past the end of the object is
            // unsatisfiable; S3 returns 416 InvalidRange.  Without this GCS
            // reads zero bytes and the declared Content-Length desyncs.
            if (rangeOffset >= blobSize) {
                throw httpResponseException(416, null);
            }
            // Clamp an end that runs past the last byte (still satisfiable).
            if (rangeEnd != null && rangeEnd >= blobSize) {
                rangeEnd = blobSize - 1;
            }
        }

        InputStream is;
        long contentLength;
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
        var builder = org.gaul.s3proxy.blobstore.domain.Blob.builder(key)
                .userMetadata(metadata != null ? metadata : Map.of())
                .payload(is)
                .cacheControl(gcsBlob.getCacheControl())
                .contentDisposition(gcsBlob.getContentDisposition())
                .contentEncoding(gcsBlob.getContentEncoding())
                .contentLanguage(gcsBlob.getContentLanguage())
                .contentLength(contentLength)
                .contentType(gcsBlob.getContentType())
                .eTag(gcsBlob.getEtag())
                .storageClass(fromGcsStorageClass(gcsBlob.getStorageClass()))
                .creationDate(toDate(gcsBlob.getCreateTimeOffsetDateTime()))
                .lastModified(toDate(gcsBlob.getUpdateTimeOffsetDateTime()));
        if (rangeOffset != null) {
            long end = rangeEnd != null ? rangeEnd :
                    blobSize - 1;
            builder.contentRange(
                    "bytes " + rangeOffset + "-" + end + "/" + blobSize);
        }
        return builder.build();
    }

    // Enforce S3 conditional-GET headers (If-Match / If-None-Match /
    // If-Modified-Since / If-Unmodified-Since).  GCS uses generation
    // preconditions rather than ETag/time matching, so evaluate them here
    // against the object's metadata.  Every failure is reported as 412;
    // S3ProxyHandlerJetty maps GET/HEAD If-None-Match and If-Modified-Since
    // misses to 304 Not Modified.
    private static void enforceConditionalGet(GetOptions options,
            @Nullable String eTag, @Nullable Date lastModified) {
        String ifMatch = options.ifMatch();
        String ifNoneMatch = options.ifNoneMatch();
        // The wildcard "*" matches any existing object rather than a literal
        // ETag.  The object exists here (getBlob already fetched it), so
        // If-Match: * always passes and If-None-Match: * always fails the
        // precondition (which the frontend remaps to 304 for GET/HEAD).
        if ("*".equals(ifMatch)) {
            ifMatch = null;
        }
        if ("*".equals(ifNoneMatch)) {
            throw preconditionFailed(eTag);
        }
        if (eTag != null) {
            String quoted = maybeQuoteETag(eTag);
            if (ifMatch != null && !maybeQuoteETag(ifMatch).equals(quoted)) {
                throw preconditionFailed(eTag);
            }
            if (ifNoneMatch != null &&
                    maybeQuoteETag(ifNoneMatch).equals(quoted)) {
                throw preconditionFailed(eTag);
            }
        }
        if (lastModified != null) {
            Date modified = truncateToSecond(lastModified);
            Date ifModifiedSince = options.ifModifiedSince();
            if (ifModifiedSince != null &&
                    modified.compareTo(ifModifiedSince) <= 0) {
                throw preconditionFailed(eTag);
            }
            Date ifUnmodifiedSince = options.ifUnmodifiedSince();
            if (ifUnmodifiedSince != null &&
                    modified.compareTo(ifUnmodifiedSince) > 0) {
                throw preconditionFailed(eTag);
            }
        }
    }

    // HTTP dates (Last-Modified, If-Modified-Since, If-Unmodified-Since) have
    // one-second granularity, but GCS timestamps carry sub-second precision.
    // Truncate to whole seconds so a conditional header compares equal to the
    // Last-Modified value the client previously saw.
    private static Date truncateToSecond(Date date) {
        return new Date(Math.floorDiv(date.getTime(), 1000L) * 1000L);
    }

    private static String maybeQuoteETag(String eTag) {
        if (!eTag.startsWith("\"") && !eTag.endsWith("\"")) {
            eTag = "\"" + eTag + "\"";
        }
        return eTag;
    }

    @Override
    public String putBlob(String container,
            org.gaul.s3proxy.blobstore.domain.Blob blob) {
        return putBlob(container, blob, PutOptions.NONE);
    }

    @Override
    public String putBlob(String container,
            org.gaul.s3proxy.blobstore.domain.Blob blob, PutOptions options) {
        var contentMetadata = blob.getMetadata().getContentMetadata();
        var blobInfo = BlobInfo.newBuilder(
                BlobId.of(container, blob.getMetadata().getName()));
        blobInfo.setContentType(contentMetadata.contentType());
        blobInfo.setContentDisposition(
                contentMetadata.contentDisposition());
        blobInfo.setContentEncoding(contentMetadata.contentEncoding());
        blobInfo.setContentLanguage(contentMetadata.contentLanguage());
        blobInfo.setCacheControl(contentMetadata.cacheControl());
        var hash = contentMetadata.contentMD5();
        if (hash != null) {
            blobInfo.setMd5(Base64.getEncoder().encodeToString(hash.asBytes()));
        }
        if (blob.getMetadata().getUserMetadata() != null) {
            blobInfo.setMetadata(blob.getMetadata().getUserMetadata());
        }
        if (blob.getMetadata().getStorageClass() != null &&
                blob.getMetadata().getStorageClass() != StorageClass.STANDARD) {
            blobInfo.setStorageClass(
                    toGcsStorageClass(blob.getMetadata().getStorageClass()));
        }

        var writeOptions = new java.util.ArrayList<BlobWriteOption>();
        if (hash != null) {
            // The Java SDK strips blobInfo's md5 from resumable upload
            // metadata unless md5Match is requested, so without this GCS
            // never validates the client-supplied Content-MD5.  md5Match
            // re-sends the md5 and requests server-side validation.
            writeOptions.add(BlobWriteOption.md5Match());
        }
        if (options != null) {
            String name = blob.getMetadata().getName();
            String ifMatch = options.ifMatch();
            String ifNoneMatch = options.ifNoneMatch();
            if (ifMatch != null) {
                if (ifMatch.equals("*")) {
                    // If-Match: * — overwrite only an existing object.  Pin
                    // the write to its current generation so a concurrent
                    // delete fails the precondition instead of recreating it.
                    Blob existing = storage.get(BlobId.of(container, name));
                    if (existing == null) {
                        throw preconditionFailed(null);
                    }
                    writeOptions.add(BlobWriteOption.generationMatch(
                            existing.getGeneration()));
                } else {
                    // If-Match: <etag> — gate the write on the matching
                    // generation; mismatch or absence fails the precondition.
                    writeOptions.add(BlobWriteOption.generationMatch(
                            getGeneration(container, name, ifMatch)));
                }
            }
            if (ifNoneMatch != null) {
                if (ifNoneMatch.equals("*")) {
                    writeOptions.add(BlobWriteOption.doesNotExist());
                } else {
                    // If-None-Match: <etag> — fail if an object with that ETag
                    // currently exists.  GCS has no etag precondition, but
                    // pinning generationNotMatch to the matching object's
                    // generation makes the rejection atomic: if it is still
                    // that version the write fails, and if it has since changed
                    // or been deleted the write proceeds.
                    Blob existing = storage.get(BlobId.of(container, name));
                    if (existing != null && maybeQuoteETag(ifNoneMatch).equals(
                            maybeQuoteETag(existing.getEtag()))) {
                        writeOptions.add(BlobWriteOption.generationNotMatch(
                                existing.getGeneration()));
                    }
                }
            }
        }
        if (options.blobAccess() == BlobAccess.PUBLIC_READ) {
            writeOptions.add(BlobWriteOption.predefinedAcl(
                    Storage.PredefinedAcl.PUBLIC_READ));
        }

        try (var is = blob.getPayload().openStream()) {
            Blob gcsBlob = storage.createFrom(blobInfo.build(), is,
                    writeOptions.toArray(new BlobWriteOption[0]));
            return gcsBlob.getEtag();
        } catch (StorageException se) {
            // GCS has no dedicated error code for a checksum mismatch: it
            // reports the md5Match validation we requested as a generic 400
            // "invalid".  Only surface BadDigest when we actually asked GCS to
            // validate the checksum; other 400s are unrelated client errors.
            if (se.getCode() == 400 && hash != null) {
                throw httpResponseException(400, se);
            }
            throw translate(se, container, null);
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
            if (contentMetadata.cacheControl() != null) {
                targetBuilder.setCacheControl(
                        contentMetadata.cacheControl());
            }
            if (contentMetadata.contentDisposition() != null) {
                targetBuilder.setContentDisposition(
                        contentMetadata.contentDisposition());
            }
            if (contentMetadata.contentEncoding() != null) {
                targetBuilder.setContentEncoding(
                        contentMetadata.contentEncoding());
            }
            if (contentMetadata.contentLanguage() != null) {
                targetBuilder.setContentLanguage(
                        contentMetadata.contentLanguage());
            }
            if (contentMetadata.contentType() != null) {
                targetBuilder.setContentType(
                        contentMetadata.contentType());
            }
        }
        var userMetadata = options.userMetadata();
        if (userMetadata != null) {
            targetBuilder.setMetadata(userMetadata);
        }

        // GCS has no native ETag/time copy-source preconditions, so emulate the
        // x-amz-copy-source-if-* conditions against the source object's current
        // metadata.  For If-Match, additionally pin the copy to the verified
        // generation so a concurrent change to the source fails the copy rather
        // than silently copying a different version.
        var sourceOptions = new java.util.ArrayList<BlobSourceOption>();
        String ifMatch = options.ifMatch();
        String ifNoneMatch = options.ifNoneMatch();
        Date ifModifiedSince = options.ifModifiedSince();
        Date ifUnmodifiedSince = options.ifUnmodifiedSince();
        if (ifMatch != null || ifNoneMatch != null ||
                ifModifiedSince != null || ifUnmodifiedSince != null) {
            Blob sourceBlob = storage.get(source);
            if (sourceBlob != null) {
                String sourceETag = sourceBlob.getEtag();
                if (sourceETag != null) {
                    String quoted = maybeQuoteETag(sourceETag);
                    if (ifMatch != null &&
                            !maybeQuoteETag(ifMatch).equals(quoted)) {
                        throw preconditionFailed(sourceETag);
                    }
                    if (ifNoneMatch != null &&
                            maybeQuoteETag(ifNoneMatch).equals(quoted)) {
                        throw preconditionFailed(sourceETag);
                    }
                }
                Date lastModified = toDate(
                        sourceBlob.getUpdateTimeOffsetDateTime());
                if (lastModified != null) {
                    Date modified = truncateToSecond(lastModified);
                    if (ifModifiedSince != null &&
                            modified.compareTo(ifModifiedSince) <= 0) {
                        throw preconditionFailed(sourceETag);
                    }
                    if (ifUnmodifiedSince != null &&
                            modified.compareTo(ifUnmodifiedSince) > 0) {
                        throw preconditionFailed(sourceETag);
                    }
                }
                if (ifMatch != null) {
                    sourceOptions.add(BlobSourceOption.generationMatch(
                            sourceBlob.getGeneration()));
                }
            }
        }

        try {
            var copyRequest = CopyRequest.newBuilder()
                    .setSource(source)
                    .setSourceOptions(sourceOptions)
                    .setTarget(targetBuilder.build())
                    .build();
            var result = storage.copy(copyRequest);
            return result.getResult().getEtag();
        } catch (StorageException se) {
            throw translate(se, fromContainer, fromName);
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
            throw translate(se, container, null);
        }
        if (gcsBlob == null) {
            return null;
        }
        return new BlobMetadata(StorageType.BLOB, key,
                gcsBlob.getMetadata() != null ?
                        gcsBlob.getMetadata() : Map.of(),
                gcsBlob.getEtag(),
                toDate(gcsBlob.getCreateTimeOffsetDateTime()),
                toDate(gcsBlob.getUpdateTimeOffsetDateTime()),
                fromGcsStorageClass(gcsBlob.getStorageClass()),
                container,
                toContentMetadata(gcsBlob));
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
            // The emulator returns ACL responses the SDK cannot deserialize
            // (StorageException with no HTTP status, code 0); tolerate those
            // but surface real failures rather than reporting PRIVATE.
            if (se.getCode() != 0) {
                throw translate(se, container, /*key=*/ null);
            }
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
            // The emulator returns ACL responses the SDK cannot deserialize
            // (StorageException with no HTTP status, code 0); the ACL is
            // applied server-side, so tolerate those.  Surface real failures
            // (permission denied, uniform bucket-level access, missing bucket)
            // rather than reporting success for a change that did not apply.
            if (se.getCode() != 0) {
                throw translate(se, container, /*key=*/ null);
            }
        }
    }

    @Override
    public BlobAccess getBlobAccess(String container, String key) {
        try {
            var acls = storage.listAcls(BlobId.of(container, key));
            for (var acl : acls) {
                if (acl.getEntity().equals(Acl.User.ofAllUsers())) {
                    return BlobAccess.PUBLIC_READ;
                }
            }
        } catch (StorageException se) {
            // On 404, distinguish a missing bucket from a missing object so
            // the caller can emit NoSuchBucket vs NoSuchKey.
            if (se.getCode() == 404) {
                if (storage.get(container) == null) {
                    throw new ContainerNotFoundException(container, "");
                }
                throw new KeyNotFoundException(container, key, "");
            }
            // The emulator returns ACL responses the SDK cannot deserialize
            // (StorageException with no HTTP status, code 0); tolerate those
            // but surface real failures rather than reporting PRIVATE.
            if (se.getCode() != 0) {
                throw translate(se, container, key);
            }
        }
        return BlobAccess.PRIVATE;
    }

    @Override
    public void setBlobAccess(String container, String key,
            BlobAccess access) {
        try {
            if (access == BlobAccess.PUBLIC_READ) {
                storage.createAcl(BlobId.of(container, key),
                        Acl.of(Acl.User.ofAllUsers(), Acl.Role.READER));
            } else {
                storage.deleteAcl(BlobId.of(container, key),
                        Acl.User.ofAllUsers());
            }
        } catch (StorageException se) {
            // The emulator returns ACL responses the SDK cannot deserialize
            // (StorageException with no HTTP status, code 0); the ACL is
            // applied server-side, so tolerate those.  Surface real failures
            // (permission denied, uniform bucket-level access, missing object)
            // rather than reporting success for a change that did not apply.
            if (se.getCode() != 0) {
                throw translate(se, container, key);
            }
        }
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
            if (contentMetadata.contentType() != null) {
                stubMetadata.put("s3proxy_content_type",
                        contentMetadata.contentType());
            }
            if (contentMetadata.contentDisposition() != null) {
                stubMetadata.put("s3proxy_content_disposition",
                        contentMetadata.contentDisposition());
            }
            if (contentMetadata.contentEncoding() != null) {
                stubMetadata.put("s3proxy_content_encoding",
                        contentMetadata.contentEncoding());
            }
            if (contentMetadata.contentLanguage() != null) {
                stubMetadata.put("s3proxy_content_language",
                        contentMetadata.contentLanguage());
            }
            if (contentMetadata.cacheControl() != null) {
                stubMetadata.put("s3proxy_cache_control",
                        contentMetadata.cacheControl());
            }
        }

        var userMetadata = blobMetadata.getUserMetadata();
        if (userMetadata != null) {
            for (var entry : userMetadata.entrySet()) {
                stubMetadata.put("s3proxy_user_" + entry.getKey(),
                        entry.getValue());
            }
        }

        if (blobMetadata.getStorageClass() != null &&
                blobMetadata.getStorageClass() != StorageClass.STANDARD) {
            stubMetadata.put("s3proxy_storage_class",
                    blobMetadata.getStorageClass().name());
        }

        var stubInfo = BlobInfo.newBuilder(
                BlobId.of(container, uploadKey))
                .setMetadata(stubMetadata)
                .build();
        storage.create(stubInfo, new byte[0]);

        return new MultipartUpload(container, targetBlobName,
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
        if (stubMetadata.containsKey("s3proxy_storage_class")) {
            targetBuilder.setStorageClass(toGcsStorageClass(
                    StorageClass.valueOf(stubMetadata.get(
                            "s3proxy_storage_class"))));
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
            int partNumber, org.gaul.s3proxy.blobstore.Payload payload) {
        if (partNumber < 1 || partNumber > 10_000) {
            throw new IllegalArgumentException(
                    "Part number must be between 1 and 10,000, got: " +
                    partNumber);
        }

        Long contentLength = payload.getContentMetadata()
                .contentLength();
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
                    .contentMD5();
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
            throw translate(se, mpu.containerName(), mpu.blobName());
        } catch (IOException ioe) {
            throw new RuntimeException((
                    "Failed to upload part %d for blob '%s' in " +
                    "container '%s': %s").formatted(
                    partNumber, mpu.blobName(), mpu.containerName(),
                    ioe.getMessage()), ioe);
        }

        String eTag = BaseEncoding.base16().lowerCase().encode(md5Hash);
        return new MultipartPart(partNumber, contentLength, eTag, null);
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
            // Report the part's hex MD5 as its ETag (matching
            // uploadMultipartPart) so CompleteMultipartUpload can validate the
            // client-supplied part ETags.
            parts.add(new MultipartPart(partNumber, blob.getSize(),
                    blob.getMd5ToHexString(), null));
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
            builder.add(new MultipartUpload(container, targetBlobName,
                    name, null, null));
        }
        return builder.build();
    }

    @Override
    public long getMinimumMultipartPartSize() {
        // GCS minimum part is 5 MB except for last part
        return 5L * 1024 * 1024;
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
        // If the ETag doesn't match, the precondition fails.
        if (!eTag.equals("*") && !maybeQuoteETag(eTag).equals(
                maybeQuoteETag(blob.getEtag()))) {
            throw preconditionFailed(blob.getEtag());
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

    private static com.google.cloud.storage.StorageClass toGcsStorageClass(
            StorageClass storageClass) {
        return switch (storageClass) {
        case GLACIER, DEEP_ARCHIVE ->
            com.google.cloud.storage.StorageClass.ARCHIVE;
        case GLACIER_IR -> com.google.cloud.storage.StorageClass.COLDLINE;
        case STANDARD_IA, ONEZONE_IA ->
            com.google.cloud.storage.StorageClass.NEARLINE;
        default -> com.google.cloud.storage.StorageClass.STANDARD;
        };
    }

    private static StorageClass fromGcsStorageClass(
            com.google.cloud.storage.@Nullable StorageClass storageClass) {
        if (storageClass == null) {
            return StorageClass.STANDARD;
        } else if (storageClass.equals(
                com.google.cloud.storage.StorageClass.ARCHIVE)) {
            return StorageClass.DEEP_ARCHIVE;
        } else if (storageClass.equals(
                com.google.cloud.storage.StorageClass.COLDLINE)) {
            return StorageClass.GLACIER_IR;
        } else if (storageClass.equals(
                com.google.cloud.storage.StorageClass.NEARLINE)) {
            return StorageClass.STANDARD_IA;
        } else {
            return StorageClass.STANDARD;
        }
    }

    private static ContentMetadata toContentMetadata(Blob blob) {
        return ContentMetadata.builder()
                .cacheControl(blob.getCacheControl())
                .contentDisposition(blob.getContentDisposition())
                .contentEncoding(blob.getContentEncoding())
                .contentLanguage(blob.getContentLanguage())
                .contentLength(blob.getSize())
                .contentType(blob.getContentType())
                .build();
    }

    /**
     * Translate StorageException to a jclouds exception, returning the
     * original StorageException unchanged if no translation applies.
     */
    private static RuntimeException translate(StorageException se,
            String container, @Nullable String key) {
        switch (se.getCode()) {
        case 404 -> {
            if (key != null) {
                var keyEx = new KeyNotFoundException(container, key, "");
                keyEx.initCause(se);
                return keyEx;
            } else {
                var containerEx = new ContainerNotFoundException(
                        container, "");
                containerEx.initCause(se);
                return containerEx;
            }
        }
        case 412 -> {
            return httpResponseException(412, se);
        }
        case 401, 403 -> {
            // Surface a permission failure as 403 AccessDenied rather than a
            // generic 500.
            return httpResponseException(403, se);
        }
        default -> { }
        }
        return se;
    }

    // Build a jclouds HttpResponseException carrying a status code so that
    // S3ProxyHandler translates it to the matching S3 error code (e.g.
    // 400 -> BadDigest, 412 -> PreconditionFailed, 416 -> InvalidRange).
    private static HttpResponseException httpResponseException(int statusCode,
            Throwable cause) {
        return new HttpResponseException(new HttpResponse(statusCode), cause);
    }

    // Build a 412 for a failed conditional-GET precondition, echoing the
    // object's ETag so the frontend can emit it on the 304 Not Modified
    // response (required by RFC 7232).
    private static HttpResponseException preconditionFailed(
            @Nullable String eTag) {
        return new HttpResponseException(new HttpResponse(412,
                eTag == null ? null : maybeQuoteETag(eTag)));
    }
}
