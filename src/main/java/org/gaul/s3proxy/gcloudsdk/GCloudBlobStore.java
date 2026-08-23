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

import static java.util.Objects.requireNonNull;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.channels.Channels;
import java.nio.charset.StandardCharsets;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.UUID;

import com.google.api.gax.paging.Page;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.auth.oauth2.ServiceAccountCredentials;
import com.google.cloud.NoCredentials;
import com.google.cloud.ReadChannel;
import com.google.cloud.ServiceOptions;
import com.google.cloud.http.HttpTransportOptions;
import com.google.cloud.storage.Acl;
import com.google.cloud.storage.Blob;
import com.google.cloud.storage.BlobId;
import com.google.cloud.storage.BlobInfo;
import com.google.cloud.storage.Bucket;
import com.google.cloud.storage.BucketInfo;
import com.google.cloud.storage.CopyWriter;
import com.google.cloud.storage.Storage;
import com.google.cloud.storage.Storage.BlobField;
import com.google.cloud.storage.Storage.BlobGetOption;
import com.google.cloud.storage.Storage.BlobListOption;
import com.google.cloud.storage.Storage.BlobSourceOption;
import com.google.cloud.storage.Storage.BlobTargetOption;
import com.google.cloud.storage.Storage.BlobWriteOption;
import com.google.cloud.storage.Storage.BucketField;
import com.google.cloud.storage.Storage.BucketGetOption;
import com.google.cloud.storage.Storage.ComposeRequest;
import com.google.cloud.storage.Storage.CopyRequest;
import com.google.cloud.storage.StorageBatchResult;
import com.google.cloud.storage.StorageException;
import com.google.cloud.storage.StorageOptions;
import com.google.common.base.Supplier;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.Credentials;
import org.gaul.s3proxy.blobstore.MD5;
import org.gaul.s3proxy.blobstore.S3Exceptions;
import org.gaul.s3proxy.blobstore.SdkRequests;
import org.gaul.s3proxy.blobstore.SdkResponses;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.jspecify.annotations.Nullable;

import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.services.s3.model.BucketCannedACL;
import software.amazon.awssdk.services.s3.model.BucketVersioningStatus;
import software.amazon.awssdk.services.s3.model.CommonPrefix;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.CompletedPart;
import software.amazon.awssdk.services.s3.model.CopyObjectRequest;
import software.amazon.awssdk.services.s3.model.CopyObjectResponse;
import software.amazon.awssdk.services.s3.model.CreateBucketRequest;
import software.amazon.awssdk.services.s3.model.CreateBucketResponse;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.Delete;
import software.amazon.awssdk.services.s3.model.DeleteMarkerEntry;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.DeleteObjectResponse;
import software.amazon.awssdk.services.s3.model.DeleteObjectsRequest;
import software.amazon.awssdk.services.s3.model.DeleteObjectsResponse;
import software.amazon.awssdk.services.s3.model.DeletedObject;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.HeadBucketRequest;
import software.amazon.awssdk.services.s3.model.HeadBucketResponse;
import software.amazon.awssdk.services.s3.model.HeadObjectRequest;
import software.amazon.awssdk.services.s3.model.HeadObjectResponse;
import software.amazon.awssdk.services.s3.model.ListBucketsResponse;
import software.amazon.awssdk.services.s3.model.ListObjectVersionsRequest;
import software.amazon.awssdk.services.s3.model.ListObjectVersionsResponse;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Response;
import software.amazon.awssdk.services.s3.model.MetadataDirective;
import software.amazon.awssdk.services.s3.model.ObjectCannedACL;
import software.amazon.awssdk.services.s3.model.ObjectIdentifier;
import software.amazon.awssdk.services.s3.model.ObjectVersion;
import software.amazon.awssdk.services.s3.model.Part;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.awssdk.services.s3.model.S3Error;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.services.s3.model.S3Object;
import software.amazon.awssdk.services.s3.model.StorageClass;
import software.amazon.awssdk.services.s3.model.UploadPartCopyRequest;
import software.amazon.awssdk.services.s3.model.UploadPartCopyResponse;
import software.amazon.awssdk.services.s3.model.UploadPartRequest;
import software.amazon.awssdk.services.s3.model.UploadPartResponse;

public final class GCloudBlobStore implements BlobStore {
    private static final String STUB_BLOB_PREFIX = ".s3proxy/stubs/";
    private static final String TARGET_BLOB_NAME_KEY =
            "s3proxy_target_blob_name";
    private static final String BLOB_ACCESS_KEY = "s3proxy_blob_access";
    // GCS has no delete markers: a versioned delete archives the live
    // generation and a later read is a plain 404.  S3's marker is emulated
    // as a zero-byte generation wearing this metadata, hidden from
    // unversioned listings and reads.
    private static final String DELETE_MARKER_KEY = "s3proxy_delete_marker";
    // S3's version an object holds where versioning never applied.  GCS
    // assigns real generations from the first write, so only an unversioned
    // container resolves it, as the live object.
    private static final String NULL_VERSION_ID = "null";
    // GCS deprecated md5Match in favor of crc32cMatch but the client
    // supplies a Content-MD5 to validate, not a CRC32C.
    @SuppressWarnings("deprecation")
    private static final BlobWriteOption MD5_MATCH =
            BlobWriteOption.md5Match();
    // GCS compose supports up to 32 source objects
    private static final int MAX_COMPOSE_PARTS = 32;
    /** How many deletes GCS accepts in one batch request. */
    private static final int MAX_BATCH_DELETES = 100;
    // The chunk an upload buffers, which the SDK defaults to 15 MiB and
    // allocates twice: once as the ByteBuffer it reads the payload into and
    // again as the write channel's own array.
    private static final int MAX_UPLOAD_CHUNK_SIZE = 15 * 1024 * 1024;
    // The unit GCS accepts a resumable chunk in, and the SDK's rounding unit.
    private static final int UPLOAD_CHUNK_UNIT = 256 * 1024;

    private final Storage storage;
    private final boolean atomicBucketAcl;
    /**
     * Whether a container versions objects, which decides if writes report
     * version ids and deletes leave markers.  S3 asks this on every
     * operation while GCS answers only through bucket metadata, so the
     * answer is cached briefly; setContainerVersioning through this store
     * updates it immediately, and a change made behind its back is seen
     * within the expiry.
     */
    private final Cache<String, Boolean> versionedContainers =
            CacheBuilder.newBuilder()
                    .expireAfterWrite(java.time.Duration.ofSeconds(5))
                    .maximumSize(1000)
                    .build();

    public GCloudBlobStore(
            Supplier<Credentials> creds,
            String endpointUrl) {
        var cred = creds.get();
        var storageBuilder = StorageOptions.newBuilder();
        // Fail rather than hanging forever on a stale connection.
        storageBuilder.setTransportOptions(HttpTransportOptions.newBuilder()
                .setConnectTimeout(60 * 1000)
                .setReadTimeout(60 * 1000)
                .build());
        // Disable SDK retries so failures surface to the S3 client on the
        // first request, which retries the whole operation instead.  Mirrors
        // the no-retry AwsS3SdkBlobStore and AzureBlobStore clients.
        storageBuilder.setRetrySettings(ServiceOptions.getNoRetrySettings());
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
        boolean customEndpoint = endpoint != null && !endpoint.isEmpty() &&
                !endpoint.equals("https://storage.googleapis.com");
        if (customEndpoint) {
            storageBuilder.setHost(endpoint);
        }
        // Only Google's own service is known to apply a predefined ACL named
        // on buckets.insert; fake-gcs-server accepts the parameter and drops
        // it, leaving a private bucket.  Anything but the real endpoint
        // therefore sets the ACL in a second request.  Keyed on the endpoint
        // rather than on it being local because an emulator is often reached
        // by container hostname rather than at localhost.
        // TODO: create every bucket atomically after
        // https://github.com/fsouza/fake-gcs-server/pull/2309 is released
        atomicBucketAcl = !customEndpoint;
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
    public ListBucketsResponse list() {
        var buckets = ImmutableList.<software.amazon.awssdk.services.s3.model.Bucket>builder();
        for (Bucket bucket : storage.list().iterateAll()) {
            buckets.add(SdkResponses.bucket(bucket.getName(),
                    toInstant(bucket.getCreateTimeOffsetDateTime())));
        }
        return ListBucketsResponse.builder()
                .buckets(buckets.build())
                .build();
    }

    @Override
    public ListObjectsV2Response list(ListObjectsV2Request request) {
        String container = request.bucket();
        String marker0 = request.continuationToken() != null ?
                request.continuationToken() : request.startAfter();
        var gcsOptions = new java.util.ArrayList<BlobListOption>();
        if (request.prefix() != null) {
            gcsOptions.add(BlobListOption.prefix(request.prefix()));
        }
        if (request.maxKeys() != null) {
            gcsOptions.add(BlobListOption.pageSize(
                    request.maxKeys()));
        }
        String marker = marker0;
        if (marker != null) {
            // Begin the server-side scan at the marker rather than paging from
            // the start of the bucket, which would make listing a bucket of N
            // objects cost O(N^2).  GCS startOffset is inclusive while the S3
            // marker is exclusive, so the loop below still skips the single
            // entry equal to the marker; results are otherwise identical.
            gcsOptions.add(BlobListOption.startOffset(marker));
        }
        if (request.delimiter() != null) {
            gcsOptions.add(BlobListOption.delimiter(request.delimiter()));
        }

        com.google.api.gax.paging.Page<Blob> page;
        try {
            page = storage.list(container,
                    gcsOptions.toArray(new BlobListOption[0]));
        } catch (StorageException se) {
            throw translate(se, container, null);
        }

        var contents = ImmutableList.<S3Object>builder();
        var prefixes = ImmutableList.<CommonPrefix>builder();
        Integer maxResults = request.maxKeys();
        int count = 0;
        boolean hasMore = false;
        String lastName = null;
        for (Blob blob : page.iterateAll()) {
            // Skip blobs at or before the marker (S3 marker is exclusive)
            if (marker != null && blob.getName().compareTo(marker) <= 0) {
                continue;
            }
            // A key whose current version is a delete marker holds nothing
            // an unversioned listing shows.
            if (!blob.isDirectory() && isDeleteMarker(blob)) {
                continue;
            }
            if (maxResults != null && count >= maxResults) {
                hasMore = true;
                break;
            }
            if (blob.isDirectory()) {
                prefixes.add(SdkResponses.commonPrefix(blob.getName()));
            } else {
                contents.add(SdkResponses.objectEntry(blob.getName(),
                        blob.getEtag(),
                        toInstant(blob.getUpdateTimeOffsetDateTime()),
                        blob.getSize(),
                        fromGcsStorageClass(blob.getStorageClass())));
            }
            lastName = blob.getName();
            count++;
        }

        // Synthesize a next marker if we truncated results
        String nextMarker = hasMore ? lastName : null;
        return SdkResponses.objectsPage(contents.build(), prefixes.build(),
                nextMarker);
    }

    @Override
    public HeadBucketResponse headBucket(HeadBucketRequest request) {
        if (storage.get(request.bucket(),
                BucketGetOption.fields(BucketField.NAME)) == null) {
            throw S3Exceptions.noSuchBucket(request.bucket(), "");
        }
        return HeadBucketResponse.builder().build();
    }

    @Override
    public CreateBucketResponse createContainer(CreateBucketRequest request) {
        String container = request.bucket();
        boolean publicRead = request.acl() == BucketCannedACL.PUBLIC_READ;
        boolean publicReadWrite =
                request.acl() == BucketCannedACL.PUBLIC_READ_WRITE;
        try {
            var bucketInfo = BucketInfo.newBuilder(container).build();
            if ((publicRead || publicReadWrite) && atomicBucketAcl) {
                storage.create(bucketInfo, Storage.BucketTargetOption
                        .predefinedAcl(publicReadWrite ?
                                Storage.PredefinedAcl.PUBLIC_READ_WRITE :
                                Storage.PredefinedAcl.PUBLIC_READ));
            } else {
                storage.create(bucketInfo);
                if (publicRead || publicReadWrite) {
                    storage.createAcl(container,
                            Acl.of(Acl.User.ofAllUsers(), publicReadWrite ?
                                    Acl.Role.WRITER : Acl.Role.READER));
                }
            }
            return CreateBucketResponse.builder().build();
        } catch (StorageException se) {
            if (se.getCode() == 409) {
                throw S3Exceptions.bucketAlreadyOwnedByYou(container);
            }
            throw se;
        }
    }

    /**
     * Deletes the container and everything it holds, archived generations
     * and delete markers included.  The interface default empties it with
     * plain deletes, which a versioning-enabled bucket answers by
     * archiving -- and, for the markers {@link #removeBlob} lays down, by
     * adding live objects -- so it fills the bucket it means to drain and
     * the bucket delete never happens.
     */
    @Override
    public void deleteContainer(String container) {
        try {
            deleteGenerations(storage.list(container,
                    BlobListOption.versions(true)));
            storage.delete(container);
        } catch (StorageException se) {
            if (se.getCode() == 404) {
                // The container is already gone; deleteContainer is
                // idempotent.
                return;
            }
            throw translate(se, container, /*key=*/ null);
        }
    }

    /**
     * Deletes each listed blob by the generation its blobId carries,
     * removing that version outright where a nameless delete would
     * archive it.
     */
    private void deleteGenerations(Page<Blob> page) {
        for (Blob blob : page.iterateAll()) {
            try {
                storage.delete(blob.getBlobId());
            } catch (StorageException se) {
                if (se.getCode() != 404) {
                    throw se;
                }
            }
        }
    }

    @Override
    public void deleteBucket(String container) {
        var page = storage.list(container,
                BlobListOption.pageSize(1));
        if (page.getValues().iterator().hasNext()) {
            throw S3Exceptions.bucketNotEmpty(container);
        }
        try {
            storage.delete(container);
        } catch (StorageException se) {
            if (se.getCode() == 409) {
                // Noncurrent generations keep a bucket alive even when no
                // live object answers the listing above.
                throw S3Exceptions.bucketNotEmpty(container);
            }
            if (se.getCode() != 404) {
                throw se;
            }
        }
    }

    @Override
    public boolean blobExists(String container, String key) {
        Blob blob = storage.get(BlobId.of(container, key),
                BlobGetOption.fields(BlobField.NAME, BlobField.METADATA));
        return blob != null && !isDeleteMarker(blob);
    }

    @Override
    public boolean supportsVersioning() {
        return true;
    }

    @Override
    @Nullable
    public BucketVersioningStatus getContainerVersioning(String container) {
        Bucket bucket;
        try {
            bucket = storage.get(container,
                    BucketGetOption.fields(BucketField.VERSIONING));
        } catch (StorageException se) {
            throw translate(se, container, /*key=*/ null);
        }
        if (bucket == null) {
            throw S3Exceptions.noSuchBucket(container, "");
        }
        boolean enabled = Boolean.TRUE.equals(bucket.versioningEnabled());
        versionedContainers.put(container, enabled);
        // GCS versioning is on or off with no marking of ever having been
        // on, so off answers as never versioned rather than Suspended.
        return enabled ? BucketVersioningStatus.ENABLED : null;
    }

    @Override
    public void setContainerVersioning(String container,
            BucketVersioningStatus status) {
        if (status != BucketVersioningStatus.ENABLED) {
            // Turning GCS versioning off keeps the noncurrent generations,
            // but S3's Suspended also replaces a "null" version on every
            // write and reports no version ids, which GCS cannot express.
            throw new UnsupportedOperationException(
                    "suspended versioning not supported");
        }
        try {
            storage.update(BucketInfo.newBuilder(container)
                    .setVersioningEnabled(true)
                    .build());
        } catch (StorageException se) {
            throw translate(se, container, /*key=*/ null);
        }
        versionedContainers.put(container, true);
    }

    /** Whether writes to the container version rather than replace. */
    private boolean isVersioned(String container) {
        Boolean cached = versionedContainers.getIfPresent(container);
        if (cached != null) {
            return cached;
        }
        Bucket bucket;
        try {
            bucket = storage.get(container,
                    BucketGetOption.fields(BucketField.VERSIONING));
        } catch (StorageException se) {
            throw translate(se, container, /*key=*/ null);
        }
        boolean enabled = bucket != null &&
                Boolean.TRUE.equals(bucket.versioningEnabled());
        versionedContainers.put(container, enabled);
        return enabled;
    }

    private static boolean isDeleteMarker(BlobInfo blob) {
        var metadata = blob.getMetadata();
        return metadata != null &&
                "true".equals(metadata.get(DELETE_MARKER_KEY));
    }

    /**
     * The generation a version id names.  S3 version ids on this store are
     * the decimal GCS generations, which are always positive.
     */
    private static long parseVersionId(String versionId) {
        try {
            long generation = Long.parseLong(versionId);
            if (generation > 0) {
                return generation;
            }
        } catch (NumberFormatException nfe) {
            // fall through
        }
        throw S3Exceptions.invalidArgument("Invalid version id specified");
    }

    /**
     * The version a read names: the live object when {@code versionId} is
     * null -- or the newest remaining generation when the live one was
     * deleted by id, which is S3's promotion -- and otherwise the
     * generation named.  Returns null when the key holds nothing to read.
     * Throws the way S3 answers a read whose current version is a delete
     * marker (404 naming the marker), one that names a marker outright
     * (405), and one that names a version that does not exist.
     */
    @Nullable
    private Blob resolveVersion(String container, String key,
            @Nullable String versionId) {
        if (versionId == null || (versionId.equals(NULL_VERSION_ID) &&
                !isVersioned(container))) {
            Blob live;
            try {
                live = storage.get(BlobId.of(container, key));
            } catch (StorageException se) {
                throw translate(se, container, key);
            }
            if (live != null) {
                if (isDeleteMarker(live)) {
                    throw S3Exceptions.noSuchKeyDeleteMarker(container, key,
                            Long.toString(live.getGeneration()),
                            "current version is a delete marker");
                }
                return live;
            }
            // The SDK collapses a missing bucket and a missing object both
            // to null; distinguish them so the frontend emits NoSuchBucket
            // vs NoSuchKey.
            if (storage.get(container) == null) {
                throw S3Exceptions.noSuchBucket(container, "");
            }
            if (versionId == null && isVersioned(container)) {
                Blob newest = newestGeneration(container, key);
                if (newest != null) {
                    if (isDeleteMarker(newest)) {
                        throw S3Exceptions.noSuchKeyDeleteMarker(container,
                                key, Long.toString(newest.getGeneration()),
                                "current version is a delete marker");
                    }
                    return newest;
                }
            }
            return null;
        }
        if (versionId.equals(NULL_VERSION_ID)) {
            throw S3Exceptions.noSuchVersion(container, key, versionId,
                    "no such version");
        }
        long generation = parseVersionId(versionId);
        Blob blob;
        try {
            blob = storage.get(BlobId.of(container, key, generation));
        } catch (StorageException se) {
            throw translate(se, container, key);
        }
        if (blob == null) {
            if (storage.get(container) == null) {
                throw S3Exceptions.noSuchBucket(container, "");
            }
            throw S3Exceptions.noSuchVersion(container, key, versionId,
                    "no such version");
        }
        if (isDeleteMarker(blob)) {
            // As on S3: a delete marker has no content to read, and saying
            // so is not the same as saying the key is gone.
            throw S3Exceptions.fromStatusCode(405, /*eTag=*/ null,
                    Map.of("x-amz-delete-marker", "true",
                            "x-amz-version-id", versionId),
                    /*cause=*/ null);
        }
        return blob;
    }

    /**
     * The newest generation of one key, archived generations included, or
     * null when the key holds none.  The scan is bounded to the key itself:
     * the offsets stop it at the shortest name after {@code key}, so
     * sibling keys sharing the prefix are never pulled.
     */
    @Nullable
    private Blob newestGeneration(String container, String key) {
        com.google.api.gax.paging.Page<Blob> page;
        try {
            page = storage.list(container,
                    BlobListOption.prefix(key),
                    BlobListOption.versions(true),
                    BlobListOption.startOffset(key),
                    BlobListOption.endOffset(key + '\0'));
        } catch (StorageException se) {
            throw translate(se, container, key);
        }
        Blob newest = null;
        for (Blob blob : page.iterateAll()) {
            if (!blob.getName().equals(key)) {
                continue;
            }
            if (newest == null ||
                    blob.getGeneration() > newest.getGeneration()) {
                newest = blob;
            }
        }
        return newest;
    }

    /**
     * The version id a read or write reports: the generation on a
     * versioned container or whenever the caller named a version, and
     * nothing otherwise -- S3 sends no x-amz-version-id header for a
     * container that has never been versioned.
     */
    @Nullable
    private String reportedVersionId(String container, BlobInfo blob,
            @Nullable String requestVersionId) {
        if (NULL_VERSION_ID.equals(requestVersionId)) {
            // The null version resolved on an unversioned container, whose
            // reads report no version id.
            return null;
        }
        if (requestVersionId != null || isVersioned(container)) {
            return Long.toString(blob.getGeneration());
        }
        return null;
    }

    @Override
    public ListObjectVersionsResponse listVersions(
            ListObjectVersionsRequest request) {
        String container = request.bucket();
        String delimiter = request.delimiter();
        String keyMarker = request.keyMarker();
        int maxKeys = request.maxKeys() == null ? 1000 : request.maxKeys();

        var gcsOptions = new ArrayList<BlobListOption>();
        gcsOptions.add(BlobListOption.versions(true));
        if (request.prefix() != null) {
            gcsOptions.add(BlobListOption.prefix(request.prefix()));
        }
        if (delimiter != null) {
            gcsOptions.add(BlobListOption.delimiter(delimiter));
        }
        if (keyMarker != null) {
            // Begin the server-side scan at the marker rather than at the
            // start of the bucket.  startOffset is inclusive, which the
            // slice below wants: resuming within a key needs that key's own
            // rows.
            gcsOptions.add(BlobListOption.startOffset(keyMarker));
        }

        com.google.api.gax.paging.Page<Blob> page;
        try {
            page = storage.list(container,
                    gcsOptions.toArray(new BlobListOption[0]));
        } catch (StorageException se) {
            throw translate(se, container, /*key=*/ null);
        }

        // Flatten every generation into S3's order -- keys ascending,
        // newest first -- and slice one page out of it.  GCS orders the
        // listing by name but says nothing about the versions within one,
        // so the sort does not lean on it.
        var rows = new ArrayList<VersionRow>();
        var commonPrefixes = new TreeSet<String>();
        for (Blob blob : page.iterateAll()) {
            if (blob.isDirectory()) {
                commonPrefixes.add(blob.getName());
                continue;
            }
            rows.add(new VersionRow(blob.getName(), blob.getGeneration(),
                    isDeleteMarker(blob), blob.getEtag(),
                    toInstant(blob.getUpdateTimeOffsetDateTime()),
                    blob.getSize(),
                    fromGcsStorageClass(blob.getStorageClass())));
        }
        rows.sort(Comparator.comparing(VersionRow::key)
                .thenComparing(Comparator
                        .comparingLong(VersionRow::generation).reversed()));

        int start = 0;
        if (keyMarker != null) {
            String versionIdMarker = request.versionIdMarker();
            for (int i = 0; i < rows.size(); i++) {
                var candidate = rows.get(i);
                if (versionIdMarker == null) {
                    if (candidate.key().compareTo(keyMarker) > 0) {
                        start = i;
                        break;
                    }
                } else if (candidate.key().equals(keyMarker) &&
                        candidate.versionId().equals(versionIdMarker)) {
                    start = i + 1;
                    break;
                }
                start = i + 1;
            }
        }
        int end = Math.min(rows.size(), start + maxKeys);
        var pageRows = rows.subList(start, end);
        String nextKeyMarker = null;
        String nextVersionIdMarker = null;
        if (end < rows.size() && !pageRows.isEmpty()) {
            var last = pageRows.get(pageRows.size() - 1);
            nextKeyMarker = last.key();
            nextVersionIdMarker = last.versionId();
        }

        var versions = new ArrayList<ObjectVersion>();
        var markers = new ArrayList<DeleteMarkerEntry>();
        for (int i = start; i < end; i++) {
            var row = rows.get(i);
            // The newest generation of a key is its latest, marker or not;
            // the row before it in the flattened order belongs to another
            // key exactly then.
            boolean latest = i == 0 ||
                    !rows.get(i - 1).key().equals(row.key());
            if (row.deleteMarker()) {
                markers.add(DeleteMarkerEntry.builder()
                        .key(row.key())
                        .versionId(row.versionId())
                        .isLatest(latest)
                        .lastModified(row.lastModified())
                        .build());
            } else {
                versions.add(ObjectVersion.builder()
                        .key(row.key())
                        .versionId(row.versionId())
                        .isLatest(latest)
                        .eTag(row.eTag())
                        .lastModified(row.lastModified())
                        .size(row.size())
                        .storageClass(row.storageClass().toString())
                        .build());
            }
        }
        return ListObjectVersionsResponse.builder()
                .versions(versions)
                .deleteMarkers(markers)
                .commonPrefixes(commonPrefixes.stream()
                        .map(SdkResponses::commonPrefix)
                        .toList())
                .nextKeyMarker(nextKeyMarker)
                .nextVersionIdMarker(nextVersionIdMarker)
                .isTruncated(nextKeyMarker != null)
                .build();
    }

    /** One row of the flattened versions listing. */
    private record VersionRow(String key, long generation,
            boolean deleteMarker, @Nullable String eTag,
            @Nullable Instant lastModified, @Nullable Long size,
            StorageClass storageClass) {
        String versionId() {
            return Long.toString(generation);
        }
    }

    @Override
    public ResponseInputStream<GetObjectResponse> getBlob(
            GetObjectRequest request) {
        String container = request.bucket();
        String key = request.key();
        Blob gcsBlob = resolveVersion(container, key, request.versionId());
        if (gcsBlob == null) {
            throw S3Exceptions.noSuchKey(container, key, "no such object");
        }

        // Enforce conditional-GET preconditions before streaming.  The
        // backends report every conditional-header failure as 412; the
        // frontend (S3ProxyHandlerJetty) remaps GET/HEAD If-None-Match and
        // If-Modified-Since misses to 304 Not Modified.
        String eTag = gcsBlob.getEtag();
        Instant lastModified = toInstant(gcsBlob.getUpdateTimeOffsetDateTime());
        enforceConditionalGet(request, eTag, lastModified);

        long blobSize = gcsBlob.getSize();
        Long rangeOffset = null;
        Long rangeEnd = null;
        var range = SdkRequests.parseRange(request.range());
        if (range != null) {
            if (range.first() == null) {
                // trailing range: last N bytes
                rangeOffset = Math.max(0,
                        blobSize - requireNonNull(range.last()));
                rangeEnd = blobSize - 1;
            } else if (range.last() == null) {
                rangeOffset = range.first();
            } else {
                rangeOffset = range.first();
                rangeEnd = range.last();
            }
            // A range starting at or past the end of the object is
            // unsatisfiable; S3 returns 416 InvalidRange.  Without this GCS
            // reads zero bytes and the declared Content-Length desyncs.
            if (rangeOffset >= blobSize) {
                throw S3Exceptions.fromStatusCode(416);
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

        var builder = GetObjectResponse.builder()
                .metadata(sanitizeUserMetadata(gcsBlob.getMetadata()))
                .cacheControl(gcsBlob.getCacheControl())
                .contentDisposition(gcsBlob.getContentDisposition())
                .contentEncoding(gcsBlob.getContentEncoding())
                .contentLanguage(gcsBlob.getContentLanguage())
                .contentLength(contentLength)
                .contentType(gcsBlob.getContentType())
                .eTag(gcsBlob.getEtag())
                .storageClass(
                        fromGcsStorageClass(gcsBlob.getStorageClass())
                                .toString())
                .versionId(reportedVersionId(container, gcsBlob,
                        request.versionId()))
                .lastModified(toInstant(
                        gcsBlob.getUpdateTimeOffsetDateTime()));
        if (rangeOffset != null) {
            long end = rangeEnd != null ? rangeEnd :
                    blobSize - 1;
            builder.contentRange(
                    "bytes " + rangeOffset + "-" + end + "/" + blobSize);
        }
        return SdkResponses.getResponse(builder.build(), is);
    }

    // Enforce S3 conditional-GET headers (If-Match / If-None-Match /
    // If-Modified-Since / If-Unmodified-Since).  GCS uses generation
    // preconditions rather than ETag/time matching, so evaluate them here
    // against the object's metadata.  Every failure is reported as 412;
    // S3ProxyHandlerJetty maps GET/HEAD If-None-Match and If-Modified-Since
    // misses to 304 Not Modified.
    private static void enforceConditionalGet(GetObjectRequest request,
            @Nullable String eTag, @Nullable Instant lastModified) {
        String ifMatch = request.ifMatch();
        String ifNoneMatch = request.ifNoneMatch();
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
            Instant modified = truncateToSecond(lastModified);
            Instant ifModifiedSince = request.ifModifiedSince();
            if (ifModifiedSince != null &&
                    modified.compareTo(ifModifiedSince) <= 0) {
                throw preconditionFailed(eTag);
            }
            Instant ifUnmodifiedSince = request.ifUnmodifiedSince();
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
    private static Instant truncateToSecond(Instant instant) {
        return instant.truncatedTo(ChronoUnit.SECONDS);
    }

    private static String maybeQuoteETag(String eTag) {
        if (!eTag.startsWith("\"") && !eTag.endsWith("\"")) {
            eTag = "\"" + eTag + "\"";
        }
        return eTag;
    }

    /**
     * Chunks an upload to the payload it carries.  The SDK otherwise buffers
     * its 15 MiB default whatever the object weighs, so a one byte write costs
     * 30 MiB of allocation, and a server admitting many concurrent writes
     * holds that per write.  The chunk exceeds the payload rather than
     * matching it: the write channel flushes a chunk the moment it fills, so
     * an exact fit would send the payload and then a second request to
     * finalize it.  Uploads at or above the default keep it and so still cost
     * the requests they cost before.
     */
    private static int uploadChunkSize(@Nullable Long contentLength) {
        if (contentLength == null || contentLength >= MAX_UPLOAD_CHUNK_SIZE) {
            return MAX_UPLOAD_CHUNK_SIZE;
        }
        long units = contentLength / UPLOAD_CHUNK_UNIT + 1;
        return (int) Math.min(MAX_UPLOAD_CHUNK_SIZE,
                units * UPLOAD_CHUNK_UNIT);
    }

    @Override
    public PutObjectResponse putBlob(PutObjectRequest request,
            InputStream payload) {
        String container = request.bucket();
        String name = request.key();
        var blobInfo = BlobInfo.newBuilder(BlobId.of(container, name));
        blobInfo.setContentType(request.contentType());
        blobInfo.setContentDisposition(request.contentDisposition());
        blobInfo.setContentEncoding(request.contentEncoding());
        blobInfo.setContentLanguage(request.contentLanguage());
        blobInfo.setCacheControl(request.cacheControl());
        var hash = request.contentMD5();
        if (hash != null) {
            blobInfo.setMd5(hash);
        }
        if (request.hasMetadata()) {
            blobInfo.setMetadata(request.metadata());
        }
        if (request.storageClass() != null &&
                request.storageClass() != StorageClass.STANDARD) {
            blobInfo.setStorageClass(
                    toGcsStorageClass(request.storageClass()));
        }

        var writeOptions = new java.util.ArrayList<BlobWriteOption>();
        if (hash != null) {
            // The Java SDK strips blobInfo's md5 from resumable upload
            // metadata unless md5Match is requested, so without this GCS
            // never validates the client-supplied Content-MD5.  md5Match
            // re-sends the md5 and requests server-side validation.
            writeOptions.add(MD5_MATCH);
        }
        String ifMatch = request.ifMatch();
        String ifNoneMatch = request.ifNoneMatch();
        if (ifMatch != null) {
            if (ifMatch.equals("*")) {
                // If-Match: * — overwrite only an existing object.  Pin
                // the write to its current generation so a concurrent
                // delete fails the precondition instead of recreating it.
                Blob existing = storage.get(BlobId.of(container, name));
                if (existing == null || isDeleteMarker(existing)) {
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
                Blob existing = storage.get(BlobId.of(container, name));
                if (existing != null && isDeleteMarker(existing)) {
                    // A delete marker counts as no current object, so the
                    // write proceeds -- atomically, by requiring the marker
                    // to still be what it replaces.
                    writeOptions.add(BlobWriteOption.generationMatch(
                            existing.getGeneration()));
                } else {
                    writeOptions.add(BlobWriteOption.doesNotExist());
                }
            } else {
                // If-None-Match: <etag> — fail if an object with that ETag
                // currently exists.  GCS has no etag precondition, but
                // pinning generationNotMatch to the matching object's
                // generation makes the rejection atomic: if it is still
                // that version the write fails, and if it has since changed
                // or been deleted the write proceeds.
                Blob existing = storage.get(BlobId.of(container, name));
                if (existing != null && !isDeleteMarker(existing) &&
                        maybeQuoteETag(ifNoneMatch).equals(
                                maybeQuoteETag(existing.getEtag()))) {
                    writeOptions.add(BlobWriteOption.generationNotMatch(
                            existing.getGeneration()));
                }
            }
        }
        if (request.acl() == ObjectCannedACL.PUBLIC_READ) {
            writeOptions.add(BlobWriteOption.predefinedAcl(
                    Storage.PredefinedAcl.PUBLIC_READ));
        }

        try (var is = payload) {
            Blob gcsBlob = storage.createFrom(blobInfo.build(), is,
                    uploadChunkSize(request.contentLength()),
                    writeOptions.toArray(new BlobWriteOption[0]));
            return SdkResponses.putResponse(gcsBlob.getEtag(),
                    isVersioned(container) ?
                            Long.toString(gcsBlob.getGeneration()) : null);
        } catch (StorageException se) {
            // GCS has no dedicated error code for a checksum mismatch: it
            // reports the md5Match validation we requested as a generic 400
            // "invalid".  Only surface BadDigest when we actually asked GCS to
            // validate the checksum; other 400s are unrelated client errors.
            if (se.getCode() == 400 && hash != null) {
                throw S3Exceptions.fromStatusCode(400, se);
            }
            throw translate(se, container, null);
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }

    @Override
    public CopyObjectResponse copyBlob(CopyObjectRequest request) {
        String fromContainer = request.sourceBucket();
        String fromName = request.sourceKey();
        Blob sourceBlob = resolveVersion(fromContainer, fromName,
                request.sourceVersionId());
        if (sourceBlob == null) {
            throw S3Exceptions.noSuchKey(fromContainer, fromName,
                    "while copying");
        }
        // The copy reads the generation the resolution named rather than
        // whatever is live by the time it runs, which also lets it read a
        // noncurrent version -- restoring one is a copy of it onto its key.
        var source = sourceBlob.getBlobId();
        var targetBuilder = BlobInfo.newBuilder(BlobId.of(
                request.destinationBucket(), request.destinationKey()));

        if (request.metadataDirective() == MetadataDirective.REPLACE) {
            if (request.cacheControl() != null) {
                targetBuilder.setCacheControl(request.cacheControl());
            }
            if (request.contentDisposition() != null) {
                targetBuilder.setContentDisposition(
                        request.contentDisposition());
            }
            if (request.contentEncoding() != null) {
                targetBuilder.setContentEncoding(request.contentEncoding());
            }
            if (request.contentLanguage() != null) {
                targetBuilder.setContentLanguage(request.contentLanguage());
            }
            if (request.contentType() != null) {
                targetBuilder.setContentType(request.contentType());
            }
            targetBuilder.setMetadata(request.metadata());
        }

        String ifMatch = request.copySourceIfMatch();
        String ifNoneMatch = request.copySourceIfNoneMatch();
        Instant ifModifiedSince = request.copySourceIfModifiedSince();
        Instant ifUnmodifiedSince = request.copySourceIfUnmodifiedSince();
        List<BlobSourceOption> sourceOptions = List.of();
        if (ifMatch != null || ifNoneMatch != null ||
                ifModifiedSince != null || ifUnmodifiedSince != null) {
            sourceOptions = checkCopySourceConditions(sourceBlob,
                    ifMatch, ifNoneMatch, ifModifiedSince, ifUnmodifiedSince);
        }

        var targetOptions = new java.util.ArrayList<BlobTargetOption>();
        if (request.acl() == ObjectCannedACL.PUBLIC_READ) {
            targetOptions.add(BlobTargetOption.predefinedAcl(
                    Storage.PredefinedAcl.PUBLIC_READ));
        }

        try {
            var copyRequest = CopyRequest.newBuilder()
                    .setSource(source)
                    .setSourceOptions(sourceOptions)
                    .setTarget(targetBuilder.build(), targetOptions)
                    .build();
            var result = storage.copy(copyRequest).getResult();
            return SdkResponses.copyResponse(result.getEtag(),
                    isVersioned(request.destinationBucket()) ?
                            Long.toString(result.getGeneration()) : null,
                    reportedVersionId(fromContainer, sourceBlob,
                            request.sourceVersionId()));
        } catch (StorageException se) {
            throw translate(se, fromContainer, fromName);
        }
    }

    /**
     * Emulates the x-amz-copy-source-if-* conditions against the source
     * object's current metadata since GCS has no native ETag or time
     * copy-source preconditions.  For If-Match the returned options pin the
     * copy to the verified generation so a concurrent change to the source
     * fails the copy rather than silently copying a different version.
     */
    private static List<BlobSourceOption> checkCopySourceConditions(
            @Nullable Blob sourceBlob, @Nullable String ifMatch,
            @Nullable String ifNoneMatch, @Nullable Instant ifModifiedSince,
            @Nullable Instant ifUnmodifiedSince) {
        var sourceOptions = new java.util.ArrayList<BlobSourceOption>();
        if (sourceBlob == null) {
            return sourceOptions;
        }
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
        Instant lastModified = toInstant(
                sourceBlob.getUpdateTimeOffsetDateTime());
        if (lastModified != null) {
            Instant modified = truncateToSecond(lastModified);
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
        return sourceOptions;
    }

    @Override
    public DeleteObjectResponse removeBlob(DeleteObjectRequest request) {
        if (request.ifMatch() != null || request.ifMatchSize() != null ||
                request.ifMatchLastModifiedTime() != null) {
            throw new UnsupportedOperationException(
                    "conditional delete not supported");
        }
        String container = request.bucket();
        String key = request.key();
        String versionId = request.versionId();
        if (versionId == null) {
            if (!isVersioned(container)) {
                try {
                    storage.delete(BlobId.of(container, key));
                } catch (StorageException se) {
                    if (se.getCode() != 404) {
                        throw translate(se, container, key);
                    }
                }
                return DeleteObjectResponse.builder().build();
            }
            // Versioned: the generations stay and a marker goes on top of
            // them, archiving the live object the way any write does.  S3
            // leaves a marker even over a key that holds nothing.
            var markerInfo = BlobInfo.newBuilder(BlobId.of(container, key))
                    .setMetadata(Map.of(DELETE_MARKER_KEY, "true"))
                    .build();
            Blob marker;
            try {
                marker = storage.create(markerInfo, new byte[0]);
            } catch (StorageException se) {
                throw translate(se, container, /*key=*/ null);
            }
            return DeleteObjectResponse.builder()
                    .versionId(Long.toString(marker.getGeneration()))
                    .deleteMarker(true)
                    .build();
        }
        if (versionId.equals(NULL_VERSION_ID)) {
            if (!isVersioned(container)) {
                // The null version names the live object on a container
                // that was never versioned.
                try {
                    storage.delete(BlobId.of(container, key));
                } catch (StorageException se) {
                    if (se.getCode() != 404) {
                        throw translate(se, container, key);
                    }
                }
                return DeleteObjectResponse.builder().build();
            }
            throw S3Exceptions.noSuchVersion(container, key, versionId,
                    "no such version");
        }
        // Deleting the one version named removes data, live or archived,
        // with no marker; removing the newest promotes whatever it hid.
        long generation = parseVersionId(versionId);
        Blob blob;
        try {
            blob = storage.get(BlobId.of(container, key, generation));
        } catch (StorageException se) {
            throw translate(se, container, key);
        }
        if (blob == null) {
            if (storage.get(container) == null) {
                throw S3Exceptions.noSuchBucket(container, "");
            }
            throw S3Exceptions.noSuchVersion(container, key, versionId,
                    "no such version");
        }
        boolean deleteMarker = isDeleteMarker(blob);
        try {
            // The blobId carries the generation, so this removes exactly
            // the version read above; one deleted meanwhile counts as
            // deleted, the way S3 answers.
            storage.delete(blob.getBlobId());
        } catch (StorageException se) {
            if (se.getCode() != 404) {
                throw translate(se, container, key);
            }
        }
        return DeleteObjectResponse.builder()
                .versionId(versionId)
                .deleteMarker(deleteMarker ? true : null)
                .build();
    }

    /**
     * Deletes the objects a batch at a time, which GCS answers in one
     * request each -- where the interface default would spend a request per
     * object.
     *
     * <p>A batch that any object refused is asked again one object at a
     * time: the batch raises a GCS exception, while the single delete raises
     * the typed failure the frontend turns into that object's error code.
     * Refusals are rare, so the second pass is too.
     */
    @Override
    public DeleteObjectsResponse removeBlobs(DeleteObjectsRequest request) {
        var objects = request.delete() == null ? List.<ObjectIdentifier>of() :
                request.delete().objects();
        if (objects.isEmpty()) {
            return DeleteObjectsResponse.builder().build();
        }
        String container = request.bucket();
        if (isVersioned(container) ||
                objects.stream().anyMatch(o -> o.versionId() != null)) {
            // Versioned deletes each carry their own semantics -- a marker
            // to write and report, or one generation to remove outright --
            // which the batch cannot express.
            return BlobStore.super.removeBlobs(request);
        }
        var deleted = new ImmutableList.Builder<DeletedObject>();
        var errors = new ImmutableList.Builder<S3Error>();

        for (List<ObjectIdentifier> chunk :
                Lists.partition(objects, MAX_BATCH_DELETES)) {
            var batch = storage.batch();
            var results = new ArrayList<StorageBatchResult<Boolean>>(
                    chunk.size());
            for (ObjectIdentifier object : chunk) {
                results.add(batch.delete(
                        BlobId.of(container, object.key())));
            }
            batch.submit();

            boolean refused = false;
            for (StorageBatchResult<Boolean> result : results) {
                try {
                    // The Boolean reports whether the object was there, which
                    // an idempotent delete does not care about; only a
                    // failure to carry it out matters.
                    result.get();
                } catch (StorageException se) {
                    if (se.getCode() != 404) {
                        refused = true;
                        break;
                    }
                }
            }

            if (refused) {
                var oneByOne = BlobStore.super.removeBlobs(request.toBuilder()
                        .delete(Delete.builder().objects(chunk).build())
                        .build());
                deleted.addAll(oneByOne.deleted());
                errors.addAll(oneByOne.errors());
                continue;
            }
            for (ObjectIdentifier object : chunk) {
                deleted.add(DeletedObject.builder()
                        .key(object.key())
                        .build());
            }
        }

        return DeleteObjectsResponse.builder()
                .deleted(deleted.build())
                .errors(errors.build())
                .build();
    }

    @Override
    public HeadObjectResponse blobMetadata(HeadObjectRequest request) {
        String container = request.bucket();
        String key = request.key();
        Blob gcsBlob = resolveVersion(container, key, request.versionId());
        if (gcsBlob == null) {
            throw S3Exceptions.noSuchKey(container, key, "no such object");
        }
        return HeadObjectResponse.builder()
                .metadata(sanitizeUserMetadata(gcsBlob.getMetadata()))
                .eTag(gcsBlob.getEtag())
                .lastModified(toInstant(
                        gcsBlob.getUpdateTimeOffsetDateTime()))
                .storageClass(
                        fromGcsStorageClass(gcsBlob.getStorageClass())
                                .toString())
                .cacheControl(gcsBlob.getCacheControl())
                .contentDisposition(gcsBlob.getContentDisposition())
                .contentEncoding(gcsBlob.getContentEncoding())
                .contentLanguage(gcsBlob.getContentLanguage())
                .contentLength(gcsBlob.getSize())
                .contentType(gcsBlob.getContentType())
                .versionId(reportedVersionId(container, gcsBlob,
                        request.versionId()))
                .build();
    }


    @Override
    public BucketCannedACL getContainerAccess(String container) {
        var bucket = storage.get(container);
        if (bucket == null) {
            throw S3Exceptions.noSuchBucket(container, "");
        }
        try {
            var acls = bucket.listAcls();
            for (var acl : acls) {
                if (acl.getEntity().equals(Acl.User.ofAllUsers())) {
                    return Acl.Role.READER.equals(acl.getRole()) ?
                            BucketCannedACL.PUBLIC_READ :
                            BucketCannedACL.PUBLIC_READ_WRITE;
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
        return BucketCannedACL.PRIVATE;
    }

    @Override
    public void setContainerAccess(String container,
            BucketCannedACL access) {
        try {
            if (access == BucketCannedACL.PUBLIC_READ_WRITE) {
                storage.createAcl(container,
                        Acl.of(Acl.User.ofAllUsers(), Acl.Role.WRITER));
            } else if (access == BucketCannedACL.PUBLIC_READ) {
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
    public ObjectCannedACL getBlobAccess(String container, String key) {
        try {
            var acls = storage.listAcls(BlobId.of(container, key));
            for (var acl : acls) {
                if (acl.getEntity().equals(Acl.User.ofAllUsers())) {
                    return ObjectCannedACL.PUBLIC_READ;
                }
            }
        } catch (StorageException se) {
            // On 404, distinguish a missing bucket from a missing object so
            // the caller can emit NoSuchBucket vs NoSuchKey.
            if (se.getCode() == 404) {
                if (storage.get(container) == null) {
                    throw S3Exceptions.noSuchBucket(container, "");
                }
                throw S3Exceptions.noSuchKey(container, key, "");
            }
            // The emulator returns ACL responses the SDK cannot deserialize
            // (StorageException with no HTTP status, code 0); tolerate those
            // but surface real failures rather than reporting PRIVATE.
            if (se.getCode() != 0) {
                throw translate(se, container, key);
            }
        }
        return ObjectCannedACL.PRIVATE;
    }

    @Override
    public ObjectCannedACL getBlobAccess(String container, String key,
            @Nullable String versionId) {
        Blob blob = resolveVersion(container, key, versionId);
        if (blob == null) {
            throw S3Exceptions.noSuchKey(container, key, "");
        }
        try {
            // The blobId carries the generation, so the ACL read is the
            // version's own rather than the live object's.
            var acls = storage.listAcls(blob.getBlobId());
            for (var acl : acls) {
                if (acl.getEntity().equals(Acl.User.ofAllUsers())) {
                    return ObjectCannedACL.PUBLIC_READ;
                }
            }
        } catch (StorageException se) {
            if (se.getCode() == 404) {
                throw S3Exceptions.noSuchKey(container, key, "");
            }
            // The emulator returns ACL responses the SDK cannot deserialize
            // (StorageException with no HTTP status, code 0); tolerate those
            // but surface real failures rather than reporting PRIVATE.
            if (se.getCode() != 0) {
                throw translate(se, container, key);
            }
        }
        return ObjectCannedACL.PRIVATE;
    }

    @Override
    public void setBlobAccess(String container, String key,
            ObjectCannedACL access) {
        try {
            if (access == ObjectCannedACL.PUBLIC_READ) {
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
    public void setBlobAccess(String container, String key,
            ObjectCannedACL access, @Nullable String versionId) {
        Blob blob = resolveVersion(container, key, versionId);
        if (blob == null) {
            throw S3Exceptions.noSuchKey(container, key, "");
        }
        try {
            if (access == ObjectCannedACL.PUBLIC_READ) {
                storage.createAcl(blob.getBlobId(),
                        Acl.of(Acl.User.ofAllUsers(), Acl.Role.READER));
            } else {
                storage.deleteAcl(blob.getBlobId(), Acl.User.ofAllUsers());
            }
        } catch (StorageException se) {
            // As in the unversioned overload: tolerate the emulator's
            // undeserializable ACL responses, surface real failures.
            if (se.getCode() != 0) {
                throw translate(se, container, key);
            }
        }
    }

    @Override
    public MultipartUpload initiateMultipartUpload(
            CreateMultipartUploadRequest request) {
        String container = request.bucket();
        if (!containerExists(container)) {
            throw S3Exceptions.noSuchBucket(container, "");
        }

        String uploadKey = STUB_BLOB_PREFIX + UUID.randomUUID().toString();
        String targetBlobName = request.key();

        // Store stub blob with metadata for later use during complete
        var stubMetadata = new HashMap<String, String>();
        stubMetadata.put(TARGET_BLOB_NAME_KEY, targetBlobName);

        if (request.contentType() != null) {
            stubMetadata.put("s3proxy_content_type", request.contentType());
        }
        if (request.contentDisposition() != null) {
            stubMetadata.put("s3proxy_content_disposition",
                    request.contentDisposition());
        }
        if (request.contentEncoding() != null) {
            stubMetadata.put("s3proxy_content_encoding",
                    request.contentEncoding());
        }
        if (request.contentLanguage() != null) {
            stubMetadata.put("s3proxy_content_language",
                    request.contentLanguage());
        }
        if (request.cacheControl() != null) {
            stubMetadata.put("s3proxy_cache_control",
                    request.cacheControl());
        }

        for (var entry : request.metadata().entrySet()) {
            stubMetadata.put("s3proxy_user_" + entry.getKey(),
                    entry.getValue());
        }

        if (request.storageClass() != null &&
                request.storageClass() != StorageClass.STANDARD) {
            stubMetadata.put("s3proxy_storage_class",
                    request.storageClass().name());
        }

        // The access rides on the stub because it is only offered here.  This
        // backend does not require a stub as far as Quirks is concerned, so
        // the completion cannot be asked what the caller wanted.
        if (request.acl() == ObjectCannedACL.PUBLIC_READ) {
            stubMetadata.put(BLOB_ACCESS_KEY,
                    ObjectCannedACL.PUBLIC_READ.name());
        }

        var stubInfo = BlobInfo.newBuilder(
                BlobId.of(container, uploadKey))
                .setMetadata(stubMetadata)
                .build();
        storage.create(stubInfo, new byte[0]);

        return new MultipartUpload(uploadKey, request);
    }

    @Override
    public void abortMultipartUpload(MultipartUpload mpu) {
        String uploadKey = mpu.id();

        if (!uploadKey.startsWith(STUB_BLOB_PREFIX)) {
            throw S3Exceptions.noSuchKey(mpu.containerName(), uploadKey,
                    "Multipart upload not found: " + uploadKey);
        }

        String nonce = uploadKey.substring(STUB_BLOB_PREFIX.length());

        if (storage.get(BlobId.of(mpu.containerName(), uploadKey),
                BlobGetOption.fields(BlobField.NAME)) == null) {
            throw S3Exceptions.noSuchKey(mpu.containerName(), uploadKey,
                    "Multipart upload not found: " + uploadKey);
        }
        removeStubGenerations(mpu.containerName(), nonce);
    }

    /**
     * Removes every generation of the upload's bookkeeping -- parts,
     * intermediate composes and the stub.  On a versioning-enabled
     * container a plain delete would archive them instead, and the hidden
     * versions would outlive every upload and hold the bucket undeletable
     * on the real service.
     */
    private void removeStubGenerations(String container, String nonce) {
        deleteGenerations(storage.list(container,
                BlobListOption.prefix(STUB_BLOB_PREFIX + nonce),
                BlobListOption.versions(true)));
    }

    @Override
    public CompleteMultipartUploadResponse completeMultipartUpload(MultipartUpload mpu,
            CompleteMultipartUploadRequest request) {
        List<CompletedPart> parts = request.multipartUpload() == null ?
                List.of() : request.multipartUpload().parts();
        String uploadKey = mpu.id();
        String nonce = uploadKey.substring(STUB_BLOB_PREFIX.length());

        Blob stubBlob = storage.get(
                BlobId.of(mpu.containerName(), uploadKey));
        if (stubBlob == null) {
            throw new IllegalArgumentException(
                    "Upload not found: uploadId=" + uploadKey);
        }

        var stubMetadata = stubBlob.getMetadata();
        if (stubMetadata == null) {
            throw new IllegalArgumentException(
                    "Stub blob missing target name: uploadId=" + uploadKey);
        }
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

        // The publish conditions, enforced as on a plain put: the check
        // resolves the current object and the write pins its generation, so
        // a concurrent change fails the publish rather than being clobbered.
        // If-Match: * never arrives -- the frontend resolves existence and
        // clears it -- so only named ETags and If-None-Match do.
        var conditionOptions = new java.util.ArrayList<BlobTargetOption>();
        String ifMatch = request.ifMatch();
        String ifNoneMatch = request.ifNoneMatch();
        if (ifMatch != null || ifNoneMatch != null) {
            Blob current = storage.get(
                    BlobId.of(mpu.containerName(), targetBlobName));
            if (ifMatch != null) {
                if (current == null || isDeleteMarker(current)) {
                    throw S3Exceptions.noSuchKey(mpu.containerName(),
                            targetBlobName, "");
                }
                if (!maybeQuoteETag(ifMatch).equals(
                        maybeQuoteETag(current.getEtag()))) {
                    throw preconditionFailed(current.getEtag());
                }
            }
            if (ifNoneMatch != null && current != null &&
                    !isDeleteMarker(current) &&
                    (ifNoneMatch.equals("*") ||
                            maybeQuoteETag(ifNoneMatch).equals(
                                    maybeQuoteETag(current.getEtag())))) {
                throw preconditionFailed(current.getEtag());
            }
            // A live object -- a delete marker included, which counts as
            // absent but still holds the key's generation -- pins the
            // publish to what the checks saw; nothing at all requires the
            // key to still be empty.
            conditionOptions.add(current != null ?
                    BlobTargetOption.generationMatch(current.getGeneration()) :
                    BlobTargetOption.doesNotExist());
        }

        // A single part is copied onto the target and can name the access on
        // that request, so no later one can fail and leave a private blob
        // where the caller asked for a public one.  Compose cannot; see below.
        var targetOptions = new java.util.ArrayList<BlobTargetOption>();
        if (ObjectCannedACL.PUBLIC_READ.name().equals(
                stubMetadata.get(BLOB_ACCESS_KEY))) {
            targetOptions.add(BlobTargetOption.predefinedAcl(
                    Storage.PredefinedAcl.PUBLIC_READ));
        }
        targetOptions.addAll(conditionOptions);

        // If single part, just copy it to the target
        if (parts.size() == 1) {
            String partBlobName = makePartBlobName(nonce,
                    parts.get(0).partNumber());
            var source = BlobId.of(mpu.containerName(), partBlobName);
            var copyRequest = CopyRequest.newBuilder()
                    .setSource(source)
                    .setTarget(targetBuilder.build(), targetOptions)
                    .build();
            CopyWriter copyWriter;
            try {
                copyWriter = storage.copy(copyRequest);
            } catch (StorageException se) {
                throw translate(se, mpu.containerName(), targetBlobName);
            }
            var result = copyWriter.getResult();
            removeStubGenerations(mpu.containerName(), nonce);
            return SdkResponses.completeResponse(result.getEtag(),
                    isVersioned(mpu.containerName()) ?
                            Long.toString(result.getGeneration()) : null);
        }

        // GCS compose supports up to 32 parts.
        // For more parts, compose recursively.
        var sourceBlobIds = new java.util.ArrayList<BlobId>();
        for (var part : parts) {
            String partBlobName = makePartBlobName(nonce, part.partNumber());
            sourceBlobIds.add(BlobId.of(mpu.containerName(), partBlobName));
        }

        Blob composed = composeRecursive(mpu.containerName(),
                targetBuilder.build(), sourceBlobIds, nonce,
                conditionOptions);

        // objects.compose accepts destinationPredefinedAcl, but the SDK drops
        // it: HttpStorageRpc.compose forwards only the generation,
        // metageneration and userProject options.  Naming it here would do
        // nothing, so set the access in a second request -- cheaper than
        // composing to a temporary name and copying that onto the target
        // solely to carry the ACL.
        // TODO: name the ACL on the compose itself, as the single-part copy
        // above does, after
        // https://github.com/googleapis/google-cloud-java/pull/13975 is
        // released and google-cloud-storage is bumped past it
        if (!targetOptions.isEmpty()) {
            storage.createAcl(composed.getBlobId(),
                    Acl.of(Acl.User.ofAllUsers(), Acl.Role.READER));
        }

        removeStubGenerations(mpu.containerName(), nonce);

        return SdkResponses.completeResponse(composed.getEtag(),
                isVersioned(mpu.containerName()) ?
                        Long.toString(composed.getGeneration()) : null);
    }

    /**
     * Recursively compose blobs to handle more than 32 parts.
     * GCS compose supports max 32 sources, so for N > 32 parts we
     * compose in groups of 32, then compose those results.
     */
    private Blob composeRecursive(String container, BlobInfo target,
            List<BlobId> sources, String nonce,
            List<BlobTargetOption> conditionOptions) {
        if (sources.size() <= MAX_COMPOSE_PARTS) {
            var composeBuilder = ComposeRequest.newBuilder();
            composeBuilder.setTarget(target);
            // The publish conditions ride only here, on the compose that
            // writes the target; the intermediates below are unconditional.
            composeBuilder.setTargetOptions(conditionOptions);
            for (var source : sources) {
                composeBuilder.addSource(source.getName());
            }
            try {
                return storage.compose(composeBuilder.build());
            } catch (StorageException se) {
                throw translate(se, container, target.getName());
            }
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
                nonce, conditionOptions);
    }

    @Override
    public UploadPartResponse uploadMultipartPart(MultipartUpload mpu,
            UploadPartRequest request, InputStream is) {
        int partNumber = request.partNumber();
        long contentLength = request.contentLength();
        var contentMD5 = SdkRequests.contentMD5(request);
        if (partNumber < 1 || partNumber > 10_000) {
            throw new IllegalArgumentException(
                    "Part number must be between 1 and 10,000, got: " +
                    partNumber);
        }

        String uploadKey = mpu.id();
        String nonce = uploadKey.substring(STUB_BLOB_PREFIX.length());
        String partBlobName = makePartBlobName(nonce, partNumber);

        byte[] md5Hash;
        var digest = MD5.newDigest();
        try (var dis = new DigestInputStream(is, digest)) {
            var partInfo = BlobInfo.newBuilder(
                    BlobId.of(mpu.containerName(), partBlobName)).build();
            storage.createFrom(partInfo, dis,
                    uploadChunkSize(contentLength));

            md5Hash = digest.digest();

            if (contentMD5 != null) {
                if (!MessageDigest.isEqual(md5Hash,
                        contentMD5.asBytes())) {
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

        String eTag = HexFormat.of().formatHex(md5Hash);
        return SdkResponses.uploadedPart(eTag);
    }

    @Override
    public boolean supportsCopyMultipartPart() {
        return true;
    }

    @Override
    public UploadPartCopyResponse copyMultipartPart(MultipartUpload mpu,
            UploadPartCopyRequest request) {
        int partNumber = request.partNumber();
        if (partNumber < 1 || partNumber > 10_000) {
            throw new IllegalArgumentException(
                    "Part number must be between 1 and 10,000, got: " +
                    partNumber);
        }

        String sourceContainer = request.sourceBucket();
        String sourceName = request.sourceKey();
        Blob sourceBlob = resolveVersion(sourceContainer, sourceName,
                request.sourceVersionId());
        if (sourceBlob == null) {
            throw S3Exceptions.noSuchKey(sourceContainer, sourceName, "");
        }
        // The generation rides on the blobId, so the copy reads the version
        // the resolution named.
        var source = sourceBlob.getBlobId();

        // GCS cannot copy a byte range server-side; a range covering the
        // whole object is equivalent to no range, anything else falls back
        // to streamed emulation in the caller.
        String copySourceRange = request.copySourceRange();
        if (copySourceRange != null && !isEntireObject(copySourceRange,
                sourceBlob.getSize())) {
            throw new UnsupportedOperationException(
                    "GCS does not support ranged server-side copies");
        }

        var sourceOptions = checkCopySourceConditions(sourceBlob,
                request.copySourceIfMatch(), request.copySourceIfNoneMatch(),
                request.copySourceIfModifiedSince(),
                request.copySourceIfUnmodifiedSince());

        String uploadKey = mpu.id();
        String nonce = uploadKey.substring(STUB_BLOB_PREFIX.length());
        String partBlobName = makePartBlobName(nonce, partNumber);

        try {
            var copyRequest = CopyRequest.newBuilder()
                    .setSource(source)
                    .setSourceOptions(sourceOptions)
                    .setTarget(BlobInfo.newBuilder(BlobId.of(
                            mpu.containerName(), partBlobName)).build())
                    .build();
            var result = storage.copy(copyRequest).getResult();
            // Match uploadMultipartPart's hex MD5 part ETag;
            // listMultipartUpload reads the same value back from GCS.
            return SdkResponses.copiedPart(result.getMd5ToHexString(),
                    /*lastModified=*/ null,
                    reportedVersionId(sourceContainer, sourceBlob,
                            request.sourceVersionId()));
        } catch (StorageException se) {
            throw translate(se, sourceContainer, sourceName);
        }
    }

    /** Whether a strict bytes=first-last range spans the whole object. */
    private static boolean isEntireObject(String range, long size) {
        if (!range.startsWith("bytes=") || range.indexOf(',') != -1) {
            return false;
        }
        String[] parts = range.substring("bytes=".length()).split("-", 2);
        if (parts.length != 2 || parts[0].isEmpty() || parts[1].isEmpty()) {
            return false;
        }
        try {
            return Long.parseLong(parts[0]) == 0 &&
                    Long.parseLong(parts[1]) == size - 1;
        } catch (NumberFormatException nfe) {
            return false;
        }
    }

    @Override
    public List<Part> listMultipartUpload(MultipartUpload mpu) {
        String uploadKey = mpu.id();
        if (!uploadKey.startsWith(STUB_BLOB_PREFIX)) {
            throw S3Exceptions.noSuchKey(mpu.containerName(), uploadKey,
                    "Multipart upload not found: " + uploadKey);
        }

        String nonce = uploadKey.substring(STUB_BLOB_PREFIX.length());
        String prefix = STUB_BLOB_PREFIX + nonce + "/part_";

        var parts = ImmutableList.<Part>builder();
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
            parts.add(SdkResponses.part(partNumber, blob.getSize(),
                    blob.getMd5ToHexString(), null));
        }
        return parts.build();
    }

    @Override
    public List<software.amazon.awssdk.services.s3.model.MultipartUpload>
            listMultipartUploads(String container) {
        var builder = ImmutableList.<software.amazon.awssdk.services.s3
                .model.MultipartUpload>builder();
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
            builder.add(SdkResponses.upload(targetBlobName, name));
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
            throw S3Exceptions.noSuchKey(container, name, "");
        }
        if (isDeleteMarker(blob)) {
            throw S3Exceptions.noSuchKeyDeleteMarker(container, name,
                    Long.toString(blob.getGeneration()),
                    "current version is a delete marker");
        }
        // If the ETag doesn't match, the precondition fails.
        if (!eTag.equals("*") && !maybeQuoteETag(eTag).equals(
                maybeQuoteETag(blob.getEtag()))) {
            throw preconditionFailed(blob.getEtag());
        }
        return blob.getGeneration();
    }

    // GCS permits null values in user metadata; filter them out since the
    // S3 model does not.
    private static Map<String, String> sanitizeUserMetadata(
            @Nullable Map<String, @Nullable String> metadata) {
        if (metadata == null) {
            return Map.of();
        }
        var result = new LinkedHashMap<String, String>();
        metadata.forEach((key, value) -> {
            if (value != null) {
                result.put(key, value);
            }
        });
        return result;
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

    private static java.time.@Nullable Instant toInstant(
            java.time.@Nullable OffsetDateTime dateTime) {
        return dateTime == null ? null : dateTime.toInstant();
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

    /**
     * Translate StorageException to an S3-shaped SDK exception, returning
     * the original StorageException unchanged if no translation applies.
     */
    private static RuntimeException translate(StorageException se,
            String container, @Nullable String key) {
        switch (se.getCode()) {
        case 404 -> {
            if (key != null) {
                return S3Exceptions.noSuchKey(container, key, "", se);
            } else {
                return S3Exceptions.noSuchBucket(container, "", se);
            }
        }
        case 412 -> {
            return S3Exceptions.fromStatusCode(412, se);
        }
        case 401, 403 -> {
            // Surface a permission failure as 403 AccessDenied rather than a
            // generic 500.
            return S3Exceptions.fromStatusCode(403, se);
        }
        default -> { }
        }
        return se;
    }

    // Build a 412 for a failed conditional-GET precondition, echoing the
    // object's ETag so the frontend can emit it on the 304 Not Modified
    // response (required by RFC 7232).
    private static S3Exception preconditionFailed(@Nullable String eTag) {
        return S3Exceptions.fromStatusCode(412,
                eTag == null ? null : maybeQuoteETag(eTag), Map.of(),
                /*cause=*/ null);
    }
}
