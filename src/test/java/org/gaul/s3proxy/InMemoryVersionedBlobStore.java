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
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
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
import software.amazon.awssdk.services.s3.model.Bucket;
import software.amazon.awssdk.services.s3.model.BucketCannedACL;
import software.amazon.awssdk.services.s3.model.BucketVersioningStatus;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.CopyObjectRequest;
import software.amazon.awssdk.services.s3.model.CopyObjectResponse;
import software.amazon.awssdk.services.s3.model.CopyObjectResult;
import software.amazon.awssdk.services.s3.model.CreateBucketRequest;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.DeleteMarkerEntry;
import software.amazon.awssdk.services.s3.model.DeleteObjectResponse;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.HeadObjectRequest;
import software.amazon.awssdk.services.s3.model.HeadObjectResponse;
import software.amazon.awssdk.services.s3.model.ListBucketsResponse;
import software.amazon.awssdk.services.s3.model.ListObjectVersionsRequest;
import software.amazon.awssdk.services.s3.model.ListObjectVersionsResponse;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Response;
import software.amazon.awssdk.services.s3.model.ObjectCannedACL;
import software.amazon.awssdk.services.s3.model.ObjectVersion;
import software.amazon.awssdk.services.s3.model.ObjectVersionStorageClass;
import software.amazon.awssdk.services.s3.model.Part;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.awssdk.services.s3.model.S3Object;
import software.amazon.awssdk.services.s3.model.StorageClass;
import software.amazon.awssdk.services.s3.model.UploadPartResponse;

/**
 * A minimal in-memory BlobStore with S3 versioning semantics, standing in
 * for a versioned S3 backend so the handler's versioning paths can be
 * exercised end-to-end without one.  Objects live wholly in memory; the
 * multipart operations are unsupported.
 */
final class InMemoryVersionedBlobStore implements BlobStore {
    /** The version id every unversioned write carries, as on S3. */
    private static final String NULL_VERSION_ID = "null";

    private static final AtomicLong LAST_MILLIS = new AtomicLong();

    private final SortedMap<String, Container> containers = new TreeMap<>();
    private final AtomicLong versionCounter = new AtomicLong();

    /**
     * A strictly increasing timestamp: the frontend interleaves versions
     * and delete markers by (key, lastModified desc), so two writes in the
     * same millisecond would list in an arbitrary order.
     */
    private static Date mintTime() {
        return new Date(LAST_MILLIS.updateAndGet(
                last -> Math.max(last + 1, System.currentTimeMillis())));
    }

    private record Version(String versionId, boolean deleteMarker,
            byte[] content, @Nullable String contentType, String eTag,
            Date lastModified) {
    }

    private static final class Container {
        // newest version first for every key
        private final SortedMap<String, List<Version>> keys = new TreeMap<>();
        private @Nullable BucketVersioningStatus status;
    }

    private synchronized Container getContainer(String containerName) {
        var container = containers.get(containerName);
        if (container == null) {
            throw S3Exceptions.noSuchBucket(containerName, "");
        }
        return container;
    }

    @Override
    public synchronized ListBucketsResponse list() {
        var buckets = new ArrayList<Bucket>();
        for (var name : containers.keySet()) {
            buckets.add(SdkResponses.bucket(name, new Date(0)));
        }
        return ListBucketsResponse.builder().buckets(buckets).build();
    }

    @Override
    public synchronized ListObjectsV2Response list(
            ListObjectsV2Request request) {
        String containerName = request.bucket();
        var container = getContainer(containerName);
        var contents = new ArrayList<S3Object>();
        for (var entry : container.keys.entrySet()) {
            if (request.prefix() != null &&
                    !entry.getKey().startsWith(request.prefix())) {
                continue;
            }
            var current = entry.getValue().get(0);
            if (current.deleteMarker()) {
                continue;
            }
            contents.add(SdkResponses.objectEntry(entry.getKey(),
                    current.eTag(), current.lastModified(),
                    (long) current.content().length, StorageClass.STANDARD));
        }
        return SdkResponses.objectsPage(contents, List.of(), null);
    }

    @Override
    public synchronized boolean containerExists(String containerName) {
        return containers.containsKey(containerName);
    }

    @Override
    public synchronized boolean createContainer(CreateBucketRequest request) {
        return containers.putIfAbsent(request.bucket(),
                new Container()) == null;
    }

    @Override
    public BucketCannedACL getContainerAccess(String containerName) {
        getContainer(containerName);
        return BucketCannedACL.PRIVATE;
    }

    @Override
    public void setContainerAccess(String containerName,
            BucketCannedACL access) {
        getContainer(containerName);
    }

    @Override
    public synchronized boolean deleteContainerIfEmpty(String containerName) {
        var container = getContainer(containerName);
        // versions and delete markers keep a bucket non-empty, as on S3
        if (!container.keys.isEmpty()) {
            return false;
        }
        containers.remove(containerName);
        return true;
    }

    @Override
    public synchronized boolean blobExists(String containerName, String key) {
        var versions = getContainer(containerName).keys.get(key);
        return versions != null && !versions.get(0).deleteMarker();
    }

    @Override
    public synchronized boolean supportsVersioning() {
        return true;
    }

    @Override
    @Nullable
    public synchronized BucketVersioningStatus getContainerVersioning(
            String containerName) {
        return getContainer(containerName).status;
    }

    @Override
    public synchronized void setContainerVersioning(String containerName,
            BucketVersioningStatus status) {
        getContainer(containerName).status = status;
    }

    @Override
    public synchronized PutObjectResponse putBlob(PutObjectRequest request,
            InputStream payload) {
        var container = getContainer(request.bucket());
        var key = request.key();
        byte[] content = readPayload(payload);
        @SuppressWarnings("deprecation")
        var eTag = Hashing.md5().hashBytes(content).toString();
        var version = new Version(mintVersionId(container),
                /*deleteMarker=*/ false, content,
                request.contentType(), eTag,
                mintTime());
        insertVersion(container, key, version);
        return PutObjectResponse.builder()
                .eTag(eTag)
                .versionId(container.status == null ? null :
                        version.versionId())
                .build();
    }

    @Override
    public synchronized CopyObjectResponse copyBlob(
            CopyObjectRequest request) {
        String fromContainer = request.sourceBucket();
        String fromName = request.sourceKey();
        var source = getContainer(fromContainer);
        var sourceVersion = resolveVersion(source, fromName,
                request.sourceVersionId());
        if (sourceVersion == null || sourceVersion.deleteMarker()) {
            throw S3Exceptions.noSuchKey(fromContainer, fromName,
                    "while copying");
        }

        var dest = getContainer(request.destinationBucket());
        var destVersion = new Version(mintVersionId(dest),
                /*deleteMarker=*/ false, sourceVersion.content(),
                sourceVersion.contentType(), sourceVersion.eTag(),
                mintTime());
        insertVersion(dest, request.destinationKey(), destVersion);
        return CopyObjectResponse.builder()
                .copyObjectResult(CopyObjectResult.builder()
                        .eTag(destVersion.eTag())
                        .build())
                .versionId(dest.status == null ? null :
                        destVersion.versionId())
                .copySourceVersionId(source.status == null ? null :
                        sourceVersion.versionId())
                .build();
    }

    @Override
    @Nullable
    public synchronized HeadObjectResponse blobMetadata(
            HeadObjectRequest request) {
        String containerName = request.bucket();
        String key = request.key();
        var container = getContainer(containerName);
        var version = resolveVersionOrThrow(containerName, container, key,
                request.versionId());
        if (version == null) {
            return null;
        }
        return HeadObjectResponse.builder()
                .eTag(version.eTag())
                .lastModified(version.lastModified().toInstant())
                .contentLength((long) version.content().length)
                .contentType(version.contentType())
                .versionId(container.status == null ? null :
                        version.versionId())
                .build();
    }

    @Override
    @Nullable
    public synchronized ResponseInputStream<GetObjectResponse> getBlob(
            GetObjectRequest request) {
        String containerName = request.bucket();
        var container = getContainer(containerName);
        var version = resolveVersionOrThrow(containerName, container,
                request.key(), request.versionId());
        if (version == null) {
            return null;
        }
        return SdkResponses.getResponse(GetObjectResponse.builder()
                        .contentLength((long) version.content().length)
                        .contentType(version.contentType())
                        .eTag(version.eTag())
                        .lastModified(version.lastModified().toInstant())
                        .versionId(container.status == null ? null :
                                version.versionId())
                        .build(),
                new ByteArrayInputStream(version.content()));
    }

    @Override
    public synchronized void removeBlob(String containerName, String key) {
        removeBlob(containerName, key, null);
    }

    @Override
    public synchronized DeleteObjectResponse removeBlob(
            String containerName,
            String key, @Nullable String versionId) {
        var container = getContainer(containerName);
        var versions = container.keys.get(key);

        if (versionId != null) {
            if (versions == null) {
                throw S3Exceptions.noSuchVersion(containerName, key,
                        versionId, "no such version");
            }
            var iterator = versions.iterator();
            while (iterator.hasNext()) {
                var version = iterator.next();
                if (version.versionId().equals(versionId)) {
                    iterator.remove();
                    if (versions.isEmpty()) {
                        container.keys.remove(key);
                    }
                    return DeleteObjectResponse.builder()
                            .versionId(versionId)
                            .deleteMarker(version.deleteMarker())
                            .build();
                }
            }
            throw S3Exceptions.noSuchVersion(containerName, key, versionId,
                    "no such version");
        }

        if (container.status == null) {
            // unversioned: remove the data
            container.keys.remove(key);
            return DeleteObjectResponse.builder().build();
        }

        // versioned: leave the versions alone and put a marker on top
        var marker = new Version(mintVersionId(container),
                /*deleteMarker=*/ true, new byte[0], null, "", mintTime());
        insertVersion(container, key, marker);
        return DeleteObjectResponse.builder()
                .versionId(marker.versionId())
                .deleteMarker(true)
                .build();
    }

    private record VersionRow(String key, String versionId, boolean latest,
            boolean deleteMarker, @Nullable String eTag, Date lastModified,
            @Nullable Long size) {
    }

    @Override
    public synchronized ListObjectVersionsResponse listVersions(
            ListObjectVersionsRequest request) {
        String containerName = request.bucket();
        var container = getContainer(containerName);
        String prefix = request.prefix() == null ? "" : request.prefix();
        String delimiter = request.delimiter();
        int maxResults = request.maxKeys() == null ?
                1000 : request.maxKeys();

        // Flatten to S3's total order -- keys ascending, newest first --
        // then slice out one page.  Simplicity over efficiency: this store
        // exists to exercise the handler, not to scale.
        var all = new ArrayList<VersionRow>();
        var commonPrefixes = new ArrayList<String>();
        for (var entry : container.keys.entrySet()) {
            String key = entry.getKey();
            if (!key.startsWith(prefix)) {
                continue;
            }
            if (delimiter != null) {
                int index = key.indexOf(delimiter, prefix.length());
                if (index != -1) {
                    String commonPrefix = key.substring(0,
                            index + delimiter.length());
                    if (!commonPrefixes.contains(commonPrefix)) {
                        commonPrefixes.add(commonPrefix);
                    }
                    continue;
                }
            }
            boolean latest = true;
            for (var version : entry.getValue()) {
                all.add(new VersionRow(key, version.versionId(),
                        latest, version.deleteMarker(),
                        version.deleteMarker() ? null : version.eTag(),
                        version.lastModified(),
                        version.deleteMarker() ? null :
                                (long) version.content().length));
                latest = false;
            }
        }

        int start = 0;
        String keyMarker = request.keyMarker();
        if (keyMarker != null) {
            String versionIdMarker = request.versionIdMarker();
            for (int i = 0; i < all.size(); i++) {
                var candidate = all.get(i);
                if (versionIdMarker == null) {
                    // resume after the whole marker key
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

        int end = Math.min(all.size(), start + maxResults);
        var page = all.subList(start, end);
        String nextKeyMarker = null;
        String nextVersionIdMarker = null;
        if (end < all.size() && !page.isEmpty()) {
            var last = page.get(page.size() - 1);
            nextKeyMarker = last.key();
            nextVersionIdMarker = last.versionId();
        }

        var versions = new ArrayList<ObjectVersion>();
        var markers = new ArrayList<DeleteMarkerEntry>();
        for (var row : page) {
            if (row.deleteMarker()) {
                markers.add(DeleteMarkerEntry.builder()
                        .key(row.key())
                        .versionId(row.versionId())
                        .isLatest(row.latest())
                        .lastModified(row.lastModified().toInstant())
                        .build());
            } else {
                versions.add(ObjectVersion.builder()
                        .key(row.key())
                        .versionId(row.versionId())
                        .isLatest(row.latest())
                        .eTag(row.eTag())
                        .lastModified(row.lastModified().toInstant())
                        .size(row.size())
                        .storageClass(ObjectVersionStorageClass.STANDARD)
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

    @Override
    public ObjectCannedACL getBlobAccess(String containerName, String key) {
        return ObjectCannedACL.PRIVATE;
    }

    @Override
    public void setBlobAccess(String containerName, String key,
            ObjectCannedACL access) {
    }

    @Override
    public MultipartUpload initiateMultipartUpload(
            CreateMultipartUploadRequest request) {
        throw new UnsupportedOperationException("multipart not supported");
    }

    @Override
    public void abortMultipartUpload(MultipartUpload mpu) {
        throw new UnsupportedOperationException("multipart not supported");
    }

    @Override
    public CompleteMultipartUploadResponse completeMultipartUpload(
            MultipartUpload mpu, CompleteMultipartUploadRequest request) {
        throw new UnsupportedOperationException("multipart not supported");
    }

    @Override
    public UploadPartResponse uploadMultipartPart(MultipartUpload mpu,
            int partNumber, InputStream is, long contentLength,
            @Nullable HashCode contentMD5) {
        throw new UnsupportedOperationException("multipart not supported");
    }

    @Override
    public List<Part> listMultipartUpload(MultipartUpload mpu) {
        throw new UnsupportedOperationException("multipart not supported");
    }

    @Override
    public List<software.amazon.awssdk.services.s3.model.MultipartUpload>
            listMultipartUploads(String containerName) {
        throw new UnsupportedOperationException("multipart not supported");
    }

    @Override
    public long getMinimumMultipartPartSize() {
        return 1;
    }

    /**
     * A fresh version id on an enabled container, or the "null" id every
     * write mints while versioning is off or suspended.  Zero-padded so
     * lexicographic and numeric order agree.
     */
    private String mintVersionId(Container container) {
        return container.status == BucketVersioningStatus.ENABLED ?
                "v%016d".formatted(versionCounter.incrementAndGet()) :
                NULL_VERSION_ID;
    }

    /**
     * Stacks a version on top of a key's history.  A "null" version -- a
     * write on an unversioned or suspended container -- replaces the
     * previous "null" version rather than accumulating, as on S3.
     */
    private static void insertVersion(Container container, String key,
            Version version) {
        var versions = container.keys.computeIfAbsent(key,
                unused -> new ArrayList<>());
        if (version.versionId().equals(NULL_VERSION_ID)) {
            versions.removeIf(existing ->
                    existing.versionId().equals(NULL_VERSION_ID));
        }
        versions.add(0, version);
    }

    /**
     * The version a read names: the current one for a null versionId.
     * Returns null when the key does not exist; throws for a read of a
     * delete marker or of a version that does not exist, mirroring how the
     * S3 backend reports those.
     */
    @Nullable
    private Version resolveVersionOrThrow(String containerName,
            Container container, String key, @Nullable String versionId) {
        var versions = container.keys.get(key);
        if (versionId == null) {
            if (versions == null) {
                return null;
            }
            var current = versions.get(0);
            if (current.deleteMarker()) {
                throw S3Exceptions.noSuchKeyDeleteMarker(containerName, key,
                        current.versionId(),
                        "current version is a delete marker");
            }
            return current;
        }
        if (versions != null) {
            for (var version : versions) {
                if (version.versionId().equals(versionId)) {
                    if (version.deleteMarker()) {
                        // as on S3: reading a delete marker is refused
                        throw S3Exceptions.fromStatusCode(405, null, Map.of(
                                "x-amz-delete-marker", "true",
                                "x-amz-version-id", version.versionId()),
                                /*cause=*/ null);
                    }
                    return version;
                }
            }
        }
        throw S3Exceptions.noSuchVersion(containerName, key, versionId,
                "no such version");
    }

    @Nullable
    private Version resolveVersion(Container container, String key,
            @Nullable String versionId) {
        var versions = container.keys.get(key);
        if (versions == null) {
            return null;
        }
        if (versionId == null) {
            return versions.get(0);
        }
        for (var version : versions) {
            if (version.versionId().equals(versionId)) {
                return version;
            }
        }
        return null;
    }

    private static byte[] readPayload(InputStream payload) {
        try (var is = payload) {
            return is.readAllBytes();
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }
}
