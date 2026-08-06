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

import static java.util.Objects.requireNonNull;

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
import org.gaul.s3proxy.blobstore.ContentMetadata;
import org.gaul.s3proxy.blobstore.S3Exceptions;
import org.gaul.s3proxy.blobstore.domain.Blob;
import org.gaul.s3proxy.blobstore.domain.BlobAccess;
import org.gaul.s3proxy.blobstore.domain.BlobMetadata;
import org.gaul.s3proxy.blobstore.domain.ContainerAccess;
import org.gaul.s3proxy.blobstore.domain.ContainerMetadata;
import org.gaul.s3proxy.blobstore.domain.CopyResult;
import org.gaul.s3proxy.blobstore.domain.MultipartPart;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.gaul.s3proxy.blobstore.domain.PageSet;
import org.gaul.s3proxy.blobstore.domain.PutResult;
import org.gaul.s3proxy.blobstore.domain.RemoveResult;
import org.gaul.s3proxy.blobstore.domain.StorageClass;
import org.gaul.s3proxy.blobstore.domain.StorageMetadata;
import org.gaul.s3proxy.blobstore.domain.StorageType;
import org.gaul.s3proxy.blobstore.domain.VersionMetadata;
import org.gaul.s3proxy.blobstore.domain.VersionPage;
import org.gaul.s3proxy.blobstore.domain.VersioningStatus;
import org.gaul.s3proxy.blobstore.options.CopyOptions;
import org.gaul.s3proxy.blobstore.options.CreateContainerOptions;
import org.gaul.s3proxy.blobstore.options.GetOptions;
import org.gaul.s3proxy.blobstore.options.ListContainerOptions;
import org.gaul.s3proxy.blobstore.options.ListVersionsOptions;
import org.gaul.s3proxy.blobstore.options.PutOptions;
import org.jspecify.annotations.Nullable;

/**
 * A minimal in-memory BlobStore with S3 versioning semantics, standing in
 * for a versioned S3 backend so the handler's versioning paths can be
 * exercised end-to-end without one.  Objects live wholly in memory; the
 * multipart operations are unsupported.
 */
final class InMemoryVersionedBlobStore implements BlobStore {
    /** The version id every unversioned write carries, as on S3. */
    private static final String NULL_VERSION_ID = "null";

    private final SortedMap<String, Container> containers = new TreeMap<>();
    private final AtomicLong versionCounter = new AtomicLong();

    private record Version(String versionId, boolean deleteMarker,
            byte[] content, @Nullable String contentType, String eTag,
            Date lastModified) {
    }

    private static final class Container {
        // newest version first for every key
        private final SortedMap<String, List<Version>> keys = new TreeMap<>();
        private @Nullable VersioningStatus status;
    }

    private synchronized Container getContainer(String containerName) {
        var container = containers.get(containerName);
        if (container == null) {
            throw S3Exceptions.noSuchBucket(containerName, "");
        }
        return container;
    }

    @Override
    public synchronized PageSet<? extends StorageMetadata> list() {
        var entries = new ArrayList<StorageMetadata>();
        for (var name : containers.keySet()) {
            entries.add(new ContainerMetadata(name, new Date(0)));
        }
        return new PageSet<>(entries, null);
    }

    @Override
    public synchronized PageSet<? extends StorageMetadata> list(
            String containerName, ListContainerOptions options) {
        var container = getContainer(containerName);
        var entries = new ArrayList<StorageMetadata>();
        for (var entry : container.keys.entrySet()) {
            if (options.prefix() != null &&
                    !entry.getKey().startsWith(options.prefix())) {
                continue;
            }
            var current = entry.getValue().get(0);
            if (current.deleteMarker()) {
                continue;
            }
            entries.add(toBlobMetadata(containerName, entry.getKey(), current,
                    container));
        }
        return new PageSet<>(entries, null);
    }

    @Override
    public synchronized boolean containerExists(String containerName) {
        return containers.containsKey(containerName);
    }

    @Override
    public synchronized boolean createContainer(String containerName,
            CreateContainerOptions options) {
        return containers.putIfAbsent(containerName, new Container()) == null;
    }

    @Override
    public ContainerAccess getContainerAccess(String containerName) {
        getContainer(containerName);
        return ContainerAccess.PRIVATE;
    }

    @Override
    public void setContainerAccess(String containerName,
            ContainerAccess access) {
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
    public synchronized VersioningStatus getContainerVersioning(
            String containerName) {
        return getContainer(containerName).status;
    }

    @Override
    public synchronized void setContainerVersioning(String containerName,
            VersioningStatus status) {
        getContainer(containerName).status = status;
    }

    @Override
    public synchronized PutResult putBlob(String containerName, Blob blob,
            PutOptions options) {
        var container = getContainer(containerName);
        var key = blob.getMetadata().name();
        byte[] content = readPayload(blob);
        @SuppressWarnings("deprecation")
        var eTag = Hashing.md5().hashBytes(content).toString();
        var version = new Version(mintVersionId(container),
                /*deleteMarker=*/ false, content,
                blob.getMetadata().contentMetadata().contentType(), eTag,
                new Date());
        insertVersion(container, key, version);
        return new PutResult(eTag,
                container.status == null ? null : version.versionId());
    }

    @Override
    public synchronized CopyResult copyBlob(String fromContainer,
            String fromName, String toContainer, String toName,
            CopyOptions options) {
        var source = getContainer(fromContainer);
        var sourceVersion = resolveVersion(source, fromName,
                options.sourceVersionId());
        if (sourceVersion == null || sourceVersion.deleteMarker()) {
            throw S3Exceptions.noSuchKey(fromContainer, fromName,
                    "while copying");
        }

        var dest = getContainer(toContainer);
        var destVersion = new Version(mintVersionId(dest),
                /*deleteMarker=*/ false, sourceVersion.content(),
                sourceVersion.contentType(), sourceVersion.eTag(),
                new Date());
        insertVersion(dest, toName, destVersion);
        return new CopyResult(destVersion.eTag(),
                dest.status == null ? null : destVersion.versionId(),
                source.status == null ? null : sourceVersion.versionId());
    }

    @Override
    @Nullable
    public synchronized BlobMetadata blobMetadata(String containerName,
            String key) {
        return blobMetadata(containerName, key, null);
    }

    @Override
    @Nullable
    public synchronized BlobMetadata blobMetadata(String containerName,
            String key, @Nullable String versionId) {
        var container = getContainer(containerName);
        var version = resolveVersionOrThrow(containerName, container, key,
                versionId);
        if (version == null) {
            return null;
        }
        return toBlobMetadata(containerName, key, version, container);
    }

    @Override
    @Nullable
    public synchronized Blob getBlob(String containerName, String key,
            GetOptions options) {
        var container = getContainer(containerName);
        var version = resolveVersionOrThrow(containerName, container, key,
                options.versionId());
        if (version == null) {
            return null;
        }
        var builder = Blob.builder(key)
                .payload(new ByteArrayInputStream(version.content()))
                .contentLength(version.content().length)
                .contentType(version.contentType())
                .eTag(version.eTag())
                .lastModified(version.lastModified())
                .container(containerName);
        if (container.status != null) {
            builder.versionId(version.versionId());
        }
        return builder.build();
    }

    @Override
    public synchronized void removeBlob(String containerName, String key) {
        removeBlob(containerName, key, null);
    }

    @Override
    public synchronized RemoveResult removeBlob(String containerName,
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
                    return new RemoveResult(versionId,
                            version.deleteMarker());
                }
            }
            throw S3Exceptions.noSuchVersion(containerName, key, versionId,
                    "no such version");
        }

        if (container.status == null) {
            // unversioned: remove the data
            container.keys.remove(key);
            return RemoveResult.NONE;
        }

        // versioned: leave the versions alone and put a marker on top
        var marker = new Version(mintVersionId(container),
                /*deleteMarker=*/ true, new byte[0], null, "", new Date());
        insertVersion(container, key, marker);
        return new RemoveResult(marker.versionId(), /*deleteMarker=*/ true);
    }

    @Override
    public synchronized VersionPage listVersions(String containerName,
            ListVersionsOptions options) {
        var container = getContainer(containerName);
        String prefix = options.prefix() == null ? "" : options.prefix();
        String delimiter = options.delimiter();
        int maxResults = options.maxResults() == null ?
                1000 : options.maxResults();

        // Flatten to S3's total order -- keys ascending, newest first --
        // then slice out one page.  Simplicity over efficiency: this store
        // exists to exercise the handler, not to scale.
        var all = new ArrayList<VersionMetadata>();
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
                all.add(new VersionMetadata(key, version.versionId(),
                        latest, version.deleteMarker(),
                        version.deleteMarker() ? null : version.eTag(),
                        version.lastModified(),
                        version.deleteMarker() ? null :
                                (long) version.content().length,
                        StorageClass.STANDARD));
                latest = false;
            }
        }

        int start = 0;
        String keyMarker = options.keyMarker();
        if (keyMarker != null) {
            String versionIdMarker = options.versionIdMarker();
            for (int i = 0; i < all.size(); i++) {
                var candidate = all.get(i);
                if (versionIdMarker == null) {
                    // resume after the whole marker key
                    if (candidate.name().compareTo(keyMarker) > 0) {
                        start = i;
                        break;
                    }
                } else if (candidate.name().equals(keyMarker) &&
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
            nextKeyMarker = last.name();
            nextVersionIdMarker = last.versionId();
        }

        return new VersionPage(page, commonPrefixes, nextKeyMarker,
                nextVersionIdMarker);
    }

    @Override
    public BlobAccess getBlobAccess(String containerName, String key) {
        return BlobAccess.PRIVATE;
    }

    @Override
    public void setBlobAccess(String containerName, String key,
            BlobAccess access) {
    }

    @Override
    public MultipartUpload initiateMultipartUpload(String containerName,
            BlobMetadata blobMetadata, PutOptions options) {
        throw new UnsupportedOperationException("multipart not supported");
    }

    @Override
    public void abortMultipartUpload(MultipartUpload mpu) {
        throw new UnsupportedOperationException("multipart not supported");
    }

    @Override
    public PutResult completeMultipartUpload(MultipartUpload mpu,
            List<MultipartPart> parts) {
        throw new UnsupportedOperationException("multipart not supported");
    }

    @Override
    public MultipartPart uploadMultipartPart(MultipartUpload mpu,
            int partNumber, InputStream is, long contentLength,
            @Nullable HashCode contentMD5) {
        throw new UnsupportedOperationException("multipart not supported");
    }

    @Override
    public List<MultipartPart> listMultipartUpload(MultipartUpload mpu) {
        throw new UnsupportedOperationException("multipart not supported");
    }

    @Override
    public List<MultipartUpload> listMultipartUploads(String containerName) {
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
        return container.status == VersioningStatus.ENABLED ?
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

    private static BlobMetadata toBlobMetadata(String containerName,
            String key, Version version, Container container) {
        return new BlobMetadata(StorageType.BLOB, key, Map.of(),
                version.eTag(), version.lastModified(),
                StorageClass.STANDARD, containerName,
                ContentMetadata.builder()
                        .contentLength((long) version.content().length)
                        .contentType(version.contentType())
                        .build(),
                container.status == null ? null : version.versionId());
    }

    private static byte[] readPayload(Blob blob) {
        try (var is = requireNonNull(blob.getPayload())) {
            return is.readAllBytes();
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }
}
