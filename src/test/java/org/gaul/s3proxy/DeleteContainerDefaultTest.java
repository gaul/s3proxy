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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.gaul.s3proxy.blobstore.S3Exceptions;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.awscore.exception.AwsErrorDetails;
import software.amazon.awssdk.services.s3.model.BucketVersioningStatus;
import software.amazon.awssdk.services.s3.model.DeleteMarkerEntry;
import software.amazon.awssdk.services.s3.model.DeleteObjectResponse;
import software.amazon.awssdk.services.s3.model.ListObjectVersionsRequest;
import software.amazon.awssdk.services.s3.model.ListObjectVersionsResponse;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Response;
import software.amazon.awssdk.services.s3.model.ObjectVersion;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.services.s3.model.S3Object;

/**
 * Covers the deleteContainer the BlobStore interface supplies: the embedder
 * and test convenience that aborts in-progress uploads, empties the
 * container -- by version id where it has ever versioned -- and reports a
 * container the store still refuses rather than leaving it behind in
 * silence.
 */
public final class DeleteContainerDefaultTest {
    private static final String CONTAINER = "container";

    @Test
    public void testClearsAbortsAndDeletesTheContainer() {
        var blobStore = new FakeBlobStore(/*supportsVersioning=*/ false,
                /*status=*/ null);
        blobStore.addObject("blob-1");
        blobStore.addObject("blob-2");
        blobStore.addUpload("upload-1", "pending");

        blobStore.deleteContainer(CONTAINER);

        assertThat(blobStore.removedByKey)
                .containsExactlyInAnyOrder("blob-1", "blob-2");
        assertThat(blobStore.aborted).hasSize(1);
        MultipartUpload carrier = blobStore.aborted.get(0);
        assertThat(carrier.id()).isEqualTo("upload-1");
        assertThat(carrier.containerName()).isEqualTo(CONTAINER);
        assertThat(carrier.blobName()).isEqualTo("pending");
        assertThat(blobStore.containerDeleted).isTrue();
    }

    /**
     * A container that has ever versioned is emptied version by version --
     * every version and marker removed by its id, never by the versionless
     * delete, which would lay one more marker instead of removing data.
     */
    @Test
    public void testPurgesEveryVersionAndMarkerById() {
        var blobStore = new FakeBlobStore(/*supportsVersioning=*/ true,
                BucketVersioningStatus.ENABLED);
        blobStore.addVersion("blob", "v1");
        blobStore.addVersion("blob", "v2");
        blobStore.addMarker("blob", "v3");
        blobStore.addVersion("other", "v4");

        blobStore.deleteContainer(CONTAINER);

        assertThat(blobStore.removedById).containsExactlyInAnyOrder(
                "blob@v1", "blob@v2", "blob@v3", "other@v4");
        assertThat(blobStore.removedByKey).isEmpty();
        assertThat(blobStore.containerDeleted).isTrue();
    }

    @Test
    public void testPurgesAcrossListingPages() {
        var blobStore = new FakeBlobStore(/*supportsVersioning=*/ true,
                BucketVersioningStatus.ENABLED);
        blobStore.versionPageSize = 2;
        for (int i = 0; i < 5; ++i) {
            blobStore.addVersion("blob-" + i, "v" + i);
        }

        blobStore.deleteContainer(CONTAINER);

        assertThat(blobStore.removedById).hasSize(5);
        assertThat(blobStore.containerDeleted).isTrue();
    }

    /** A store that could version is not a container that ever has. */
    @Test
    public void testNeverVersionedContainerTakesTheUnversionedPath() {
        var blobStore = new FakeBlobStore(/*supportsVersioning=*/ true,
                /*status=*/ null);
        blobStore.addObject("blob");

        blobStore.deleteContainer(CONTAINER);

        assertThat(blobStore.removedByKey).containsExactly("blob");
        assertThat(blobStore.removedById).isEmpty();
        assertThat(blobStore.containerDeleted).isTrue();
    }

    /**
     * A container the store still refuses -- a concurrent writer, or
     * bookkeeping its listings hide -- is a failure to report: the old
     * shape discarded deleteContainerIfEmpty's answer, and teardowns
     * leaked containers in silence.
     */
    @Test
    public void testThrowsWhenTheStoreStillRefuses() {
        var blobStore = new FakeBlobStore(/*supportsVersioning=*/ false,
                /*status=*/ null);
        blobStore.refuseFinalDelete = true;

        assertThatThrownBy(() -> blobStore.deleteContainer(CONTAINER))
                .isInstanceOf(S3Exception.class)
                .satisfies(thrown -> assertThat(
                        S3Exceptions.errorCode((S3Exception) thrown))
                        .isEqualTo("BucketNotEmpty"));
    }

    /** Deleting a container already gone succeeds quietly. */
    @Test
    public void testMissingContainerIsQuietlyDone() {
        var blobStore = new MissingContainerBlobStore(
                S3Exceptions.noSuchBucket(CONTAINER, "gone"));

        blobStore.deleteContainer(CONTAINER);
    }

    /**
     * A pass-through backend reports a missing bucket as a generic
     * S3Exception carrying the NoSuchBucket code, not the SDK's typed
     * exception -- GetBucketVersioning and ListMultipartUploads do not
     * model it -- so the default reads the code.
     */
    @Test
    public void testPassthroughNoSuchBucketIsQuietlyDone() {
        var blobStore = new MissingContainerBlobStore(
                (S3Exception) S3Exception.builder()
                        .message("no such bucket")
                        .statusCode(404)
                        .awsErrorDetails(AwsErrorDetails.builder()
                                .errorCode("NoSuchBucket")
                                .errorMessage(
                                        "The specified bucket does not exist")
                                .build())
                        .build());

        blobStore.deleteContainer(CONTAINER);
    }

    /** Refuses every operation the way a store misses a container. */
    private static final class MissingContainerBlobStore
            extends AbstractUnsupportedBlobStore {
        private final S3Exception missing;

        MissingContainerBlobStore(S3Exception missing) {
            this.missing = missing;
        }

        @Override
        public List<software.amazon.awssdk.services.s3.model.MultipartUpload>
                listMultipartUploads(String container) {
            throw missing;
        }
    }

    /**
     * An in-memory container for the default to empty, recording whether
     * each removal named a version id.
     */
    private static final class FakeBlobStore extends AbstractUnsupportedBlobStore {
        private record Entry(String key, String versionId, boolean marker) {
        }

        private record Upload(String id, String key) {
        }

        private final boolean supportsVersioning;
        @Nullable
        private final BucketVersioningStatus status;
        // Listings page over this in order; removals mark entries gone
        // rather than reshuffling what a page marker points into.
        private final List<Entry> entries = new ArrayList<>();
        private final Set<String> gone = new HashSet<>();
        private final List<Upload> uploads = new ArrayList<>();
        private final List<MultipartUpload> aborted = new ArrayList<>();
        private final List<String> removedByKey = new ArrayList<>();
        private final List<String> removedById = new ArrayList<>();
        private int versionPageSize = Integer.MAX_VALUE;
        private boolean refuseFinalDelete;
        private boolean containerDeleted;

        FakeBlobStore(boolean supportsVersioning,
                @Nullable BucketVersioningStatus status) {
            this.supportsVersioning = supportsVersioning;
            this.status = status;
        }

        void addObject(String key) {
            entries.add(new Entry(key, "null", /*marker=*/ false));
        }

        void addVersion(String key, String versionId) {
            entries.add(new Entry(key, versionId, /*marker=*/ false));
        }

        void addMarker(String key, String versionId) {
            entries.add(new Entry(key, versionId, /*marker=*/ true));
        }

        void addUpload(String id, String key) {
            uploads.add(new Upload(id, key));
        }

        @Override
        public boolean supportsVersioning() {
            return supportsVersioning;
        }

        @Override
        @Nullable
        public BucketVersioningStatus getContainerVersioning(
                String container) {
            return status;
        }

        @Override
        public List<software.amazon.awssdk.services.s3.model.MultipartUpload>
                listMultipartUploads(String container) {
            return uploads.stream()
                    .map(upload -> software.amazon.awssdk.services.s3.model
                            .MultipartUpload.builder()
                            .uploadId(upload.id())
                            .key(upload.key())
                            .build())
                    .toList();
        }

        @Override
        public void abortMultipartUpload(MultipartUpload mpu) {
            aborted.add(mpu);
        }

        @Override
        public ListObjectsV2Response list(ListObjectsV2Request request) {
            var contents = new ArrayList<S3Object>();
            for (Entry entry : entries) {
                if (!gone.contains(entry.key())) {
                    contents.add(S3Object.builder()
                            .key(entry.key())
                            .build());
                }
            }
            return ListObjectsV2Response.builder()
                    .contents(contents)
                    .build();
        }

        @Override
        public void removeBlob(String container, String name) {
            if (status != null) {
                throw new AssertionError("versionless delete would lay a" +
                        " marker on a versioned container");
            }
            removedByKey.add(name);
            gone.add(name);
        }

        @Override
        public DeleteObjectResponse removeBlob(String container, String name,
                @Nullable String versionId) {
            removedById.add(name + "@" + versionId);
            gone.add(name + "@" + versionId);
            return DeleteObjectResponse.builder().build();
        }

        @Override
        public ListObjectVersionsResponse listVersions(
                ListObjectVersionsRequest request) {
            int start = 0;
            if (request.keyMarker() != null) {
                while (start < entries.size()) {
                    Entry entry = entries.get(start);
                    ++start;
                    if (entry.key().equals(request.keyMarker()) &&
                            entry.versionId().equals(
                                    request.versionIdMarker())) {
                        break;
                    }
                }
            }
            var versions = new ArrayList<ObjectVersion>();
            var markers = new ArrayList<DeleteMarkerEntry>();
            int end = Math.min(entries.size(), start + versionPageSize);
            for (int i = start; i < end; ++i) {
                Entry entry = entries.get(i);
                if (entry.marker()) {
                    markers.add(DeleteMarkerEntry.builder()
                            .key(entry.key())
                            .versionId(entry.versionId())
                            .build());
                } else {
                    versions.add(ObjectVersion.builder()
                            .key(entry.key())
                            .versionId(entry.versionId())
                            .build());
                }
            }
            boolean truncated = end < entries.size();
            Entry last = truncated ? entries.get(end - 1) : null;
            return ListObjectVersionsResponse.builder()
                    .versions(versions)
                    .deleteMarkers(markers)
                    .isTruncated(truncated)
                    .nextKeyMarker(last == null ? null : last.key())
                    .nextVersionIdMarker(
                            last == null ? null : last.versionId())
                    .build();
        }

        @Override
        public boolean deleteContainerIfEmpty(String container) {
            if (refuseFinalDelete) {
                return false;
            }
            containerDeleted = true;
            return true;
        }
    }
}
