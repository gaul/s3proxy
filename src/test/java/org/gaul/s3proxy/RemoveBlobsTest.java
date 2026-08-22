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

import java.util.List;
import java.util.Set;
import java.util.concurrent.BrokenBarrierException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;

import com.google.common.collect.ImmutableList;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.awscore.exception.AwsErrorDetails;
import software.amazon.awssdk.services.s3.model.Delete;
import software.amazon.awssdk.services.s3.model.DeleteObjectResponse;
import software.amazon.awssdk.services.s3.model.DeleteObjectsRequest;
import software.amazon.awssdk.services.s3.model.DeletedObject;
import software.amazon.awssdk.services.s3.model.ObjectIdentifier;
import software.amazon.awssdk.services.s3.model.S3Error;
import software.amazon.awssdk.services.s3.model.S3Exception;

/**
 * Covers the parallel removeBlobs the BlobStore interface supplies to every
 * store that has no bulk delete of its own.
 */
public final class RemoveBlobsTest {
    private static final String CONTAINER = "container";

    @Test
    public void testRemovesEveryObject() {
        var blobStore = new RecordingBlobStore();
        var keys = new ImmutableList.Builder<String>();
        for (int i = 0; i < 50; ++i) {
            keys.add("key-" + i);
        }
        var expected = keys.build();

        var response = blobStore.removeBlobs(requestFor(expected));

        assertThat(blobStore.removed).containsExactlyInAnyOrderElementsOf(
                expected);
        assertThat(response.deleted()).extracting(DeletedObject::key)
                .containsExactlyElementsOf(expected);
        assertThat(response.errors()).isEmpty();
    }

    @Test
    public void testRemovesTheOnlyObject() {
        var blobStore = new RecordingBlobStore();

        var response = blobStore.removeBlobs(
                requestFor(ImmutableList.of("only")));

        assertThat(blobStore.removed).containsExactly("only");
        assertThat(response.deleted()).extracting(DeletedObject::key)
                .containsExactly("only");
    }

    @Test
    public void testRemovesNothingWhenGivenNothing() {
        var blobStore = new RecordingBlobStore();

        var response = blobStore.removeBlobs(
                requestFor(ImmutableList.of()));

        assertThat(blobStore.removed).isEmpty();
        assertThat(response.deleted()).isEmpty();
        assertThat(response.errors()).isEmpty();
    }

    /**
     * The deletes overlap rather than running one after another.  Every key
     * waits at a barrier that only a concurrent implementation can clear, so
     * a sequential one leaves the first waiter to time out.
     */
    @Test
    public void testDeletesRunConcurrently() {
        var blobStore = new BarrierBlobStore(BlobStore.REMOVE_BLOBS_THREADS);
        var keys = new ImmutableList.Builder<String>();
        for (int i = 0; i < BlobStore.REMOVE_BLOBS_THREADS; ++i) {
            keys.add("key-" + i);
        }

        blobStore.removeBlobs(requestFor(keys.build()));

        assertThat(blobStore.timeouts.get()).isZero();
        assertThat(blobStore.removed).hasSize(BlobStore.REMOVE_BLOBS_THREADS);
    }

    /**
     * One key failing is reported against that key and leaves the rest
     * deleted, which is what DeleteObjects answers: a 200 carrying an Error
     * element for each key the store refused.
     */
    @Test
    public void testReportsTheRefusedObjectAndRemovesTheRest() {
        var blobStore = new RecordingBlobStore("bad");

        var response = blobStore.removeBlobs(requestFor(
                ImmutableList.of("first", "bad", "last")));

        assertThat(blobStore.removed).containsExactlyInAnyOrder(
                "first", "last");
        assertThat(response.deleted()).extracting(DeletedObject::key)
                .containsExactly("first", "last");
        assertThat(response.errors()).hasSize(1);
        S3Error error = response.errors().get(0);
        assertThat(error.key()).isEqualTo("bad");
        assertThat(error.code()).isEqualTo("InvalidArgument");
        assertThat(error.message()).contains("bad");
    }

    /** Each refusal is reported, in the order the request named them. */
    @Test
    public void testReportsEveryRefusalInOrder() {
        var blobStore = new RecordingBlobStore("second", "third");

        var response = blobStore.removeBlobs(requestFor(
                ImmutableList.of("first", "second", "third", "fourth")));

        assertThat(response.errors()).extracting(S3Error::key)
                .containsExactly("second", "third");
        assertThat(response.deleted()).extracting(DeletedObject::key)
                .containsExactly("first", "fourth");
    }

    /**
     * A store that does not implement the operation at all has refused the
     * request, not the keys: reporting it against each key would read as
     * though those keys in particular could not be deleted.
     */
    @Test
    public void testThrowsWhenTheRequestItselfIsRefused() {
        var blobStore = new UnimplementedBlobStore();

        assertThatThrownBy(() -> blobStore.removeBlobs(requestFor(
                ImmutableList.of("first", "second"))))
                .isInstanceOf(S3Exception.class)
                .hasMessageContaining("NotImplemented");
    }

    /** A versioned delete reports the marker it wrote over the object. */
    @Test
    public void testReportsTheDeleteMarker() {
        var blobStore = new VersionedBlobStore();

        var response = blobStore.removeBlobs(requestFor(
                ImmutableList.of("key")));

        assertThat(response.deleted()).hasSize(1);
        DeletedObject removed = response.deleted().get(0);
        assertThat(removed.key()).isEqualTo("key");
        assertThat(removed.deleteMarker()).isTrue();
        assertThat(removed.deleteMarkerVersionId()).isEqualTo("marker-1");
    }

    private static DeleteObjectsRequest requestFor(List<String> keys) {
        var objects = new ImmutableList.Builder<ObjectIdentifier>();
        for (String key : keys) {
            objects.add(ObjectIdentifier.builder().key(key).build());
        }
        return DeleteObjectsRequest.builder()
                .bucket(CONTAINER)
                .delete(Delete.builder().objects(objects.build()).build())
                .build();
    }

    private static S3Exception refusal(String code, String message) {
        return (S3Exception) S3Exception.builder()
                .awsErrorDetails(AwsErrorDetails.builder()
                        .errorCode(code)
                        .errorMessage(message)
                        .build())
                .message(code + ": " + message)
                .build();
    }

    /** Refuses every key the same way, as an unimplemented store would. */
    private static final class UnimplementedBlobStore
            extends AbstractUnsupportedBlobStore {
        @Override
        public void removeBlob(String container, String name) {
            throw refusal("NotImplemented",
                    "This operation is not implemented.");
        }
    }

    /** Versions its objects, so a delete leaves a marker to report. */
    private static final class VersionedBlobStore
            extends AbstractUnsupportedBlobStore {
        @Override
        public boolean supportsVersioning() {
            return true;
        }

        @Override
        public DeleteObjectResponse removeBlob(String container, String name,
                @Nullable String versionId) {
            return DeleteObjectResponse.builder()
                    .deleteMarker(true)
                    .versionId("marker-1")
                    .build();
        }

        @Override
        public void removeBlob(String container, String name) {
            throw new UnsupportedOperationException();
        }
    }

    /** Records what it was asked to delete, refusing the named few. */
    private static class RecordingBlobStore
            extends AbstractUnsupportedBlobStore {
        private final Set<String> removed = ConcurrentHashMap.newKeySet();
        private final Set<String> refused;

        RecordingBlobStore(String... refused) {
            this.refused = Set.of(refused);
        }

        @Override
        public void removeBlob(String container, String name) {
            if (refused.contains(name)) {
                throw refusal("InvalidArgument",
                        "refusing to delete " + name);
            }
            removed.add(name);
        }
    }

    /** Holds every delete until the expected number are in flight at once. */
    private static class BarrierBlobStore
            extends AbstractUnsupportedBlobStore {
        private final Set<String> removed = ConcurrentHashMap.newKeySet();
        private final AtomicInteger timeouts = new AtomicInteger();
        private final CyclicBarrier barrier;

        BarrierBlobStore(int parties) {
            this.barrier = new CyclicBarrier(parties);
        }

        @Override
        public void removeBlob(String container, String name) {
            try {
                barrier.await(10, TimeUnit.SECONDS);
            } catch (TimeoutException | BrokenBarrierException e) {
                // The first waiter times out when nothing joins it and
                // breaks the barrier, which the rest then report.
                timeouts.incrementAndGet();
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                timeouts.incrementAndGet();
            }
            removed.add(name);
        }
    }

}
