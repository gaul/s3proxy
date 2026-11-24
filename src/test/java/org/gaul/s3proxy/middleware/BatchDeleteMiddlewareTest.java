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

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import com.google.common.collect.ImmutableBiMap;
import com.google.common.io.ByteSource;

import org.gaul.s3proxy.TestUtils;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.ForwardingBlobStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.Delete;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.DeleteObjectResponse;
import software.amazon.awssdk.services.s3.model.DeleteObjectsRequest;
import software.amazon.awssdk.services.s3.model.DeleteObjectsResponse;
import software.amazon.awssdk.services.s3.model.DeletedObject;
import software.amazon.awssdk.services.s3.model.ObjectIdentifier;

/**
 * A DeleteObjects reaches the backend as a batch through each middleware
 * that can hand one down, so a backend with a bulk delete of its own spends
 * one round trip rather than one a key.  Not forwarding it had sent every
 * key of every batch through the middleware's single delete: a thousand
 * DeleteObject calls to S3, Azure or GCS for one request from the client.
 */
public final class BatchDeleteMiddlewareTest {
    private static final ByteSource CONTENT = ByteSource.wrap(new byte[] {1});

    private BlobStore backend;
    private Recorder recorder;
    private String container;

    /** What reached the backend: its batches, and its single deletes. */
    private static final class Recorder extends ForwardingBlobStore {
        private final List<DeleteObjectsRequest> batches = new ArrayList<>();
        private final List<DeleteObjectRequest> singles = new ArrayList<>();

        Recorder(BlobStore delegate) {
            super(delegate);
        }

        @Override
        public synchronized DeleteObjectsResponse removeBlobs(
                DeleteObjectsRequest request) {
            batches.add(request);
            return delegate().removeBlobs(request);
        }

        @Override
        public DeleteObjectResponse removeBlob(DeleteObjectRequest request) {
            synchronized (this) {
                singles.add(request);
            }
            return delegate().removeBlob(request);
        }

        /** Every key the backend was asked to delete, in any batch. */
        Set<String> batchedKeys() {
            return batches.stream()
                    .flatMap(batch -> batch.delete().objects().stream())
                    .map(ObjectIdentifier::key)
                    .collect(Collectors.toSet());
        }
    }

    @BeforeEach
    public void setUp() {
        backend = TestUtils.createTransientBlobStore();
        recorder = new Recorder(backend);
        container = TestUtils.createRandomContainerName();
    }

    @AfterEach
    public void tearDown() {
        backend.close();
    }

    private static DeleteObjectsRequest deleteRequest(String container,
            List<String> keys) {
        return DeleteObjectsRequest.builder()
                .bucket(container)
                .delete(Delete.builder()
                        .objects(keys.stream()
                                .map(key -> ObjectIdentifier.builder()
                                        .key(key).build())
                                .toList())
                        .build())
                .build();
    }

    private static Set<String> deletedKeys(DeleteObjectsResponse response) {
        assertThat(response.errors()).isEmpty();
        return response.deleted().stream()
                .map(DeletedObject::key)
                .collect(Collectors.toSet());
    }

    private void put(BlobStore store, String container, List<String> keys)
            throws IOException {
        for (String key : keys) {
            TestUtils.putBlob(store, container, key, CONTENT);
        }
    }

    @Test
    public void testAliasSendsOneBatchToTheBackendBucket()
            throws IOException {
        String alias = TestUtils.createRandomContainerName();
        backend.createContainer(container);
        BlobStore store = AliasBlobStore.newAliasBlobStore(recorder,
                ImmutableBiMap.of(alias, container));
        var keys = List.of("a", "b", "c");
        put(store, alias, keys);

        var response = store.removeBlobs(deleteRequest(alias, keys));

        assertThat(deletedKeys(response)).containsExactlyInAnyOrderElementsOf(
                keys);
        assertThat(recorder.singles).isEmpty();
        assertThat(recorder.batches).hasSize(1);
        assertThat(recorder.batches.get(0).bucket()).isEqualTo(container);
        assertThat(backend.list(container).contents()).isEmpty();
    }

    @Test
    public void testPrefixSendsOneBatchOfPrefixedKeys() throws IOException {
        backend.createContainer(container);
        BlobStore store = PrefixBlobStore.newPrefixBlobStore(recorder,
                Map.of(container, "tenant/"));
        var keys = List.of("a", "b", "c");
        put(store, container, keys);
        // the same name outside the prefix is another object
        put(backend, container, List.of("a"));

        var response = store.removeBlobs(deleteRequest(container, keys));

        assertThat(deletedKeys(response)).containsExactlyInAnyOrderElementsOf(
                keys);
        assertThat(recorder.singles).isEmpty();
        assertThat(recorder.batches).hasSize(1);
        assertThat(recorder.batchedKeys()).containsExactlyInAnyOrder(
                "tenant/a", "tenant/b", "tenant/c");
        assertThat(backend.blobExists(container, "a")).isTrue();
        assertThat(backend.blobExists(container, "tenant/a")).isFalse();
    }

    @Test
    public void testRegexSendsOneBatchOfRenamedKeys() throws IOException {
        backend.createContainer(container);
        BlobStore store = RegexBlobStore.newRegexBlobStore(recorder,
                List.of(new SimpleEntry<>(Pattern.compile("^old"), "new")));
        var keys = List.of("old-a", "old-b", "other");
        put(store, container, keys);

        var response = store.removeBlobs(deleteRequest(container, keys));

        assertThat(deletedKeys(response)).containsExactlyInAnyOrderElementsOf(
                keys);
        assertThat(recorder.singles).isEmpty();
        assertThat(recorder.batchedKeys()).containsExactlyInAnyOrder(
                "new-a", "new-b", "other");
        assertThat(backend.list(container).contents()).isEmpty();
    }

    /**
     * Two keys a rule renames onto one object could not each be answered
     * from a batch naming that object once, so they go one at a time.
     */
    @Test
    public void testRegexDeletesKeysRenamedOntoOneObjectOneAtATime()
            throws IOException {
        backend.createContainer(container);
        BlobStore store = RegexBlobStore.newRegexBlobStore(recorder,
                List.of(new SimpleEntry<>(Pattern.compile("^old"), "new")));
        put(store, container, List.of("old-a"));
        var keys = List.of("old-a", "new-a");

        var response = store.removeBlobs(deleteRequest(container, keys));

        assertThat(deletedKeys(response)).containsExactlyInAnyOrderElementsOf(
                keys);
        assertThat(recorder.batches).isEmpty();
        assertThat(recorder.singles).hasSize(2);
        assertThat(backend.list(container).contents()).isEmpty();
    }

    @Test
    public void testShardedSendsOneBatchPerShard() throws IOException {
        int shards = 4;
        String prefix = TestUtils.createRandomContainerName();
        BlobStore store = ShardedBlobStore.newShardedBlobStore(recorder,
                Map.of(container, shards), Map.of(container, prefix));
        store.createContainer(container);
        var keys = new ArrayList<String>();
        for (int i = 0; i < 40; ++i) {
            keys.add("key-" + i);
        }
        put(store, container, keys);

        var response = store.removeBlobs(deleteRequest(container, keys));

        assertThat(deletedKeys(response)).containsExactlyInAnyOrderElementsOf(
                keys);
        assertThat(recorder.singles).isEmpty();
        assertThat(recorder.batches).hasSizeLessThanOrEqualTo(shards);
        assertThat(recorder.batchedKeys()).containsExactlyInAnyOrderElementsOf(
                keys);
        for (var batch : recorder.batches) {
            assertThat(batch.bucket()).startsWith(prefix + "-");
            for (var object : batch.delete().objects()) {
                assertThat(store.blobExists(container, object.key()))
                        .isFalse();
            }
        }
    }

    /** Wrappers that rename nothing hand the request down as it came. */
    @Test
    public void testPassThroughWrappersForwardTheRequest() {
        backend.createContainer(container);
        List<BlobStore> stores = List.of(
                NoCacheBlobStore.newNoCacheBlobStore(recorder),
                NullBlobStore.newNullBlobStore(recorder),
                StorageClassBlobStore.newStorageClassBlobStore(recorder,
                        "STANDARD"),
                UserMetadataReplacerBlobStore
                        .newUserMetadataReplacerBlobStore(recorder, "-", "_"),
                LatencyBlobStore.newLatencyBlobStore(recorder, Map.of(),
                        Map.of()));
        for (BlobStore store : stores) {
            recorder.batches.clear();
            var request = deleteRequest(container, List.of("a", "b"));

            store.removeBlobs(request);

            assertThat(recorder.batches)
                    .as(store.getClass().getSimpleName())
                    .containsExactly(request);
        }
        assertThat(recorder.singles).isEmpty();
    }
}
