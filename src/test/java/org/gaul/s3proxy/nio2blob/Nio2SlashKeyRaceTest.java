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

package org.gaul.s3proxy.nio2blob;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.BucketVersioningStatus;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.HeadObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

/**
 * "key" and "key/" share a path, which is also the directory of the keys
 * below "key/".  A request naming the directory looks at the path and then
 * acts through it, and must not act on the object "key" that is published
 * there in between: each of these gave it the directory marker's metadata,
 * or deleted it, within a few hundred writes.
 */
public final class Nio2SlashKeyRaceTest {
    private static final String CONTAINER = "container";
    private static final String KEY = "key";
    private static final byte[] CONTENT =
            "content".getBytes(StandardCharsets.UTF_8);
    private static final int ATTEMPTS = 2_000;

    private TransientNio2BlobStore store;

    @BeforeEach
    public void setUp() {
        store = new TransientNio2BlobStore();
        store.createContainer(CONTAINER);
    }

    @Test
    public void testPutOfSlashKeyLeavesObjectBeingWritten() throws Exception {
        assertWritesSurvive(() -> put(KEY + "/", Map.of("marker", "true")));
    }

    @Test
    public void testPutOfSlashKeyLeavesVersionBeingWritten()
            throws Exception {
        store.putBucketVersioning(CONTAINER, BucketVersioningStatus.ENABLED);
        assertWritesSurvive(() -> put(KEY + "/", Map.of("marker", "true")));
    }

    @Test
    public void testDeleteOfSlashKeyLeavesVersionBeingWritten()
            throws Exception {
        store.putBucketVersioning(CONTAINER, BucketVersioningStatus.ENABLED);
        assertWritesSurvive(() -> delete(KEY + "/"));
    }

    @Test
    public void testDeleteOfKeyLeavesVersionWrittenOverDirectory()
            throws Exception {
        store.putBucketVersioning(CONTAINER, BucketVersioningStatus.ENABLED);
        // A delete that finds the directory of "key/" has nothing to delete,
        // whatever is written there next.
        assertWritesSurvive(() -> {
            put(KEY + "/", Map.of());
            String marker = delete(KEY);
            if (marker != null) {
                // It found the version instead, and left a marker on it.
                store.removeBlob(CONTAINER, KEY, marker);
            }
        });
    }

    @Test
    public void testDeleteBelowKeyLeavesVersionBeingWritten()
            throws Exception {
        store.putBucketVersioning(CONTAINER, BucketVersioningStatus.ENABLED);
        // Deleting the last key below "key/" removes the directory.
        assertWritesSurvive(() -> {
            put(KEY + "/below/", Map.of());
            delete(KEY + "/below/");
        });
    }

    @Test
    public void testFailedPutBelowKeyLeavesVersionBeingWritten()
            throws Exception {
        store.putBucketVersioning(CONTAINER, BucketVersioningStatus.ENABLED);
        // So does a write below "key/" that stores nothing.
        String mismatch = Base64.getEncoder().encodeToString(new byte[16]);
        assertWritesSurvive(() -> store.putBlob(PutObjectRequest.builder()
                .bucket(CONTAINER).key(KEY + "/below").contentMD5(mismatch)
                .contentLength((long) CONTENT.length).build(),
                new ByteArrayInputStream(CONTENT)));
    }

    /**
     * Writes the key again and again while other threads repeat a request,
     * and expects to read each object back as it was written.
     */
    private void assertWritesSurvive(Runnable request) throws Exception {
        // Held shared by each request, so that taking it exclusively waits
        // for the ones that raced a write to be over.
        var requests = new ReentrantReadWriteLock();
        var stop = new AtomicBoolean();
        var threads = new ArrayList<Thread>();
        for (int i = 0; i < 2; ++i) {
            threads.add(new Thread(() -> {
                while (!stop.get()) {
                    requests.readLock().lock();
                    try {
                        request.run();
                    } catch (RuntimeException re) {
                        // refused while the path holds the other key
                    } finally {
                        requests.readLock().unlock();
                    }
                }
            }));
        }
        threads.forEach(Thread::start);
        try {
            for (int i = 0; i < ATTEMPTS; ++i) {
                String versionId;
                try {
                    versionId = put(KEY, Map.of());
                } catch (RuntimeException re) {
                    // refused while the path holds the keys below "key/"
                    continue;
                }
                // Reads take no lock in the store, and one that raced a
                // request says nothing about what the write came to.
                requests.writeLock().lock();
                try {
                    var written = store.blobMetadata(
                            HeadObjectRequest.builder().bucket(CONTAINER)
                                    .key(KEY).versionId(versionId).build());
                    assertThat(written.contentLength())
                            .isEqualTo(CONTENT.length);
                    assertThat(written.metadata()).isEmpty();
                    // In a versioned container only naming the version
                    // removes it.
                    store.removeBlob(CONTAINER, KEY, versionId);
                } finally {
                    requests.writeLock().unlock();
                }
            }
        } finally {
            stop.set(true);
            for (var thread : threads) {
                thread.join();
            }
        }
    }

    /** Returns the version id the write was given, if it was given one. */
    @Nullable
    private String put(String key, Map<String, String> metadata) {
        byte[] content = key.endsWith("/") ? new byte[0] : CONTENT;
        return store.putBlob(PutObjectRequest.builder()
                .bucket(CONTAINER).key(key).metadata(metadata)
                .contentLength((long) content.length).build(),
                new ByteArrayInputStream(content)).versionId();
    }

    /** Returns the id of the delete marker this left, if it left one. */
    @Nullable
    private String delete(String key) {
        return store.removeBlob(DeleteObjectRequest.builder()
                .bucket(CONTAINER).key(key).build()).versionId();
    }
}
