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
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.BucketVersioningStatus;
import software.amazon.awssdk.services.s3.model.ObjectCannedACL;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

/**
 * The current version of a key is the file at the key's own path, and a
 * write publishes its successor by renaming over that.  Access given to a
 * version has to reach the version it was given to all the same: set by way
 * of the path after another write had landed there, public-read went to an
 * object stored private, which nothing had ever asked to publish.
 */
public final class Nio2VersionAccessRaceTest {
    private static final String CONTAINER = "container";
    private static final byte[] CONTENT =
            "content".getBytes(StandardCharsets.UTF_8);
    /**
     * How long each test races for.  Every round within it overwrites a
     * fresh key once, which is one chance for a request being repeated to
     * find its version replaced under it.
     */
    private static final long RACE_NANOS = 2_000_000_000L;
    /** Two, so that one is seldom between requests when the write lands. */
    private static final int RACERS = 2;

    private TransientNio2BlobStore store;

    @BeforeEach
    public void setUp() {
        store = new TransientNio2BlobStore();
        store.createContainer(CONTAINER);
        store.putBucketVersioning(CONTAINER, BucketVersioningStatus.ENABLED);
    }

    /** PutObjectAcl of a version, repeated while a write replaces it. */
    @Test
    public void testSetAccessOfVersionRacingOverwrite() throws Exception {
        long deadline = System.nanoTime() + RACE_NANOS;
        for (int round = 0; System.nanoTime() < deadline; ++round) {
            String key = "myobj-" + round;
            String versionId = write(key, ObjectCannedACL.PRIVATE);
            String successor = racing(
                    () -> store.setBlobAccess(CONTAINER, key,
                            ObjectCannedACL.PUBLIC_READ, versionId),
                    () -> write(key, ObjectCannedACL.PRIVATE));

            assertThat(store.getBlobAccess(CONTAINER, key, versionId))
                    .isEqualTo(ObjectCannedACL.PUBLIC_READ);
            assertThat(store.getBlobAccess(CONTAINER, key, successor))
                    .isEqualTo(ObjectCannedACL.PRIVATE);
        }
    }

    /** GetObjectAcl of a private version while a public one replaces it. */
    @Test
    public void testGetAccessOfVersionRacingOverwrite() throws Exception {
        long deadline = System.nanoTime() + RACE_NANOS;
        for (int round = 0; System.nanoTime() < deadline; ++round) {
            String key = "myobj-" + round;
            String versionId = write(key, ObjectCannedACL.PRIVATE);
            racing(
                    () -> assertThat(
                            store.getBlobAccess(CONTAINER, key, versionId))
                            .isEqualTo(ObjectCannedACL.PRIVATE),
                    () -> write(key, ObjectCannedACL.PUBLIC_READ));
        }
    }

    /** Stores one more version of the key, and returns its id. */
    private String write(String key, ObjectCannedACL access) {
        return store.putBlob(PutObjectRequest.builder()
                        .bucket(CONTAINER).key(key)
                        .contentLength((long) CONTENT.length)
                        .acl(access)
                        .build(),
                new ByteArrayInputStream(CONTENT)).versionId();
    }

    /**
     * Answers {@code write} while other threads repeat {@code request},
     * each of which has made it once before the write begins and stops
     * once it has ended.  Whatever a request throws fails the test.
     */
    private static String racing(Runnable request, Supplier<String> write)
            throws InterruptedException {
        var started = new CountDownLatch(RACERS);
        var stop = new AtomicBoolean();
        var failure = new AtomicReference<Throwable>();
        var threads = new ArrayList<Thread>();
        for (int i = 0; i < RACERS; ++i) {
            threads.add(new Thread(() -> {
                try {
                    do {
                        request.run();
                        started.countDown();
                    } while (!stop.get());
                } catch (RuntimeException | AssertionError e) {
                    failure.compareAndSet(null, e);
                    started.countDown();
                }
            }));
        }
        threads.forEach(Thread::start);
        String result;
        try {
            started.await();
            result = write.get();
        } finally {
            stop.set(true);
            for (Thread thread : threads) {
                thread.join();
            }
        }
        if (failure.get() != null) {
            throw new AssertionError(failure.get());
        }
        return result;
    }
}
