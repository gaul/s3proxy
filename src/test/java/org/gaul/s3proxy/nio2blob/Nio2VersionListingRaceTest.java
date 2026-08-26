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
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.services.s3.model.BucketVersioningStatus;
import software.amazon.awssdk.services.s3.model.ListObjectVersionsRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

/**
 * The versions of a key live as files in a sidecar directory, so listing
 * them is a readdir followed by a stat of each entry, and anything deleting
 * a version at the same time can take an entry away in between.  A vanished
 * version simply does not appear in the listing; it is not an error, and it
 * was answered as 500 InternalError until this was fixed.
 */
public final class Nio2VersionListingRaceTest {
    private static final String CONTAINER = "container";
    private static final String KEY = "myobj";

    private TransientNio2BlobStore store;

    @BeforeEach
    public void setUp() {
        store = new TransientNio2BlobStore();
        store.createContainer(CONTAINER);
        store.putBucketVersioning(CONTAINER, BucketVersioningStatus.ENABLED);
    }

    private void write() {
        byte[] content = "content".getBytes(StandardCharsets.UTF_8);
        store.putBlob(PutObjectRequest.builder()
                        .bucket(CONTAINER).key(KEY)
                        .contentLength((long) content.length)
                        .build(),
                new ByteArrayInputStream(content));
    }

    @Test
    public void testListVersionsRacingDeletes() throws Exception {
        // Enough versions that a lister is always mid-directory while the
        // deleters work through them.
        for (int i = 0; i < 300; ++i) {
            write();
        }

        var failure = new AtomicReference<Throwable>();
        var stop = new AtomicBoolean();
        var ready = new CountDownLatch(1);
        var threads = new ArrayList<Thread>();

        // Writers keep minting versions, deleters keep taking them away, and
        // a lister reads the directory throughout.  The writers work to a
        // budget: this store keeps its filesystem in memory, and unbounded
        // writing exhausts the heap long before it proves anything.
        var budget = new AtomicInteger(1_500);
        for (int i = 0; i < 2; ++i) {
            threads.add(new Thread(() -> {
                await(ready);
                while (!stop.get() && budget.decrementAndGet() > 0) {
                    try {
                        write();
                    } catch (RuntimeException re) {
                        failure.compareAndSet(null, re);
                        return;
                    }
                }
            }));
        }
        // One deleter, deliberately: more of them empty the directory faster
        // than the writers fill it, and the listings then run short enough
        // that a delete rarely lands inside one.  Outnumbered, it leaves a
        // long directory for every listing to walk.
        threads.add(new Thread(() -> {
            await(ready);
            while (!stop.get()) {
                try {
                    deleteEverythingListed();
                } catch (RuntimeException re) {
                    failure.compareAndSet(null, re);
                    return;
                }
            }
        }));

        threads.forEach(Thread::start);
        ready.countDown();
        long deadline = System.nanoTime() + 2_000_000_000L;
        int listings = 0;
        try {
            while (System.nanoTime() < deadline && failure.get() == null) {
                store.listVersions(ListObjectVersionsRequest.builder()
                        .bucket(CONTAINER).build());
                ++listings;
            }
        } catch (RuntimeException re) {
            failure.compareAndSet(null, re);
        } finally {
            stop.set(true);
            for (Thread thread : threads) {
                thread.join();
            }
        }

        if (failure.get() != null) {
            throw new AssertionError(
                    "listing raced a delete after " + listings + " listings",
                    failure.get());
        }
        assertThat(listings).isGreaterThan(0);
    }

    /**
     * Deletes every version one listing named.  A concurrent write may have
     * archived one out from under this between the listing and the delete,
     * which answers 404 by design and is not what this pins.
     */
    private void deleteEverythingListed() {
        var listing = store.listVersions(ListObjectVersionsRequest.builder()
                .bucket(CONTAINER).build());
        for (var version : listing.versions()) {
            try {
                store.removeBlob(CONTAINER, version.key(),
                        version.versionId());
            } catch (AwsServiceException ase) {
                if (ase.statusCode() != 404) {
                    throw ase;
                }
            }
        }
    }

    private static void await(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(ie);
        }
    }
}
