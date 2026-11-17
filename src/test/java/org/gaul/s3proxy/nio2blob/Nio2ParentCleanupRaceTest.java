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
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.PutObjectRequest;

/**
 * A delete removes the directories it leaves empty.  A write into the same
 * directory makes sure of the directory and then moves its file in, and a
 * delete landing between the two took the directory away: the write failed
 * with NoSuchFileException, answered 500.
 */
public final class Nio2ParentCleanupRaceTest {
    private static final String CONTAINER = "container";
    private static final int ROUNDS = 3_000;

    private static void write(TransientNio2BlobStore store, String key) {
        byte[] content = "content".getBytes(StandardCharsets.UTF_8);
        store.putBlob(PutObjectRequest.builder()
                        .bucket(CONTAINER).key(key)
                        .contentLength((long) content.length)
                        .build(),
                new ByteArrayInputStream(content));
    }

    @Test
    public void testWriteRacingTheCleanupOfItsDirectory() throws Exception {
        var store = new TransientNio2BlobStore();
        store.createContainer(CONTAINER);

        var failure = new AtomicReference<Throwable>();
        var ready = new CountDownLatch(1);
        var threads = new ArrayList<Thread>();
        // Each thread fills and empties the same deep directory, so every
        // delete leaves it empty for a moment and removes it.
        for (int i = 0; i < 4; ++i) {
            String key = "a/b/c/key-" + i;
            threads.add(new Thread(() -> {
                try {
                    ready.await();
                    for (int round = 0; round < ROUNDS; ++round) {
                        write(store, key);
                        store.removeBlob(CONTAINER, key);
                    }
                } catch (Throwable t) {
                    failure.compareAndSet(null, t);
                }
            }));
        }
        threads.forEach(Thread::start);
        ready.countDown();
        for (var thread : threads) {
            thread.join();
        }

        assertThat(failure.get()).isNull();
    }
}
