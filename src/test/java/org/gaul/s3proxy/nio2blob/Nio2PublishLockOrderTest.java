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
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.PutObjectRequest;

/**
 * A put claiming its key with If-None-Match: * and a put publishing through
 * publish() take the same two locks, in the same order.
 */
public final class Nio2PublishLockOrderTest {
    private static final String CONTAINER = "container";
    private static final byte[] CONTENT =
            "content".getBytes(StandardCharsets.UTF_8);
    /** How long the puts race for. */
    private static final long RACE_NANOS = 2_000_000_000L;
    /** Half claim their keys and half do not. */
    private static final int RACERS = 8;

    @Test
    public void testConditionalAndPlainPutsRacing() throws Exception {
        var store = new TransientNio2BlobStore();
        store.createContainer(CONTAINER);
        var keys = new AtomicInteger();
        var failure = new AtomicReference<Throwable>();
        long deadline = System.nanoTime() + RACE_NANOS;
        var threads = new ArrayList<Thread>();
        for (int i = 0; i < RACERS; ++i) {
            String ifNoneMatch = i % 2 == 0 ? "*" : null;
            var thread = new Thread(() -> {
                try {
                    while (System.nanoTime() < deadline) {
                        String key = "key-" + keys.incrementAndGet();
                        store.putBlob(PutObjectRequest.builder()
                                        .bucket(CONTAINER)
                                        .key(key)
                                        .contentLength((long) CONTENT.length)
                                        .ifNoneMatch(ifNoneMatch)
                                        .build(),
                                new ByteArrayInputStream(CONTENT));
                        store.removeBlob(CONTAINER, key);
                    }
                } catch (RuntimeException e) {
                    failure.compareAndSet(null, e);
                }
            });
            thread.setDaemon(true);
            threads.add(thread);
        }
        threads.forEach(Thread::start);
        for (var thread : threads) {
            thread.join(TimeUnit.SECONDS.toMillis(30));
            assertThat(thread.isAlive()).as("put still waiting").isFalse();
        }
        assertThat(failure.get()).isNull();
    }
}
