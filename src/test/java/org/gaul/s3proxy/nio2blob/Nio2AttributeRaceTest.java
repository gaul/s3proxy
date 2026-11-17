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
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

/**
 * A read lists a file's attributes and then reads each by name, and both
 * go through the path.  An overwrite renames a new file over the key, so
 * one landing in between leaves the read asking the new file for a name
 * only the old one had.  That failed the read -- 500, or 400 on the
 * in-memory store -- where either version of the object would have done.
 */
public final class Nio2AttributeRaceTest {
    private static final String CONTAINER = "container";
    private static final String KEY = "key";
    private static final int ROUNDS = 5_000;

    @Test
    public void testReadRacingAnOverwriteWithOtherMetadata() throws Exception {
        var store = new TransientNio2BlobStore();
        store.createContainer(CONTAINER);
        write(store, 0);

        var failure = new AtomicReference<Throwable>();
        var stop = new AtomicBoolean();
        var reader = new Thread(() -> {
            try {
                while (!stop.get()) {
                    var head = store.blobMetadata(CONTAINER, KEY);
                    assertThat(head.metadata()).hasSize(1);
                    try (var blob = store.getBlob(GetObjectRequest.builder()
                            .bucket(CONTAINER).key(KEY).build())) {
                        assertThat(blob.response().metadata()).hasSize(1);
                    }
                }
            } catch (Throwable t) {
                failure.compareAndSet(null, t);
            }
        });
        reader.start();
        // each write carries a metadata name the one before it did not
        for (int round = 1; round < ROUNDS && failure.get() == null;
                ++round) {
            write(store, round);
        }
        stop.set(true);
        reader.join();

        assertThat(failure.get()).isNull();
    }

    private static void write(TransientNio2BlobStore store, int round) {
        byte[] content = "content".getBytes(StandardCharsets.UTF_8);
        store.putBlob(PutObjectRequest.builder()
                        .bucket(CONTAINER).key(KEY)
                        .contentLength((long) content.length)
                        .metadata(Map.of("name-" + round % 7, "value"))
                        .build(),
                new ByteArrayInputStream(content));
    }
}
