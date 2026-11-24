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

import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import com.google.common.io.ByteSource;

import org.gaul.s3proxy.TestUtils;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.checksum.FlexChecksum;
import org.junit.jupiter.api.Test;

/**
 * A checksum sent as an aws-chunked trailer is attached to the object after
 * it is written, once the store has checked that the key still holds that
 * object.  A write publishing another object between the check and the
 * attribute write had that object labelled with a checksum of other bytes,
 * which SDKs that validate on read then refused.  Here one thread keeps
 * attaching while another keeps replacing the object, and the other object
 * must never carry the checksum.
 */
public final class Nio2TrailerChecksumRaceTest {
    private static final String CONTAINER = "container";
    private static final String KEY = "object";
    private static final ByteSource LABELLED = ByteSource.wrap(
            "the bytes the checksum describes".getBytes(
                    StandardCharsets.UTF_8));
    private static final ByteSource OTHER = ByteSource.wrap(
            "some other bytes".getBytes(StandardCharsets.UTF_8));

    @Test
    public void testChecksumLandsOnlyOnTheObjectItDescribes()
            throws Exception {
        BlobStore blobStore = TestUtils.createTransientBlobStore();
        blobStore.createContainer(CONTAINER);
        String eTag = TestUtils.putBlob(blobStore, CONTAINER, KEY, LABELLED)
                .eTag();
        String metadataKey = FlexChecksum.CRC32.metadataKey();

        var stop = new AtomicBoolean();
        var mislabelled = new AtomicInteger();
        var writer = CompletableFuture.runAsync(() -> {
            try {
                while (!stop.get()) {
                    TestUtils.putBlob(blobStore, CONTAINER, KEY, OTHER);
                    var metadata = blobStore.blobMetadata(CONTAINER, KEY);
                    if (metadata.metadata().containsKey(metadataKey)) {
                        mislabelled.incrementAndGet();
                    }
                    TestUtils.putBlob(blobStore, CONTAINER, KEY, LABELLED);
                }
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });

        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
        while (System.nanoTime() < deadline && mislabelled.get() == 0) {
            blobStore.recordChecksumMetadata(CONTAINER, KEY, eTag,
                    metadataKey, "AAAAAA==");
        }
        stop.set(true);
        writer.get(30, TimeUnit.SECONDS);

        assertThat(mislabelled.get()).isZero();
    }
}
