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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.management.ManagementFactory;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Base64;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;

import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.S3Exception;

/**
 * The transient store keeps its objects on the heap, which it shares with
 * every request.  It used to take Jimfs's defaults, which report the store
 * full at 4 GiB whatever the heap is and keep the blocks of a deleted file
 * for the life of the process: one upload of about the heap's size, refused
 * or not, left the proxy without memory to answer anybody.  Now the store
 * is full at half of the heap, gives back what it no longer holds, and an
 * upload it has no room for is refused like one with the wrong digest, after
 * its body.  Isolated because two of the tests measure the heap, which every
 * other test allocates from.
 */
@Isolated
public final class Nio2TransientMemoryTest {
    private static final String CONTAINER = "container";
    private static final long SIZE = 64L * 1024 * 1024;

    private TransientNio2BlobStore blobStore;

    @BeforeEach
    public void setUp() {
        blobStore = new TransientNio2BlobStore();
        blobStore.createContainer(CONTAINER);
    }

    /** An upload that cannot fit runs out of store, not out of heap. */
    @Test
    public void testStoreIsFullBeforeTheHeapIs() throws Exception {
        assertThat(Files.getFileStore(blobStore.getRoot()).getTotalSpace())
                .isLessThanOrEqualTo(Runtime.getRuntime().maxMemory() / 2);
    }

    /**
     * Read to its end, so that the client is through sending and hears the
     * answer; and out of the store from the moment it did not fit.
     */
    @Test
    public void testUploadWithoutRoomIsReadToItsEnd() throws Exception {
        long room = 1024 * 1024;
        var small = new TransientNio2BlobStore(room);
        small.createContainer(CONTAINER);
        var store = Files.getFileStore(small.getRoot());
        long unallocated = store.getUnallocatedSpace();
        var atEnd = new long[1];
        var body = new FilterInputStream(payload(4 * room)) {
            @Override
            public int read(byte[] b, int off, int len) throws IOException {
                int count = super.read(b, off, len);
                if (count == -1) {
                    atEnd[0] = store.getUnallocatedSpace();
                }
                return count;
            }
        };

        assertThatThrownBy(() -> small.putBlob(PutObjectRequest.builder()
                .bucket(CONTAINER).key("blob").contentLength(4 * room)
                .build(), body))
                .hasRootCauseInstanceOf(IOException.class);

        assertThat(body.read()).isEqualTo(-1);
        assertThat(atEnd[0]).isEqualTo(unallocated);
        assertThat(small.list(CONTAINER).contents()).isEmpty();
        // nor is the store the worse for it
        small.putBlob(PutObjectRequest.builder()
                .bucket(CONTAINER).key("blob").contentLength(room / 2)
                .build(), payload(room / 2));
        assertThat(small.list(CONTAINER).contents()).hasSize(1);
    }

    /** As when the bearer of a presigned URL sends another, larger body. */
    @Test
    public void testRefusedUploadReturnsItsMemory() throws Exception {
        long before = reachableHeap();

        var request = PutObjectRequest.builder()
                .bucket(CONTAINER).key("blob").contentLength(SIZE)
                // the digest of some other body
                .contentMD5(Base64.getEncoder().encodeToString(new byte[16]))
                .build();
        assertThatThrownBy(() -> blobStore.putBlob(request, payload(SIZE)))
                .isInstanceOfSatisfying(S3Exception.class, e ->
                        assertThat(e.statusCode()).isEqualTo(400));

        assertThat(reachableHeap() - before).isLessThan(SIZE / 2);
        // and the store that was measured is still in use
        assertThat(blobStore.list(CONTAINER).contents()).isEmpty();
    }

    @Test
    public void testRemovedBlobReturnsItsMemory() throws Exception {
        long before = reachableHeap();

        blobStore.putBlob(PutObjectRequest.builder()
                .bucket(CONTAINER).key("blob").contentLength(SIZE).build(),
                payload(SIZE));
        assertThat(reachableHeap() - before).isGreaterThan(SIZE / 2);
        blobStore.removeBlob(CONTAINER, "blob");

        assertThat(reachableHeap() - before).isLessThan(SIZE / 2);
        assertThat(blobStore.list(CONTAINER).contents()).isEmpty();
    }

    /** A body that takes no heap of its own. */
    private static InputStream payload(long size) {
        return new InputStream() {
            private long remaining = size;

            @Override
            public int read() {
                if (remaining == 0) {
                    return -1;
                }
                --remaining;
                return 0;
            }

            @Override
            public int read(byte[] b, int off, int len) {
                if (remaining == 0) {
                    return -1;
                }
                int count = (int) Math.min(len, remaining);
                Arrays.fill(b, off, off + count, (byte) 0);
                remaining -= count;
                return count;
            }
        };
    }

    /** What is left in use after a collection. */
    private static long reachableHeap() {
        var memory = ManagementFactory.getMemoryMXBean();
        memory.gc();
        return memory.getHeapMemoryUsage().getUsed();
    }
}
