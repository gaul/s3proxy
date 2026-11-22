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
import java.io.ByteArrayOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Random;

import com.google.common.io.ByteSource;
import com.google.common.jimfs.Configuration;
import com.google.common.jimfs.Jimfs;

import org.gaul.s3proxy.TestUtils;
import org.gaul.s3proxy.blobstore.SdkRequests;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import software.amazon.awssdk.services.s3.model.CompletedPart;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;

/**
 * A write seeks over the zeros it is handed rather than storing them, which
 * must never show in what is read back: the same bytes, the same length, the
 * same ETag.  Issue #538.
 */
public final class Nio2SparseWriteTest {
    private static final String CONTAINER = "container";
    private static final int BLOCK = 4096;
    private static final int BUFFER = 16 * BLOCK;

    @TempDir
    private Path root;

    @Test
    public void testEmpty() throws Exception {
        assertRoundTrips(new byte[0]);
    }

    @Test
    public void testSingleZero() throws Exception {
        assertRoundTrips(new byte[1]);
    }

    @Test
    public void testAllZerosShortOfABlock() throws Exception {
        assertRoundTrips(new byte[BLOCK - 1]);
    }

    @Test
    public void testAllZerosAcrossBuffers() throws Exception {
        assertRoundTrips(new byte[3 * BUFFER]);
        assertRoundTrips(new byte[3 * BUFFER + 1]);
        assertRoundTrips(new byte[3 * BUFFER - 1]);
    }

    @Test
    public void testNoZeros() throws Exception {
        var content = new byte[2 * BUFFER + 17];
        Arrays.fill(content, (byte) 1);
        assertRoundTrips(content);
    }

    @Test
    public void testHoleAtTheStart() throws Exception {
        var content = new byte[BUFFER + BLOCK];
        content[content.length - 1] = 1;
        assertRoundTrips(content);
    }

    @Test
    public void testHoleAtTheEnd() throws Exception {
        var content = new byte[BUFFER + BLOCK + 5];
        content[0] = 1;
        assertRoundTrips(content);
    }

    @Test
    public void testHoleInTheMiddle() throws Exception {
        var content = new byte[4 * BUFFER];
        content[BLOCK - 1] = 1;
        content[3 * BUFFER + BLOCK] = 1;
        assertRoundTrips(content);
    }

    /** A block with one byte set, at either edge, is not a hole. */
    @Test
    public void testBlockEdges() throws Exception {
        var content = new byte[8 * BLOCK];
        content[2 * BLOCK] = 1;
        content[5 * BLOCK - 1] = 1;
        assertRoundTrips(content);
    }

    @Test
    public void testRandomRuns() throws Exception {
        var random = new Random(538);
        for (int i = 0; i < 50; ++i) {
            var content = new byte[random.nextInt(6 * BUFFER)];
            int offset = 0;
            while (offset < content.length) {
                int run = Math.min(1 + random.nextInt(3 * BLOCK),
                        content.length - offset);
                if (random.nextBoolean()) {
                    var data = new byte[run];
                    random.nextBytes(data);
                    System.arraycopy(data, 0, content, offset, run);
                }
                offset += run;
            }
            assertRoundTrips(content);
        }
    }

    /** What the store hands back is what a dense write would have. */
    @Test
    public void testPutThroughTheStore() throws Exception {
        var content = new byte[2 * BUFFER + 100];
        content[BUFFER + 7] = 42;
        var store = new FilesystemNio2BlobStore(root.toString());
        store.createContainer(CONTAINER);

        var put = TestUtils.putBlob(store, CONTAINER, "key",
                ByteSource.wrap(content));

        assertThat(put.eTag()).contains(
                HexFormat.of().formatHex(MessageDigest.getInstance("MD5")
                        .digest(content)));
        assertThat(store.blobMetadata(CONTAINER, "key").contentLength())
                .isEqualTo(content.length);
        assertThat(Files.readAllBytes(root.resolve(CONTAINER).resolve("key")))
                .isEqualTo(content);
    }

    /** Blocks of zeros are counted as holes, and nothing else is. */
    @Test
    public void testHolesAreCounted() throws Exception {
        var content = new byte[4 * BLOCK + 10];
        content[BLOCK] = 1;
        Path path = Files.createTempFile(root, "sparse", null);
        try (var dst = Files.newByteChannel(path, StandardOpenOption.WRITE)) {
            assertThat(AbstractNio2BlobStore.writeSparse(
                    new ByteArrayInputStream(content), dst))
                    .isEqualTo(3 * BLOCK + 10);
        }
        var dense = new byte[BLOCK];
        Arrays.fill(dense, (byte) 1);
        try (var dst = Files.newByteChannel(path, StandardOpenOption.WRITE,
                StandardOpenOption.TRUNCATE_EXISTING)) {
            assertThat(AbstractNio2BlobStore.writeSparse(
                    new ByteArrayInputStream(dense), dst)).isZero();
        }
    }

    /** A second stream lands after the first, holes and all. */
    @Test
    public void testAppends() throws Exception {
        var first = new byte[BLOCK + 3];
        first[0] = 1;
        var second = new byte[2 * BLOCK];
        second[BLOCK + 1] = 2;
        Path path = Files.createTempFile(root, "sparse", null);
        try (var dst = Files.newByteChannel(path, StandardOpenOption.WRITE)) {
            AbstractNio2BlobStore.writeSparse(
                    new ByteArrayInputStream(first), dst);
            assertThat(dst.position()).isEqualTo(first.length);
            AbstractNio2BlobStore.writeSparse(
                    new ByteArrayInputStream(second), dst);
            assertThat(dst.position()).isEqualTo(
                    first.length + second.length);
        }
        var expected = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, expected, first.length, second.length);
        assertThat(Arrays.equals(Files.readAllBytes(path), expected))
                .isTrue();
    }

    /**
     * A multipart upload of sparse and dense parts reads back as its parts
     * end to end.
     */
    @Test
    public void testMultipartThroughTheStore() throws Exception {
        var store = new FilesystemNio2BlobStore(root.toString());
        store.createContainer(CONTAINER);
        var sparse = new byte[BUFFER + 11];
        sparse[BLOCK] = 7;
        var zeros = new byte[BUFFER];
        var dense = new byte[BLOCK + 1];
        Arrays.fill(dense, (byte) 9);
        var mpu = store.initiateMultipartUpload(
                CreateMultipartUploadRequest.builder()
                        .bucket(CONTAINER).key("key").build());
        var parts = new ArrayList<CompletedPart>();
        var expected = new ByteArrayOutputStream();
        int number = 0;
        for (var content : new byte[][] {sparse, zeros, dense, zeros}) {
            var part = TestUtils.uploadPart(store, mpu, ++number,
                    new ByteArrayInputStream(content), content.length);
            parts.add(CompletedPart.builder().partNumber(number)
                    .eTag(part.eTag()).build());
            expected.write(content);
        }

        store.completeMultipartUpload(mpu,
                SdkRequests.completeRequest(mpu, parts));

        assertThat(Arrays.equals(
                Files.readAllBytes(root.resolve(CONTAINER).resolve("key")),
                expected.toByteArray())).isTrue();
    }

    private void assertRoundTrips(byte[] content) throws Exception {
        // A filesystem that keeps holes, where the temporary directory lies
        // on one, and one that does not.
        assertRoundTrips(Files.createTempFile(root, "sparse", null), content);
        try (FileSystem jimfs = Jimfs.newFileSystem(Configuration.unix())) {
            assertRoundTrips(Files.createFile(jimfs.getPath("/file")),
                    content);
        }
    }

    private static void assertRoundTrips(Path path, byte[] content)
            throws Exception {
        for (boolean trickle : new boolean[] {false, true}) {
            try (var dst = Files.newByteChannel(path,
                    StandardOpenOption.WRITE,
                    StandardOpenOption.TRUNCATE_EXISTING)) {
                InputStream is = new ByteArrayInputStream(content);
                if (trickle) {
                    is = new TrickleInputStream(is);
                }
                assertThat(AbstractNio2BlobStore.writeSparse(is, dst))
                        .isBetween(0L, (long) content.length);
            }
            assertThat(Files.size(path)).isEqualTo(content.length);
            assertThat(Arrays.equals(Files.readAllBytes(path), content))
                    .isTrue();
        }
    }

    /** Hands over fewer bytes than asked for, as a socket does. */
    private static final class TrickleInputStream extends FilterInputStream {
        TrickleInputStream(InputStream is) {
            super(is);
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            return super.read(b, off, Math.min(len, 1000));
        }
    }
}
