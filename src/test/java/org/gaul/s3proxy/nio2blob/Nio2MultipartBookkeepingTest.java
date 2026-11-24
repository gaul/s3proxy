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
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.CompletedPart;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.UploadPartRequest;

/**
 * The store reads an upload id and a blob name back out of each stub's file
 * name.  A name it did not write -- left in the container by hand, or by a
 * client back when the namespace was writable -- must not decide whether the
 * bucket's real uploads can be listed at all.
 */
public final class Nio2MultipartBookkeepingTest {
    private static final String CONTAINER = "container";

    @TempDir
    private Path root;
    private FilesystemNio2BlobStore blobStore;

    @BeforeEach
    public void setUp() {
        blobStore = new FilesystemNio2BlobStore(root.toString());
        blobStore.createContainer(CONTAINER);
    }

    /**
     * The fallback the join takes where the kernel declines to copy leaves
     * the destination open for the parts still to come.
     */
    @Test
    public void testCopyRemainderLeavesTheDestinationOpen() throws Exception {
        Path first = Files.write(root.resolve("first"), new byte[] {1, 2, 3});
        Path second = Files.write(root.resolve("second"), new byte[] {4, 5});
        Path joined = root.resolve("joined");
        try (var dst = FileChannel.open(joined, StandardOpenOption.CREATE,
                StandardOpenOption.WRITE)) {
            for (Path part : new Path[] {first, second}) {
                try (var src = FileChannel.open(part,
                        StandardOpenOption.READ)) {
                    // from the second byte, as after a partial transfer
                    dst.write(java.nio.ByteBuffer.wrap(
                            new byte[] {Files.readAllBytes(part)[0]}));
                    AbstractNio2BlobStore.copyRemainder(src, 1, dst);
                }
                assertThat(dst.isOpen()).isTrue();
            }
            assertThat(dst.size()).isEqualTo(5);
        }
        assertThat(Files.readAllBytes(joined)).containsExactly(1, 2, 3, 4, 5);
    }

    /**
     * An upload's stub and parts lie in a directory of the store's own,
     * not among the bucket's objects, so that listing them reads that
     * directory rather than every entry of the container -- and the
     * directory goes once nothing is in flight.
     */
    @Test
    public void testBookkeepingIsKeptOutOfTheContainer() throws Exception {
        var container = root.resolve(CONTAINER);
        for (String key : List.of("blob", "dir/blob")) {
            var mpu = blobStore.initiateMultipartUpload(
                    CreateMultipartUploadRequest.builder()
                            .bucket(CONTAINER).key(key).build());
            var etag = blobStore.uploadMultipartPart(mpu,
                    UploadPartRequest.builder().bucket(CONTAINER).key(key)
                            .uploadId(mpu.id()).partNumber(1)
                            .contentLength(4L).build(),
                    new ByteArrayInputStream(new byte[4])).eTag();
            try (var entries = Files.list(container)) {
                assertThat(entries.map(p -> p.getFileName().toString()))
                        .as(key).containsExactly(".s3proxy-mpus");
            }
            assertThat(blobStore.listMultipartUploads(CONTAINER))
                    .extracting(u -> u.key()).containsExactly(key);
            assertThat(blobStore.listMultipartUpload(mpu)).hasSize(1);

            blobStore.completeMultipartUpload(mpu,
                    CompleteMultipartUploadRequest.builder()
                            .bucket(CONTAINER).key(key).uploadId(mpu.id())
                            .multipartUpload(m -> m.parts(CompletedPart
                                    .builder().partNumber(1).eTag(etag)
                                    .build()))
                            .build());
            assertThat(container.resolve(".s3proxy-mpus")).doesNotExist();
            blobStore.removeBlob(CONTAINER, key);
        }
    }

    @Test
    public void testUnparsableStubNamesAreIgnored() throws Exception {
        var bookkeeping = Files.createDirectories(
                root.resolve(CONTAINER).resolve(".s3proxy-mpus"));
        // Too short to hold an upload id at all.
        Files.createFile(bookkeeping.resolve("short-stub"));
        // Long enough, but naming no blob: the id runs into the suffix.
        Files.createFile(bookkeeping.resolve(
                "00000000-0000-0000-0000-000000000000-stub"));

        assertThat(blobStore.listMultipartUploads(CONTAINER)).isEmpty();
    }

    @Test
    public void testRealUploadsStillListBesideAnUnparsableStub()
            throws Exception {
        var mpu = blobStore.initiateMultipartUpload(
                CreateMultipartUploadRequest.builder()
                        .bucket(CONTAINER).key("blob").build());
        Files.createFile(root.resolve(CONTAINER).resolve(".s3proxy-mpus")
                .resolve("short-stub"));

        var uploads = blobStore.listMultipartUploads(CONTAINER);
        assertThat(uploads).hasSize(1);
        assertThat(uploads.get(0).uploadId()).isEqualTo(mpu.id());
        assertThat(uploads.get(0).key()).isEqualTo("blob");
    }
}
