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

import java.io.ByteArrayInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import software.amazon.awssdk.services.s3.model.BucketVersioningStatus;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.S3Exception;

/**
 * A write makes the directories of its key, reads its body, and only then
 * renames the finished file into them.  Until then they may be empty, and
 * an empty directory is removed by whatever else finishes in it: a write
 * that fails, or a delete of the last key there.  The write that was still
 * reading its body then found no directory to publish into and was answered
 * 500 InternalError, so that whoever could begin a write below a prefix and
 * abandon it kept everybody else's out of it.
 */
public final class Nio2DirectoryInUseTest {
    private static final String CONTAINER = "container";
    private static final byte[] CONTENT = "content".getBytes(
            StandardCharsets.UTF_8);

    @TempDir
    private Path root;
    private AbstractNio2BlobStore blobStore;

    @BeforeEach
    public void setUp() {
        blobStore = new FilesystemNio2BlobStore(root.toString());
        blobStore.createContainer(CONTAINER);
    }

    @Test
    public void testWriteOutlastsFailedWriteToItsDirectory()
            throws Exception {
        put("dir/sub/blob", during(() -> putFails("dir/sub/other")), null);

        assertThat(blobStore.blobExists(CONTAINER, "dir/sub/blob")).isTrue();
        assertThat(blobStore.blobExists(CONTAINER, "dir/sub/other"))
                .isFalse();
    }

    @Test
    public void testWriteOutlastsDeleteOfLastKeyInItsDirectory()
            throws Exception {
        put("dir/old", new ByteArrayInputStream(CONTENT), null);

        put("dir/blob", during(
                () -> blobStore.removeBlob(CONTAINER, "dir/old")), null);

        assertThat(blobStore.blobExists(CONTAINER, "dir/blob")).isTrue();
    }

    /** The write that may only create its key publishes with a link. */
    @Test
    public void testConditionalWriteOutlastsFailedWriteToItsDirectory()
            throws Exception {
        put("dir/blob", during(() -> putFails("dir/other")), "*");

        assertThat(blobStore.blobExists(CONTAINER, "dir/blob")).isTrue();
        assertThatThrownBy(() -> put("dir/blob",
                during(() -> putFails("dir/other")), "*"))
                .isInstanceOfSatisfying(S3Exception.class, e ->
                        assertThat(e.statusCode()).isEqualTo(412));
    }

    @Test
    public void testVersionedWriteOutlastsFailedWriteToItsDirectory()
            throws Exception {
        blobStore = new TransientNio2BlobStore();
        blobStore.createContainer(CONTAINER);
        blobStore.putBucketVersioning(CONTAINER,
                BucketVersioningStatus.ENABLED);

        put("dir/blob", during(() -> putFails("dir/other")), null);

        assertThat(blobStore.blobExists(CONTAINER, "dir/blob")).isTrue();
    }

    /**
     * The directories are made again; the container is not.  One deleted
     * while the body arrived stays deleted.
     */
    @Test
    public void testWriteDoesNotBringDeletedContainerBack()
            throws Exception {
        assertThatThrownBy(() -> put("dir/blob", during(() -> {
            putFails("dir/other");
            blobStore.deleteBucket(CONTAINER);
        }), null)).isInstanceOf(RuntimeException.class);

        assertThat(root.resolve(CONTAINER)).doesNotExist();
    }

    /**
     * There are no directories to make again below an object, and the key
     * that cannot be stored there is refused as such: 400, not the 412 of
     * a key that exists.
     */
    @Test
    public void testConditionalWriteBelowAnObjectIsNotAnExistingKey()
            throws Exception {
        blobStore = new TransientNio2BlobStore();
        blobStore.createContainer(CONTAINER);
        put("dir", new ByteArrayInputStream(CONTENT), null);

        assertThatThrownBy(() -> put("dir/blob",
                new ByteArrayInputStream(CONTENT), "*"))
                .isInstanceOfSatisfying(S3Exception.class,
                        e -> assertThat(e.statusCode()).isEqualTo(400));

        assertThat(blobStore.blobExists(CONTAINER, "dir")).isTrue();
        assertThat(blobStore.blobExists(CONTAINER, "dir/blob")).isFalse();
    }

    private void put(String key, InputStream payload,
            String ifNoneMatch) {
        blobStore.putBlob(PutObjectRequest.builder()
                .bucket(CONTAINER).key(key)
                .contentLength((long) CONTENT.length)
                .ifNoneMatch(ifNoneMatch).build(), payload);
    }

    /** A write whose client hangs up before the end of the body. */
    private void putFails(String key) {
        assertThatThrownBy(() -> put(key, new FilterInputStream(
                new ByteArrayInputStream(CONTENT)) {
            @Override
            public int read(byte[] b, int off, int len) throws IOException {
                throw new IOException("client hung up");
            }
        }, null)).isInstanceOf(RuntimeException.class);
    }

    /** A body during whose arrival something else happens in the store. */
    private static InputStream during(Runnable event) {
        return new FilterInputStream(new ByteArrayInputStream(CONTENT)) {
            private boolean happened;

            @Override
            public int read(byte[] b, int off, int len) throws IOException {
                if (!happened) {
                    happened = true;
                    event.run();
                }
                return super.read(b, off, len);
            }
        };
    }
}
