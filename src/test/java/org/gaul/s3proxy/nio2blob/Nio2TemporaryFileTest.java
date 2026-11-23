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
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import software.amazon.awssdk.services.s3.model.CopyObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.services.s3.model.S3Object;

/**
 * A write is assembled in a file of its own and renamed onto its key.  That
 * file used to lie beside the key under the key's name and a suffix, where
 * it was an object to every listing and read until the rename, and for good
 * if the process died first.
 */
public final class Nio2TemporaryFileTest {
    private static final String CONTAINER = "container";
    private static final byte[] CONTENT = "content".getBytes(
            StandardCharsets.UTF_8);

    @TempDir
    private Path root;
    private FilesystemNio2BlobStore blobStore;

    @BeforeEach
    public void setUp() {
        blobStore = new FilesystemNio2BlobStore(root.toString());
        blobStore.createContainer(CONTAINER);
    }

    @Test
    public void testWriteInFlightIsNotListed() throws Exception {
        var during = new ArrayList<String>();
        InputStream payload = new FilterInputStream(
                new ByteArrayInputStream(CONTENT)) {
            private boolean listed;

            @Override
            public int read(byte[] b, int off, int len) throws IOException {
                if (!listed) {
                    listed = true;
                    during.addAll(keys());
                }
                return super.read(b, off, len);
            }
        };

        put("dir/blob", payload);

        assertThat(during).isEmpty();
        assertThat(keys()).containsExactly("dir/blob");
    }

    /** The key's own name is all of the file name the key needs. */
    @Test
    public void testKeySegmentOfTheLongestFileName() throws Exception {
        String key = "k".repeat(255);
        put(key, new ByteArrayInputStream(CONTENT));
        assertThat(keys()).containsExactly(key);
    }

    /** What a write that died left behind does not keep the bucket. */
    @Test
    public void testAbandonedWriteGoesWithTheBucket() throws Exception {
        put("blob", new ByteArrayInputStream(CONTENT));
        var temporary = root.resolve(CONTAINER).resolve(".s3proxy-tmp");
        // gone with the write that used it
        assertThat(temporary).doesNotExist();
        Files.createDirectory(temporary);
        Files.createFile(temporary.resolve("abandoned"));

        assertThat(keys()).containsExactly("blob");
        assertThatThrownBy(() -> blobStore.deleteBucket(CONTAINER))
                .isInstanceOf(S3Exception.class);
        // refused for the object, which left the write alone
        assertThat(temporary.resolve("abandoned")).exists();

        // nor does it stop a later write
        put("other", new ByteArrayInputStream(CONTENT));
        assertThat(temporary.resolve("abandoned")).exists();

        blobStore.removeBlob(CONTAINER, "blob");
        blobStore.removeBlob(CONTAINER, "other");
        blobStore.deleteBucket(CONTAINER);
        assertThat(root.resolve(CONTAINER)).doesNotExist();
    }

    @Test
    public void testTemporaryDirectoryIsNotAKey() {
        for (String key : List.of(".s3proxy-tmp", ".s3proxy-tmp/blob")) {
            assertThatThrownBy(() -> put(key,
                    new ByteArrayInputStream(CONTENT)))
                    .isInstanceOfSatisfying(S3Exception.class, e ->
                            assertThat(e.statusCode()).isEqualTo(400));
        }
    }

    /**
     * Nor is what the directory holds an object to a request that names
     * it: a key reaching into the directory read the write in flight
     * there, and went on reading one that died.
     */
    @Test
    public void testTemporaryFileIsNotAnObject() throws Exception {
        var temporary = root.resolve(CONTAINER).resolve(".s3proxy-tmp");
        Files.createDirectory(temporary);
        Files.write(temporary.resolve("abandoned"), CONTENT);

        String key = ".s3proxy-tmp/abandoned";
        assertThatThrownBy(() -> blobStore.getBlob(CONTAINER, key))
                .isInstanceOfSatisfying(S3Exception.class, e ->
                        assertThat(e.statusCode()).isEqualTo(400));
        assertThatThrownBy(() -> blobStore.blobMetadata(CONTAINER, key))
                .isInstanceOfSatisfying(S3Exception.class, e ->
                        assertThat(e.statusCode()).isEqualTo(400));
        assertThatThrownBy(() -> blobStore.getBlobAccess(CONTAINER, key))
                .isInstanceOfSatisfying(S3Exception.class, e ->
                        assertThat(e.statusCode()).isEqualTo(400));
        assertThatThrownBy(() -> blobStore.copyBlob(
                CopyObjectRequest.builder()
                        .sourceBucket(CONTAINER).sourceKey(key)
                        .destinationBucket(CONTAINER).destinationKey("copy")
                        .build()))
                .isInstanceOfSatisfying(S3Exception.class, e ->
                        assertThat(e.statusCode()).isEqualTo(400));
        assertThat(keys()).isEmpty();
    }

    private void put(String key, InputStream payload) {
        blobStore.putBlob(PutObjectRequest.builder()
                .bucket(CONTAINER).key(key)
                .contentLength((long) CONTENT.length).build(), payload);
    }

    private List<String> keys() {
        return blobStore.list(CONTAINER).contents().stream()
                .map(S3Object::key).toList();
    }
}
