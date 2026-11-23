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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.S3Object;
import software.amazon.awssdk.services.s3.model.UploadPartRequest;

/**
 * The store's own names are hidden from a listing where the walk meets them,
 * directly under the container.  A prefix holding a slash starts the walk at
 * its directory instead, which used to be trusted: inside a reserved
 * directory, at the container under another spelling, or above it.
 */
public final class Nio2ReservedNameListingTest {
    private static final String CONTAINER = "container";
    private static final byte[] CONTENT = "content".getBytes(
            StandardCharsets.UTF_8);

    @TempDir
    private Path root;
    private FilesystemNio2BlobStore blobStore;
    private MultipartUpload mpu;

    @BeforeEach
    public void setUp() throws Exception {
        blobStore = new FilesystemNio2BlobStore(root.toString());
        blobStore.createContainer(CONTAINER);
        put(CONTAINER, "dir/blob");
        // a part of an upload whose key has a slash lies in a directory
        mpu = blobStore.initiateMultipartUpload(
                CreateMultipartUploadRequest.builder()
                        .bucket(CONTAINER).key("dir/upload").build());
        blobStore.uploadMultipartPart(mpu, UploadPartRequest.builder()
                .bucket(CONTAINER).key("dir/upload").uploadId(mpu.id())
                .partNumber(1).contentLength((long) CONTENT.length).build(),
                new ByteArrayInputStream(CONTENT));
        var container = root.resolve(CONTAINER);
        for (String reserved : List.of(".s3proxy-tmp", ".s3proxy-versions")) {
            Files.createDirectory(container.resolve(reserved));
            Files.createFile(container.resolve(reserved).resolve("file"));
        }
    }

    @Test
    public void testPrefixInsideReservedDirectoryListsNothing() {
        for (String prefix : List.of(".mpus-" + mpu.id() + "-dir/",
                ".mpus-" + mpu.id() + "-dir/upload-",
                ".s3proxy-tmp/", ".s3proxy-versions/", ".s3proxy-slash/")) {
            assertThat(keys(prefix, null)).as(prefix).isEmpty();
            assertThat(keys(prefix, "/")).as(prefix).isEmpty();
        }
        // which the store's own listing of the upload is not
        assertThat(blobStore.listMultipartUpload(mpu)).hasSize(1);
    }

    /** No key holds a dot segment, so no key begins with one. */
    @Test
    public void testPrefixWithDotSegmentListsNothing() {
        for (String prefix : List.of("./", "./.mpus-", "dir/../", "dir/./",
                "./dir/", "dir/../.s3proxy-tmp/")) {
            assertThat(keys(prefix, null)).as(prefix).isEmpty();
            assertThat(keys(prefix, "/")).as(prefix).isEmpty();
        }
        assertThat(keys("dir/", null)).containsExactly("dir/blob");
        assertThat(keys("dir/", "/")).containsExactly("dir/blob");
    }

    /** Nor does the walk start above the container for a prefix inside it. */
    @Test
    public void testPrefixDirectoryOutsideContainerIsRefused() {
        blobStore.createContainer(CONTAINER + "-other");
        put(CONTAINER + "-other", "blob");
        for (String prefix : List.of("../" + CONTAINER,
                "dir/../../" + CONTAINER,
                root.resolve(CONTAINER).toAbsolutePath().toString())) {
            assertThatThrownBy(() -> keys(prefix, null)).as(prefix)
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    private void put(String container, String key) {
        blobStore.putBlob(PutObjectRequest.builder()
                .bucket(container).key(key)
                .contentLength((long) CONTENT.length).build(),
                new ByteArrayInputStream(CONTENT));
    }

    /** The keys and common prefixes of a listing. */
    private List<String> keys(String prefix, String delimiter) {
        var page = blobStore.list(ListObjectsV2Request.builder()
                .bucket(CONTAINER).prefix(prefix).delimiter(delimiter)
                .build());
        var keys = new ArrayList<String>();
        page.contents().stream().map(S3Object::key).forEach(keys::add);
        page.commonPrefixes().forEach(p -> keys.add(p.prefix()));
        return keys;
    }
}
