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
import java.nio.file.Path;
import java.util.List;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import software.amazon.awssdk.services.s3.model.BucketCannedACL;
import software.amazon.awssdk.services.s3.model.BucketVersioningStatus;
import software.amazon.awssdk.services.s3.model.CopyObjectRequest;
import software.amazon.awssdk.services.s3.model.CreateBucketRequest;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.s3.model.ObjectCannedACL;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.S3Exception;

/**
 * The nio2 stores keep an object's ACL in its file mode and store a key
 * ending in a slash as a directory.  Writing such a key never set the mode,
 * so the directory kept the one it was created with, which as a rule lets
 * others read: the object was public-read whatever its write had asked for,
 * and an anonymous GET or HEAD of it in a private bucket was answered.
 */
public final class Nio2DirectoryMarkerAccessTest {
    private static final String CONTAINER = "container";
    private static final byte[] CONTENT = "content".getBytes(
            StandardCharsets.UTF_8);

    @TempDir
    private Path root;

    /**
     * The filesystem store keeps an ACL in POSIX permission bits, which a
     * filesystem without them -- NTFS -- cannot hold, so every object there
     * reads back private; it is checked only where they exist.
     */
    private List<BlobStore> blobStores() {
        var transient_ = new TransientNio2BlobStore();
        if (!root.getFileSystem().supportedFileAttributeViews()
                .contains("posix")) {
            return List.of(transient_);
        }
        return List.of(new FilesystemNio2BlobStore(root.toString()),
                transient_);
    }

    @Test
    public void testDirectoryMarkerHasTheAccessItsWriteAsked() {
        for (var blobStore : blobStores()) {
            blobStore.createContainer(CONTAINER);
            put(blobStore, CONTAINER, "private/", null);
            put(blobStore, CONTAINER, "public/", ObjectCannedACL.PUBLIC_READ);
            put(blobStore, CONTAINER, "/", null);
            // the key below it made the directory before the marker did
            put(blobStore, CONTAINER, "parent/blob", null);
            put(blobStore, CONTAINER, "parent/", null);

            for (String key : List.of("private/", "/", "parent/")) {
                assertThat(blobStore.getBlobAccess(CONTAINER, key)).as(key)
                        .isEqualTo(ObjectCannedACL.PRIVATE);
            }
            assertThat(blobStore.getBlobAccess(CONTAINER, "public/"))
                    .isEqualTo(ObjectCannedACL.PUBLIC_READ);

            // as for a file, an overwrite that asks for nothing is private
            put(blobStore, CONTAINER, "public/", null);
            assertThat(blobStore.getBlobAccess(CONTAINER, "public/"))
                    .isEqualTo(ObjectCannedACL.PRIVATE);
        }
    }

    /** A copy is written the way a put is, and carries metadata to hide. */
    @Test
    public void testCopyOntoDirectoryMarkerIsPrivate() {
        for (var blobStore : blobStores()) {
            blobStore.createContainer(CONTAINER);
            // a marker holds no content, so the copy's source is one too
            put(blobStore, CONTAINER, "source/", null);
            blobStore.copyBlob(CopyObjectRequest.builder()
                    .sourceBucket(CONTAINER).sourceKey("source/")
                    .destinationBucket(CONTAINER).destinationKey("copy/")
                    .build());

            assertThat(blobStore.getBlobAccess(CONTAINER, "copy/"))
                    .isEqualTo(ObjectCannedACL.PRIVATE);
        }
    }

    /**
     * A directory that only holds other keys is not an object and has no
     * access to report.  On a versioned bucket it reported its mode, so an
     * anonymous read passed the ACL check and answered 404 where a prefix
     * no key has answers 403.
     */
    @Test
    public void testDirectoryWithoutMarkerHasNoAccess() {
        var blobStore = new TransientNio2BlobStore();
        blobStore.createContainer(CONTAINER);
        String versioned = CONTAINER + "-versioned";
        blobStore.createContainer(versioned);
        blobStore.putBucketVersioning(versioned,
                BucketVersioningStatus.ENABLED);

        for (String container : List.of(CONTAINER, versioned)) {
            put(blobStore, container, "dir/sub/blob", null);
            for (String key : List.of("dir", "dir/", "dir/sub", "dir/sub/")) {
                assertThatThrownBy(() -> blobStore.getBlobAccess(container,
                        key)).as("%s %s", container, key)
                        .isInstanceOf(NoSuchKeyException.class);
            }

            // while one that is an object still answers, versioned or not
            put(blobStore, container, "dir/", ObjectCannedACL.PUBLIC_READ);
            assertThat(blobStore.getBlobAccess(container, "dir/"))
                    .isEqualTo(ObjectCannedACL.PUBLIC_READ);
            blobStore.setBlobAccess(container, "dir/",
                    ObjectCannedACL.PRIVATE);
            assertThat(blobStore.getBlobAccess(container, "dir/"))
                    .isEqualTo(ObjectCannedACL.PRIVATE);
        }

        // a directory carries no version id, and is not the null version
        assertThatThrownBy(() -> blobStore.getBlobAccess(versioned,
                "dir/sub", "null")).isInstanceOfSatisfying(
                        S3Exception.class, e ->
                                assertThat(e.statusCode()).isEqualTo(404));
    }

    /**
     * The bucket's directory carries the bucket's ACL in its own mode, and
     * an absolute key can name it.  A marker written there must not take a
     * public-read-write bucket private on behalf of whoever may write to it.
     */
    @Test
    public void testDirectoryMarkerCannotNameTheBucket() {
        for (var blobStore : blobStores()) {
            blobStore.createContainer(CreateBucketRequest.builder()
                    .bucket(CONTAINER)
                    .acl(BucketCannedACL.PUBLIC_READ_WRITE).build());
            String base = blobStore instanceof TransientNio2BlobStore ?
                    "" : root.toString();

            assertThatThrownBy(() -> put(blobStore, CONTAINER,
                    base + "/" + CONTAINER + "/", null))
                    .isInstanceOfSatisfying(S3Exception.class, e ->
                            assertThat(e.statusCode()).isEqualTo(400));
            assertThat(blobStore.getContainerAccess(CONTAINER))
                    .isEqualTo(BucketCannedACL.PUBLIC_READ_WRITE);
        }
    }

    /** A key ending in a slash is written empty, as a marker has to be. */
    private static void put(BlobStore blobStore, String container, String key,
            ObjectCannedACL acl) {
        byte[] content = key.endsWith("/") ? new byte[0] : CONTENT;
        blobStore.putBlob(PutObjectRequest.builder()
                .bucket(container).key(key).acl(acl)
                .contentLength((long) content.length).build(),
                new ByteArrayInputStream(content));
    }
}
