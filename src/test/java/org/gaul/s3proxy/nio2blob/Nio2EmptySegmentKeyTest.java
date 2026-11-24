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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.stream.Stream;

import com.google.common.io.ByteSource;

import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.gaul.s3proxy.TestUtils;
import org.gaul.s3proxy.blobstore.S3Exceptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.BucketVersioningStatus;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.ListObjectVersionsRequest;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.S3Exception;

/**
 * A key is a byte string to S3 and a path to the nio2 stores, and a path has
 * no empty segment: {@code a//b} resolves to the file {@code a/b}.  The
 * versions of a key are filed under the key as spelled, though, so a DELETE
 * or a PUT of {@code a//b} in a versioned bucket archived the current version
 * of {@code a/b} as a version of {@code a//b}, and the key its owner wrote no
 * longer answered for it.  The store refuses such a key as it refuses one
 * holding a dot segment, which resolves away likewise.
 */
public final class Nio2EmptySegmentKeyTest {
    private static final String CONTAINER = "container";
    private static final ByteSource CONTENT = ByteSource.wrap(
            "content".getBytes(StandardCharsets.UTF_8));

    private TransientNio2BlobStore store;

    @BeforeEach
    public void setUp() {
        store = new TransientNio2BlobStore();
        store.createContainer(CONTAINER);
    }

    /** A DELETE of the other spelling must not archive the key's version. */
    @Test
    public void testDeleteDoesNotTakeAVersionFromAnotherKey()
            throws IOException {
        store.putBucketVersioning(CONTAINER, BucketVersioningStatus.ENABLED);
        String versionId = TestUtils.putBlob(store, CONTAINER,
                "logs/victim.txt", CONTENT).versionId();

        assertRefused(() -> store.removeBlob(CONTAINER, "logs//victim.txt"));

        assertThat(store.blobExists(CONTAINER, "logs/victim.txt")).isTrue();
        try (var in = store.getBlob(GetObjectRequest.builder()
                .bucket(CONTAINER).key("logs/victim.txt")
                .versionId(versionId).build())) {
            assertThat(in.readAllBytes()).isEqualTo(CONTENT.read());
        }
        assertThat(versionKeys()).containsExactly("logs/victim.txt");
    }

    /** A write collapsed the same way, and replaced the object besides. */
    @Test
    public void testPutDoesNotReplaceAnotherKey() throws IOException {
        store.putBucketVersioning(CONTAINER, BucketVersioningStatus.ENABLED);
        String versionId = TestUtils.putBlob(store, CONTAINER,
                "logs/victim.txt", CONTENT).versionId();

        assertRefused(() -> TestUtils.putBlob(store, CONTAINER,
                "logs//victim.txt", ByteSource.wrap(new byte[] {1})));
        assertRefused(() -> store.initiateMultipartUpload(
                CreateMultipartUploadRequest.builder()
                        .bucket(CONTAINER).key("logs//victim.txt").build()));

        assertThat(store.blobMetadata(CONTAINER, "logs/victim.txt")
                .versionId()).isEqualTo(versionId);
        assertThat(versionKeys()).containsExactly("logs/victim.txt");
    }

    /** Wherever the empty segment falls, short of the end of the key. */
    @Test
    public void testKeyHoldingAnEmptySegmentIsRefused() throws IOException {
        TestUtils.putBlob(store, CONTAINER, "a/b", CONTENT);

        for (String key : new String[] {"a//b", "/a/b", "//", "a//", "a/b//"}) {
            assertRefused(() -> TestUtils.putBlob(store, CONTAINER, key,
                    CONTENT));
            assertRefused(() -> store.removeBlob(CONTAINER, key));
            // reading one is refused too, or it would answer for another key
            assertRefused(() -> store.blobMetadata(CONTAINER, key));
        }

        assertThat(keys()).containsExactly("a/b");
    }

    /**
     * The slash that ends a key is a directory marker's and the key "/" is
     * an object of its own, neither of which resolves to another key.
     */
    @Test
    public void testTrailingSlashAndSlashKeysAreKept() throws IOException {
        TestUtils.putBlob(store, CONTAINER, "dir/sub/", ByteSource.empty());
        TestUtils.putBlob(store, CONTAINER, "/", ByteSource.empty());

        assertThat(store.blobExists(CONTAINER, "dir/sub/")).isTrue();
        assertThat(store.blobExists(CONTAINER, "/")).isTrue();

        store.removeBlob(CONTAINER, "/");
        store.removeBlob(CONTAINER, "dir/sub/");
        assertThat(store.blobExists(CONTAINER, "dir/sub/")).isFalse();
    }

    private static void assertRefused(ThrowingCallable call) {
        assertThatThrownBy(call)
                .isInstanceOf(S3Exception.class)
                .matches(e -> S3Exceptions.errorCode((S3Exception) e)
                        .equals("InvalidArgument"));
    }

    private List<String> keys() {
        return store.list(ListObjectsV2Request.builder().bucket(CONTAINER)
                .build()).contents().stream().map(o -> o.key()).toList();
    }

    /** The key of every version and delete marker the container holds. */
    private List<String> versionKeys() {
        var listing = store.listVersions(ListObjectVersionsRequest.builder()
                .bucket(CONTAINER).build());
        return Stream.concat(
                listing.versions().stream().map(v -> v.key()),
                listing.deleteMarkers().stream().map(m -> m.key())).toList();
    }
}
