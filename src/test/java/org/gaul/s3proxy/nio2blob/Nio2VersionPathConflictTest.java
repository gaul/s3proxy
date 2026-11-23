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
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.services.s3.model.BucketVersioningStatus;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.ListObjectVersionsRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

/**
 * A key's current version is the file at its path, and a key that has none
 * leaves the path to whoever comes next: the keys below it, which make a
 * directory of it, or a key above it, which makes a file of one of its
 * directories.  Neither is a version of the key, whose versions are then
 * all in the sidecar, and neither leaves room for one of them to become
 * current again.
 */
public final class Nio2VersionPathConflictTest {
    private static final String CONTAINER = "container";
    private static final byte[] CONTENT = "content".getBytes(
            StandardCharsets.UTF_8);

    private TransientNio2BlobStore store;

    @BeforeEach
    public void setUp() {
        store = new TransientNio2BlobStore();
        store.createContainer(CONTAINER);
    }

    /** A key ending in a slash is written empty, as a marker has to be. */
    private void write(String key) {
        byte[] content = key.endsWith("/") ? new byte[0] : CONTENT;
        store.putBlob(PutObjectRequest.builder()
                        .bucket(CONTAINER).key(key)
                        .contentLength((long) content.length)
                        .build(),
                new ByteArrayInputStream(content));
    }

    /** Lays a delete marker over the key and returns the marker's id. */
    private String delete(String key) {
        return store.removeBlob(CONTAINER, key, /*versionId=*/ null)
                .versionId();
    }

    private byte[] read(String key, String versionId) throws IOException {
        try (var is = store.getBlob(GetObjectRequest.builder()
                .bucket(CONTAINER).key(key).versionId(versionId).build())) {
            return is.readAllBytes();
        }
    }

    private long versionsOf(String key) {
        return store.listVersions(ListObjectVersionsRequest.builder()
                .bucket(CONTAINER).build()).versions().stream()
                .filter(version -> version.key().equals(key)).count();
    }

    private void assertLatestIsDeleteMarker(String key, String marker) {
        assertThat(store.listVersions(ListObjectVersionsRequest.builder()
                .bucket(CONTAINER).build()).deleteMarkers())
                .anySatisfy(entry -> {
                    assertThat(entry.key()).isEqualTo(key);
                    assertThat(entry.versionId()).isEqualTo(marker);
                    assertThat(entry.isLatest()).isTrue();
                });
    }

    private static void assertErrorCode(Throwable thrown, String code) {
        assertThat(thrown).isInstanceOfSatisfying(AwsServiceException.class,
                e -> assertThat(e.awsErrorDetails().errorCode())
                        .isEqualTo(code));
    }

    @Test
    public void testNullVersionUnderKeysBelowIsReadAndRemoved()
            throws Exception {
        nullVersionIsReadAndRemoved("key/below");
    }

    @Test
    public void testNullVersionUnderDirectoryMarkerIsReadAndRemoved()
            throws Exception {
        nullVersionIsReadAndRemoved("key/");
    }

    /**
     * The directory {@code other} makes of the path of "key" carries no
     * version id, as a version written before versioning was enabled does
     * not, and must not be taken for that version.
     */
    private void nullVersionIsReadAndRemoved(String other) throws Exception {
        write("key");
        store.putBucketVersioning(CONTAINER, BucketVersioningStatus.ENABLED);
        String marker = delete("key");
        write(other);

        assertThat(read("key", "null")).isEqualTo(CONTENT);
        assertThat(versionsOf("key")).isEqualTo(1);
        assertLatestIsDeleteMarker("key", marker);
        assertThatThrownBy(() -> read("key", /*versionId=*/ null))
                .satisfies(thrown -> assertErrorCode(thrown, "NoSuchKey"));

        store.removeBlob(CONTAINER, "key", "null");

        assertThat(versionsOf("key")).isZero();
        assertThatThrownBy(() -> read("key", "null"))
                .satisfies(thrown -> assertErrorCode(thrown, "NoSuchVersion"));
        assertThat(store.blobExists(CONTAINER, other)).isTrue();
    }

    @Test
    public void testDeleteMarkerStaysUnderKeysBelow() throws Exception {
        deleteMarkerStaysWhileItsVersionHasNoRoom("key", "key/below");
    }

    @Test
    public void testDeleteMarkerStaysUnderDirectoryMarker() throws Exception {
        deleteMarkerStaysWhileItsVersionHasNoRoom("key", "key/");
    }

    @Test
    public void testDeleteMarkerStaysBelowAnotherKey() throws Exception {
        deleteMarkerStaysWhileItsVersionHasNoRoom("dir/sub/key", "dir");
    }

    /**
     * Removing the delete marker of {@code key} would make the version
     * below it current, at a path {@code other} leaves no room at.  Removing
     * it all the same left a key with versions, none of them current, and
     * no delete marker: listed as latest and answered 404 from then on.
     */
    private void deleteMarkerStaysWhileItsVersionHasNoRoom(String key,
            String other) throws Exception {
        store.putBucketVersioning(CONTAINER, BucketVersioningStatus.ENABLED);
        write(key);
        String marker = delete(key);
        write(other);

        assertThatThrownBy(() -> store.removeBlob(CONTAINER, key, marker))
                .satisfies(thrown -> assertErrorCode(thrown,
                        "InvalidArgument"));
        assertLatestIsDeleteMarker(key, marker);

        // with the path free again the marker goes and the object is back
        delete(other);
        store.removeBlob(CONTAINER, key, marker);
        assertThat(read(key, /*versionId=*/ null)).isEqualTo(CONTENT);
        assertThat(store.blobExists(CONTAINER, key)).isTrue();
    }
}
