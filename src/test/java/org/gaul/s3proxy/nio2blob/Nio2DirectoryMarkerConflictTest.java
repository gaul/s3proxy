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

import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

/**
 * A directory marker whose directory an object's file is in the way of is
 * refused, as an object written there is, on either store.  A file above
 * the directory is "Not a directory" on Linux and NoSuchFileException on
 * the transient store's in-memory filesystem, and on both stores that
 * reached the client as a 500.
 */
public final class Nio2DirectoryMarkerConflictTest {
    private static final String CONTAINER = "container";
    private static final byte[] CONTENT = "content".getBytes(
            StandardCharsets.UTF_8);

    @TempDir
    private Path root;

    private List<BlobStore> blobStores() {
        return List.of(new FilesystemNio2BlobStore(root.toString()),
                new TransientNio2BlobStore());
    }

    @Test
    public void testMarkerBeneathAnObjectIsRefused() throws Exception {
        for (var blobStore : blobStores()) {
            blobStore.createContainer(CONTAINER);
            put(blobStore, "a");
            for (String marker : List.of("a/b/", "a/b/c/")) {
                assertRefused(blobStore, marker, "The key lies beneath");
            }
            assertThat(read(blobStore, "a")).as(name(blobStore))
                    .isEqualTo(CONTENT);
        }
    }

    @Test
    public void testMarkerOverAnObjectIsRefused() throws Exception {
        for (var blobStore : blobStores()) {
            blobStore.createContainer(CONTAINER);
            put(blobStore, "a");
            assertRefused(blobStore, "a/", "The key names a directory");
            assertThat(read(blobStore, "a")).as(name(blobStore))
                    .isEqualTo(CONTENT);
        }
    }

    private static void assertRefused(BlobStore blobStore, String key,
            String message) {
        assertThatThrownBy(() -> put(blobStore, key))
                .as("%s %s", name(blobStore), key)
                .isInstanceOfSatisfying(AwsServiceException.class, e -> {
                    assertThat(e.statusCode()).isEqualTo(400);
                    assertThat(e.awsErrorDetails().errorCode())
                            .isEqualTo("InvalidArgument");
                    assertThat(e.awsErrorDetails().errorMessage())
                            .startsWith(message);
                });
    }

    /** A key ending in a slash is written empty, as a marker has to be. */
    private static void put(BlobStore blobStore, String key) {
        byte[] content = key.endsWith("/") ? new byte[0] : CONTENT;
        blobStore.putBlob(PutObjectRequest.builder()
                .bucket(CONTAINER).key(key)
                .contentLength((long) content.length).build(),
                new ByteArrayInputStream(content));
    }

    private static byte[] read(BlobStore blobStore, String key)
            throws Exception {
        try (var in = blobStore.getBlob(GetObjectRequest.builder()
                .bucket(CONTAINER).key(key).build())) {
            return in.readAllBytes();
        }
    }

    private static String name(BlobStore blobStore) {
        return blobStore.getClass().getSimpleName();
    }
}
