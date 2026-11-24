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
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.S3Object;

/**
 * A listing that starts past a directory does not read it: every key below
 * it sorts before the marker.  Each page of a bucket used to read every
 * directory ahead of it again.  A directory the walk may not read shows
 * whether it went in, since reading it fails the listing.
 */
public final class Nio2ListingSkipTest {
    private static final String CONTAINER = "container";

    @TempDir
    private Path root;

    @Test
    public void testPageAfterADirectoryDoesNotReadIt() throws Exception {
        assumeTrue(root.getFileSystem().supportedFileAttributeViews()
                .contains("posix"));
        var blobStore = new FilesystemNio2BlobStore(root.toString());
        blobStore.createContainer(CONTAINER);
        for (String key : List.of("a/1", "a/2", "b/1", "c/1", "c/2", "d")) {
            blobStore.putBlob(PutObjectRequest.builder().bucket(CONTAINER)
                    .key(key).contentLength(0L).build(),
                    new ByteArrayInputStream(new byte[0]));
        }
        Path behind = root.resolve(CONTAINER).resolve("a");
        Files.setPosixFilePermissions(behind,
                PosixFilePermissions.fromString("---------"));
        try {
            // a user the permissions do not bind, such as root, shows
            // nothing here
            assumeTrue(!Files.isReadable(behind));

            // "a0" sorts after every key below "a/", '0' after '/'
            assertThat(keys(blobStore, ListObjectsV2Request.builder()
                    .bucket(CONTAINER).startAfter("a0").build()))
                    .containsExactly("b/1", "c/1", "c/2", "d");

            // and every page after the first, a key at a time
            var listed = new ArrayList<String>();
            String token = "a0";
            do {
                var page = blobStore.list(ListObjectsV2Request.builder()
                        .bucket(CONTAINER).maxKeys(1)
                        .continuationToken(token).build());
                page.contents().forEach(object -> listed.add(object.key()));
                token = page.nextContinuationToken();
            } while (token != null);
            assertThat(listed).containsExactly("b/1", "c/1", "c/2", "d");
        } finally {
            Files.setPosixFilePermissions(behind,
                    PosixFilePermissions.fromString("rwx------"));
        }
    }

    private static List<String> keys(FilesystemNio2BlobStore blobStore,
            ListObjectsV2Request request) {
        return blobStore.list(request).contents().stream()
                .map(S3Object::key).toList();
    }
}
