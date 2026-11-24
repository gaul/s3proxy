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
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;

import com.google.common.jimfs.Configuration;
import com.google.common.jimfs.Jimfs;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.BucketVersioningStatus;
import software.amazon.awssdk.services.s3.model.ListObjectVersionsRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

/**
 * A read of a key that has no current object looks through that key's
 * archived versions for a delete marker, and does so before the caller is
 * authorized.  With every key's versions in one directory that enumerated
 * the whole of it: one anonymous GET of a key that did not exist cost the
 * store in proportion to all the versions its bucket held.
 */
public final class Nio2VersionDirectoryTest {
    private static final String CONTAINER = "container";

    private FileSystem fileSystem;
    private AbstractNio2BlobStore store;

    /** A versioning store over a filesystem the test can look into. */
    private static final class Nio2Store extends AbstractNio2BlobStore {
        Nio2Store(Path root) {
            super(root);
        }

        @Override
        public boolean supportsVersioning() {
            return true;
        }
    }

    @BeforeEach
    public void setUp() {
        fileSystem = Jimfs.newFileSystem(Configuration.unix().toBuilder()
                .setAttributeViews("posix", "user")
                .setWorkingDirectory("/")
                .build());
        store = new Nio2Store(fileSystem.getPath("/"));
        store.createContainer(CONTAINER);
        store.putBucketVersioning(CONTAINER, BucketVersioningStatus.ENABLED);
    }

    @AfterEach
    public void tearDown() throws IOException {
        fileSystem.close();
    }

    private void write(String key) {
        byte[] content = "content".getBytes(StandardCharsets.UTF_8);
        store.putBlob(PutObjectRequest.builder()
                        .bucket(CONTAINER).key(key)
                        .contentLength((long) content.length)
                        .build(),
                new ByteArrayInputStream(content));
    }

    /** Looking for one key's versions does not walk another key's. */
    @Test
    public void testVersionsOfAKeyAreKeptApartFromOtherKeys()
            throws Exception {
        for (int i = 0; i < 20; ++i) {
            write("busy");
        }
        write("dir/quiet");
        write("dir/quiet");
        store.removeBlob(CONTAINER, "dir/quiet");

        var versions = fileSystem.getPath("/", CONTAINER,
                ".s3proxy-versions");
        try (var entries = Files.list(versions)) {
            // one to a key, however many versions each key has
            assertThat(entries).hasSize(2)
                    .allSatisfy(entry -> assertThat(entry).isDirectory());
        }
        try (var files = Files.walk(versions)) {
            // 19 of the one key; 2 and a delete marker of the other
            assertThat(files.filter(Files::isRegularFile)).hasSize(22);
        }
        var listing = store.listVersions(ListObjectVersionsRequest.builder()
                .bucket(CONTAINER).build());
        assertThat(listing.versions()).hasSize(22);
        assertThat(listing.deleteMarkers()).hasSize(1);
    }
}
