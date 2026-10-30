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
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import com.google.common.io.ByteSource;
import com.google.common.jimfs.Configuration;
import com.google.common.jimfs.Jimfs;

import org.gaul.s3proxy.TestUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

/**
 * The filesystem store keeps everything about an object but its bytes in
 * user extended attributes, which some filesystems do not have: NFSv3, vfat,
 * some container bind mounts.  See issue #1210.  Jimfs configured without the
 * "user" view stands in for one of those.
 */
public final class Nio2UserAttributesTest {
    private static final String CONTAINER = "container";
    private static final ByteSource CONTENT = ByteSource.wrap(
            "hello world".getBytes(StandardCharsets.UTF_8));

    private FileSystem without;
    private AbstractNio2BlobStore store;

    /** A store over whatever filesystem it is handed. */
    private static final class Nio2Store extends AbstractNio2BlobStore {
        Nio2Store(Path root) {
            super(root);
        }
    }

    @BeforeEach
    public void setUp() {
        without = Jimfs.newFileSystem(Configuration.unix().toBuilder()
                .setAttributeViews("posix")
                .setWorkingDirectory("/")
                .build());
        store = new Nio2Store(without.getPath("/"));
        store.createContainer(CONTAINER);
    }

    @AfterEach
    public void tearDown() throws IOException {
        without.close();
    }

    /** Whether the store's filesystem keeps them is asked of the mount. */
    @Test
    public void testSupportFollowsTheFilesystem() throws IOException {
        try (var with = Jimfs.newFileSystem(Configuration.unix().toBuilder()
                .setAttributeViews("posix", "user")
                .build());
             var bare = Jimfs.newFileSystem(
                     Configuration.unix().toBuilder()
                             .setAttributeViews("posix")
                             .build())) {
            assertThat(AbstractNio2BlobStore.supportsUserAttributes(
                    with.getPath("/"))).isTrue();
            assertThat(AbstractNio2BlobStore.supportsUserAttributes(
                    bare.getPath("/"))).isFalse();
        }
    }

    /**
     * Without attributes to keep it in, an object is stored without its
     * metadata, as it always has been: refusing it would break every
     * deployment already running on such a filesystem.
     */
    @Test
    public void testWithoutAttributesTheWriteSucceeds() throws IOException {
        store.putBlob(TestUtils.putRequest(CONTAINER, "key", CONTENT)
                .toBuilder().metadata(Map.of("owner", "alice")).build(),
                CONTENT.openStream());

        assertThat(store.blobExists(CONTAINER, "key")).isTrue();
    }

    /**
     * Where the filesystem does keep attributes, failing to write them is a
     * real failure, and the write fails rather than answering success over
     * metadata dropped part way.  A value past Linux's 64 KiB limit for one
     * attribute is refused by every filesystem there.
     */
    @Test
    @EnabledOnOs(OS.LINUX)
    public void testAttributesThatCannotBeWrittenFailTheWrite(
            @TempDir Path temp) throws IOException {
        var real = new FilesystemNio2BlobStore(temp.toString());
        real.createContainer(CONTAINER);

        assertThatThrownBy(() -> real.putBlob(
                TestUtils.putRequest(CONTAINER, "key", CONTENT).toBuilder()
                        .metadata(Map.of("big", "x".repeat(70_000)))
                        .build(),
                CONTENT.openStream()))
                .isInstanceOf(RuntimeException.class);

        assertThat(real.blobExists(CONTAINER, "key")).isFalse();
        try (var entries = Files.list(temp.resolve(CONTAINER))) {
            assertThat(entries).isEmpty();
        }
    }
}
