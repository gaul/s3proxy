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
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import software.amazon.awssdk.services.s3.model.BucketVersioningStatus;
import software.amazon.awssdk.services.s3.model.ListObjectVersionsRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

/**
 * The two nio2 stores share the versioning implementation and differ in
 * whether they own up to it: the transient store's versions live in a
 * filesystem that dies with the process, while the filesystem store's would
 * be a layout on a real disk that S3Proxy would owe its users from then on.
 * Until that layout is settled the filesystem store answers no, which is what
 * turns every versioning request into a 501 at the frontend.  Issue #74.
 */
public final class Nio2VersioningSupportTest {
    private static final String CONTAINER = "container";

    @TempDir
    private Path root;
    private FilesystemNio2BlobStore filesystemStore;
    private TransientNio2BlobStore transientStore;

    @BeforeEach
    public void setUp() {
        filesystemStore = new FilesystemNio2BlobStore(root.toString());
        filesystemStore.createContainer(CONTAINER);
        transientStore = new TransientNio2BlobStore();
        transientStore.createContainer(CONTAINER);
    }

    @Test
    public void testTransientSupportsVersioning() {
        assertThat(transientStore.supportsVersioning()).isTrue();
        transientStore.setContainerVersioning(CONTAINER,
                BucketVersioningStatus.ENABLED);
        assertThat(transientStore.getContainerVersioning(CONTAINER))
                .isEqualTo(BucketVersioningStatus.ENABLED);
    }

    @Test
    public void testFilesystemRefusesVersioning() {
        assertThat(filesystemStore.supportsVersioning()).isFalse();

        assertThatThrownBy(() -> filesystemStore.getContainerVersioning(
                CONTAINER))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> filesystemStore.setContainerVersioning(
                CONTAINER, BucketVersioningStatus.ENABLED))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> filesystemStore.listVersions(
                ListObjectVersionsRequest.builder().bucket(CONTAINER).build()))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> filesystemStore.removeBlob(CONTAINER, "blob",
                /*versionId=*/ "v1"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    /**
     * Nothing of the version layout reaches a disk the filesystem store owns:
     * an overwrite there replaces the object as it always did.
     */
    @Test
    public void testFilesystemWritesLeaveNoVersions() throws Exception {
        for (var content : new String[] {"first", "second"}) {
            filesystemStore.putBlob(PutObjectRequest.builder()
                            .bucket(CONTAINER).key("blob")
                            .contentLength((long) content.length())
                            .build(),
                    new ByteArrayInputStream(content.getBytes()));
        }

        try (var stream = Files.newDirectoryStream(root.resolve(CONTAINER))) {
            assertThat(stream).extracting(
                    path -> path.getFileName().toString())
                    .containsExactly("blob");
        }
    }
}
