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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import software.amazon.awssdk.services.s3.model.NoSuchBucketException;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

/**
 * Every container is a directory under the store's root, so the root is not
 * one of them.  A name that resolved to it -- the empty one, which is what
 * the service root "/" hands a bucket operation -- used to be a container
 * holding every other container's objects under "container/key", whatever a
 * bucket locator or a prefix had to say about who may reach them.
 */
public final class Nio2RootContainerTest {
    private static final String CONTAINER = "container";
    private static final byte[] CONTENT = "content".getBytes(
            StandardCharsets.UTF_8);
    /** Names that pass for being inside the root and are the root. */
    private static final List<String> ROOT_NAMES = List.of(
            "", ".", CONTAINER + "/..");

    @TempDir
    private Path root;
    private FilesystemNio2BlobStore blobStore;

    @BeforeEach
    public void setUp() {
        blobStore = new FilesystemNio2BlobStore(root.toString());
        blobStore.createContainer(CONTAINER);
        blobStore.putBlob(PutObjectRequest.builder()
                .bucket(CONTAINER).key("blob")
                .contentLength((long) CONTENT.length).build(),
                new ByteArrayInputStream(CONTENT));
    }

    @Test
    public void testRootIsNoContainer() {
        for (String name : ROOT_NAMES) {
            assertThat(blobStore.containerExists(name)).as(name).isFalse();
        }
    }

    @Test
    public void testRootHoldsNoObjects() {
        for (String name : ROOT_NAMES) {
            assertThatThrownBy(() -> blobStore.blobExists(name,
                    CONTAINER + "/blob")).as(name)
                    .isInstanceOf(NoSuchBucketException.class);
            assertThatThrownBy(() -> blobStore.removeBlob(name,
                    CONTAINER + "/blob")).as(name)
                    .isInstanceOf(NoSuchBucketException.class);
        }
        assertThat(blobStore.blobExists(CONTAINER, "blob")).isTrue();
    }

    @Test
    public void testRootIsNotDeleted() {
        for (String name : ROOT_NAMES) {
            assertThatThrownBy(() -> blobStore.deleteContainer(name))
                    .as(name).isInstanceOf(NoSuchBucketException.class);
        }
        assertThat(blobStore.blobExists(CONTAINER, "blob")).isTrue();
    }
}
