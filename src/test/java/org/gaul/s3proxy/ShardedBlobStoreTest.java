/*
 * Copyright 2014-2025 Andrew Gaul <andrew@gaul.org>
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

package org.gaul.s3proxy;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.google.common.io.ByteSource;

import org.jclouds.ContextBuilder;
import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.BlobStoreContext;
import org.jclouds.blobstore.domain.Blob;
import org.jclouds.blobstore.domain.PageSet;
import org.jclouds.blobstore.domain.StorageMetadata;
import org.jclouds.blobstore.options.CopyOptions;
import org.jclouds.logging.slf4j.config.SLF4JLoggingModule;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public final class ShardedBlobStoreTest {
    private int shards;
    private String prefix;
    private String containerName;
    private BlobStoreContext context;
    private BlobStore blobStore;
    private BlobStore shardedBlobStore;
    private List<String> createdContainers;
    private Map<String, String> prefixesMap;

    @Before
    public void setUp() {
        containerName = TestUtils.createRandomContainerName();
        shards = 10;
        prefix = TestUtils.createRandomContainerName();
        context = ContextBuilder
                .newBuilder("transient")
                .credentials("identity", "credential")
                .modules(List.of(new SLF4JLoggingModule()))
                .build(BlobStoreContext.class);
        blobStore = context.getBlobStore();
        var shardsMap = Map.of(containerName, shards);
        prefixesMap = Map.of(containerName, prefix);
        shardedBlobStore = ShardedBlobStore.newShardedBlobStore(
                blobStore, shardsMap, prefixesMap);
        createdContainers = new ArrayList<>();
    }

    @After
    public void tearDown() {
        if (this.context != null) {
            for (String container : this.createdContainers) {
                blobStore.deleteContainer(container);
            }
            context.close();
        }
    }

    private void createContainer(String container) {
        String prefix = this.prefixesMap.get(container);
        if (prefix != null) {
            for (int n = 0; n < this.shards; ++n) {
                this.createdContainers.add(
                        String.format("%s-%d", this.prefix, n));
            }
        } else {
            this.createdContainers.add(container);
        }
        assertThat(shardedBlobStore.createContainerInLocation(
                null, container)).isTrue();
    }

    public int countShards() {
        PageSet<? extends StorageMetadata> listing = blobStore.list();
        int blobStoreShards = 0;
        for (StorageMetadata entry: listing) {
            if (entry.getName().startsWith(prefix)) {
                blobStoreShards++;
            }
        }
        return blobStoreShards;
    }

    @Test
    public void testCreateContainer() {
        this.createContainer(containerName);
        assertThat(blobStore.containerExists(containerName)).isFalse();
        assertThat(this.countShards()).isEqualTo(this.shards);
    }

    @Test
    public void testDeleteContainer() {
        this.createContainer(containerName);
        assertThat(this.countShards()).isEqualTo(this.shards);
        assertThat(shardedBlobStore.deleteContainerIfEmpty(containerName))
                .isTrue();
        assertThat(this.countShards()).isZero();
    }

    @Test
    public void testPutBlob() throws Exception {
        String blobName = "foo";
        String blobName2 = "bar";
        ByteSource content = TestUtils.randomByteSource().slice(0, 1024);
        ByteSource content2 = TestUtils.randomByteSource().slice(1024, 1024);
        Blob blob = shardedBlobStore.blobBuilder(blobName).payload(content)
                .build();
        Blob blob2 = shardedBlobStore.blobBuilder(blobName2).payload(content2)
                .build();

        createContainer(containerName);
        shardedBlobStore.putBlob(containerName, blob);
        shardedBlobStore.putBlob(containerName, blob2);

        blob = shardedBlobStore.getBlob(containerName, blobName);
        try (InputStream actual = blob.getPayload().openStream();
             InputStream expected = content.openStream()) {
            assertThat(actual).hasSameContentAs(expected);
        }
        blob2 = shardedBlobStore.getBlob(containerName, blobName2);
        try (InputStream actual = blob2.getPayload().openStream();
             InputStream expected = content2.openStream()) {
            assertThat(actual).hasSameContentAs(expected);
        }

        String blobContainer = null;
        String blob2Container = null;
        for (int i = 0; i < shards; i++) {
            String shard = String.format("%s-%d", prefix, i);
            for (StorageMetadata entry : blobStore.list(shard)) {
                if (entry.getName().equals(blobName)) {
                    blobContainer = shard;
                }
                if (entry.getName().equals(blobName2)) {
                    blob2Container = shard;
                }
            }
        }
        assertThat(blobContainer).isNotNull();
        assertThat(blob2Container).isNotNull();
        assertThat(blobContainer).isNotEqualTo(blob2Container);
    }

    @Test
    public void testDeleteBlob() {
        String blobName = TestUtils.createRandomBlobName();
        ByteSource content = TestUtils.randomByteSource().slice(0, 1024);
        Blob blob = shardedBlobStore.blobBuilder(blobName).payload(content)
                .build();
        this.createContainer(containerName);
        shardedBlobStore.putBlob(containerName, blob);
        assertThat(shardedBlobStore.blobExists(containerName, blobName))
                .isTrue();
        shardedBlobStore.removeBlob(containerName, blobName);
        assertThat(shardedBlobStore.blobExists(containerName, blobName))
                .isFalse();
    }

    @Test
    public void testPutBlobUnsharded() throws Exception {
        String unshardedContainer = TestUtils.createRandomContainerName();
        String blobName = TestUtils.createRandomBlobName();
        ByteSource content = TestUtils.randomByteSource().slice(0, 1024);
        Blob blob = shardedBlobStore.blobBuilder(blobName).payload(content)
                .build();
        this.createContainer(unshardedContainer);
        shardedBlobStore.putBlob(unshardedContainer, blob);
        blob = blobStore.getBlob(unshardedContainer, blobName);
        try (InputStream actual = blob.getPayload().openStream();
             InputStream expected = content.openStream()) {
            assertThat(actual).hasSameContentAs(expected);
        }
    }

    @Test
    public void testCopyBlob() throws Exception {
        String blobName = TestUtils.createRandomBlobName();
        ByteSource content = TestUtils.randomByteSource().slice(0, 1024);
        Blob blob = shardedBlobStore.blobBuilder(blobName).payload(content)
                .build();
        this.createContainer(containerName);
        shardedBlobStore.putBlob(containerName, blob);
        String copyBlobName = TestUtils.createRandomBlobName();
        shardedBlobStore.copyBlob(
                containerName, blobName, containerName, copyBlobName,
                CopyOptions.NONE);
        blob = shardedBlobStore.getBlob(containerName, copyBlobName);
        try (InputStream actual = blob.getPayload().openStream();
             InputStream expected = content.openStream()) {
            assertThat(actual).hasSameContentAs(expected);
        }
    }

    @Test
    public void testCopyBlobUnshardedToSharded() throws Exception {
        String blobName = TestUtils.createRandomBlobName();
        String unshardedContainer = TestUtils.createRandomContainerName();
        ByteSource content = TestUtils.randomByteSource().slice(0, 1024);
        Blob blob = shardedBlobStore.blobBuilder(blobName).payload(content)
                .build();
        this.createContainer(containerName);
        this.createContainer(unshardedContainer);
        shardedBlobStore.putBlob(unshardedContainer, blob);
        shardedBlobStore.copyBlob(
                unshardedContainer, blobName, containerName, blobName,
                CopyOptions.NONE);
        blob = shardedBlobStore.getBlob(containerName, blobName);
        try (InputStream actual = blob.getPayload().openStream();
             InputStream expected = content.openStream()) {
            assertThat(actual).hasSameContentAs(expected);
        }
    }

    @Test
    public void testCopyBlobShardedToUnsharded() throws Exception {
        String blobName = TestUtils.createRandomBlobName();
        String unshardedContainer = TestUtils.createRandomContainerName();
        ByteSource content = TestUtils.randomByteSource().slice(0, 1024);
        Blob blob = shardedBlobStore.blobBuilder(blobName).payload(content)
                .build();
        this.createContainer(containerName);
        this.createContainer(unshardedContainer);
        shardedBlobStore.putBlob(containerName, blob);
        shardedBlobStore.copyBlob(
                containerName, blobName, unshardedContainer, blobName,
                CopyOptions.NONE);
        blob = shardedBlobStore.getBlob(unshardedContainer, blobName);
        try (InputStream actual = blob.getPayload().openStream();
             InputStream expected = content.openStream()) {
            assertThat(actual).hasSameContentAs(expected);
        }
    }
}
