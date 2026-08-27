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

package org.gaul.s3proxy.middleware;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.google.common.io.ByteSource;

import org.gaul.s3proxy.TestUtils;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.S3Exceptions;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.CopyObjectRequest;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.services.s3.model.ServerSideEncryption;
import software.amazon.awssdk.services.s3.model.ServerSideEncryptionByDefault;
import software.amazon.awssdk.services.s3.model.ServerSideEncryptionConfiguration;
import software.amazon.awssdk.services.s3.model.ServerSideEncryptionRule;
import software.amazon.awssdk.services.s3.model.UploadPartCopyRequest;

public final class ShardedBlobStoreTest {
    private int shards;
    private String prefix;
    private String containerName;
    private BlobStore blobStore;
    private BlobStore shardedBlobStore;
    private List<String> createdContainers;
    private Map<String, String> prefixesMap;

    @BeforeEach
    public void setUp() {
        containerName = TestUtils.createRandomContainerName();
        shards = 10;
        prefix = TestUtils.createRandomContainerName();
        blobStore = TestUtils.createTransientBlobStore();
        var shardsMap = Map.of(containerName, shards);
        prefixesMap = Map.of(containerName, prefix);
        shardedBlobStore = ShardedBlobStore.newShardedBlobStore(
                blobStore, shardsMap, prefixesMap);
        createdContainers = new ArrayList<>();
    }

    @AfterEach
    public void tearDown() {
        if (this.blobStore != null) {
            for (String container : this.createdContainers) {
                blobStore.deleteContainer(container);
            }
        }
    }

    private void createContainer(String container) {
        String prefix = this.prefixesMap.get(container);
        if (prefix != null) {
            for (int n = 0; n < this.shards; ++n) {
                this.createdContainers.add(
                        "%s-%d".formatted(this.prefix, n));
            }
        } else {
            this.createdContainers.add(container);
        }
        shardedBlobStore.createContainer(container);
    }

    @Test
    public void testShardedContainerEncryptionRefused() {
        var configuration = ServerSideEncryptionConfiguration.builder()
                .rules(ServerSideEncryptionRule.builder()
                        .applyServerSideEncryptionByDefault(
                                ServerSideEncryptionByDefault.builder()
                                        .sseAlgorithm(
                                                ServerSideEncryption.AES256)
                                        .build())
                        .build())
                .build();
        // A sharded bucket spans many backend containers, so there is no
        // single one to carry a default-encryption configuration: refuse it
        // rather than let the request reach an untranslated backend name.
        assertThatThrownBy(() ->
                shardedBlobStore.getBucketEncryption(containerName))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> shardedBlobStore.putBucketEncryption(
                containerName, configuration))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() ->
                shardedBlobStore.deleteBucketEncryption(containerName))
                .isInstanceOf(UnsupportedOperationException.class);

        // A bucket that is not sharded passes straight through.
        String plain = TestUtils.createRandomContainerName();
        this.createContainer(plain);
        shardedBlobStore.putBucketEncryption(plain, configuration);
        assertThat(shardedBlobStore.getBucketEncryption(plain).rules()
                .get(0).applyServerSideEncryptionByDefault().sseAlgorithm())
                .isEqualTo(ServerSideEncryption.AES256);
    }

    public int countShards() {
        var listing = blobStore.list();
        int blobStoreShards = 0;
        for (var entry : listing.buckets()) {
            if (entry.name().startsWith(prefix)) {
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
        shardedBlobStore.deleteBucket(containerName);
        assertThat(this.countShards()).isZero();
    }

    @Test
    public void testDeleteContainerNonEmptyShard() throws Exception {
        this.createContainer(containerName);
        // Place an object directly on a non-zero shard so shard 0 keeps only
        // the superblock.  deleteBucket must report the bucket as non-empty
        // and leave every shard and the superblock intact.
        String nonZeroShard = "%s-3".formatted(prefix);
        ByteSource content = TestUtils.randomByteSource().slice(0, 1024);
        TestUtils.putBlob(blobStore, nonZeroShard, "object", content);

        assertThatThrownBy(() ->
                shardedBlobStore.deleteBucket(containerName))
                .isInstanceOf(S3Exception.class)
                .satisfies(thrown -> assertThat(
                        S3Exceptions.errorCode((S3Exception) thrown))
                        .isEqualTo("BucketNotEmpty"));
        assertThat(this.countShards()).isEqualTo(this.shards);
        assertThat(blobStore.blobExists(nonZeroShard, "object")).isTrue();
        assertThat(blobStore.blobExists("%s-0".formatted(prefix),
                ".s3proxy-sharded-superblock")).isTrue();

        blobStore.removeBlob(nonZeroShard, "object");
    }

    @Test
    public void testDeleteContainerEmptyShardZero() {
        this.createContainer(containerName);
        // Remove the superblock so shard 0 is empty; the delete must not throw
        // NoSuchElementException and the empty bucket deletes cleanly.
        blobStore.removeBlob("%s-0".formatted(prefix),
                ".s3proxy-sharded-superblock");

        shardedBlobStore.deleteBucket(containerName);
        assertThat(this.countShards()).isZero();
    }

    @Test
    public void testPutBlob() throws Exception {
        String blobName = "foo";
        String blobName2 = "bar";
        ByteSource content = TestUtils.randomByteSource().slice(0, 1024);
        ByteSource content2 = TestUtils.randomByteSource().slice(1024, 1024);
        createContainer(containerName);
        TestUtils.putBlob(shardedBlobStore, containerName, blobName, content);
        TestUtils.putBlob(shardedBlobStore, containerName, blobName2,
                content2);

        var got1 = shardedBlobStore.getBlob(containerName, blobName);
        try (InputStream actual = got1;
             InputStream expected = content.openStream()) {
            assertThat(actual).hasSameContentAs(expected);
        }
        var gotBlob2 = shardedBlobStore.getBlob(containerName, blobName2);
        try (InputStream actual = gotBlob2;
             InputStream expected = content2.openStream()) {
            assertThat(actual).hasSameContentAs(expected);
        }

        String blobContainer = null;
        String blob2Container = null;
        for (int i = 0; i < shards; i++) {
            String shard = "%s-%d".formatted(prefix, i);
            for (var entry : blobStore.list(shard).contents()) {
                if (entry.key().equals(blobName)) {
                    blobContainer = shard;
                }
                if (entry.key().equals(blobName2)) {
                    blob2Container = shard;
                }
            }
        }
        assertThat(blobContainer).isNotNull();
        assertThat(blob2Container).isNotNull();
        assertThat(blobContainer).isNotEqualTo(blob2Container);
    }

    @Test
    public void testDeleteBlob() throws Exception {
        String blobName = TestUtils.createRandomBlobName();
        ByteSource content = TestUtils.randomByteSource().slice(0, 1024);
        this.createContainer(containerName);
        TestUtils.putBlob(shardedBlobStore, containerName, blobName, content);
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
        this.createContainer(unshardedContainer);
        TestUtils.putBlob(shardedBlobStore, unshardedContainer, blobName,
                content);
        var got2 = blobStore.getBlob(unshardedContainer, blobName);
        try (InputStream actual = got2;
             InputStream expected = content.openStream()) {
            assertThat(actual).hasSameContentAs(expected);
        }
    }

    @Test
    public void testCopyBlob() throws Exception {
        String blobName = TestUtils.createRandomBlobName();
        ByteSource content = TestUtils.randomByteSource().slice(0, 1024);
        this.createContainer(containerName);
        TestUtils.putBlob(shardedBlobStore, containerName, blobName, content);
        String copyBlobName = TestUtils.createRandomBlobName();
        shardedBlobStore.copyBlob(CopyObjectRequest.builder()
                .sourceBucket(containerName).sourceKey(blobName)
                .destinationBucket(containerName).destinationKey(copyBlobName)
                .build());
        var got3 = shardedBlobStore.getBlob(containerName, copyBlobName);
        try (InputStream actual = got3;
             InputStream expected = content.openStream()) {
            assertThat(actual).hasSameContentAs(expected);
        }
    }

    @Test
    public void testCopyBlobUnshardedToSharded() throws Exception {
        String blobName = TestUtils.createRandomBlobName();
        String unshardedContainer = TestUtils.createRandomContainerName();
        ByteSource content = TestUtils.randomByteSource().slice(0, 1024);
        this.createContainer(containerName);
        this.createContainer(unshardedContainer);
        TestUtils.putBlob(shardedBlobStore, unshardedContainer, blobName,
                content);
        shardedBlobStore.copyBlob(CopyObjectRequest.builder()
                .sourceBucket(unshardedContainer).sourceKey(blobName)
                .destinationBucket(containerName).destinationKey(blobName)
                .build());
        var got4 = shardedBlobStore.getBlob(containerName, blobName);
        try (InputStream actual = got4;
             InputStream expected = content.openStream()) {
            assertThat(actual).hasSameContentAs(expected);
        }
    }

    @Test
    public void testCopyBlobShardedToUnsharded() throws Exception {
        String blobName = TestUtils.createRandomBlobName();
        String unshardedContainer = TestUtils.createRandomContainerName();
        ByteSource content = TestUtils.randomByteSource().slice(0, 1024);
        this.createContainer(containerName);
        this.createContainer(unshardedContainer);
        TestUtils.putBlob(shardedBlobStore, containerName, blobName, content);
        shardedBlobStore.copyBlob(CopyObjectRequest.builder()
                .sourceBucket(containerName).sourceKey(blobName)
                .destinationBucket(unshardedContainer).destinationKey(blobName)
                .build());
        var got5 = shardedBlobStore.getBlob(unshardedContainer, blobName);
        try (InputStream actual = got5;
             InputStream expected = content.openStream()) {
            assertThat(actual).hasSameContentAs(expected);
        }
    }

    /**
     * A part the backend can copy itself has to reach it naming the shard
     * the source key hashes to, the same one {@link ShardedBlobStore#copyBlob}
     * reads.  The wrapper used to keep the interface's refusal instead, so
     * S3Proxy streamed every part down and back up.
     */
    @Test
    public void testCopiesAPartOutOfTheShardItLandedIn() throws Exception {
        String blobName = TestUtils.createRandomBlobName();
        String unshardedContainer = TestUtils.createRandomContainerName();
        this.createContainer(containerName);
        this.createContainer(unshardedContainer);
        TestUtils.putBlob(shardedBlobStore, containerName, blobName,
                TestUtils.randomByteSource().slice(0, 1024));
        String shard = null;
        for (int i = 0; i < shards; i++) {
            String candidate = "%s-%d".formatted(prefix, i);
            for (var entry : blobStore.list(candidate).contents()) {
                if (entry.key().equals(blobName)) {
                    shard = candidate;
                }
            }
        }
        assertThat(shard).isNotNull();

        var recorder = new PartCopyRecorder(blobStore);
        BlobStore store = ShardedBlobStore.newShardedBlobStore(recorder,
                Map.of(containerName, shards), prefixesMap);
        assertThat(store.supportsCopyMultipartPart()).isTrue();
        var mpu = new MultipartUpload("upload-id",
                TestUtils.createRequest(unshardedContainer, blobName));

        store.copyMultipartPart(mpu, UploadPartCopyRequest.builder()
                .sourceBucket(containerName)
                .sourceKey(blobName)
                .destinationBucket(unshardedContainer)
                .destinationKey(blobName)
                .uploadId("upload-id")
                .partNumber(1)
                .build());

        assertThat(recorder.request()).isNotNull();
        assertThat(recorder.request().sourceBucket()).isEqualTo(shard);
        // the upload's own bucket shards nothing and is left alone
        assertThat(recorder.request().destinationBucket())
                .isEqualTo(unshardedContainer);
    }

    /** A sharded bucket holds no upload, so no part is copied into one. */
    @Test
    public void testRefusesAPartCopyIntoAShardedBucket() {
        var recorder = new PartCopyRecorder(blobStore);
        BlobStore store = ShardedBlobStore.newShardedBlobStore(recorder,
                Map.of(containerName, shards), prefixesMap);
        var mpu = new MultipartUpload("upload-id",
                TestUtils.createRequest(containerName, "object"));

        assertThatThrownBy(() -> store.copyMultipartPart(mpu,
                UploadPartCopyRequest.builder()
                        .sourceBucket(containerName)
                        .sourceKey("source")
                        .destinationBucket(containerName)
                        .destinationKey("object")
                        .uploadId("upload-id")
                        .partNumber(1)
                        .build()))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThat(recorder.request()).isNull();
    }

    /**
     * Where the backend cannot copy a part itself the wrapper must not claim
     * it can, since the caller reads that as leave to skip the streamed copy.
     */
    @Test
    public void testFollowsABackendThatCopiesNoPart() {
        assertThat(shardedBlobStore.supportsCopyMultipartPart()).isFalse();
    }
}
