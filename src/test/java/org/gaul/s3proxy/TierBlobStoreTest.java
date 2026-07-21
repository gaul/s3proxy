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

package org.gaul.s3proxy;

import static org.assertj.core.api.Assertions.assertThat;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.ByteSourcePayload;
import org.gaul.s3proxy.blobstore.domain.Blob;
import org.gaul.s3proxy.blobstore.domain.StorageClass;
import org.gaul.s3proxy.blobstore.options.PutOptions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

@SuppressWarnings("UnstableApiUsage")
public final class TierBlobStoreTest {
    private BlobStore blobStore;
    private String containerName;
    private BlobStore tierBlobStore;

    @BeforeEach
    public void setUp() throws Exception {
        containerName = TestUtils.createRandomContainerName();

        //noinspection UnstableApiUsage
        blobStore = TestUtils.createTransientBlobStore();
        blobStore.createContainer(containerName);

        tierBlobStore = StorageClassBlobStore.newStorageClassBlobStore(
                blobStore, StorageClass.DEEP_ARCHIVE.toString());
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (blobStore != null) {
            blobStore.deleteContainer(containerName);
        }
    }

    @Test
    public void testPutNewBlob() {
        var blobName = TestUtils.createRandomBlobName();
        var content = TestUtils.randomByteSource().slice(0, 1024);
        var blob = Blob.builder(blobName).payload(content).build();
        tierBlobStore.putBlob(containerName, blob);

        var blobMetadata = tierBlobStore.blobMetadata(containerName, blobName);
        assertThat(blobMetadata.storageClass()).isEqualTo(StorageClass.DEEP_ARCHIVE);
    }

    @Test
    public void testGetExistingBlob() {
        var blobName = TestUtils.createRandomBlobName();
        var content = TestUtils.randomByteSource().slice(0, 1024);
        var blob = Blob.builder(blobName).payload(content).build();
        blobStore.putBlob(containerName, blob);

        var blobMetadata = tierBlobStore.blobMetadata(containerName, blobName);
        assertThat(blobMetadata.storageClass()).isEqualTo(StorageClass.STANDARD);
    }

    @Test
    public void testPutNewMpu() {
        var blobName = TestUtils.createRandomBlobName();
        var content = TestUtils.randomByteSource().slice(0, 1024);
        var blob = Blob.builder(blobName).payload(content).build();

        var mpu = tierBlobStore.initiateMultipartUpload(
                containerName, blob.getMetadata(), PutOptions.NONE);

        var payload = new ByteSourcePayload(content);
        tierBlobStore.uploadMultipartPart(mpu, 1, payload);

        var parts = tierBlobStore.listMultipartUpload(mpu);
        tierBlobStore.completeMultipartUpload(mpu, parts);

        var blobMetadata = tierBlobStore.blobMetadata(containerName, blobName);
        assertThat(blobMetadata.storageClass()).isEqualTo(StorageClass.DEEP_ARCHIVE);
    }

    @Test
    public void testGetExistingMpu() {
        var blobName = TestUtils.createRandomBlobName();
        var content = TestUtils.randomByteSource().slice(0, 1024);
        var blob = Blob.builder(blobName).payload(content).build();

        var mpu = blobStore.initiateMultipartUpload(
                containerName, blob.getMetadata(), PutOptions.NONE);

        var payload = new ByteSourcePayload(content);
        blobStore.uploadMultipartPart(mpu, 1, payload);

        var parts = blobStore.listMultipartUpload(mpu);
        blobStore.completeMultipartUpload(mpu, parts);

        var blobMetadata = tierBlobStore.blobMetadata(containerName, blobName);
        assertThat(blobMetadata.storageClass()).isEqualTo(StorageClass.STANDARD);
    }
}
