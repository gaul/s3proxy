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

import java.util.List;

import org.jclouds.ContextBuilder;
import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.BlobStoreContext;
import org.jclouds.blobstore.domain.Tier;
import org.jclouds.blobstore.options.PutOptions;
import org.jclouds.io.Payloads;
import org.jclouds.logging.slf4j.config.SLF4JLoggingModule;
import org.jclouds.s3.domain.ObjectMetadata.StorageClass;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

@SuppressWarnings("UnstableApiUsage")
public final class TierBlobStoreTest {
    private BlobStoreContext context;
    private BlobStore blobStore;
    private String containerName;
    private BlobStore tierBlobStore;

    @Before
    public void setUp() throws Exception {
        containerName = TestUtils.createRandomContainerName();

        //noinspection UnstableApiUsage
        context = ContextBuilder
                .newBuilder("transient")
                .credentials("identity", "credential")
                .modules(List.of(new SLF4JLoggingModule()))
                .build(BlobStoreContext.class);
        blobStore = context.getBlobStore();
        blobStore.createContainerInLocation(null, containerName);

        tierBlobStore = StorageClassBlobStore.newStorageClassBlobStore(
                blobStore, StorageClass.DEEP_ARCHIVE.toString());
    }

    @After
    public void tearDown() throws Exception {
        if (context != null) {
            blobStore.deleteContainer(containerName);
            context.close();
        }
    }

    @Test
    public void testPutNewBlob() {
        var blobName = TestUtils.createRandomBlobName();
        var content = TestUtils.randomByteSource().slice(0, 1024);
        var blob = tierBlobStore.blobBuilder(blobName).payload(content).build();
        tierBlobStore.putBlob(containerName, blob);

        var blobMetadata = tierBlobStore.blobMetadata(containerName, blobName);
        assertThat(blobMetadata.getTier()).isEqualTo(Tier.ARCHIVE);
    }

    @Test
    public void testGetExistingBlob() {
        var blobName = TestUtils.createRandomBlobName();
        var content = TestUtils.randomByteSource().slice(0, 1024);
        var blob = blobStore.blobBuilder(blobName).payload(content).build();
        blobStore.putBlob(containerName, blob);

        var blobMetadata = tierBlobStore.blobMetadata(containerName, blobName);
        assertThat(blobMetadata.getTier()).isEqualTo(Tier.STANDARD);
    }

    @Test
    public void testPutNewMpu() {
        var blobName = TestUtils.createRandomBlobName();
        var content = TestUtils.randomByteSource().slice(0, 1024);
        var blob = tierBlobStore.blobBuilder(blobName).payload(content).build();

        var mpu = tierBlobStore.initiateMultipartUpload(
                containerName, blob.getMetadata(), new PutOptions());

        var payload = Payloads.newByteSourcePayload(content);
        tierBlobStore.uploadMultipartPart(mpu, 1, payload);

        var parts = tierBlobStore.listMultipartUpload(mpu);
        tierBlobStore.completeMultipartUpload(mpu, parts);

        var blobMetadata = tierBlobStore.blobMetadata(containerName, blobName);
        assertThat(blobMetadata.getTier()).isEqualTo(Tier.ARCHIVE);
    }

    @Test
    public void testGetExistingMpu() {
        var blobName = TestUtils.createRandomBlobName();
        var content = TestUtils.randomByteSource().slice(0, 1024);
        var blob = blobStore.blobBuilder(blobName).payload(content).build();

        var mpu = blobStore.initiateMultipartUpload(
                containerName, blob.getMetadata(), new PutOptions());

        var payload = Payloads.newByteSourcePayload(content);
        blobStore.uploadMultipartPart(mpu, 1, payload);

        var parts = blobStore.listMultipartUpload(mpu);
        blobStore.completeMultipartUpload(mpu, parts);

        var blobMetadata = tierBlobStore.blobMetadata(containerName, blobName);
        assertThat(blobMetadata.getTier()).isEqualTo(Tier.STANDARD);
    }
}
