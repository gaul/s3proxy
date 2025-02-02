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
import java.util.Map;

import org.jclouds.ContextBuilder;
import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.BlobStoreContext;
import org.jclouds.blobstore.options.PutOptions;
import org.jclouds.logging.slf4j.config.SLF4JLoggingModule;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

@SuppressWarnings("UnstableApiUsage")
public final class UserMetadataReplacerBlobStoreTest {
    private BlobStoreContext context;
    private BlobStore blobStore;
    private String containerName;
    // TODO: better name?
    private BlobStore userMetadataReplacerBlobStore;

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

        userMetadataReplacerBlobStore = UserMetadataReplacerBlobStore
                .newUserMetadataReplacerBlobStore(blobStore, "-", "_");
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
        var blob = userMetadataReplacerBlobStore.blobBuilder(blobName)
                .payload(content)
                .userMetadata(Map.of("my-key", "my-value-"))
                .build();
        userMetadataReplacerBlobStore.putBlob(containerName, blob);

        // check underlying blobStore
        var mutableBlobMetadata = blobStore.getBlob(containerName, blobName)
                .getMetadata();
        var userMetadata = mutableBlobMetadata.getUserMetadata();
        assertThat(userMetadata).hasSize(1);
        var entry = userMetadata.entrySet().iterator().next();
        assertThat(entry.getKey()).isEqualTo("my_key");
        assertThat(entry.getValue()).isEqualTo("my_value_");

        // check getBlob
        mutableBlobMetadata = userMetadataReplacerBlobStore.getBlob(
                containerName, blobName).getMetadata();
        userMetadata = mutableBlobMetadata.getUserMetadata();
        assertThat(userMetadata).hasSize(1);
        entry = userMetadata.entrySet().iterator().next();
        assertThat(entry.getKey()).isEqualTo("my-key");
        assertThat(entry.getValue()).isEqualTo("my-value-");

        // check blobMetadata
        var blobMetadata = userMetadataReplacerBlobStore.blobMetadata(
                containerName, blobName);
        userMetadata = blobMetadata.getUserMetadata();
        assertThat(userMetadata).hasSize(1);
        entry = userMetadata.entrySet().iterator().next();
        assertThat(entry.getKey()).isEqualTo("my-key");
        assertThat(entry.getValue()).isEqualTo("my-value-");
    }

    @Test
    public void testPutNewMultipartBlob() {
        var blobName = TestUtils.createRandomBlobName();
        var content = TestUtils.randomByteSource().slice(0, 1024);
        var blob = userMetadataReplacerBlobStore.blobBuilder(blobName)
                .payload(content)
                .userMetadata(Map.of("my-key", "my-value-"))
                .build();
        var mpu = userMetadataReplacerBlobStore.initiateMultipartUpload(
                containerName, blob.getMetadata(), new PutOptions());
        var part = userMetadataReplacerBlobStore.uploadMultipartPart(
                mpu, 1, blob.getPayload());
        userMetadataReplacerBlobStore.completeMultipartUpload(
                mpu, List.of(part));

        // check underlying blobStore
        var mutableBlobMetadata = blobStore.getBlob(containerName, blobName)
                .getMetadata();
        var userMetadata = mutableBlobMetadata.getUserMetadata();
        assertThat(userMetadata).hasSize(1);
        var entry = userMetadata.entrySet().iterator().next();
        assertThat(entry.getKey()).isEqualTo("my_key");
        assertThat(entry.getValue()).isEqualTo("my_value_");

        // check getBlob
        mutableBlobMetadata = userMetadataReplacerBlobStore.getBlob(
                containerName, blobName).getMetadata();
        userMetadata = mutableBlobMetadata.getUserMetadata();
        assertThat(userMetadata).hasSize(1);
        entry = userMetadata.entrySet().iterator().next();
        assertThat(entry.getKey()).isEqualTo("my-key");
        assertThat(entry.getValue()).isEqualTo("my-value-");

        // check blobMetadata
        var blobMetadata = userMetadataReplacerBlobStore.blobMetadata(
                containerName, blobName);
        userMetadata = blobMetadata.getUserMetadata();
        assertThat(userMetadata).hasSize(1);
        entry = userMetadata.entrySet().iterator().next();
        assertThat(entry.getKey()).isEqualTo("my-key");
        assertThat(entry.getValue()).isEqualTo("my-value-");
    }
}
