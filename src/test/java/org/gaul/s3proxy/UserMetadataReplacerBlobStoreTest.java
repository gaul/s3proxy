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

import java.util.List;
import java.util.Map;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.domain.Blob;
import org.gaul.s3proxy.blobstore.options.CopyOptions;
import org.gaul.s3proxy.blobstore.options.PutOptions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

@SuppressWarnings("UnstableApiUsage")
public final class UserMetadataReplacerBlobStoreTest {
    private BlobStore blobStore;
    private String containerName;
    // TODO: better name?
    private BlobStore userMetadataReplacerBlobStore;

    @BeforeEach
    public void setUp() throws Exception {
        containerName = TestUtils.createRandomContainerName();

        //noinspection UnstableApiUsage
        blobStore = TestUtils.createTransientBlobStore();
        blobStore.createContainer(containerName);

        userMetadataReplacerBlobStore = UserMetadataReplacerBlobStore
                .newUserMetadataReplacerBlobStore(blobStore, "-", "_");
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
        var blob = Blob.builder(blobName)
                .payload(content)
                .userMetadata(Map.of("my-key", "my-value-"))
                .build();
        userMetadataReplacerBlobStore.putBlob(containerName, blob);

        // check underlying blobStore
        var mutableBlobMetadata = blobStore.getBlob(containerName, blobName)
                .getMetadata();
        var userMetadata = mutableBlobMetadata.userMetadata();
        assertThat(userMetadata).hasSize(1);
        var entry = userMetadata.entrySet().iterator().next();
        assertThat(entry.getKey()).isEqualTo("my_key");
        assertThat(entry.getValue()).isEqualTo("my_value_");

        // check getBlob
        mutableBlobMetadata = userMetadataReplacerBlobStore.getBlob(
                containerName, blobName).getMetadata();
        userMetadata = mutableBlobMetadata.userMetadata();
        assertThat(userMetadata).hasSize(1);
        entry = userMetadata.entrySet().iterator().next();
        assertThat(entry.getKey()).isEqualTo("my-key");
        assertThat(entry.getValue()).isEqualTo("my-value-");

        // check blobMetadata
        var blobMetadata = userMetadataReplacerBlobStore.blobMetadata(
                containerName, blobName);
        userMetadata = blobMetadata.userMetadata();
        assertThat(userMetadata).hasSize(1);
        entry = userMetadata.entrySet().iterator().next();
        assertThat(entry.getKey()).isEqualTo("my-key");
        assertThat(entry.getValue()).isEqualTo("my-value-");
    }

    @Test
    public void testCopyBlobReplaceMetadata() {
        var fromName = TestUtils.createRandomBlobName();
        var toName = TestUtils.createRandomBlobName();
        var content = TestUtils.randomByteSource().slice(0, 1024);
        var blob = Blob.builder(fromName)
                .payload(content)
                .build();
        userMetadataReplacerBlobStore.putBlob(containerName, blob);

        // A copy with a metadata-replace directive must munge the new
        // metadata into the backend the same way putBlob does.
        userMetadataReplacerBlobStore.copyBlob(containerName, fromName,
                containerName, toName, CopyOptions.builder()
                        .userMetadata(Map.of("my-key", "my-value-"))
                        .build());

        // check underlying blobStore stores the munged form
        var backend = blobStore.blobMetadata(containerName, toName)
                .userMetadata();
        assertThat(backend).isEqualTo(Map.of("my_key", "my_value_"));

        // check getBlob reverses it
        var replaced = userMetadataReplacerBlobStore.getBlob(
                containerName, toName).getMetadata().userMetadata();
        assertThat(replaced).isEqualTo(Map.of("my-key", "my-value-"));
    }

    @Test
    public void testCopyBlobPreservesMetadata() {
        var fromName = TestUtils.createRandomBlobName();
        var toName = TestUtils.createRandomBlobName();
        var content = TestUtils.randomByteSource().slice(0, 1024);
        var blob = Blob.builder(fromName)
                .payload(content)
                .userMetadata(Map.of("my-key", "my-value-"))
                .build();
        userMetadataReplacerBlobStore.putBlob(containerName, blob);

        // A copy without a replace directive carries the source's stored
        // (already-munged) metadata forward untouched; it must not be
        // re-munged or wiped.
        userMetadataReplacerBlobStore.copyBlob(containerName, fromName,
                containerName, toName, CopyOptions.NONE);

        // backend still holds the single munged form
        assertThat(blobStore.blobMetadata(containerName, toName)
                .userMetadata()).isEqualTo(Map.of("my_key", "my_value_"));

        // getBlob reverses it
        assertThat(userMetadataReplacerBlobStore.getBlob(containerName, toName)
                .getMetadata().userMetadata())
                .isEqualTo(Map.of("my-key", "my-value-"));
    }

    @Test
    public void testPutNewMultipartBlob() throws Exception {
        var blobName = TestUtils.createRandomBlobName();
        var content = TestUtils.randomByteSource().slice(0, 1024);
        var blob = Blob.builder(blobName)
                .payload(content)
                .userMetadata(Map.of("my-key", "my-value-"))
                .build();
        var mpu = userMetadataReplacerBlobStore.initiateMultipartUpload(
                containerName, blob.getMetadata(), PutOptions.NONE);
        var part = userMetadataReplacerBlobStore.uploadMultipartPart(
                mpu, 1, content.openStream(), content.size(), null);
        userMetadataReplacerBlobStore.completeMultipartUpload(
                mpu, List.of(part));

        // check underlying blobStore
        var mutableBlobMetadata = blobStore.getBlob(containerName, blobName)
                .getMetadata();
        var userMetadata = mutableBlobMetadata.userMetadata();
        assertThat(userMetadata).hasSize(1);
        var entry = userMetadata.entrySet().iterator().next();
        assertThat(entry.getKey()).isEqualTo("my_key");
        assertThat(entry.getValue()).isEqualTo("my_value_");

        // check getBlob
        mutableBlobMetadata = userMetadataReplacerBlobStore.getBlob(
                containerName, blobName).getMetadata();
        userMetadata = mutableBlobMetadata.userMetadata();
        assertThat(userMetadata).hasSize(1);
        entry = userMetadata.entrySet().iterator().next();
        assertThat(entry.getKey()).isEqualTo("my-key");
        assertThat(entry.getValue()).isEqualTo("my-value-");

        // check blobMetadata
        var blobMetadata = userMetadataReplacerBlobStore.blobMetadata(
                containerName, blobName);
        userMetadata = blobMetadata.userMetadata();
        assertThat(userMetadata).hasSize(1);
        entry = userMetadata.entrySet().iterator().next();
        assertThat(entry.getKey()).isEqualTo("my-key");
        assertThat(entry.getValue()).isEqualTo("my-value-");
    }
}
