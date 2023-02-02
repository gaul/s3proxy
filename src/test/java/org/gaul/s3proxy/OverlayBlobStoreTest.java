/*
 * Copyright 2014-2021 Andrew Gaul <andrew@gaul.org>
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

import com.google.common.collect.ImmutableList;
import com.google.inject.Module;
import org.apache.commons.io.FileUtils;
import org.assertj.core.api.Fail;
import org.jclouds.ContextBuilder;
import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.BlobStoreContext;
import org.jclouds.blobstore.BlobStoreContext;
import org.jclouds.blobstore.domain.Blob;
import org.jclouds.blobstore.domain.BlobBuilder;
import org.jclouds.blobstore.domain.PageSet;
import org.jclouds.blobstore.domain.StorageMetadata;
import org.jclouds.blobstore.options.PutOptions;
import org.jclouds.logging.slf4j.config.SLF4JLoggingModule;
import org.jclouds.openstack.keystone.catalog.ServiceEndpoint;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.Random;

import static org.assertj.core.api.Assertions.assertThat;

public final class OverlayBlobStoreTest {
    private BlobStoreContext context;
    private BlobStore blobStore;
    private BlobStore overlayBlobStore;

    private String containerName;
    private String blobName;
    private String maskedBlobName;

    private String overlayPath = "/tmp";

    @Before
    public void setUp() throws Exception {
        containerName = createRandomContainerName();
        blobName = createRandomBlobName();
        maskedBlobName = createRandomBlobName();

        context = ContextBuilder
                .newBuilder("transient")
                .credentials("identity", "credential")
                .modules(ImmutableList.<Module>of(new SLF4JLoggingModule()))
                .build(BlobStoreContext.class);
        blobStore = context.getBlobStore();

        blobStore.createContainerInLocation(null, containerName);

        // Manually create a Blob that will be visible via the OverlayBlobStore
        BlobBuilder blobBuilder = blobStore.blobBuilder(blobName).payload("Blobby");
        blobStore.putBlob(containerName, blobBuilder.build());

        // Manually create another Blob
        blobBuilder = blobStore.blobBuilder(maskedBlobName).payload("Masked Blobby");
        blobStore.putBlob(containerName, blobBuilder.build());

        overlayBlobStore = OverlayBlobStore.newOverlayBlobStore(blobStore, overlayPath, "__deleted");
        blobBuilder = blobStore.blobBuilder(maskedBlobName + "__deleted").payload("");

        ((OverlayBlobStore)overlayBlobStore).localBlobStore().createContainerInLocation(null, containerName);
        ((OverlayBlobStore)overlayBlobStore).localBlobStore().putBlob(containerName, blobBuilder.build());
    }

    @After
    public void tearDown() throws Exception {
        if (context != null) {
            blobStore.deleteContainer(containerName);
            context.close();
        }
        if (((OverlayBlobStore)overlayBlobStore).localBlobStore().containerExists(containerName)){
            ((OverlayBlobStore)overlayBlobStore).localBlobStore().deleteContainer(containerName);
        }
    }

    @Test
    public void testContainerExists() throws Exception {
        assertThat(overlayBlobStore.containerExists(containerName)).isTrue();
        assertThat(overlayBlobStore.containerExists(
                containerName + "-fake")).isFalse();
    }

    @Test
    public void testMaskedBlobList() throws Exception {
        PageSet<? extends StorageMetadata> blobs = overlayBlobStore.list(containerName);
        for(StorageMetadata sm : blobs){
            assertThat(sm.getName()).isNotEqualTo(maskedBlobName);
        }
    }

    @Test
    public void testDeleteBlob() throws Exception {
        overlayBlobStore.removeBlob(containerName, blobName);
        PageSet<? extends StorageMetadata> blobs = overlayBlobStore.list(containerName);
        for(StorageMetadata sm : blobs){
            assertThat(sm.getName()).isNotEqualTo(blobName);
        }
        Blob test = overlayBlobStore.getBlob(containerName, blobName);
        assertThat(test).isNull();
    }

    @Test
    public void testMaskedBlobGetBlob() throws Exception {
        Blob test = overlayBlobStore.getBlob(containerName, maskedBlobName);
        assertThat(test).isNull();
    }

    @Test
    public void testUnmaskedBlobGetBlob() throws Exception {
        Blob test = overlayBlobStore.getBlob(containerName, blobName);
        assertThat(test).isNotNull();
        assertThat(test.getMetadata().getName()).isEqualTo(blobName);
    }

    @Test
    public void testLocalBlobShadowsUpstreamBlob() throws Exception {
        Blob originalTest = overlayBlobStore.getBlob(containerName, blobName);
        BlobBuilder blobBuilder = overlayBlobStore.blobBuilder(blobName).payload("testLocalBlobShadowsUpstreamBlob");
        overlayBlobStore.putBlob(containerName, blobBuilder.build());
        Blob newTest = overlayBlobStore.getBlob(containerName, blobName);
        PageSet<? extends StorageMetadata> newBlobList = overlayBlobStore.list(containerName);

        assertThat(originalTest.getMetadata().getLastModified()).isNotEqualTo(newTest.getMetadata().getLastModified());
        assertThat(new String(newTest.getPayload().getInput().readAllBytes())).isEqualTo("testLocalBlobShadowsUpstreamBlob");

        for(StorageMetadata sm : newBlobList){
            if(sm.getName().equals(blobName)){
                assertThat(sm.getLastModified()).isNotEqualTo(originalTest.getMetadata().getLastModified());
                assertThat(sm.getLastModified()).isEqualTo(newTest.getMetadata().getLastModified());
            }
        }
    }

    @Test
    public void testLocalOnlyBlob() throws Exception {
        BlobBuilder blobBuilder = overlayBlobStore.blobBuilder("testLocalOnlyBlob").payload("testLocalOnlyBlob");
        Blob newBlob = blobBuilder.build();
        overlayBlobStore.putBlob(containerName, newBlob);
        Blob newTest = overlayBlobStore.getBlob(containerName, newBlob.getMetadata().getName());
        assertThat(new String(newTest.getPayload().getInput().readAllBytes())).isEqualTo("testLocalOnlyBlob");
    }

    @Test
    public void testPutBlob() throws Exception {
        BlobBuilder blobBuilder = overlayBlobStore.blobBuilder("testPutBlob").payload("Test");
        overlayBlobStore.putBlob(containerName, blobBuilder.build());
    }

    @Test
    public void testPutBlobOptions() throws Exception {
        BlobBuilder blobBuilder = overlayBlobStore.blobBuilder("testPutBlob").payload("Test");
        overlayBlobStore.putBlob(containerName, blobBuilder.build(), new PutOptions());
    }

    private static String createRandomContainerName() {
        return "container-" + new Random().nextInt(Integer.MAX_VALUE);
    }

    private static String createRandomBlobName() {
        return "blob" + new Random().nextInt(Integer.MAX_VALUE);
    }

}
