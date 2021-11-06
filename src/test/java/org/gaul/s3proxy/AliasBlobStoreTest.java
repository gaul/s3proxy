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

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import com.google.common.collect.ImmutableBiMap;
import com.google.common.collect.ImmutableList;
import com.google.common.hash.HashCode;
import com.google.common.hash.Hashing;
import com.google.common.io.ByteSource;
import com.google.inject.Module;

import org.assertj.core.api.Assertions;
import org.jclouds.ContextBuilder;
import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.BlobStoreContext;
import org.jclouds.blobstore.domain.Blob;
import org.jclouds.blobstore.domain.BlobMetadata;
import org.jclouds.blobstore.domain.MultipartPart;
import org.jclouds.blobstore.domain.MultipartUpload;
import org.jclouds.blobstore.domain.PageSet;
import org.jclouds.blobstore.domain.StorageMetadata;
import org.jclouds.blobstore.options.PutOptions;
import org.jclouds.io.Payloads;
import org.jclouds.logging.slf4j.config.SLF4JLoggingModule;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public final class AliasBlobStoreTest {
    private String containerName;
    private String aliasContainerName;
    private BlobStoreContext context;
    private BlobStore blobStore;
    private BlobStore aliasBlobStore;
    private List<String> createdContainers;

    @Before
    public void setUp() {
        containerName = TestUtils.createRandomContainerName();
        aliasContainerName = String.format("alias-%s", containerName);
        context = ContextBuilder
                .newBuilder("transient")
                .credentials("identity", "credential")
                .modules(ImmutableList.<Module>of(new SLF4JLoggingModule()))
                .build(BlobStoreContext.class);
        blobStore = context.getBlobStore();
        ImmutableBiMap.Builder<String, String> aliasesBuilder =
                new ImmutableBiMap.Builder<>();
        aliasesBuilder.put(aliasContainerName, containerName);
        aliasBlobStore = AliasBlobStore.newAliasBlobStore(
                blobStore, aliasesBuilder.build());
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
        assertThat(aliasBlobStore.createContainerInLocation(
                null, container)).isTrue();
        if (container.equals(aliasContainerName)) {
            createdContainers.add(containerName);
        } else {
            createdContainers.add(container);
        }
    }

    @Test
    public void testListNoAliasContainers() {
        String regularContainer = TestUtils.createRandomContainerName();
        createContainer(regularContainer);
        PageSet<? extends StorageMetadata> listing = aliasBlobStore.list();
        assertThat(listing.size()).isEqualTo(1);
        assertThat(listing.iterator().next().getName()).isEqualTo(
                regularContainer);
    }

    @Test
    public void testListAliasContainer() {
        createContainer(aliasContainerName);
        PageSet<? extends StorageMetadata> listing = aliasBlobStore.list();
        assertThat(listing.size()).isEqualTo(1);
        assertThat(listing.iterator().next().getName()).isEqualTo(
                aliasContainerName);
        listing = blobStore.list();
        assertThat(listing.size()).isEqualTo(1);
        assertThat(listing.iterator().next().getName()).isEqualTo(
                containerName);
    }

    @Test
    public void testAliasBlob() throws IOException {
        createContainer(aliasContainerName);
        String blobName = TestUtils.createRandomBlobName();
        ByteSource content = TestUtils.randomByteSource().slice(0, 1024);
        String contentMD5 = Hashing.md5().hashBytes(content.read()).toString();
        Blob blob = aliasBlobStore.blobBuilder(blobName).payload(content)
                .build();
        String eTag = aliasBlobStore.putBlob(aliasContainerName, blob);
        assertThat(eTag).isEqualTo(contentMD5);
        BlobMetadata blobMetadata = aliasBlobStore.blobMetadata(
                aliasContainerName, blobName);
        assertThat(blobMetadata.getETag()).isEqualTo(contentMD5);
        blob = aliasBlobStore.getBlob(aliasContainerName, blobName);
        try (InputStream actual = blob.getPayload().openStream();
             InputStream expected = content.openStream()) {
            assertThat(actual).hasContentEqualTo(expected);
        }
    }

    @Test
    public void testAliasMultipartUpload() throws IOException {
        createContainer(aliasContainerName);
        String blobName = TestUtils.createRandomBlobName();
        ByteSource content = TestUtils.randomByteSource().slice(0, 1024);
        HashCode contentHash = Hashing.md5().hashBytes(content.read());
        Blob blob = aliasBlobStore.blobBuilder(blobName).build();
        MultipartUpload mpu = aliasBlobStore.initiateMultipartUpload(
                aliasContainerName, blob.getMetadata(), PutOptions.NONE);
        assertThat(mpu.containerName()).isEqualTo(aliasContainerName);
        MultipartPart part = aliasBlobStore.uploadMultipartPart(
                mpu, 1, Payloads.newPayload(content));
        assertThat(part.partETag()).isEqualTo(contentHash.toString());
        ImmutableList.Builder<MultipartPart> parts =
                new ImmutableList.Builder<>();
        parts.add(part);
        String mpuETag = aliasBlobStore.completeMultipartUpload(mpu,
                parts.build());
        assertThat(mpuETag).isEqualTo(
                String.format("\"%s-1\"",
                        Hashing.md5().hashBytes(contentHash.asBytes())));
        blob = aliasBlobStore.getBlob(aliasContainerName, blobName);
        try (InputStream actual = blob.getPayload().openStream();
             InputStream expected = content.openStream()) {
            assertThat(actual).hasContentEqualTo(expected);
        }
    }

    @Test
    public void testParseDuplicateAliases() {
        Properties properties = new Properties();
        properties.setProperty(String.format("%s.alias",
                S3ProxyConstants.PROPERTY_ALIAS_BLOBSTORE), "bucket");
        properties.setProperty(String.format("%s.other-alias",
                S3ProxyConstants.PROPERTY_ALIAS_BLOBSTORE), "bucket");

        try {
            AliasBlobStore.parseAliases(properties);
            Assertions.failBecauseExceptionWasNotThrown(
                    IllegalArgumentException.class);
        } catch (IllegalArgumentException exc) {
            assertThat(exc.getMessage()).isEqualTo(
                    "Backend bucket bucket is aliased twice");
        }
    }
}
