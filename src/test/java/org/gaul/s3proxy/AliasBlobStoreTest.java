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

import org.assertj.core.api.Assertions;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.ByteSourcePayload;
import org.gaul.s3proxy.blobstore.domain.Blob;
import org.gaul.s3proxy.blobstore.domain.BlobAccess;
import org.gaul.s3proxy.blobstore.domain.BlobMetadata;
import org.gaul.s3proxy.blobstore.domain.MultipartPart;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.gaul.s3proxy.blobstore.domain.PageSet;
import org.gaul.s3proxy.blobstore.domain.StorageMetadata;
import org.gaul.s3proxy.blobstore.options.PutOptions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public final class AliasBlobStoreTest {
    private String containerName;
    private String aliasContainerName;
    private BlobStore blobStore;
    private BlobStore aliasBlobStore;
    private List<String> createdContainers;

    @BeforeEach
    public void setUp() {
        containerName = TestUtils.createRandomContainerName();
        aliasContainerName = "alias-%s".formatted(containerName);
        blobStore = TestUtils.createTransientBlobStore();
        var aliasesBuilder = new ImmutableBiMap.Builder<String, String>();
        aliasesBuilder.put(aliasContainerName, containerName);
        aliasBlobStore = AliasBlobStore.newAliasBlobStore(
                blobStore, aliasesBuilder.build());
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
        assertThat(aliasBlobStore.createContainer(container)).isTrue();
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
        @SuppressWarnings("deprecation")
        String contentMD5 = Hashing.md5().hashBytes(content.read()).toString();
        Blob blob = Blob.builder(blobName).payload(content)
                .build();
        String eTag = aliasBlobStore.putBlob(aliasContainerName, blob);
        assertThat(eTag).isEqualTo(contentMD5);
        BlobMetadata blobMetadata = aliasBlobStore.blobMetadata(
                aliasContainerName, blobName);
        assertThat(blobMetadata.getETag()).isEqualTo(contentMD5);
        blob = aliasBlobStore.getBlob(aliasContainerName, blobName);
        try (InputStream actual = blob.getPayload().openStream();
             InputStream expected = content.openStream()) {
            assertThat(actual).hasSameContentAs(expected);
        }
    }

    @Test
    public void testAliasMultipartUpload() throws IOException {
        createContainer(aliasContainerName);
        String blobName = TestUtils.createRandomBlobName();
        ByteSource content = TestUtils.randomByteSource().slice(0, 1024);
        @SuppressWarnings("deprecation")
        HashCode contentHash = Hashing.md5().hashBytes(content.read());
        Blob blob = Blob.builder(blobName).build();
        MultipartUpload mpu = aliasBlobStore.initiateMultipartUpload(
                aliasContainerName, blob.getMetadata(), PutOptions.NONE);
        assertThat(mpu.containerName()).isEqualTo(aliasContainerName);
        MultipartPart part = aliasBlobStore.uploadMultipartPart(
                mpu, 1, new ByteSourcePayload(content));
        assertThat(part.partETag()).isEqualTo(contentHash.toString());
        var parts = new ImmutableList.Builder<MultipartPart>();
        parts.add(part);
        String mpuETag = aliasBlobStore.completeMultipartUpload(mpu,
                parts.build());
        @SuppressWarnings("deprecation")
        HashCode contentHash2 = Hashing.md5().hashBytes(contentHash.asBytes());
        assertThat(mpuETag).isEqualTo(
                "\"%s-1\"".formatted(contentHash2));
        blob = aliasBlobStore.getBlob(aliasContainerName, blobName);
        try (InputStream actual = blob.getPayload().openStream();
             InputStream expected = content.openStream()) {
            assertThat(actual).hasSameContentAs(expected);
        }
    }

    @Test
    public void testAliasBlobAccess() throws IOException {
        createContainer(aliasContainerName);
        String blobName = TestUtils.createRandomBlobName();
        ByteSource content = TestUtils.randomByteSource().slice(0, 1024);
        Blob blob = Blob.builder(blobName).payload(content)
                .build();
        aliasBlobStore.putBlob(aliasContainerName, blob);

        assertThat(aliasBlobStore.getBlobAccess(aliasContainerName, blobName))
                .isEqualTo(BlobAccess.PRIVATE);
        aliasBlobStore.setBlobAccess(aliasContainerName, blobName,
                BlobAccess.PUBLIC_READ);
        assertThat(aliasBlobStore.getBlobAccess(aliasContainerName, blobName))
                .isEqualTo(BlobAccess.PUBLIC_READ);
        // the change must be applied to the backend (real) container
        assertThat(blobStore.getBlobAccess(containerName, blobName))
                .isEqualTo(BlobAccess.PUBLIC_READ);
    }

    @Test
    public void testAliasListMultipartUpload() throws IOException {
        createContainer(aliasContainerName);
        String blobName = TestUtils.createRandomBlobName();
        ByteSource content = TestUtils.randomByteSource().slice(0, 1024);
        Blob blob = Blob.builder(blobName).build();
        MultipartUpload mpu = aliasBlobStore.initiateMultipartUpload(
                aliasContainerName, blob.getMetadata(), PutOptions.NONE);
        MultipartPart part = aliasBlobStore.uploadMultipartPart(
                mpu, 1, new ByteSourcePayload(content));

        List<MultipartPart> parts = aliasBlobStore.listMultipartUpload(mpu);
        assertThat(parts).hasSize(1);
        assertThat(parts.get(0).partNumber()).isEqualTo(1);

        List<MultipartUpload> uploads = aliasBlobStore.listMultipartUploads(
                aliasContainerName);
        assertThat(uploads).hasSize(1);
        assertThat(uploads.get(0).containerName()).isEqualTo(
                aliasContainerName);
        assertThat(uploads.get(0).id()).isEqualTo(mpu.id());

        aliasBlobStore.completeMultipartUpload(mpu, ImmutableList.of(part));
    }

    @Test
    public void testParseDuplicateAliases() {
        var properties = new Properties();
        properties.setProperty("%s.alias".formatted(
                S3ProxyConstants.PROPERTY_ALIAS_BLOBSTORE), "bucket");
        properties.setProperty("%s.other-alias".formatted(
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
