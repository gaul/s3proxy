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

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Properties;

import com.google.common.collect.ImmutableBiMap;
import com.google.common.io.ByteSource;

import org.assertj.core.api.Assertions;
import org.gaul.s3proxy.S3ProxyConstants;
import org.gaul.s3proxy.TestUtils;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.MD5;
import org.gaul.s3proxy.blobstore.SdkRequests;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.ObjectCannedACL;

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
        var listing = aliasBlobStore.list().buckets();
        assertThat(listing).hasSize(1);
        assertThat(listing.get(0).name()).isEqualTo(
                regularContainer);
    }

    @Test
    public void testListAliasContainer() {
        createContainer(aliasContainerName);
        var listing = aliasBlobStore.list().buckets();
        assertThat(listing).hasSize(1);
        assertThat(listing.get(0).name()).isEqualTo(
                aliasContainerName);
        listing = blobStore.list().buckets();
        assertThat(listing).hasSize(1);
        assertThat(listing.iterator().next().name()).isEqualTo(
                containerName);
    }

    @Test
    public void testAliasBlob() throws IOException {
        createContainer(aliasContainerName);
        String blobName = TestUtils.createRandomBlobName();
        ByteSource content = TestUtils.randomByteSource().slice(0, 1024);
        String contentMD5 = HexFormat.of().formatHex(
                MD5.hash(content.read()));
        String eTag = TestUtils.putBlob(aliasBlobStore, aliasContainerName,
                blobName, content).eTag();
        assertThat(eTag).isEqualTo(contentMD5);
        var blobMetadata = aliasBlobStore.blobMetadata(
                aliasContainerName, blobName);
        assertThat(blobMetadata.eTag()).isEqualTo(contentMD5);
        var got = aliasBlobStore.getBlob(aliasContainerName, blobName);
        try (InputStream actual = got;
             InputStream expected = content.openStream()) {
            assertThat(actual).hasSameContentAs(expected);
        }
    }

    @Test
    public void testAliasMultipartUpload() throws IOException {
        createContainer(aliasContainerName);
        String blobName = TestUtils.createRandomBlobName();
        ByteSource content = TestUtils.randomByteSource().slice(0, 1024);
        byte[] contentHash = MD5.hash(content.read());
        MultipartUpload mpu = aliasBlobStore.initiateMultipartUpload(
                TestUtils.createRequest(aliasContainerName, blobName));
        assertThat(mpu.containerName()).isEqualTo(aliasContainerName);
        var part = TestUtils.uploadPart(aliasBlobStore,
                mpu, 1, content.openStream(), content.size());
        assertThat(part.eTag()).isEqualTo(
                HexFormat.of().formatHex(contentHash));
        String mpuETag = aliasBlobStore.completeMultipartUpload(mpu,
                SdkRequests.completeRequest(mpu,
                        List.of(TestUtils.completedPart(1, part)))).eTag();
        byte[] contentHash2 = MD5.hash(contentHash);
        assertThat(mpuETag).isEqualTo("\"%s-1\"".formatted(
                HexFormat.of().formatHex(contentHash2)));
        var got = aliasBlobStore.getBlob(aliasContainerName, blobName);
        try (InputStream actual = got;
             InputStream expected = content.openStream()) {
            assertThat(actual).hasSameContentAs(expected);
        }
    }

    @Test
    public void testAliasBlobAccess() throws IOException {
        createContainer(aliasContainerName);
        String blobName = TestUtils.createRandomBlobName();
        ByteSource content = TestUtils.randomByteSource().slice(0, 1024);
        TestUtils.putBlob(aliasBlobStore, aliasContainerName, blobName,
                content);

        assertThat(aliasBlobStore.getBlobAccess(aliasContainerName, blobName))
                .isEqualTo(ObjectCannedACL.PRIVATE);
        aliasBlobStore.setBlobAccess(aliasContainerName, blobName,
                ObjectCannedACL.PUBLIC_READ);
        assertThat(aliasBlobStore.getBlobAccess(aliasContainerName, blobName))
                .isEqualTo(ObjectCannedACL.PUBLIC_READ);
        // the change must be applied to the backend (real) container
        assertThat(blobStore.getBlobAccess(containerName, blobName))
                .isEqualTo(ObjectCannedACL.PUBLIC_READ);
    }

    @Test
    public void testAliasListMultipartUpload() throws IOException {
        createContainer(aliasContainerName);
        String blobName = TestUtils.createRandomBlobName();
        ByteSource content = TestUtils.randomByteSource().slice(0, 1024);
        MultipartUpload mpu = aliasBlobStore.initiateMultipartUpload(
                TestUtils.createRequest(aliasContainerName, blobName));
        TestUtils.uploadPart(aliasBlobStore,
                mpu, 1, content.openStream(), content.size());

        var parts = aliasBlobStore.listMultipartUpload(mpu);
        assertThat(parts).hasSize(1);
        assertThat(parts.get(0).partNumber()).isEqualTo(1);

        var uploads = aliasBlobStore.listMultipartUploads(
                aliasContainerName);
        assertThat(uploads).hasSize(1);
        assertThat(uploads.get(0).uploadId()).isEqualTo(mpu.id());

        aliasBlobStore.completeMultipartUpload(mpu,
                TestUtils.completeRequest(mpu, parts));
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
