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
import java.util.List;
import java.util.Map;
import java.util.Properties;

import com.google.common.io.ByteSource;

import org.assertj.core.api.Assertions;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.domain.Blob;
import org.gaul.s3proxy.blobstore.domain.MultipartPart;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.gaul.s3proxy.blobstore.domain.PageSet;
import org.gaul.s3proxy.blobstore.domain.StorageMetadata;
import org.gaul.s3proxy.blobstore.options.CreateContainerOptions;
import org.gaul.s3proxy.blobstore.options.GetOptions;
import org.gaul.s3proxy.blobstore.options.ListContainerOptions;
import org.gaul.s3proxy.blobstore.options.PutOptions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public final class PrefixBlobStoreTest {
    private String containerName;
    private String prefix;
    private BlobStore blobStore;
    private BlobStore prefixBlobStore;

    @BeforeEach
    public void setUp() {
        containerName = TestUtils.createRandomContainerName();
        prefix = "forward-prefix/";
        blobStore = TestUtils.createTransientBlobStore();
        blobStore.createContainer(containerName, CreateContainerOptions.NONE);
        prefixBlobStore = PrefixBlobStore.newPrefixBlobStore(
                blobStore, Map.of(containerName, prefix));
    }

    @AfterEach
    public void tearDown() {
        if (blobStore != null) {
            blobStore.clearContainer(containerName,
                    ListContainerOptions.NONE);
            blobStore.deleteContainer(containerName);
        }
    }

    @Test
    public void testPutAndGetBlob() throws IOException {
        ByteSource content = TestUtils.randomByteSource().slice(0, 256);
        Blob blob = Blob.builder("object.txt")
                .payload(content)
                .build();
        prefixBlobStore.putBlob(containerName, blob, PutOptions.NONE);

        assertThat(blobStore.blobExists(containerName,
                prefix + "object.txt")).isTrue();

        Blob stored = prefixBlobStore.getBlob(containerName, "object.txt",
                GetOptions.NONE);
        assertThat(stored).isNotNull();
        assertThat(stored.getMetadata().name()).isEqualTo("object.txt");
        try (InputStream expected = content.openStream();
             InputStream actual = stored.getPayload()) {
            assertThat(actual).hasSameContentAs(expected);
        }
    }

    @Test
    public void testListTrimsPrefix() throws IOException {
        ByteSource content = TestUtils.randomByteSource().slice(0, 64);
        prefixBlobStore.putBlob(containerName, Blob.builder(
                "file-one.txt").payload(content).build(), PutOptions.NONE);
        blobStore.putBlob(containerName, Blob.builder(
                prefix + "file-two.txt").payload(content).build(),
                        PutOptions.NONE);
        blobStore.putBlob(containerName, Blob.builder(
                "outside.txt").payload(content).build(), PutOptions.NONE);

        PageSet<? extends StorageMetadata> listing =
                prefixBlobStore.list(containerName, ListContainerOptions.NONE);
        List<String> names = listing.entries().stream()
                .map(StorageMetadata::name)
                .toList();
        assertThat(names).containsExactlyInAnyOrder(
                "file-one.txt", "file-two.txt");
        assertThat(listing.nextMarker()).isNull();
    }

    @Test
    public void testClearContainerKeepsOtherObjects() {
        ByteSource content = TestUtils.randomByteSource().slice(0, 32);
        prefixBlobStore.putBlob(containerName, Blob.builder(
                "inside.txt").payload(content).build(), PutOptions.NONE);
        blobStore.putBlob(containerName, Blob.builder(
                "outside.txt").payload(content).build(), PutOptions.NONE);

        prefixBlobStore.clearContainer(containerName,
                ListContainerOptions.NONE);

        assertThat(blobStore.blobExists(containerName,
                prefix + "inside.txt")).isFalse();
        assertThat(blobStore.blobExists(containerName,
                "outside.txt")).isTrue();
    }

    @Test
    public void testMultipartUploadUsesPrefix() throws IOException {
        ByteSource content = TestUtils.randomByteSource().slice(0, 512);
        Blob blob = Blob.builder("archive.bin").build();
        MultipartUpload mpu = prefixBlobStore.initiateMultipartUpload(
                containerName, blob.getMetadata(), PutOptions.NONE);
        assertThat(mpu.containerName()).isEqualTo(containerName);
        assertThat(mpu.blobName()).isEqualTo("archive.bin");

        MultipartPart part = prefixBlobStore.uploadMultipartPart(
                mpu, 1, content.openStream(), content.size(), null);
        prefixBlobStore.completeMultipartUpload(mpu, List.of(part));

        assertThat(blobStore.blobExists(containerName,
                prefix + "archive.bin")).isTrue();
    }

    @Test
    public void testListMultipartUploadsTrimsPrefix() {
        Blob blob = Blob.builder("pending.bin").build();
        MultipartUpload mpu = prefixBlobStore.initiateMultipartUpload(
                containerName, blob.getMetadata(), PutOptions.NONE);

        try {
            List<MultipartUpload> uploads =
                    prefixBlobStore.listMultipartUploads(containerName);
            assertThat(uploads).hasSize(1);
            assertThat(uploads.get(0).blobName()).isEqualTo("pending.bin");
        } finally {
            prefixBlobStore.abortMultipartUpload(mpu);
        }
    }

    @Test
    public void testParseRejectsEmptyPrefix() {
        var properties = new Properties();
        properties.setProperty("%s.bucket".formatted(
                S3ProxyConstants.PROPERTY_PREFIX_BLOBSTORE), "");

        try {
            PrefixBlobStore.parsePrefixes(properties);
            Assertions.failBecauseExceptionWasNotThrown(
                    IllegalArgumentException.class);
        } catch (IllegalArgumentException exc) {
            assertThat(exc.getMessage()).isEqualTo(
                    "Prefix for bucket bucket must not be empty");
        }
    }
}
