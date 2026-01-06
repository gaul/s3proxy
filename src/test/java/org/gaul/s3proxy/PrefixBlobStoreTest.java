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

import com.google.common.collect.ImmutableList;
import com.google.common.io.ByteSource;

import org.assertj.core.api.Assertions;
import org.jclouds.ContextBuilder;
import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.BlobStoreContext;
import org.jclouds.blobstore.domain.Blob;
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

public final class PrefixBlobStoreTest {
    private String containerName;
    private String prefix;
    private BlobStoreContext context;
    private BlobStore blobStore;
    private BlobStore prefixBlobStore;

    @Before
    public void setUp() {
        containerName = TestUtils.createRandomContainerName();
        prefix = "forward-prefix/";
        context = ContextBuilder
                .newBuilder("transient")
                .credentials("identity", "credential")
                .modules(List.of(new SLF4JLoggingModule()))
                .build(BlobStoreContext.class);
        blobStore = context.getBlobStore();
        blobStore.createContainerInLocation(null, containerName);
        prefixBlobStore = PrefixBlobStore.newPrefixBlobStore(
                blobStore, Map.of(containerName, prefix));
    }

    @After
    public void tearDown() {
        if (context != null) {
            blobStore.clearContainer(containerName);
            blobStore.deleteContainer(containerName);
            context.close();
        }
    }

    @Test
    public void testPutAndGetBlob() throws IOException {
        ByteSource content = TestUtils.randomByteSource().slice(0, 256);
        Blob blob = prefixBlobStore.blobBuilder("object.txt")
                .payload(content)
                .build();
        prefixBlobStore.putBlob(containerName, blob);

        assertThat(blobStore.blobExists(containerName,
                prefix + "object.txt")).isTrue();

        Blob stored = prefixBlobStore.getBlob(containerName, "object.txt");
        assertThat(stored).isNotNull();
        assertThat(stored.getMetadata().getName()).isEqualTo("object.txt");
        try (InputStream expected = content.openStream();
             InputStream actual = stored.getPayload().openStream()) {
            assertThat(actual).hasSameContentAs(expected);
        }
    }

    @Test
    public void testListTrimsPrefix() throws IOException {
        ByteSource content = TestUtils.randomByteSource().slice(0, 64);
        prefixBlobStore.putBlob(containerName, prefixBlobStore.blobBuilder(
                "file-one.txt").payload(content).build());
        blobStore.putBlob(containerName, blobStore.blobBuilder(
                prefix + "file-two.txt").payload(content).build());
        blobStore.putBlob(containerName, blobStore.blobBuilder(
                "outside.txt").payload(content).build());

        PageSet<? extends StorageMetadata> listing =
                prefixBlobStore.list(containerName);
        List<String> names = ImmutableList.copyOf(listing).stream()
                .map(StorageMetadata::getName)
                .collect(ImmutableList.toImmutableList());
        assertThat(names).containsExactlyInAnyOrder(
                "file-one.txt", "file-two.txt");
        assertThat(listing.getNextMarker()).isNull();
    }

    @Test
    public void testClearContainerKeepsOtherObjects() {
        ByteSource content = TestUtils.randomByteSource().slice(0, 32);
        prefixBlobStore.putBlob(containerName, prefixBlobStore.blobBuilder(
                "inside.txt").payload(content).build());
        blobStore.putBlob(containerName, blobStore.blobBuilder(
                "outside.txt").payload(content).build());

        prefixBlobStore.clearContainer(containerName);

        assertThat(blobStore.blobExists(containerName,
                prefix + "inside.txt")).isFalse();
        assertThat(blobStore.blobExists(containerName,
                "outside.txt")).isTrue();
    }

    @Test
    public void testMultipartUploadUsesPrefix() throws IOException {
        ByteSource content = TestUtils.randomByteSource().slice(0, 512);
        Blob blob = prefixBlobStore.blobBuilder("archive.bin").build();
        MultipartUpload mpu = prefixBlobStore.initiateMultipartUpload(
                containerName, blob.getMetadata(), PutOptions.NONE);
        assertThat(mpu.containerName()).isEqualTo(containerName);
        assertThat(mpu.blobName()).isEqualTo("archive.bin");

        MultipartPart part = prefixBlobStore.uploadMultipartPart(
                mpu, 1, Payloads.newPayload(content));
        prefixBlobStore.completeMultipartUpload(mpu, List.of(part));

        assertThat(blobStore.blobExists(containerName,
                prefix + "archive.bin")).isTrue();
    }

    @Test
    public void testListMultipartUploadsTrimsPrefix() {
        Blob blob = prefixBlobStore.blobBuilder("pending.bin").build();
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
        properties.setProperty(String.format("%s.bucket",
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
