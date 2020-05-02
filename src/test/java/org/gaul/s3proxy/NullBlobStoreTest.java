/*
 * Copyright 2014-2020 Andrew Gaul <andrew@gaul.org>
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
import java.util.Random;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.io.ByteSource;
import com.google.common.io.ByteStreams;
import com.google.common.net.MediaType;
import com.google.inject.Module;

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
import org.jclouds.io.ContentMetadata;
import org.jclouds.io.Payload;
import org.jclouds.io.Payloads;
import org.jclouds.logging.slf4j.config.SLF4JLoggingModule;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public final class NullBlobStoreTest {
    private static final ByteSource BYTE_SOURCE =
            TestUtils.randomByteSource().slice(0, 1024);
    private BlobStoreContext context;
    private BlobStore blobStore;
    private String containerName;
    private BlobStore nullBlobStore;

    @Before
    public void setUp() throws Exception {
        containerName = createRandomContainerName();

        context = ContextBuilder
                .newBuilder("transient")
                .credentials("identity", "credential")
                .modules(ImmutableList.<Module>of(new SLF4JLoggingModule()))
                .build(BlobStoreContext.class);
        blobStore = context.getBlobStore();
        blobStore.createContainerInLocation(null, containerName);

        nullBlobStore = NullBlobStore.newNullBlobStore(blobStore);
    }

    @After
    public void tearDown() throws Exception {
        if (context != null) {
            blobStore.deleteContainer(containerName);
            context.close();
        }
    }

    @Test
    public void testCreateBlobGetBlob() throws Exception {
        String blobName = createRandomBlobName();
        Blob blob = makeBlob(nullBlobStore, blobName);
        nullBlobStore.putBlob(containerName, blob);

        blob = nullBlobStore.getBlob(containerName, blobName);
        validateBlobMetadata(blob.getMetadata());

        // content differs, only compare length
        try (InputStream actual = blob.getPayload().openStream();
                InputStream expected = BYTE_SOURCE.openStream()) {
            long actualLength = ByteStreams.copy(actual,
                    ByteStreams.nullOutputStream());
            long expectedLength = ByteStreams.copy(expected,
                    ByteStreams.nullOutputStream());
            assertThat(actualLength).isEqualTo(expectedLength);
        }

        PageSet<? extends StorageMetadata> pageSet = nullBlobStore.list(
                containerName);
        assertThat(pageSet).hasSize(1);
        StorageMetadata sm = pageSet.iterator().next();
        assertThat(sm.getName()).isEqualTo(blobName);
        assertThat(sm.getSize()).isEqualTo(0);
    }

    @Test
    public void testCreateBlobBlobMetadata() throws Exception {
        String blobName = createRandomBlobName();
        Blob blob = makeBlob(nullBlobStore, blobName);
        nullBlobStore.putBlob(containerName, blob);
        BlobMetadata metadata = nullBlobStore.blobMetadata(containerName,
                blobName);
        validateBlobMetadata(metadata);
    }

    @Test
    public void testCreateMultipartBlobGetBlob() throws Exception {
        String blobName = "multipart-upload";
        BlobMetadata blobMetadata = makeBlob(nullBlobStore, blobName)
                .getMetadata();
        MultipartUpload mpu = nullBlobStore.initiateMultipartUpload(
                containerName, blobMetadata, new PutOptions());

        ByteSource byteSource = TestUtils.randomByteSource().slice(
                0, nullBlobStore.getMinimumMultipartPartSize() + 1);
        ByteSource byteSource1 = byteSource.slice(
                0, nullBlobStore.getMinimumMultipartPartSize());
        ByteSource byteSource2 = byteSource.slice(
                nullBlobStore.getMinimumMultipartPartSize(), 1);
        Payload payload1 = Payloads.newByteSourcePayload(byteSource1);
        Payload payload2 = Payloads.newByteSourcePayload(byteSource2);
        payload1.getContentMetadata().setContentLength(byteSource1.size());
        payload2.getContentMetadata().setContentLength(byteSource2.size());
        MultipartPart part1 = nullBlobStore.uploadMultipartPart(mpu, 1,
                payload1);
        MultipartPart part2 = nullBlobStore.uploadMultipartPart(mpu, 2,
                payload2);

        List<MultipartPart> parts = nullBlobStore.listMultipartUpload(mpu);
        assertThat(parts.get(0).partNumber()).isEqualTo(1);
        assertThat(parts.get(0).partSize()).isEqualTo(byteSource1.size());
        assertThat(parts.get(0).partETag()).isEqualTo(part1.partETag());
        assertThat(parts.get(1).partNumber()).isEqualTo(2);
        assertThat(parts.get(1).partSize()).isEqualTo(byteSource2.size());
        assertThat(parts.get(1).partETag()).isEqualTo(part2.partETag());

        assertThat(nullBlobStore.listMultipartUpload(mpu)).hasSize(2);

        nullBlobStore.completeMultipartUpload(mpu, parts);

        Blob newBlob = nullBlobStore.getBlob(containerName, blobName);
        validateBlobMetadata(newBlob.getMetadata());

        // content differs, only compare length
        try (InputStream actual = newBlob.getPayload().openStream();
                InputStream expected = byteSource.openStream()) {
            long actualLength = ByteStreams.copy(actual,
                    ByteStreams.nullOutputStream());
            long expectedLength = ByteStreams.copy(expected,
                    ByteStreams.nullOutputStream());
            assertThat(actualLength).isEqualTo(expectedLength);
        }

        nullBlobStore.removeBlob(containerName, blobName);
        assertThat(nullBlobStore.list(containerName)).isEmpty();
    }

    private static String createRandomContainerName() {
        return "container-" + new Random().nextInt(Integer.MAX_VALUE);
    }

    private static String createRandomBlobName() {
        return "blob-" + new Random().nextInt(Integer.MAX_VALUE);
    }

    private static Blob makeBlob(BlobStore blobStore, String blobName)
            throws IOException {
        return blobStore.blobBuilder(blobName)
                .payload(BYTE_SOURCE)
                .contentDisposition("attachment; filename=foo.mp4")
                .contentEncoding("compress")
                .contentLength(BYTE_SOURCE.size())
                .contentType(MediaType.MP4_AUDIO)
                .contentMD5(BYTE_SOURCE.hash(TestUtils.MD5))
                .userMetadata(ImmutableMap.of("key", "value"))
                .build();
    }

    private static void validateBlobMetadata(BlobMetadata metadata)
            throws IOException {
        assertThat(metadata).isNotNull();

        ContentMetadata contentMetadata = metadata.getContentMetadata();
        assertThat(contentMetadata.getContentDisposition())
                .isEqualTo("attachment; filename=foo.mp4");
        assertThat(contentMetadata.getContentEncoding())
                .isEqualTo("compress");
        assertThat(contentMetadata.getContentType())
                .isEqualTo(MediaType.MP4_AUDIO.toString());

        assertThat(metadata.getUserMetadata())
                .isEqualTo(ImmutableMap.of("key", "value"));
    }
}
