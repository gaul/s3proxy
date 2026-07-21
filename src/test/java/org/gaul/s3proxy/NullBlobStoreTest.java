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
import java.io.OutputStream;
import java.util.List;
import java.util.Map;
import java.util.Random;

import com.google.common.io.ByteSource;
import com.google.common.net.MediaType;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.ContentMetadata;
import org.gaul.s3proxy.blobstore.domain.Blob;
import org.gaul.s3proxy.blobstore.domain.BlobMetadata;
import org.gaul.s3proxy.blobstore.domain.MultipartPart;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.gaul.s3proxy.blobstore.domain.PageSet;
import org.gaul.s3proxy.blobstore.domain.StorageMetadata;
import org.gaul.s3proxy.blobstore.options.GetOptions;
import org.gaul.s3proxy.blobstore.options.PutOptions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public final class NullBlobStoreTest {
    private static final ByteSource BYTE_SOURCE =
            TestUtils.randomByteSource().slice(0, 1024);
    private BlobStore blobStore;
    private String containerName;
    private BlobStore nullBlobStore;

    @BeforeEach
    public void setUp() throws Exception {
        containerName = createRandomContainerName();

        blobStore = TestUtils.createTransientBlobStore();
        blobStore.createContainer(containerName);

        nullBlobStore = NullBlobStore.newNullBlobStore(blobStore);
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (blobStore != null) {
            blobStore.deleteContainer(containerName);
        }
    }

    @Test
    public void testCreateBlobGetBlob() throws Exception {
        String blobName = createRandomBlobName();
        Blob blob = makeBlob(blobName);
        nullBlobStore.putBlob(containerName, blob);

        blob = nullBlobStore.getBlob(containerName, blobName);
        validateBlobMetadata(blob.getMetadata());

        // content differs, only compare length
        try (InputStream actual = blob.getPayload().openStream();
                InputStream expected = BYTE_SOURCE.openStream()) {
            long actualLength = actual.transferTo(
                    OutputStream.nullOutputStream());
            long expectedLength = expected.transferTo(
                    OutputStream.nullOutputStream());
            assertThat(actualLength).isEqualTo(expectedLength);
        }

        PageSet<? extends StorageMetadata> pageSet = nullBlobStore.list(
                containerName);
        assertThat(pageSet).hasSize(1);
        StorageMetadata sm = pageSet.iterator().next();
        assertThat(sm.name()).isEqualTo(blobName);
        assertThat(sm.size()).isEqualTo(0);
    }

    @Test
    public void testGetBlobRange() throws Exception {
        String blobName = createRandomBlobName();
        Blob blob = makeBlob(blobName);
        nullBlobStore.putBlob(containerName, blob);
        long size = BYTE_SOURCE.size();

        // bytes=A-B
        GetOptions explicit = GetOptions.builder().range(100, 199).build();
        blob = nullBlobStore.getBlob(containerName, blobName, explicit);
        try (InputStream is = blob.getPayload().openStream()) {
            assertThat(is.transferTo(OutputStream.nullOutputStream()))
                    .isEqualTo(100);
        }

        // bytes=A-
        GetOptions suffix = GetOptions.builder().startAt(500).build();
        blob = nullBlobStore.getBlob(containerName, blobName, suffix);
        try (InputStream is = blob.getPayload().openStream()) {
            assertThat(is.transferTo(OutputStream.nullOutputStream()))
                    .isEqualTo(size - 500);
        }

        // bytes=-N
        GetOptions tail = GetOptions.builder().tail(128).build();
        blob = nullBlobStore.getBlob(containerName, blobName, tail);
        try (InputStream is = blob.getPayload().openStream()) {
            assertThat(is.transferTo(OutputStream.nullOutputStream()))
                    .isEqualTo(128);
        }
    }

    @Test
    public void testCreateBlobBlobMetadata() throws Exception {
        String blobName = createRandomBlobName();
        Blob blob = makeBlob(blobName);
        nullBlobStore.putBlob(containerName, blob);
        BlobMetadata metadata = nullBlobStore.blobMetadata(containerName,
                blobName);
        validateBlobMetadata(metadata);
    }

    @Test
    public void testCreateMultipartBlobGetBlob() throws Exception {
        String blobName = "multipart-upload";
        BlobMetadata blobMetadata = makeBlob(blobName)
                .getMetadata();
        MultipartUpload mpu = nullBlobStore.initiateMultipartUpload(
                containerName, blobMetadata, PutOptions.NONE);

        ByteSource byteSource = TestUtils.randomByteSource().slice(
                0, nullBlobStore.getMinimumMultipartPartSize() + 1);
        ByteSource byteSource1 = byteSource.slice(
                0, nullBlobStore.getMinimumMultipartPartSize());
        ByteSource byteSource2 = byteSource.slice(
                nullBlobStore.getMinimumMultipartPartSize(), 1);
        MultipartPart part1 = nullBlobStore.uploadMultipartPart(mpu, 1,
                byteSource1.openStream(), byteSource1.size(), null);
        MultipartPart part2 = nullBlobStore.uploadMultipartPart(mpu, 2,
                byteSource2.openStream(), byteSource2.size(), null);

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
            long actualLength = actual.transferTo(
                    OutputStream.nullOutputStream());
            long expectedLength = expected.transferTo(
                    OutputStream.nullOutputStream());
            assertThat(actualLength).isEqualTo(expectedLength);
        }

        nullBlobStore.removeBlob(containerName, blobName);
        assertThat(nullBlobStore.list(containerName)).isEmpty();
    }

    @Test
    public void testCompleteMultipartUploadStubMetadataName() throws Exception {
        // S3ProxyHandler reconstructs the completion MPU with blobMetadata
        // taken from the upload stub, whose name is the stub name rather than
        // the target object name.  The completed object must still land under
        // blobName.
        String blobName = "multipart-target";
        MultipartUpload initiated = nullBlobStore.initiateMultipartUpload(
                containerName, makeBlob(blobName).getMetadata(),
                PutOptions.NONE);

        ByteSource byteSource = TestUtils.randomByteSource().slice(
                0, nullBlobStore.getMinimumMultipartPartSize() + 1);
        ByteSource byteSource1 = byteSource.slice(
                0, nullBlobStore.getMinimumMultipartPartSize());
        ByteSource byteSource2 = byteSource.slice(
                nullBlobStore.getMinimumMultipartPartSize(), 1);
        nullBlobStore.uploadMultipartPart(initiated, 1,
                byteSource1.openStream(), byteSource1.size(), null);
        nullBlobStore.uploadMultipartPart(initiated, 2,
                byteSource2.openStream(), byteSource2.size(), null);
        List<MultipartPart> parts = nullBlobStore.listMultipartUpload(
                initiated);

        // Rebuild the MPU the way the handler does: correct blobName, but
        // blobMetadata carrying the (different) stub name.
        BlobMetadata stubMetadata = makeBlob(
                ".s3proxy-mpu-stub-" + initiated.id()).getMetadata();
        MultipartUpload mpu = new MultipartUpload(containerName, blobName,
                initiated.id(), stubMetadata, PutOptions.NONE);

        nullBlobStore.completeMultipartUpload(mpu, parts);

        Blob newBlob = nullBlobStore.getBlob(containerName, blobName);
        assertThat(newBlob).isNotNull();
        try (InputStream actual = newBlob.getPayload().openStream();
                InputStream expected = byteSource.openStream()) {
            assertThat(actual.transferTo(OutputStream.nullOutputStream()))
                    .isEqualTo(expected.transferTo(
                            OutputStream.nullOutputStream()));
        }
        assertThat(nullBlobStore.list(containerName).stream()
                .map(StorageMetadata::name))
                .containsExactly(blobName);
    }

    private static String createRandomContainerName() {
        return "container-" + new Random().nextInt(Integer.MAX_VALUE);
    }

    private static String createRandomBlobName() {
        return "blob-" + new Random().nextInt(Integer.MAX_VALUE);
    }

    private static Blob makeBlob(String blobName) throws IOException {
        return Blob.builder(blobName)
                .payload(BYTE_SOURCE)
                .contentDisposition("attachment; filename=foo.mp4")
                .contentEncoding("compress")
                .contentLength(BYTE_SOURCE.size())
                .contentType(MediaType.MP4_AUDIO.toString())
                .contentMD5(BYTE_SOURCE.hash(TestUtils.MD5))
                .userMetadata(Map.of("key", "value"))
                .build();
    }

    private static void validateBlobMetadata(BlobMetadata metadata)
            throws IOException {
        assertThat(metadata).isNotNull();

        ContentMetadata contentMetadata = metadata.getContentMetadata();
        assertThat(contentMetadata.contentDisposition())
                .isEqualTo("attachment; filename=foo.mp4");
        assertThat(contentMetadata.contentEncoding())
                .isEqualTo("compress");
        assertThat(contentMetadata.contentType())
                .isEqualTo(MediaType.MP4_AUDIO.toString());

        assertThat(metadata.userMetadata())
                .isEqualTo(Map.of("key", "value"));
    }
}
