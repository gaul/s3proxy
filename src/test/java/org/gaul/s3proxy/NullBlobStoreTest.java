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
import java.util.Map;
import java.util.Random;

import com.google.common.io.ByteSource;
import com.google.common.net.MediaType;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.domain.Blob;
import org.gaul.s3proxy.blobstore.domain.BlobMetadata;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.gaul.s3proxy.blobstore.options.CreateContainerOptions;
import org.gaul.s3proxy.blobstore.options.ListContainerOptions;
import org.gaul.s3proxy.blobstore.options.PutOptions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.S3Object;

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
        blobStore.createContainer(containerName, CreateContainerOptions.NONE);

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
        nullBlobStore.putBlob(containerName, makeBlob(blobName),
                PutOptions.NONE);

        var blob = nullBlobStore.getBlob(containerName, blobName);
        validateBlobMetadata(nullBlobStore.blobMetadata(containerName,
                blobName));

        // content differs, only compare length
        try (InputStream actual = blob;
                InputStream expected = BYTE_SOURCE.openStream()) {
            long actualLength = actual.transferTo(
                    OutputStream.nullOutputStream());
            long expectedLength = expected.transferTo(
                    OutputStream.nullOutputStream());
            assertThat(actualLength).isEqualTo(expectedLength);
        }

        var pageSet = nullBlobStore.list(
                containerName, ListContainerOptions.NONE);
        assertThat(pageSet.contents()).hasSize(1);
        S3Object sm = pageSet.contents().get(0);
        assertThat(sm.key()).isEqualTo(blobName);
        assertThat(sm.size()).isEqualTo(0);

        // the canonical overload which S3ProxyHandler calls also zeroes sizes
        pageSet = nullBlobStore.list(containerName,
                ListContainerOptions.NONE);
        assertThat(pageSet.contents()).hasSize(1);
        assertThat(pageSet.contents().get(0).size()).isEqualTo(0);
    }

    @Test
    public void testGetBlobRange() throws Exception {
        String blobName = createRandomBlobName();
        Blob blob = makeBlob(blobName);
        nullBlobStore.putBlob(containerName, blob, PutOptions.NONE);
        long size = BYTE_SOURCE.size();

        // bytes=A-B
        var explicitGet = nullBlobStore.getBlob(GetObjectRequest.builder()
                .bucket(containerName).key(blobName)
                .range("bytes=100-199").build());
        try (InputStream is = explicitGet) {
            assertThat(is.transferTo(OutputStream.nullOutputStream()))
                    .isEqualTo(100);
        }

        // bytes=A-
        var suffixGet = nullBlobStore.getBlob(GetObjectRequest.builder()
                .bucket(containerName).key(blobName)
                .range("bytes=500-").build());
        try (InputStream is = suffixGet) {
            assertThat(is.transferTo(OutputStream.nullOutputStream()))
                    .isEqualTo(size - 500);
        }

        // bytes=-N
        var tailGet = nullBlobStore.getBlob(GetObjectRequest.builder()
                .bucket(containerName).key(blobName)
                .range("bytes=-128").build());
        try (InputStream is = tailGet) {
            assertThat(is.transferTo(OutputStream.nullOutputStream()))
                    .isEqualTo(128);
        }
    }

    @Test
    public void testCreateBlobBlobMetadata() throws Exception {
        String blobName = createRandomBlobName();
        Blob blob = makeBlob(blobName);
        nullBlobStore.putBlob(containerName, blob, PutOptions.NONE);
        var metadata = nullBlobStore.blobMetadata(containerName,
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
        var part1 = nullBlobStore.uploadMultipartPart(mpu, 1,
                byteSource1.openStream(), byteSource1.size(), null);
        var part2 = nullBlobStore.uploadMultipartPart(mpu, 2,
                byteSource2.openStream(), byteSource2.size(), null);

        var parts = nullBlobStore.listMultipartUpload(mpu);
        assertThat(parts.get(0).partNumber()).isEqualTo(1);
        assertThat(parts.get(0).size()).isEqualTo(byteSource1.size());
        assertThat(parts.get(0).eTag()).isEqualTo(part1.eTag());
        assertThat(parts.get(1).partNumber()).isEqualTo(2);
        assertThat(parts.get(1).size()).isEqualTo(byteSource2.size());
        assertThat(parts.get(1).eTag()).isEqualTo(part2.eTag());

        assertThat(nullBlobStore.listMultipartUpload(mpu)).hasSize(2);

        nullBlobStore.completeMultipartUpload(mpu,
                TestUtils.completedParts(parts));

        var newBlob = nullBlobStore.getBlob(containerName, blobName);
        validateBlobMetadata(nullBlobStore.blobMetadata(
                containerName, blobName));

        // content differs, only compare length
        try (InputStream actual = newBlob;
                InputStream expected = byteSource.openStream()) {
            long actualLength = actual.transferTo(
                    OutputStream.nullOutputStream());
            long expectedLength = expected.transferTo(
                    OutputStream.nullOutputStream());
            assertThat(actualLength).isEqualTo(expectedLength);
        }

        nullBlobStore.removeBlob(containerName, blobName);
        assertThat(nullBlobStore.list(containerName,
                ListContainerOptions.NONE).contents()).isEmpty();
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
        var parts = nullBlobStore.listMultipartUpload(
                initiated);

        // Rebuild the MPU the way the handler does: correct blobName, but
        // blobMetadata carrying the (different) stub name.
        BlobMetadata stubMetadata = makeBlob(
                ".s3proxy-mpu-stub-" + initiated.id()).getMetadata();
        MultipartUpload mpu = new MultipartUpload(containerName, blobName,
                initiated.id(), stubMetadata, PutOptions.NONE);

        nullBlobStore.completeMultipartUpload(mpu,
                TestUtils.completedParts(parts));

        var newBlob = nullBlobStore.getBlob(containerName, blobName);
        assertThat(newBlob).isNotNull();
        try (InputStream actual = newBlob;
                InputStream expected = byteSource.openStream()) {
            assertThat(actual.transferTo(OutputStream.nullOutputStream()))
                    .isEqualTo(expected.transferTo(
                            OutputStream.nullOutputStream()));
        }
        assertThat(nullBlobStore.list(containerName,
                ListContainerOptions.NONE).contents().stream()
                .map(S3Object::key))
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

    private static void validateBlobMetadata(software.amazon.awssdk.services.s3.model.HeadObjectResponse metadata)
            throws IOException {
        assertThat(metadata).isNotNull();

        var contentMetadata = metadata;
        assertThat(contentMetadata.contentDisposition())
                .isEqualTo("attachment; filename=foo.mp4");
        assertThat(contentMetadata.contentEncoding())
                .isEqualTo("compress");
        assertThat(contentMetadata.contentType())
                .isEqualTo(MediaType.MP4_AUDIO.toString());

        assertThat(metadata.metadata())
                .isEqualTo(Map.of("key", "value"));
    }
}
