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
import java.util.List;
import java.util.Map;
import java.util.Properties;

import com.google.common.io.ByteSource;

import org.assertj.core.api.Assertions;
import org.gaul.s3proxy.S3ProxyConstants;
import org.gaul.s3proxy.TestUtils;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.SdkRequests;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectAclRequest;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.S3Object;
import software.amazon.awssdk.services.s3.model.UploadPartCopyRequest;

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
        blobStore.createContainer(containerName);
        prefixBlobStore = PrefixBlobStore.newPrefixBlobStore(
                blobStore, Map.of(containerName, prefix));
    }

    @AfterEach
    public void tearDown() {
        if (blobStore != null) {
            blobStore.clearContainer(ListObjectsV2Request.builder()
                    .bucket(containerName)
                    .build());
            blobStore.deleteContainer(containerName);
        }
    }

    @Test
    public void testPutAndGetBlob() throws IOException {
        ByteSource content = TestUtils.randomByteSource().slice(0, 256);
        TestUtils.putBlob(prefixBlobStore, containerName, "object.txt",
                content);

        assertThat(blobStore.blobExists(containerName,
                prefix + "object.txt")).isTrue();

        var stored = prefixBlobStore.getBlob(containerName, "object.txt");
        assertThat(stored).isNotNull();
        try (InputStream expected = content.openStream();
             InputStream actual = stored) {
            assertThat(actual).hasSameContentAs(expected);
        }
    }

    @Test
    public void testListTrimsPrefix() throws IOException {
        ByteSource content = TestUtils.randomByteSource().slice(0, 64);
        TestUtils.putBlob(prefixBlobStore, containerName, "file-one.txt",
                content);
        TestUtils.putBlob(blobStore, containerName, prefix + "file-two.txt",
                content);
        TestUtils.putBlob(blobStore, containerName, "outside.txt", content);

        var listing =
                prefixBlobStore.list(containerName);
        List<String> names = listing.contents().stream()
                .map(S3Object::key)
                .toList();
        assertThat(names).containsExactlyInAnyOrder(
                "file-one.txt", "file-two.txt");
        assertThat(listing.nextContinuationToken()).isNull();
    }

    @Test
    public void testClearContainerKeepsOtherObjects() throws Exception {
        ByteSource content = TestUtils.randomByteSource().slice(0, 32);
        TestUtils.putBlob(prefixBlobStore, containerName, "inside.txt",
                content);
        TestUtils.putBlob(blobStore, containerName, "outside.txt", content);

        prefixBlobStore.clearContainer(ListObjectsV2Request.builder()
                .bucket(containerName)
                .build());

        assertThat(blobStore.blobExists(containerName,
                prefix + "inside.txt")).isFalse();
        assertThat(blobStore.blobExists(containerName,
                "outside.txt")).isTrue();
    }

    @Test
    public void testMultipartUploadUsesPrefix() throws IOException {
        ByteSource content = TestUtils.randomByteSource().slice(0, 512);
        MultipartUpload mpu = prefixBlobStore.initiateMultipartUpload(
                TestUtils.createRequest(containerName, "archive.bin"));
        assertThat(mpu.containerName()).isEqualTo(containerName);
        assertThat(mpu.blobName()).isEqualTo("archive.bin");

        var part = TestUtils.uploadPart(prefixBlobStore,
                mpu, 1, content.openStream(), content.size());
        prefixBlobStore.completeMultipartUpload(mpu,
                SdkRequests.completeRequest(mpu,
                        List.of(TestUtils.completedPart(1, part))));

        assertThat(blobStore.blobExists(containerName,
                prefix + "archive.bin")).isTrue();
    }

    @Test
    public void testListMultipartUploadsTrimsPrefix() {
        MultipartUpload mpu = prefixBlobStore.initiateMultipartUpload(
                TestUtils.createRequest(containerName, "pending.bin"));

        try {
            var uploads =
                    prefixBlobStore.listMultipartUploads(containerName);
            assertThat(uploads).hasSize(1);
            assertThat(uploads.get(0).key()).isEqualTo("pending.bin");
        } finally {
            prefixBlobStore.abortMultipartUpload(mpu);
        }
    }

    @Test
    public void testConditionalRemoveBlobUsesPrefix() throws IOException {
        var recorder = new TestUtils.ConditionalDeleteRecorder(blobStore);
        BlobStore prefixed = PrefixBlobStore.newPrefixBlobStore(
                recorder, Map.of(containerName, prefix));
        ByteSource content = TestUtils.randomByteSource().slice(0, 64);
        TestUtils.putBlob(blobStore, containerName, prefix + "object.txt",
                content);
        TestUtils.putBlob(blobStore, containerName, "object.txt", content);

        prefixed.removeBlob(DeleteObjectRequest.builder()
                .bucket(containerName)
                .key("object.txt")
                .ifMatch("\"etag\"")
                .build());

        var request = recorder.lastRequest();
        assertThat(request).isNotNull();
        assertThat(request.key()).isEqualTo(prefix + "object.txt");
        assertThat(request.ifMatch()).isEqualTo("\"etag\"");
        // The object outside the prefix is not this store's to delete.
        assertThat(blobStore.blobExists(containerName, "object.txt")).isTrue();
        assertThat(blobStore.blobExists(containerName,
                prefix + "object.txt")).isFalse();
    }

    @Test
    public void testBlobAclUsesPrefix() throws IOException {
        ByteSource content = TestUtils.randomByteSource().slice(0, 64);
        TestUtils.putBlob(prefixBlobStore, containerName, "object.txt",
                content);

        // Only the prefixed name is there, so a policy read that forgot the
        // prefix would ask after an object that does not exist.
        assertThat(prefixBlobStore.getBlobAcl(GetObjectAclRequest.builder()
                .bucket(containerName)
                .key("object.txt")
                .build()).grants()).isNotEmpty();
    }

    /**
     * A part the backend can copy itself has to reach it under the prefixed
     * keys.  The wrapper used to keep the interface's refusal instead, so
     * S3Proxy streamed every part down and back up.
     */
    @Test
    public void testCopiesAPartUnderThePrefixedKeys() {
        var recorder = new PartCopyRecorder(blobStore);
        BlobStore store = PrefixBlobStore.newPrefixBlobStore(recorder,
                Map.of(containerName, prefix));
        assertThat(store.supportsCopyMultipartPart()).isTrue();
        var mpu = new MultipartUpload("upload-id",
                TestUtils.createRequest(containerName, "object.txt"));

        store.copyMultipartPart(mpu, UploadPartCopyRequest.builder()
                .sourceBucket(containerName)
                .sourceKey("source.txt")
                .destinationBucket(containerName)
                .destinationKey("object.txt")
                .uploadId("upload-id")
                .partNumber(1)
                .build());

        assertThat(recorder.request()).isNotNull();
        assertThat(recorder.request().sourceKey())
                .isEqualTo(prefix + "source.txt");
        assertThat(recorder.request().destinationKey())
                .isEqualTo(prefix + "object.txt");
        // only the keys are the prefix's business
        assertThat(recorder.request().sourceBucket()).isEqualTo(containerName);
        assertThat(recorder.request().destinationBucket())
                .isEqualTo(containerName);
        assertThat(recorder.mpu().blobName())
                .isEqualTo(prefix + "object.txt");
    }

    /**
     * Where the backend cannot copy a part itself the wrapper must not claim
     * it can, since the caller reads that as leave to skip the streamed copy.
     */
    @Test
    public void testFollowsABackendThatCopiesNoPart() {
        assertThat(prefixBlobStore.supportsCopyMultipartPart()).isFalse();
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
