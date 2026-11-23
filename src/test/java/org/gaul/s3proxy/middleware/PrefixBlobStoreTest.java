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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;

import com.google.common.io.ByteSource;

import org.assertj.core.api.Assertions;
import org.gaul.s3proxy.S3ProxyConstants;
import org.gaul.s3proxy.TestUtils;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.ForwardingBlobStore;
import org.gaul.s3proxy.blobstore.SdkRequests;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.BucketCannedACL;
import software.amazon.awssdk.services.s3.model.CreateBucketRequest;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectAclRequest;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Response;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.services.s3.model.S3Object;
import software.amazon.awssdk.services.s3.model.ServerSideEncryption;
import software.amazon.awssdk.services.s3.model.ServerSideEncryptionByDefault;
import software.amazon.awssdk.services.s3.model.ServerSideEncryptionConfiguration;
import software.amazon.awssdk.services.s3.model.ServerSideEncryptionRule;
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
        if (blobStore != null && blobStore.containerExists(containerName)) {
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

    /**
     * The prefix holds for every spelling of the bucket: a backend which
     * ignores case opens the same bucket for all of them.
     */
    @Test
    public void testPrefixIgnoresBucketCase() throws IOException {
        String upperCase = containerName.toUpperCase(Locale.ROOT);
        blobStore.createContainer(upperCase);
        ByteSource content = TestUtils.randomByteSource().slice(0, 32);
        TestUtils.putBlob(prefixBlobStore, upperCase, "object.txt", content);

        assertThat(blobStore.blobExists(upperCase,
                prefix + "object.txt")).isTrue();
        assertThat(blobStore.blobExists(upperCase, "object.txt")).isFalse();
        assertThat(prefixBlobStore.blobExists(upperCase, "object.txt"))
                .isTrue();

        assertThatThrownBy(() -> PrefixBlobStore.newPrefixBlobStore(
                blobStore, Map.of("bucket", "a/", "Bucket", "b/")))
                .isInstanceOf(IllegalArgumentException.class);
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

    /**
     * A continuation token belongs to the backend that issued it and goes
     * back as it came.  Most backends issue one that is no key, and a prefix
     * put in front of it made every page after the first unreadable.
     */
    @Test
    public void testListPagesWithOpaqueTokens() throws IOException {
        var opaque = new ForwardingBlobStore(blobStore) {
            @Override
            public ListObjectsV2Response list(ListObjectsV2Request request) {
                String token = request.continuationToken();
                if (token != null) {
                    Assertions.assertThat(token).startsWith("opaque:");
                    request = request.toBuilder().continuationToken(
                            token.substring("opaque:".length())).build();
                }
                var listing = super.list(request);
                String next = listing.nextContinuationToken();
                return next == null ? listing : listing.toBuilder()
                        .nextContinuationToken("opaque:" + next).build();
            }
        };
        var store = PrefixBlobStore.newPrefixBlobStore(opaque,
                Map.of(containerName, prefix));
        ByteSource content = TestUtils.randomByteSource().slice(0, 8);
        for (String key : List.of("a", "b", "c")) {
            TestUtils.putBlob(store, containerName, key, content);
        }
        TestUtils.putBlob(blobStore, containerName, "outside", content);

        var keys = new java.util.ArrayList<String>();
        String token = null;
        do {
            var page = store.list(ListObjectsV2Request.builder()
                    .bucket(containerName).maxKeys(1)
                    .continuationToken(token).build());
            page.contents().forEach(object -> keys.add(object.key()));
            token = page.nextContinuationToken();
        } while (token != null);
        assertThat(keys).containsExactly("a", "b", "c");

        // start-after is a key, and is prefixed like one
        assertThat(store.list(ListObjectsV2Request.builder()
                .bucket(containerName).startAfter("a").build()).contents())
                .extracting(S3Object::key).containsExactly("b", "c");
    }

    /**
     * A key that happens to begin with the bucket's prefix is a key like
     * any other and is stored under the prefix too.  (A key beginning with
     * a slash is as well, which this store cannot show: a filesystem reads
     * the doubled slash that makes as one.)
     */
    @Test
    public void testKeyBeginningWithPrefixIsItsOwnObject() throws IOException {
        ByteSource one = TestUtils.randomByteSource().slice(0, 8);
        ByteSource two = TestUtils.randomByteSource().slice(8, 16);
        String other = prefix + "x";
        TestUtils.putBlob(prefixBlobStore, containerName, "x", one);
        TestUtils.putBlob(prefixBlobStore, containerName, other, two);

        try (InputStream is = prefixBlobStore.getBlob(containerName, "x")) {
            assertThat(is.readAllBytes()).isEqualTo(one.read());
        }
        assertThat(prefixBlobStore.list(containerName).contents())
                .extracting(S3Object::key)
                .containsExactlyInAnyOrder("x", other);

        prefixBlobStore.removeBlob(containerName, other);
        assertThat(prefixBlobStore.blobExists(containerName, "x")).isTrue();
    }

    @Test
    public void testDeleteContainerKeepsOtherObjects() throws Exception {
        TestUtils.putBlob(blobStore, containerName, "outside",
                TestUtils.randomByteSource().slice(0, 16));
        TestUtils.putBlob(prefixBlobStore, containerName, "inside",
                TestUtils.randomByteSource().slice(0, 16));

        prefixBlobStore.deleteContainer(containerName);

        assertThat(blobStore.blobExists(containerName, "outside")).isTrue();
        assertThat(blobStore.blobExists(containerName, prefix + "inside"))
                .isFalse();
    }

    /**
     * Other prefixes live in the backend bucket too, and would find it gone
     * however empty this one's view of it was.
     */
    @Test
    public void testDeleteContainerKeepsAnEmptiedBucket() throws Exception {
        TestUtils.putBlob(prefixBlobStore, containerName, "inside",
                TestUtils.randomByteSource().slice(0, 16));

        prefixBlobStore.deleteContainer(containerName);

        assertThat(blobStore.containerExists(containerName)).isTrue();
        assertThat(blobStore.blobExists(containerName, prefix + "inside"))
                .isFalse();
        assertThatThrownBy(() -> prefixBlobStore.deleteBucket(containerName))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThat(blobStore.containerExists(containerName)).isTrue();
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

    /** An upload outside the prefix is not one of this bucket's. */
    @Test
    public void testListMultipartUploadsOmitsOtherPrefixes() {
        MultipartUpload inside = prefixBlobStore.initiateMultipartUpload(
                TestUtils.createRequest(containerName, "pending.bin"));
        MultipartUpload outside = blobStore.initiateMultipartUpload(
                TestUtils.createRequest(containerName, "other/secret.bin"));

        try {
            assertThat(prefixBlobStore.listMultipartUploads(containerName))
                    .extracting(upload -> upload.key())
                    .containsExactly("pending.bin");
        } finally {
            prefixBlobStore.abortMultipartUpload(inside);
            blobStore.abortMultipartUpload(outside);
        }
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

    /**
     * The ACL belongs to the backend bucket and so to every prefix in it.
     * Setting it through one prefix opened the others to anonymous callers.
     */
    @Test
    public void testRefusesToChangeTheBackendBucketAccess() {
        assertThatThrownBy(() -> prefixBlobStore.setContainerAccess(
                containerName, BucketCannedACL.PUBLIC_READ_WRITE))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThat(blobStore.getContainerAccess(containerName))
                .isEqualTo(BucketCannedACL.PRIVATE);

        // restating what the bucket has is no change
        prefixBlobStore.setContainerAccess(containerName,
                BucketCannedACL.PRIVATE);

        blobStore.setContainerAccess(containerName,
                BucketCannedACL.PUBLIC_READ);
        assertThatThrownBy(() -> prefixBlobStore.setContainerAccess(
                containerName, BucketCannedACL.PRIVATE))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThat(prefixBlobStore.getContainerAccess(containerName))
                .isEqualTo(BucketCannedACL.PUBLIC_READ);
    }

    @Test
    public void testRefusesToCreateAPublicBackendBucket() {
        String other = TestUtils.createRandomContainerName();
        BlobStore store = PrefixBlobStore.newPrefixBlobStore(blobStore,
                Map.of(other, prefix));
        try {
            assertThatThrownBy(() -> store.createContainer(
                    CreateBucketRequest.builder()
                            .bucket(other)
                            .acl(BucketCannedACL.PUBLIC_READ_WRITE)
                            .build()))
                    .isInstanceOf(UnsupportedOperationException.class);
            assertThat(blobStore.containerExists(other)).isFalse();

            store.createContainer(other);
            assertThat(blobStore.getContainerAccess(other))
                    .isEqualTo(BucketCannedACL.PRIVATE);
        } finally {
            blobStore.deleteContainer(other);
        }
    }

    /** The default encryption is the backend bucket's in the same way. */
    @Test
    public void testRefusesToChangeTheBackendBucketEncryption() {
        var configuration = ServerSideEncryptionConfiguration.builder()
                .rules(ServerSideEncryptionRule.builder()
                        .applyServerSideEncryptionByDefault(
                                ServerSideEncryptionByDefault.builder()
                                        .sseAlgorithm(
                                                ServerSideEncryption.AES256)
                                        .build())
                        .build())
                .build();
        assertThatThrownBy(() -> prefixBlobStore.putBucketEncryption(
                containerName, configuration))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> blobStore.getBucketEncryption(containerName))
                .isInstanceOf(S3Exception.class);

        blobStore.putBucketEncryption(containerName, configuration);
        assertThatThrownBy(() -> prefixBlobStore.deleteBucketEncryption(
                containerName))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThat(prefixBlobStore.getBucketEncryption(containerName))
                .isEqualTo(configuration);
    }

    @Test
    public void testLeavesAnUnprefixedBucketItsAccess() {
        String other = TestUtils.createRandomContainerName();
        prefixBlobStore.createContainer(CreateBucketRequest.builder()
                .bucket(other)
                .acl(BucketCannedACL.PUBLIC_READ)
                .build());
        try {
            prefixBlobStore.setContainerAccess(other,
                    BucketCannedACL.PUBLIC_READ_WRITE);
            assertThat(blobStore.getContainerAccess(other))
                    .isEqualTo(BucketCannedACL.PUBLIC_READ_WRITE);
        } finally {
            blobStore.deleteContainer(other);
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
