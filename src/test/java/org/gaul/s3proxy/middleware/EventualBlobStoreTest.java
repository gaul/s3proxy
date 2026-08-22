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
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import com.google.common.io.ByteSource;
import com.google.common.net.MediaType;

import org.gaul.s3proxy.TestUtils;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.MD5;
import org.gaul.s3proxy.blobstore.SdkRequests;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.CopyObjectRequest;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

public final class EventualBlobStoreTest {
    private static final int DELAY = 1;
    private static final TimeUnit DELAY_UNIT = TimeUnit.SECONDS;
    private static final ByteSource BYTE_SOURCE =
            TestUtils.randomByteSource().slice(0, 1024);
    private BlobStore nearBlobStore;
    private BlobStore farBlobStore;
    private String containerName;
    private ScheduledExecutorService executorService;
    private BlobStore eventualBlobStore;

    @BeforeEach
    public void setUp() throws Exception {
        containerName = createRandomContainerName();

        nearBlobStore = TestUtils.createTransientBlobStore();
        nearBlobStore.createContainer(containerName);

        farBlobStore = TestUtils.createTransientBlobStore();
        farBlobStore.createContainer(containerName);

        executorService = Executors.newScheduledThreadPool(1);

        eventualBlobStore = EventualBlobStore.newEventualBlobStore(
                nearBlobStore, farBlobStore, executorService, DELAY,
                DELAY_UNIT, 1.0);
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (nearBlobStore != null) {
            nearBlobStore.deleteContainer(containerName);
        }
        if (farBlobStore != null) {
            farBlobStore.deleteContainer(containerName);
        }
        if (executorService != null) {
            executorService.shutdown();
        }
    }

    @Test
    public void testReadAfterCreate() throws Exception {
        String blobName = createRandomBlobName();
        eventualBlobStore.putBlob(makeRequest(containerName, blobName),
                BYTE_SOURCE.openStream());
        assertThat(eventualBlobStore.getBlob(containerName, blobName))
                .isNull();
        delay();
        validateBlob(eventualBlobStore.getBlob(containerName, blobName));
    }

    @Test
    public void testReadAfterDelete() throws Exception {
        String blobName = createRandomBlobName();
        eventualBlobStore.putBlob(makeRequest(containerName, blobName),
                BYTE_SOURCE.openStream());
        assertThat(eventualBlobStore.getBlob(containerName, blobName))
                .isNull();
        delay();
        eventualBlobStore.removeBlob(containerName, blobName);
        validateBlob(eventualBlobStore.getBlob(containerName, blobName));
        delay();
        assertThat(eventualBlobStore.getBlob(containerName, blobName))
                .isNull();
    }

    @Test
    public void testOverwriteAfterDelete() throws Exception {
        String blobName = createRandomBlobName();
        eventualBlobStore.putBlob(makeRequest(containerName, blobName),
                BYTE_SOURCE.openStream());
        delay();
        eventualBlobStore.removeBlob(containerName, blobName);
        eventualBlobStore.putBlob(makeRequest(containerName, blobName),
                BYTE_SOURCE.openStream());
        delay();
        validateBlob(eventualBlobStore.getBlob(containerName, blobName));
    }

    @Test
    public void testReadAfterCopy() throws Exception {
        String fromName = createRandomBlobName();
        String toName = createRandomBlobName();
        eventualBlobStore.putBlob(makeRequest(containerName, fromName),
                BYTE_SOURCE.openStream());
        delay();
        eventualBlobStore.copyBlob(CopyObjectRequest.builder()
                .sourceBucket(containerName).sourceKey(fromName)
                .destinationBucket(containerName).destinationKey(toName)
                .build());
        assertThat(eventualBlobStore.getBlob(containerName, toName))
                .isNull();
        delay();
        validateBlob(eventualBlobStore.getBlob(containerName, toName));
    }

    @Test
    public void testReadAfterMultipartUpload() throws Exception {
        String blobName = createRandomBlobName();
        MultipartUpload mpu = eventualBlobStore.initiateMultipartUpload(
                CreateMultipartUploadRequest.builder()
                        .bucket(containerName)
                        .key(blobName)
                        .contentDisposition("attachment; filename=foo.mp4")
                        .contentEncoding("compress")
                        .contentType(MediaType.MP4_AUDIO.toString())
                        .metadata(Map.of("key", "value"))
                        .build());
        var part = TestUtils.uploadPart(eventualBlobStore, mpu,
                /*partNumber=*/ 1, BYTE_SOURCE.openStream(),
                BYTE_SOURCE.size());
        eventualBlobStore.completeMultipartUpload(mpu,
                SdkRequests.completeRequest(mpu,
                        List.of(TestUtils.completedPart(1, part))));
        assertThat(eventualBlobStore.getBlob(containerName, blobName))
                .isNull();
        delay();
        validateBlob(eventualBlobStore.getBlob(containerName, blobName));
    }

    @Test
    public void testWritePropagatesAtProbabilityZero() throws Exception {
        var store = EventualBlobStore.newEventualBlobStore(
                nearBlobStore, farBlobStore, executorService, DELAY,
                DELAY_UNIT, /*probability=*/ 0.0);
        String blobName = createRandomBlobName();
        store.putBlob(makeRequest(containerName, blobName),
                BYTE_SOURCE.openStream());
        delay();
        assertThat(farBlobStore.blobMetadata(containerName, blobName))
                .isNotNull();
    }

    @Test
    public void testListAfterCreate() throws Exception {
        String blobName = createRandomBlobName();
        eventualBlobStore.putBlob(makeRequest(containerName, blobName),
                BYTE_SOURCE.openStream());
        assertThat(eventualBlobStore.list(containerName).contents()).isEmpty();
        delay();
        assertThat(eventualBlobStore.list(containerName).contents()).isNotEmpty();
    }

    @Test
    public void testCreateContainerInBothStores() throws Exception {
        String newContainer = createRandomContainerName();
        try {
            eventualBlobStore.createContainer(newContainer);
            // Container operations apply synchronously to both stores.
            assertThat(nearBlobStore.containerExists(newContainer)).isTrue();
            assertThat(farBlobStore.containerExists(newContainer)).isTrue();
        } finally {
            nearBlobStore.deleteContainer(newContainer);
            farBlobStore.deleteContainer(newContainer);
        }
    }

    @Test
    public void testClearContainerClearsBothStores() throws Exception {
        nearBlobStore.putBlob(
                makeRequest(containerName, createRandomBlobName()),
                BYTE_SOURCE.openStream());
        farBlobStore.putBlob(
                makeRequest(containerName, createRandomBlobName()),
                BYTE_SOURCE.openStream());
        assertThat(nearBlobStore.list(containerName).contents()).isNotEmpty();
        assertThat(farBlobStore.list(containerName).contents()).isNotEmpty();

        eventualBlobStore.clearContainer(ListObjectsV2Request.builder()
                .bucket(containerName)
                .build());

        // clearContainer must clear both stores, not only the read store.
        assertThat(nearBlobStore.list(containerName).contents()).isEmpty();
        assertThat(farBlobStore.list(containerName).contents()).isEmpty();
    }

    private static String createRandomContainerName() {
        return "container-" + new Random().nextInt(Integer.MAX_VALUE);
    }

    private static String createRandomBlobName() {
        return "blob-" + new Random().nextInt(Integer.MAX_VALUE);
    }

    private static PutObjectRequest makeRequest(String containerName,
            String blobName) throws IOException {
        return PutObjectRequest.builder()
                .bucket(containerName)
                .key(blobName)
                .contentDisposition("attachment; filename=foo.mp4")
                .contentEncoding("compress")
                .contentLength(BYTE_SOURCE.size())
                .contentType(MediaType.MP4_AUDIO.toString())
                .contentMD5(Base64.getEncoder().encodeToString(
                        MD5.hash(BYTE_SOURCE.read())))
                .metadata(Map.of("key", "value"))
                .build();
    }

    private static void validateBlob(
            software.amazon.awssdk.core.ResponseInputStream<
                    software.amazon.awssdk.services.s3.model
                            .GetObjectResponse> blob)
            throws IOException {
        assertThat(blob).isNotNull();

        var contentMetadata = blob.response();
        assertThat(contentMetadata.contentDisposition())
                .isEqualTo("attachment; filename=foo.mp4");
        assertThat(contentMetadata.contentEncoding())
                .isEqualTo("compress");
        assertThat(contentMetadata.contentLength())
                .isEqualTo(BYTE_SOURCE.size());
        assertThat(contentMetadata.contentType())
                .isEqualTo(MediaType.MP4_AUDIO.toString());

        assertThat(blob.response().metadata())
                .isEqualTo(Map.of("key", "value"));

        try (InputStream actual = blob;
                InputStream expected = BYTE_SOURCE.openStream()) {
            assertThat(actual).hasSameContentAs(expected);
        }
    }

    private static void delay() throws InterruptedException {
        DELAY_UNIT.sleep(1 + DELAY);
    }
}
