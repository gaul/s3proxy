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
import java.util.Random;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import com.google.common.io.ByteSource;
import com.google.common.net.MediaType;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.ContentMetadata;
import org.gaul.s3proxy.blobstore.domain.Blob;
import org.gaul.s3proxy.blobstore.domain.MultipartPart;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.gaul.s3proxy.blobstore.options.CopyOptions;
import org.gaul.s3proxy.blobstore.options.PutOptions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

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
        Blob blob = makeBlob(blobName);
        eventualBlobStore.putBlob(containerName, blob);
        assertThat(eventualBlobStore.getBlob(containerName, blobName))
                .isNull();
        delay();
        validateBlob(eventualBlobStore.getBlob(containerName, blobName));
    }

    @Test
    public void testReadAfterDelete() throws Exception {
        String blobName = createRandomBlobName();
        Blob blob = makeBlob(blobName);
        eventualBlobStore.putBlob(containerName, blob);
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
        Blob blob = makeBlob(blobName);
        eventualBlobStore.putBlob(containerName, blob);
        delay();
        eventualBlobStore.removeBlob(containerName, blobName);
        blob = makeBlob(blobName);
        eventualBlobStore.putBlob(containerName, blob);
        delay();
        validateBlob(eventualBlobStore.getBlob(containerName, blobName));
    }

    @Test
    public void testReadAfterCopy() throws Exception {
        String fromName = createRandomBlobName();
        String toName = createRandomBlobName();
        Blob blob = makeBlob(fromName);
        eventualBlobStore.putBlob(containerName, blob);
        delay();
        eventualBlobStore.copyBlob(containerName, fromName, containerName,
                toName, CopyOptions.NONE);
        assertThat(eventualBlobStore.getBlob(containerName, toName))
                .isNull();
        delay();
        validateBlob(eventualBlobStore.getBlob(containerName, toName));
    }

    @Test
    public void testReadAfterMultipartUpload() throws Exception {
        String blobName = createRandomBlobName();
        Blob blob = makeBlob(blobName);
        MultipartUpload mpu = eventualBlobStore.initiateMultipartUpload(
                containerName, blob.getMetadata(), PutOptions.NONE);
        MultipartPart part = eventualBlobStore.uploadMultipartPart(mpu,
                /*partNumber=*/ 1, blob.getPayload());
        eventualBlobStore.completeMultipartUpload(mpu, List.of(part));
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
        Blob blob = makeBlob(blobName);
        store.putBlob(containerName, blob);
        delay();
        assertThat(farBlobStore.blobMetadata(containerName, blobName))
                .isNotNull();
    }

    @Test
    public void testListAfterCreate() throws Exception {
        String blobName = createRandomBlobName();
        Blob blob = makeBlob(blobName);
        eventualBlobStore.putBlob(containerName, blob);
        assertThat(eventualBlobStore.list(containerName)).isEmpty();
        delay();
        assertThat(eventualBlobStore.list(containerName)).isNotEmpty();
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

    private static void validateBlob(Blob blob) throws IOException {
        assertThat(blob).isNotNull();

        ContentMetadata contentMetadata =
                blob.getMetadata().getContentMetadata();
        assertThat(contentMetadata.contentDisposition())
                .isEqualTo("attachment; filename=foo.mp4");
        assertThat(contentMetadata.contentEncoding())
                .isEqualTo("compress");
        assertThat(contentMetadata.contentLength())
                .isEqualTo(BYTE_SOURCE.size());
        assertThat(contentMetadata.contentType())
                .isEqualTo(MediaType.MP4_AUDIO.toString());

        assertThat(blob.getMetadata().getUserMetadata())
                .isEqualTo(Map.of("key", "value"));

        try (InputStream actual = blob.getPayload().openStream();
                InputStream expected = BYTE_SOURCE.openStream()) {
            assertThat(actual).hasSameContentAs(expected);
        }
    }

    private static void delay() throws InterruptedException {
        DELAY_UNIT.sleep(1 + DELAY);
    }
}
