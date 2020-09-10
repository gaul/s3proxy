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
import java.util.Random;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.io.ByteSource;
import com.google.common.net.MediaType;
import com.google.inject.Module;

import org.jclouds.ContextBuilder;
import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.BlobStoreContext;
import org.jclouds.blobstore.domain.Blob;
import org.jclouds.blobstore.domain.MultipartPart;
import org.jclouds.blobstore.domain.MultipartUpload;
import org.jclouds.blobstore.options.CopyOptions;
import org.jclouds.blobstore.options.PutOptions;
import org.jclouds.io.ContentMetadata;
import org.jclouds.logging.slf4j.config.SLF4JLoggingModule;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public final class EventualBlobStoreTest {
    private static final int DELAY = 5;
    private static final TimeUnit DELAY_UNIT = TimeUnit.SECONDS;
    private static final ByteSource BYTE_SOURCE =
            TestUtils.randomByteSource().slice(0, 1024);
    private BlobStoreContext nearContext;
    private BlobStoreContext farContext;
    private BlobStore nearBlobStore;
    private BlobStore farBlobStore;
    private String containerName;
    private ScheduledExecutorService executorService;
    private BlobStore eventualBlobStore;

    @Before
    public void setUp() throws Exception {
        containerName = createRandomContainerName();

        nearContext = ContextBuilder
                .newBuilder("transient")
                .credentials("identity", "credential")
                .modules(ImmutableList.<Module>of(new SLF4JLoggingModule()))
                .build(BlobStoreContext.class);
        nearBlobStore = nearContext.getBlobStore();
        nearBlobStore.createContainerInLocation(null, containerName);

        farContext = ContextBuilder
                .newBuilder("transient")
                .credentials("identity", "credential")
                .modules(ImmutableList.<Module>of(new SLF4JLoggingModule()))
                .build(BlobStoreContext.class);
        farBlobStore = farContext.getBlobStore();
        farBlobStore.createContainerInLocation(null, containerName);

        executorService = Executors.newScheduledThreadPool(1);

        eventualBlobStore = EventualBlobStore.newEventualBlobStore(
                nearBlobStore, farBlobStore, executorService, DELAY,
                DELAY_UNIT, 1.0);
    }

    @After
    public void tearDown() throws Exception {
        if (nearContext != null) {
            nearBlobStore.deleteContainer(containerName);
            nearContext.close();
        }
        if (farContext != null) {
            farBlobStore.deleteContainer(containerName);
            farContext.close();
        }
        if (executorService != null) {
            executorService.shutdown();
        }
    }

    @Test
    public void testReadAfterCreate() throws Exception {
        String blobName = createRandomBlobName();
        Blob blob = makeBlob(eventualBlobStore, blobName);
        eventualBlobStore.putBlob(containerName, blob);
        assertThat(eventualBlobStore.getBlob(containerName, blobName))
                .isNull();
        delay();
        validateBlob(eventualBlobStore.getBlob(containerName, blobName));
    }

    @Test
    public void testReadAfterDelete() throws Exception {
        String blobName = createRandomBlobName();
        Blob blob = makeBlob(eventualBlobStore, blobName);
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
        Blob blob = makeBlob(eventualBlobStore, blobName);
        eventualBlobStore.putBlob(containerName, blob);
        delay();
        eventualBlobStore.removeBlob(containerName, blobName);
        blob = makeBlob(eventualBlobStore, blobName);
        eventualBlobStore.putBlob(containerName, blob);
        delay();
        validateBlob(eventualBlobStore.getBlob(containerName, blobName));
    }

    @Test
    public void testReadAfterCopy() throws Exception {
        String fromName = createRandomBlobName();
        String toName = createRandomBlobName();
        Blob blob = makeBlob(eventualBlobStore, fromName);
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
        Blob blob = makeBlob(eventualBlobStore, blobName);
        MultipartUpload mpu = eventualBlobStore.initiateMultipartUpload(
                containerName, blob.getMetadata(), new PutOptions());
        MultipartPart part = eventualBlobStore.uploadMultipartPart(mpu,
                /*partNumber=*/ 1, blob.getPayload());
        eventualBlobStore.completeMultipartUpload(mpu, ImmutableList.of(part));
        assertThat(eventualBlobStore.getBlob(containerName, blobName))
                .isNull();
        delay();
        validateBlob(eventualBlobStore.getBlob(containerName, blobName));
    }

    @Test
    public void testListAfterCreate() throws Exception {
        String blobName = createRandomBlobName();
        Blob blob = makeBlob(eventualBlobStore, blobName);
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

    private static void validateBlob(Blob blob) throws IOException {
        assertThat(blob).isNotNull();

        ContentMetadata contentMetadata =
                blob.getMetadata().getContentMetadata();
        assertThat(contentMetadata.getContentDisposition())
                .isEqualTo("attachment; filename=foo.mp4");
        assertThat(contentMetadata.getContentEncoding())
                .isEqualTo("compress");
        assertThat(contentMetadata.getContentLength())
                .isEqualTo(BYTE_SOURCE.size());
        assertThat(contentMetadata.getContentType())
                .isEqualTo(MediaType.MP4_AUDIO.toString());

        assertThat(blob.getMetadata().getUserMetadata())
                .isEqualTo(ImmutableMap.of("key", "value"));

        try (InputStream actual = blob.getPayload().openStream();
                InputStream expected = BYTE_SOURCE.openStream()) {
            assertThat(actual).hasContentEqualTo(expected);
        }
    }

    private static void delay() throws InterruptedException {
        DELAY_UNIT.sleep(1 + DELAY);
    }
}
