/*
 * Copyright 2014-2021 Andrew Gaul <andrew@gaul.org>
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

import java.util.Random;

import com.google.common.collect.ImmutableList;
import com.google.common.hash.Hashing;
import com.google.inject.Module;

import org.assertj.core.api.Fail;
import org.jclouds.ContextBuilder;
import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.BlobStoreContext;
import org.jclouds.blobstore.domain.Blob;
import org.jclouds.blobstore.domain.MultipartUpload;
import org.jclouds.blobstore.options.PutOptions;
import org.jclouds.io.Payload;
import org.jclouds.io.Payloads;
import org.jclouds.logging.slf4j.config.SLF4JLoggingModule;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public final class RequiredMD5BlobStoreTest {
    private BlobStoreContext context;
    private BlobStore blobStore;
    private String containerName;
    private BlobStore requiredMD5BlobStore;

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
        requiredMD5BlobStore = RequiredMD5BlobStore.newRequiredMD5BlobStore(
                blobStore);
    }

    @After
    public void tearDown() throws Exception {
        if (context != null) {
            blobStore.deleteContainer(containerName);
            context.close();
        }
    }

    @Test
    public void testPutBlob() throws Exception {
        String blobName = TestUtils.createRandomBlobName();
        byte[] data = new byte[1];
        Blob blob = requiredMD5BlobStore.blobBuilder(blobName).payload(data)
            .build();
        try {
            requiredMD5BlobStore.putBlob(containerName, blob);
            Fail.failBecauseExceptionWasNotThrown(
                    IllegalArgumentException.class);
        } catch (IllegalArgumentException iae) {
            // expected
        }

        blob.getMetadata().getContentMetadata().setContentMD5(
                Hashing.md5().hashBytes(data));
        requiredMD5BlobStore.putBlob(containerName, blob);
    }

    @Test
    public void testPutBlobOptions() throws Exception {
        String blobName = TestUtils.createRandomBlobName();
        byte[] data = new byte[1];
        Blob blob = requiredMD5BlobStore.blobBuilder(blobName).payload(data)
            .build();
        try {
            requiredMD5BlobStore.putBlob(containerName, blob, new PutOptions());
            Fail.failBecauseExceptionWasNotThrown(
                    IllegalArgumentException.class);
        } catch (IllegalArgumentException iae) {
            // expected
        }

        blob.getMetadata().getContentMetadata().setContentMD5(
                Hashing.md5().hashBytes(data));
        requiredMD5BlobStore.putBlob(containerName, blob, new PutOptions());
    }

    @Test
    public void testUploadMultipartPart() throws Exception {
        String blobName = TestUtils.createRandomBlobName();
        Blob blob = requiredMD5BlobStore.blobBuilder(blobName).build();
        MultipartUpload mpu = requiredMD5BlobStore.initiateMultipartUpload(
                containerName, blob.getMetadata(), PutOptions.NONE);
        byte[] data = new byte[1];
        Payload payload = Payloads.newPayload(data);

        try {
            requiredMD5BlobStore.uploadMultipartPart(mpu, 1, payload);
            Fail.failBecauseExceptionWasNotThrown(
                    IllegalArgumentException.class);
        } catch (IllegalArgumentException iae) {
            // expected
        }

        payload.getContentMetadata().setContentMD5(
                Hashing.md5().hashBytes(data));
        requiredMD5BlobStore.uploadMultipartPart(mpu, 1, payload);
    }

    private static String createRandomContainerName() {
        return "container-" + new Random().nextInt(Integer.MAX_VALUE);
    }
}
