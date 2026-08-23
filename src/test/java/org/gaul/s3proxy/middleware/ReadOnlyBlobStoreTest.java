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

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;
import java.util.Set;

import com.google.common.io.ByteSource;

import org.assertj.core.api.Fail;
import org.gaul.s3proxy.TestUtils;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.ForwardingBlobStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;

public final class ReadOnlyBlobStoreTest {
    private BlobStore blobStore;
    private String containerName;
    private BlobStore readOnlyBlobStore;

    @BeforeEach
    public void setUp() throws Exception {
        containerName = createRandomContainerName();

        blobStore = TestUtils.createTransientBlobStore();
        blobStore.createContainer(containerName);
        readOnlyBlobStore = ReadOnlyBlobStore.newReadOnlyBlobStore(blobStore);
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (blobStore != null) {
            blobStore.deleteContainer(containerName);
        }
    }

    @Test
    public void testContainerExists() throws Exception {
        assertThat(readOnlyBlobStore.containerExists(containerName)).isTrue();
        assertThat(readOnlyBlobStore.containerExists(
                containerName + "-fake")).isFalse();
    }

    @Test
    public void testPutBlob() throws Exception {
        try {
            readOnlyBlobStore.putBlob(TestUtils.putRequest(containerName,
                    "blob", ByteSource.empty()), null);
            Fail.failBecauseExceptionWasNotThrown(
                    UnsupportedOperationException.class);
        } catch (UnsupportedOperationException ne) {
            // expected
        }
    }

    @Test
    public void testPutBlobOptions() throws Exception {
        try {
            readOnlyBlobStore.putBlob(TestUtils.putRequest(containerName,
                    "blob", ByteSource.empty()), null);
            Fail.failBecauseExceptionWasNotThrown(
                    UnsupportedOperationException.class);
        } catch (UnsupportedOperationException ne) {
            // expected
        }
    }

    @Test
    public void testCreateContainer() throws Exception {
        try {
            readOnlyBlobStore.createContainer(containerName);
            Fail.failBecauseExceptionWasNotThrown(
                    UnsupportedOperationException.class);
        } catch (UnsupportedOperationException ne) {
            // expected
        }
    }

    @Test
    public void testCreateContainerOptions() throws Exception {
        try {
            readOnlyBlobStore.createContainer(containerName);
            Fail.failBecauseExceptionWasNotThrown(
                    UnsupportedOperationException.class);
        } catch (UnsupportedOperationException ne) {
            // expected
        }
    }

    @Test
    public void testConditionalRemoveBlob() throws Exception {
        var recorder = new TestUtils.ConditionalDeleteRecorder(blobStore);
        BlobStore readOnly = ReadOnlyBlobStore.newReadOnlyBlobStore(recorder);
        TestUtils.putBlob(blobStore, containerName, "blob", ByteSource.empty());

        try {
            readOnly.removeBlob(DeleteObjectRequest.builder()
                    .bucket(containerName)
                    .key("blob")
                    .ifMatch("\"d41d8cd98f00b204e9800998ecf8427e\"")
                    .build());
            Fail.failBecauseExceptionWasNotThrown(
                    UnsupportedOperationException.class);
        } catch (UnsupportedOperationException ne) {
            // expected
        }

        assertThat(recorder.lastRequest()).isNull();
        assertThat(blobStore.blobExists(containerName, "blob")).isTrue();
    }

    /**
     * Every mutating operation ForwardingBlobStore passes to its delegate
     * has to be refused here, or the middleware stops meaning anything for
     * whichever operation was missed -- a conditional delete once reached the
     * backend of a read-only proxy this way.  Overloads count separately:
     * two of the three removeBlob spellings were refused and the third was
     * not.  A new mutating operation fails this until it is refused; a new
     * read-only one belongs in the set below.
     */
    @Test
    public void testRefusesEveryForwardedMutation() throws Exception {
        var readOnlyOperations = Set.of(
                "blobExists", "blobMetadata", "close", "delegate", "getBlob",
                "getBlobAccess", "getBucketEncryption",
                "getBucketVersioning", "getContainerAccess",
                "getMinimumMultipartPartSize", "headBucket", "list",
                "listMultipartUpload",
                "listMultipartUploads", "listV1", "listVersions",
                "supportsBucketEncryption", "supportsCopyMultipartPart",
                "supportsServerSideEncryption", "supportsVersioning");

        var missing = new ArrayList<String>();
        for (Method method : ForwardingBlobStore.class.getDeclaredMethods()) {
            if (method.isSynthetic() ||
                    readOnlyOperations.contains(method.getName())) {
                continue;
            }
            try {
                var unused = ReadOnlyBlobStore.class.getDeclaredMethod(
                        method.getName(), method.getParameterTypes());
            } catch (NoSuchMethodException nsme) {
                missing.add(method.getName() + Arrays.toString(
                        method.getParameterTypes()));
            }
        }

        assertThat(missing).isEmpty();
    }

    private static String createRandomContainerName() {
        return "container-" + new Random().nextInt(Integer.MAX_VALUE);
    }
}
