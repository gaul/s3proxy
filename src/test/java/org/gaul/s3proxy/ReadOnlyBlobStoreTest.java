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

import java.util.Random;

import org.assertj.core.api.Fail;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.options.CreateContainerOptions;
import org.gaul.s3proxy.blobstore.options.PutOptions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public final class ReadOnlyBlobStoreTest {
    private BlobStore blobStore;
    private String containerName;
    private BlobStore readOnlyBlobStore;

    @BeforeEach
    public void setUp() throws Exception {
        containerName = createRandomContainerName();

        blobStore = TestUtils.createTransientBlobStore();
        blobStore.createContainer(containerName, CreateContainerOptions.NONE);
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
            readOnlyBlobStore.putBlob(containerName, null, PutOptions.NONE);
            Fail.failBecauseExceptionWasNotThrown(
                    UnsupportedOperationException.class);
        } catch (UnsupportedOperationException ne) {
            // expected
        }
    }

    @Test
    public void testPutBlobOptions() throws Exception {
        try {
            readOnlyBlobStore.putBlob(containerName, null, PutOptions.NONE);
            Fail.failBecauseExceptionWasNotThrown(
                    UnsupportedOperationException.class);
        } catch (UnsupportedOperationException ne) {
            // expected
        }
    }

    @Test
    public void testCreateContainer() throws Exception {
        try {
            readOnlyBlobStore.createContainer(containerName,
                    CreateContainerOptions.NONE);
            Fail.failBecauseExceptionWasNotThrown(
                    UnsupportedOperationException.class);
        } catch (UnsupportedOperationException ne) {
            // expected
        }
    }

    @Test
    public void testCreateContainerOptions() throws Exception {
        try {
            readOnlyBlobStore.createContainer(containerName,
                    new CreateContainerOptions(false));
            Fail.failBecauseExceptionWasNotThrown(
                    UnsupportedOperationException.class);
        } catch (UnsupportedOperationException ne) {
            // expected
        }
    }

    private static String createRandomContainerName() {
        return "container-" + new Random().nextInt(Integer.MAX_VALUE);
    }
}
