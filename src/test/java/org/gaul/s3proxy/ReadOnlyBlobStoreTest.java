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

import java.util.Random;

import com.google.common.collect.ImmutableList;
import com.google.inject.Module;

import org.assertj.core.api.Fail;
import org.jclouds.ContextBuilder;
import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.BlobStoreContext;
import org.jclouds.blobstore.options.PutOptions;
import org.jclouds.logging.slf4j.config.SLF4JLoggingModule;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public final class ReadOnlyBlobStoreTest {
    private BlobStoreContext context;
    private BlobStore blobStore;
    private String containerName;
    private BlobStore readOnlyBlobStore;

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
        readOnlyBlobStore = ReadOnlyBlobStore.newReadOnlyBlobStore(blobStore);
    }

    @After
    public void tearDown() throws Exception {
        if (context != null) {
            blobStore.deleteContainer(containerName);
            context.close();
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
            readOnlyBlobStore.putBlob(containerName, null);
            Fail.failBecauseExceptionWasNotThrown(
                    UnsupportedOperationException.class);
        } catch (UnsupportedOperationException ne) {
            // expected
        }
    }

    @Test
    public void testPutBlobOptions() throws Exception {
        try {
            readOnlyBlobStore.putBlob(containerName, null, new PutOptions());
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
