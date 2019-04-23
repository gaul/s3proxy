/*
 * Copyright 2014-2018 Andrew Gaul <andrew@gaul.org>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.gaul.s3proxy;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.io.ByteSource;
import com.google.common.io.ByteStreams;
import com.google.common.net.MediaType;
import com.google.inject.Module;

import org.assertj.core.api.Assertions;
import org.assertj.core.api.Fail;
import org.jclouds.ContextBuilder;
import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.BlobStoreContext;
import org.jclouds.blobstore.domain.Blob;
import org.jclouds.blobstore.domain.BlobMetadata;
import org.jclouds.blobstore.domain.PageSet;
import org.jclouds.blobstore.domain.StorageMetadata;
import org.jclouds.blobstore.options.PutOptions;
import org.jclouds.io.ContentMetadata;
import org.jclouds.logging.slf4j.config.SLF4JLoggingModule;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public final class EncryptedBlobStoreTest {
    private static final int BYTE_SOURCE_SIZE = 1024;
    private static final ByteSource BYTE_SOURCE = TestUtils.randomByteSource()
        .slice(0, BYTE_SOURCE_SIZE);
    private BlobStoreContext context;
    private BlobStore blobStore;
    private String containerName;
    private BlobStore encryptedBlobStore;

    @Before
    public void setUp() throws Exception {
        containerName = TestUtils.createRandomContainerName();

        context = ContextBuilder
                .newBuilder("transient")
                .credentials("identity", "credential")
                .modules(ImmutableList.<Module>of(new SLF4JLoggingModule()))
                .build(BlobStoreContext.class);
        blobStore = context.getBlobStore();
        blobStore.createContainerInLocation(null, containerName);

        Properties properties = new Properties();
        properties.put(S3ProxyConstants.PROPERTY_ENCRYPTED_BLOBSTORE, "true");
        properties.put(S3ProxyConstants.PROPERTY_ENCRYPTION_KEY,
            "my-little-secret");
        properties.put(S3ProxyConstants.PROPERTY_ENCRYPTION_SALT, "salty");

        encryptedBlobStore = EncryptedBlobStore.newEncryptedBlobStore(blobStore,
            properties);
    }

    @After
    public void tearDown() throws Exception {
        if (context != null) {
            blobStore.deleteContainer(containerName);
            context.close();
        }
    }

    @Test
    public void testCreateBlobGetBlob() throws Exception {
        String blobName = TestUtils.createRandomBlobName();
        Blob blob = makeBlob(encryptedBlobStore, blobName);
        encryptedBlobStore.putBlob(containerName, blob);

        blob = encryptedBlobStore.getBlob(containerName, blobName);
        validateBlobMetadata(blob.getMetadata());

        // content differs, only compare length
        InputStream actual = blob.getPayload().openStream();
        InputStream expected = BYTE_SOURCE.openStream();
        long actualLength = ByteStreams.copy(actual,
            ByteStreams.nullOutputStream());
        long expectedLength = ByteStreams.copy(expected,
            ByteStreams.nullOutputStream());
        Assertions.assertThat(actualLength).isEqualTo(expectedLength);

        PageSet<? extends StorageMetadata> pageSet = encryptedBlobStore.list(
            containerName);
        Assertions.assertThat(pageSet).hasSize(1);
        StorageMetadata sm = pageSet.iterator().next();
        Assertions.assertThat(sm.getName()).isEqualTo(blobName);
        Assertions.assertThat(sm.getSize() - 17).isEqualTo(BYTE_SOURCE_SIZE);
    }

    @Test
    public void testCreateBlobBlobMetadata() throws Exception {
        String blobName = TestUtils.createRandomBlobName();
        Blob blob = makeBlob(encryptedBlobStore, blobName);
        encryptedBlobStore.putBlob(containerName, blob);
        BlobMetadata metadata = encryptedBlobStore.blobMetadata(containerName,
            blobName);
        validateBlobMetadata(metadata);
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testCreateMultipartBlobGetBlob() throws Exception {
        BlobMetadata blobMetadata = makeBlob(encryptedBlobStore, TestUtils
            .createRandomBlobName()).getMetadata();
        encryptedBlobStore.initiateMultipartUpload(TestUtils
            .createRandomContainerName(), blobMetadata, new PutOptions());
        Fail.failBecauseExceptionWasNotThrown(UnsupportedOperationException
            .class);
    }

    private Blob makeBlob(BlobStore blobStore, String blobName)
            throws IOException {
        return blobStore.blobBuilder(blobName)
                .payload(BYTE_SOURCE)
                .contentDisposition("attachment; filename=secret-recording.mp4")
                .contentEncoding("compress")
                .contentLength(BYTE_SOURCE.size())
                .contentType(MediaType.MP4_AUDIO)
                .contentMD5(BYTE_SOURCE.hash(TestUtils.MD5))
                .userMetadata(ImmutableMap.of("key", "value"))
                .build();
    }

    private void validateBlobMetadata(BlobMetadata metadata)
            throws IOException {
        Assertions.assertThat(metadata).isNotNull();

        ContentMetadata contentMetadata = metadata.getContentMetadata();
        Assertions.assertThat(contentMetadata.getContentDisposition())
            .isEqualTo("attachment; filename=secret-recording.mp4");
        Assertions.assertThat(contentMetadata.getContentEncoding())
            .isEqualTo("compress");
        Assertions.assertThat(contentMetadata.getContentType())
            .isEqualTo(MediaType.MP4_AUDIO.toString());

        Assertions.assertThat(metadata.getUserMetadata())
            .isEqualTo(ImmutableMap.of("key", "value"));
    }
}
