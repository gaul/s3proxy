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

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Properties;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.middleware.EncryptedBlobStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

/**
 * An encrypted object is stored under its key plus ".s3enc", and a listing
 * removes exactly one suffix to answer with the key again.  Adding one only
 * to the keys that did not already end in the suffix broke that inversion for
 * a client key that does: "X" and "X.s3enc" named one stored object, so
 * writing either replaced the other, deleting either deleted the other, and
 * only "X" was ever listed.  A key ending in ".s3enc" is an ordinary S3 key
 * and must name only itself.
 */
public final class EncryptedBlobStoreSuffixTest {
    private static final String CONTAINER = "container";
    private static final String PLAIN_KEY = "report";
    private static final String SUFFIXED_KEY = "report.s3enc";
    private static final String PLAIN_CONTENT = "the-plain-key-content";
    private static final String SUFFIXED_CONTENT = "the-suffixed-key-content";

    private BlobStore blobStore;

    @BeforeEach
    public void setUp() throws Exception {
        BlobStore backing = TestUtils.createTransientBlobStore();
        backing.createContainer(CONTAINER);
        var properties = new Properties();
        properties.setProperty(
                S3ProxyConstants.PROPERTY_ENCRYPTED_BLOBSTORE_PASSWORD,
                "password");
        properties.setProperty(
                S3ProxyConstants.PROPERTY_ENCRYPTED_BLOBSTORE_SALT, "salt");
        blobStore = EncryptedBlobStore.newEncryptedBlobStore(backing,
                properties);
    }

    /** Writing one key leaves the other's content alone. */
    @Test
    public void testSuffixedKeyDoesNotOverwritePlainKey() throws Exception {
        put(PLAIN_KEY, PLAIN_CONTENT);
        put(SUFFIXED_KEY, SUFFIXED_CONTENT);

        assertThat(read(PLAIN_KEY)).isEqualTo(PLAIN_CONTENT);
        assertThat(read(SUFFIXED_KEY)).isEqualTo(SUFFIXED_CONTENT);
    }

    /** Written in the other order, with the same answer. */
    @Test
    public void testPlainKeyDoesNotOverwriteSuffixedKey() throws Exception {
        put(SUFFIXED_KEY, SUFFIXED_CONTENT);
        put(PLAIN_KEY, PLAIN_CONTENT);

        assertThat(read(SUFFIXED_KEY)).isEqualTo(SUFFIXED_CONTENT);
        assertThat(read(PLAIN_KEY)).isEqualTo(PLAIN_CONTENT);
    }

    /**
     * A read of the suffixed key answers with its plaintext.  It used to
     * resolve to the plain key's stored object and hand back the raw
     * ciphertext and padding, that object having no suffixed name of its own.
     */
    @Test
    public void testSuffixedKeyReadsBackAsPlaintext() throws Exception {
        put(SUFFIXED_KEY, SUFFIXED_CONTENT);

        String content = read(SUFFIXED_KEY);
        assertThat(content).isEqualTo(SUFFIXED_CONTENT);
        assertThat(content).doesNotContain("-S3-ENC-");
    }

    /** Both keys are listed, under the names the client used. */
    @Test
    public void testBothKeysAreListed() throws Exception {
        put(PLAIN_KEY, PLAIN_CONTENT);
        put(SUFFIXED_KEY, SUFFIXED_CONTENT);

        assertThat(keys()).containsExactlyInAnyOrder(PLAIN_KEY, SUFFIXED_KEY);
    }

    /** Each key reports its own plaintext size. */
    @Test
    public void testEachKeyReportsItsOwnSize() throws Exception {
        put(PLAIN_KEY, PLAIN_CONTENT);
        put(SUFFIXED_KEY, SUFFIXED_CONTENT);

        assertThat(blobStore.blobMetadata(CONTAINER, PLAIN_KEY)
                .contentLength()).isEqualTo(PLAIN_CONTENT.length());
        assertThat(blobStore.blobMetadata(CONTAINER, SUFFIXED_KEY)
                .contentLength()).isEqualTo(SUFFIXED_CONTENT.length());
    }

    /** Deleting one leaves the other in place. */
    @Test
    public void testDeletingSuffixedKeyKeepsPlainKey() throws Exception {
        put(PLAIN_KEY, PLAIN_CONTENT);
        put(SUFFIXED_KEY, SUFFIXED_CONTENT);

        blobStore.removeBlob(CONTAINER, SUFFIXED_KEY);

        assertThat(blobStore.blobExists(CONTAINER, PLAIN_KEY)).isTrue();
        assertThat(read(PLAIN_KEY)).isEqualTo(PLAIN_CONTENT);
        assertThat(keys()).containsExactly(PLAIN_KEY);
    }

    /** And the other way round. */
    @Test
    public void testDeletingPlainKeyKeepsSuffixedKey() throws Exception {
        put(PLAIN_KEY, PLAIN_CONTENT);
        put(SUFFIXED_KEY, SUFFIXED_CONTENT);

        blobStore.removeBlob(CONTAINER, PLAIN_KEY);

        assertThat(read(SUFFIXED_KEY)).isEqualTo(SUFFIXED_CONTENT);
        assertThat(keys()).containsExactly(SUFFIXED_KEY);
    }

    /**
     * The multipart path applies the same transform, so an upload to a key
     * ending in the suffix is reported under the key the client named rather
     * than the one a suffix short of it.
     */
    @Test
    public void testMultipartUploadKeepsTheSuffixedKey() {
        blobStore.initiateMultipartUpload(
                CreateMultipartUploadRequest.builder()
                        .bucket(CONTAINER)
                        .key(SUFFIXED_KEY)
                        .build());

        assertThat(blobStore.listMultipartUploads(CONTAINER).stream()
                .map(upload -> upload.key()))
                .containsExactly(SUFFIXED_KEY);
    }

    private void put(String key, String content) {
        byte[] bytes = content.getBytes(StandardCharsets.UTF_8);
        blobStore.putBlob(PutObjectRequest.builder()
                .bucket(CONTAINER)
                .key(key)
                .contentLength((long) bytes.length)
                .build(), new ByteArrayInputStream(bytes));
    }

    private String read(String key) throws Exception {
        try (var stream = blobStore.getBlob(CONTAINER, key)) {
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private List<String> keys() {
        return blobStore.list(ListObjectsV2Request.builder()
                .bucket(CONTAINER)
                .build())
                .contents().stream().map(object -> object.key()).toList();
    }
}
