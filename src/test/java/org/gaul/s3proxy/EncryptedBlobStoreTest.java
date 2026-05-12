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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Random;
import java.util.stream.Collectors;

import com.google.common.io.ByteSource;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.ByteSourcePayload;
import org.gaul.s3proxy.blobstore.HttpResponseException;
import org.gaul.s3proxy.blobstore.Payload;
import org.gaul.s3proxy.blobstore.domain.Blob;
import org.gaul.s3proxy.blobstore.domain.BlobAccess;
import org.gaul.s3proxy.blobstore.domain.BlobMetadata;
import org.gaul.s3proxy.blobstore.domain.MultipartPart;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.gaul.s3proxy.blobstore.domain.PageSet;
import org.gaul.s3proxy.blobstore.domain.StorageMetadata;
import org.gaul.s3proxy.blobstore.domain.StorageType;
import org.gaul.s3proxy.blobstore.options.CopyOptions;
import org.gaul.s3proxy.blobstore.options.GetOptions;
import org.gaul.s3proxy.blobstore.options.ListContainerOptions;
import org.gaul.s3proxy.blobstore.options.PutOptions;
import org.gaul.s3proxy.crypto.Constants;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@SuppressWarnings("UnstableApiUsage")
public final class EncryptedBlobStoreTest {
    private static final Logger logger =
        LoggerFactory.getLogger(EncryptedBlobStoreTest.class);
    private BlobStore blobStore;
    private String containerName;
    private BlobStore encryptedBlobStore;

    private static Blob makeBlob(String blobName, InputStream is,
        long contentLength) {

        return Blob.builder(blobName)
            .payload(is)
            .contentLength(contentLength)
            .build();
    }

    private static Blob makeBlob(String blobName, byte[] payload,
        long contentLength) {

        return Blob.builder(blobName)
            .payload(ByteSource.wrap(payload))
            .contentLength(contentLength)
            .build();
    }

    private static Blob makeBlobWithContentType(String blobName,
        long contentLength,
        InputStream is,
        String contentType) {

        return Blob.builder(blobName)
            .payload(is)
            .contentLength(contentLength)
            .contentType(contentType)
            .build();
    }

    @BeforeEach
    public void setUp() throws Exception {
        String password = "Password1234567!";
        String salt = "12345678";

        containerName = TestUtils.createRandomContainerName();

        //noinspection UnstableApiUsage
        blobStore = TestUtils.createTransientBlobStore();
        blobStore.createContainer(containerName);

        var properties = new Properties();
        properties.put(S3ProxyConstants.PROPERTY_ENCRYPTED_BLOBSTORE, "true");
        properties.put(S3ProxyConstants.PROPERTY_ENCRYPTED_BLOBSTORE_PASSWORD,
            password);
        properties.put(S3ProxyConstants.PROPERTY_ENCRYPTED_BLOBSTORE_SALT,
            salt);

        encryptedBlobStore =
            EncryptedBlobStore.newEncryptedBlobStore(blobStore, properties);
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (blobStore != null) {
            blobStore.deleteContainer(containerName);
        }
    }

    @Test
    public void testBlobNotExists() {

        String blobName = TestUtils.createRandomBlobName();
        Blob blob = encryptedBlobStore.getBlob(containerName, blobName);
        assertThat(blob).isNull();

        blob = encryptedBlobStore.getBlob(containerName, blobName,
            GetOptions.NONE);
        assertThat(blob).isNull();
    }

    @Test
    public void testBlobNotEncrypted() throws Exception {

        var tests = new String[] {
            "1", // only 1 char
            "123456789A12345", // lower then the AES block
            "123456789A1234567", // one byte bigger then the AES block
            "123456789A123456123456789B123456123456789C" +
                "1234123456789A123456123456789B123456123456789C1234"
        };

        Map<String, Long> contentLengths = new HashMap<>();
        for (String content : tests) {
            String blobName = TestUtils.createRandomBlobName();

            InputStream is = new ByteArrayInputStream(
                content.getBytes(StandardCharsets.UTF_8));
            contentLengths.put(blobName, (long) content.length());
            Blob blob = makeBlob(blobName, is, content.length());
            blobStore.putBlob(containerName, blob);
            blob = encryptedBlobStore.getBlob(containerName, blobName);

            try (InputStream blobIs = blob.getPayload().openStream()) {
                var reader = new BufferedReader(new InputStreamReader(blobIs));
                String plaintext = reader.lines().collect(Collectors.joining());
                logger.debug("plaintext {}", plaintext);
                assertThat(content).isEqualTo(plaintext);
            }

            var options = GetOptions.NONE;
            blob = encryptedBlobStore.getBlob(containerName, blobName, options);

            try (InputStream blobIs = blob.getPayload().openStream()) {
                var reader = new BufferedReader(new InputStreamReader(blobIs));
                String plaintext = reader.lines().collect(Collectors.joining());
                logger.debug("plaintext {} with empty options ", plaintext);
                assertThat(content).isEqualTo(plaintext);
            }
        }

        PageSet<? extends StorageMetadata> blobs =
            encryptedBlobStore.list(containerName, ListContainerOptions.NONE);
        for (StorageMetadata blob : blobs) {
            assertThat(blob.getSize()).isEqualTo(
                contentLengths.get(blob.getName()));
        }

        blobs = encryptedBlobStore.list();
        StorageMetadata metadata = blobs.iterator().next();
        assertThat(StorageType.CONTAINER).isEqualTo(metadata.getType());
    }

    @Test
    public void testListEncrypted() {
        var contents = new String[] {
            "1", // only 1 char
            "123456789A12345", // lower then the AES block
            "123456789A1234567", // one byte bigger then the AES block
            "123456789A123456123456789B123456123456789C1234"
        };

        Map<String, Long> contentLengths = new HashMap<>();
        for (String content : contents) {
            String blobName = TestUtils.createRandomBlobName();

            InputStream is = new ByteArrayInputStream(
                content.getBytes(StandardCharsets.UTF_8));
            contentLengths.put(blobName, (long) content.length());
            Blob blob =
                makeBlob(blobName, is, content.length());
            encryptedBlobStore.putBlob(containerName, blob);
        }

        PageSet<? extends StorageMetadata> blobs =
            encryptedBlobStore.list(containerName);
        for (StorageMetadata blob : blobs) {
            assertThat(blob.getSize()).isEqualTo(
                contentLengths.get(blob.getName()));
        }

        blobs =
            encryptedBlobStore.list(containerName, ListContainerOptions.NONE);
        for (StorageMetadata blob : blobs) {
            assertThat(blob.getSize()).isEqualTo(
                contentLengths.get(blob.getName()));
            encryptedBlobStore.removeBlob(containerName, blob.getName());
        }

        blobs =
            encryptedBlobStore.list(containerName, ListContainerOptions.NONE);
        assertThat(blobs.size()).isEqualTo(0);
    }

    @Test
    public void testListEncryptedPagination() {
        var expected = new java.util.TreeMap<String, Long>();
        for (int i = 0; i < 5; i++) {
            String blobName = "blob-" + i;
            byte[] content = new byte[10 + i];
            java.util.Arrays.fill(content, (byte) 'c');
            expected.put(blobName, (long) content.length);
            Blob blob = makeBlob(blobName, content, content.length);
            encryptedBlobStore.putBlob(containerName, blob);
        }

        // Page one blob at a time: the marker must advance so every blob is
        // returned exactly once, with its unencrypted size.
        var seen = new java.util.LinkedHashMap<String, Long>();
        String marker = null;
        for (int i = 0; i < expected.size() * 3; i++) {
            var optionsBuilder = ListContainerOptions.builder().maxResults(1);
            if (marker != null) {
                optionsBuilder.afterMarker(marker);
            }
            PageSet<? extends StorageMetadata> page =
                encryptedBlobStore.list(containerName, optionsBuilder.build());
            for (StorageMetadata sm : page) {
                assertThat(seen).doesNotContainKey(sm.getName());
                seen.put(sm.getName(), sm.getSize());
            }
            marker = page.getNextMarker();
            if (marker == null) {
                break;
            }
        }

        assertThat(seen).isEqualTo(expected);
    }

    @Test
    public void testEncryptedEmptyBlob() throws Exception {
        String blobName = TestUtils.createRandomBlobName();
        Blob blob = makeBlob(blobName, new byte[0], 0);
        encryptedBlobStore.putBlob(containerName, blob);

        // An empty object is stored as a single 64-byte padding block.  HEAD
        // and the list view report zero; GET must also return zero bytes
        // rather than exposing the padding block.
        BlobMetadata metadata = encryptedBlobStore.blobMetadata(
            containerName, blobName);
        assertThat(metadata.getSize()).isEqualTo(0L);

        Blob got = encryptedBlobStore.getBlob(containerName, blobName);
        try (InputStream is = got.getPayload().openStream()) {
            assertThat(is.readAllBytes()).isEmpty();
        }
        assertThat(got.getMetadata().getContentMetadata().contentLength())
            .isEqualTo(0L);

        PageSet<? extends StorageMetadata> blobs =
            encryptedBlobStore.list(containerName);
        assertThat(blobs.iterator().next().getSize()).isEqualTo(0L);
    }

    @Test
    public void testListEncryptedMultipart() {

        String blobName = TestUtils.createRandomBlobName();

        var contentParts = new String[] {
            "123456789A123456123456789B123456123456789C1234",
            "123456789D123456123456789E123456123456789F123456",
            "123456789G123456123456789H123456123456789I123"
        };

        String content = contentParts[0] + contentParts[1] + contentParts[2];
        BlobMetadata blobMetadata = makeBlob(blobName,
            content.getBytes(StandardCharsets.UTF_8),
            content.length()).getMetadata();

        MultipartUpload mpu =
            encryptedBlobStore.initiateMultipartUpload(containerName,
                blobMetadata, PutOptions.NONE);

        Payload payload1 = new ByteSourcePayload(ByteSource.wrap(contentParts[0].getBytes(StandardCharsets.UTF_8)));
        Payload payload2 = new ByteSourcePayload(ByteSource.wrap(contentParts[1].getBytes(StandardCharsets.UTF_8)));
        Payload payload3 = new ByteSourcePayload(ByteSource.wrap(contentParts[2].getBytes(StandardCharsets.UTF_8)));

        encryptedBlobStore.uploadMultipartPart(mpu, 1, payload1);
        encryptedBlobStore.uploadMultipartPart(mpu, 2, payload2);
        encryptedBlobStore.uploadMultipartPart(mpu, 3, payload3);

        List<MultipartPart> parts = encryptedBlobStore.listMultipartUpload(mpu);

        int index = 0;
        for (MultipartPart part : parts) {
            assertThat((long) contentParts[index].length()).isEqualTo(
                part.partSize());
            index++;
        }

        encryptedBlobStore.completeMultipartUpload(mpu, parts);

        PageSet<? extends StorageMetadata> blobs =
            encryptedBlobStore.list(containerName);
        StorageMetadata metadata = blobs.iterator().next();
        assertThat((long) content.length()).isEqualTo(metadata.getSize());

        var options = ListContainerOptions.builder().detailed(true).build();
        blobs = encryptedBlobStore.list(containerName, options);
        metadata = blobs.iterator().next();
        assertThat((long) content.length()).isEqualTo(metadata.getSize());

        blobs = encryptedBlobStore.list();
        metadata = blobs.iterator().next();
        assertThat(StorageType.CONTAINER).isEqualTo(metadata.getType());

        List<String> singleList = new ArrayList<>();
        singleList.add(blobName);
        encryptedBlobStore.removeBlobs(containerName, singleList);
        blobs = encryptedBlobStore.list(containerName);
        assertThat(blobs.size()).isEqualTo(0);
    }

    @Test
    public void testEncryptionMultipartUploadAbort() throws Exception {
        String blobName = TestUtils.createRandomBlobName();
        var content = "0123456789ABCDEF0123456789ABCDEF";
        BlobMetadata blobMetadata = makeBlob(blobName,
            content.getBytes(StandardCharsets.UTF_8),
            content.length()).getMetadata();

        MultipartUpload mpu = encryptedBlobStore.initiateMultipartUpload(
            containerName, blobMetadata, PutOptions.NONE);
        List<MultipartPart> parts = new ArrayList<>();
        parts.add(encryptedBlobStore.uploadMultipartPart(mpu, 1,
            new ByteSourcePayload(ByteSource.wrap(
                content.getBytes(StandardCharsets.UTF_8)))));

        encryptedBlobStore.abortMultipartUpload(mpu);

        // The abort removed the in-progress upload: nothing was committed and
        // no encrypted (.s3enc) backend blob was left behind, on either the
        // wrapper or the underlying delegate.
        assertThat(encryptedBlobStore.list(containerName)).isEmpty();
        assertThat(blobStore.list(containerName)).isEmpty();

        // The upload no longer exists, so completing it now fails rather than
        // resurrecting the object from a dangling upload.
        assertThatThrownBy(() ->
            encryptedBlobStore.completeMultipartUpload(mpu, parts))
            .isInstanceOf(RuntimeException.class);
    }

    @Test
    public void testBlobNotEncryptedRanges() throws Exception {

        for (int run = 0; run < 100; run++) {
            var tests = new String[] {
                "123456789A12345", // lower then the AES block
                "123456789A1234567", // one byte bigger then the AES block
                "123456789A123456123456789B123456123456789C" +
                    "1234123456789A123456123456789B123456123456789C1234"
            };

            for (String content : tests) {
                String blobName = TestUtils.createRandomBlobName();
                var rand = new Random();

                InputStream is = new ByteArrayInputStream(
                    content.getBytes(StandardCharsets.UTF_8));
                Blob blob = makeBlob(blobName, is, content.length());
                blobStore.putBlob(containerName, blob);

                int offset = rand.nextInt(content.length() - 1);
                logger.debug("content {} with offset {}", content, offset);

                var options = GetOptions.builder().startAt(offset).build();
                blob = encryptedBlobStore.getBlob(containerName, blobName,
                    options);

                try (InputStream blobIs = blob.getPayload().openStream()) {
                    var reader = new BufferedReader(
                        new InputStreamReader(blobIs));
                    String plaintext = reader.lines().collect(
                        Collectors.joining());
                    logger.debug("plaintext {} with offset {}", plaintext,
                        offset);
                    assertThat(plaintext).isEqualTo(content.substring(offset));
                }

                int tail = rand.nextInt(content.length());
                if (tail == 0) {
                    tail++;
                }
                logger.debug("content {} with tail {}", content, tail);

                options = GetOptions.builder().tail(tail).build();
                blob = encryptedBlobStore.getBlob(containerName, blobName,
                    options);

                try (InputStream blobIs = blob.getPayload().openStream()) {
                    var reader = new BufferedReader(
                        new InputStreamReader(blobIs));
                    String plaintext = reader.lines().collect(
                        Collectors.joining());
                    logger.debug("plaintext {} with tail {}", plaintext, tail);
                    assertThat(plaintext).isEqualTo(
                        content.substring(content.length() - tail));
                }

                offset = 1;
                int end = content.length() - 2;
                logger.debug("content {} with range {}-{}", content, offset,
                    end);

                options = GetOptions.builder().range(offset, end).build();
                blob = encryptedBlobStore.getBlob(containerName, blobName,
                    options);

                try (InputStream blobIs = blob.getPayload().openStream()) {
                    var reader = new BufferedReader(
                        new InputStreamReader(blobIs));
                    String plaintext = reader.lines().collect(
                        Collectors.joining());
                    logger.debug("plaintext {} with range {}-{}", plaintext,
                        offset, end);
                    assertThat(plaintext).isEqualTo(
                        content.substring(offset, end + 1));
                }
            }
        }
    }

    @Test
    public void testEncryptContent() throws Exception {
        var tests = new String[] {
            "1", // only 1 char
            "123456789A12345", // lower then the AES block
            "123456789A1234567", // one byte bigger then the AES block
            "123456789A123456123456789B123456123456789C1234"
        };

        for (String content : tests) {
            String blobName = TestUtils.createRandomBlobName();
            String contentType = "plain/text";

            InputStream is = new ByteArrayInputStream(
                content.getBytes(StandardCharsets.UTF_8));
            Blob blob = makeBlobWithContentType(blobName,
                content.length(), is, contentType);
            encryptedBlobStore.putBlob(containerName, blob);

            blob = encryptedBlobStore.getBlob(containerName, blobName);

            try (InputStream blobIs = blob.getPayload().openStream()) {
                var reader = new BufferedReader(new InputStreamReader(blobIs));
                String plaintext = reader.lines().collect(Collectors.joining());
                logger.debug("plaintext {}", plaintext);
                assertThat(plaintext).isEqualTo(content);
            }

            blob = blobStore.getBlob(containerName,
                blobName + Constants.S3_ENC_SUFFIX);

            try (InputStream blobIs = blob.getPayload().openStream()) {
                var reader = new BufferedReader(new InputStreamReader(blobIs));
                String encrypted = reader.lines().collect(Collectors.joining());
                logger.debug("encrypted {}", encrypted);
                assertThat(content).isNotEqualTo(encrypted);
            }

            assertThat(encryptedBlobStore.blobExists(containerName,
                blobName)).isTrue();

            BlobAccess access =
                encryptedBlobStore.getBlobAccess(containerName, blobName);
            assertThat(access).isEqualTo(BlobAccess.PRIVATE);

            encryptedBlobStore.setBlobAccess(containerName, blobName,
                BlobAccess.PUBLIC_READ);
            access = encryptedBlobStore.getBlobAccess(containerName, blobName);
            assertThat(access).isEqualTo(BlobAccess.PUBLIC_READ);
        }
    }

    @Test
    public void testEncryptContentWithOptions() throws Exception {
        var tests = new String[] {
            "1", // only 1 char
            "123456789A12345", // lower then the AES block
            "123456789A1234567", // one byte bigger then the AES block
            "123456789A123456123456789B123456123456789C1234"
        };

        for (String content : tests) {
            String blobName = TestUtils.createRandomBlobName();
            String contentType = "plain/text; charset=utf-8";

            InputStream is = new ByteArrayInputStream(
                content.getBytes(StandardCharsets.UTF_8));
            Blob blob = makeBlobWithContentType(blobName,
                content.length(), is, contentType);
            var options = PutOptions.NONE;
            encryptedBlobStore.putBlob(containerName, blob, options);

            blob = encryptedBlobStore.getBlob(containerName, blobName);

            try (InputStream blobIs = blob.getPayload().openStream()) {
                var reader = new BufferedReader(new InputStreamReader(blobIs));
                String plaintext = reader.lines().collect(Collectors.joining());
                logger.debug("plaintext {}", plaintext);
                assertThat(content).isEqualTo(plaintext);
            }

            blob = blobStore.getBlob(containerName,
                blobName + Constants.S3_ENC_SUFFIX);

            try (InputStream blobIs = blob.getPayload().openStream()) {
                var reader = new BufferedReader(new InputStreamReader(blobIs));
                String encrypted = reader.lines().collect(Collectors.joining());
                logger.debug("encrypted {}", encrypted);
                assertThat(content).isNotEqualTo(encrypted);
            }

            BlobMetadata metadata =
                encryptedBlobStore.blobMetadata(containerName,
                    blobName + Constants.S3_ENC_SUFFIX);
            assertThat(contentType).isEqualTo(
                metadata.getContentMetadata().contentType());

            encryptedBlobStore.copyBlob(containerName, blobName,
                containerName, blobName + "-copy", CopyOptions.NONE);

            blob = blobStore.getBlob(containerName,
                blobName + Constants.S3_ENC_SUFFIX);

            try (InputStream blobIs = blob.getPayload().openStream()) {
                var reader = new BufferedReader(new InputStreamReader(blobIs));
                String encrypted = reader.lines().collect(Collectors.joining());
                logger.debug("encrypted {}", encrypted);
                assertThat(content).isNotEqualTo(encrypted);
            }

            blob =
                encryptedBlobStore.getBlob(containerName, blobName + "-copy");

            try (InputStream blobIs = blob.getPayload().openStream()) {
                var reader = new BufferedReader(new InputStreamReader(blobIs));
                String plaintext = reader.lines().collect(Collectors.joining());
                logger.debug("plaintext {}", plaintext);
                assertThat(content).isEqualTo(plaintext);
            }
        }
    }

    @Test
    public void testEncryptMultipartContent() throws Exception {
        String blobName = TestUtils.createRandomBlobName();

        String content1 = "123456789A123456123456789B123456123456789C1234";
        String content2 = "123456789D123456123456789E123456123456789F123456";
        String content3 = "123456789G123456123456789H123456123456789I123";

        String content = content1 + content2 + content3;
        BlobMetadata blobMetadata = makeBlob(blobName,
            content.getBytes(StandardCharsets.UTF_8),
            content.length()).getMetadata();
        MultipartUpload mpu =
            encryptedBlobStore.initiateMultipartUpload(containerName,
                blobMetadata, PutOptions.NONE);

        Payload payload1 = new ByteSourcePayload(ByteSource.wrap(content1.getBytes(StandardCharsets.UTF_8)));
        Payload payload2 = new ByteSourcePayload(ByteSource.wrap(content2.getBytes(StandardCharsets.UTF_8)));
        Payload payload3 = new ByteSourcePayload(ByteSource.wrap(content3.getBytes(StandardCharsets.UTF_8)));

        encryptedBlobStore.uploadMultipartPart(mpu, 1, payload1);
        encryptedBlobStore.uploadMultipartPart(mpu, 2, payload2);
        encryptedBlobStore.uploadMultipartPart(mpu, 3, payload3);

        List<MultipartUpload> mpus =
            encryptedBlobStore.listMultipartUploads(containerName);
        assertThat(mpus.size()).isEqualTo(1);

        List<MultipartPart> parts = encryptedBlobStore.listMultipartUpload(mpu);
        assertThat(mpus.get(0).id()).isEqualTo(mpu.id());

        encryptedBlobStore.completeMultipartUpload(mpu, parts);
        Blob blob = encryptedBlobStore.getBlob(containerName, blobName);

        try (InputStream blobIs = blob.getPayload().openStream()) {
            var reader = new BufferedReader(new InputStreamReader(blobIs));
            String plaintext = reader.lines().collect(Collectors.joining());
            logger.debug("plaintext {}", plaintext);
            assertThat(plaintext).isEqualTo(content);
        }

        blob = blobStore.getBlob(containerName,
            blobName + Constants.S3_ENC_SUFFIX);

        try (InputStream blobIs = blob.getPayload().openStream()) {
            var reader = new BufferedReader(new InputStreamReader(blobIs));
            String encrypted = reader.lines().collect(Collectors.joining());
            logger.debug("encrypted {}", encrypted);
            assertThat(content).isNotEqualTo(encrypted);
        }
    }

    @Test
    public void testReadPartial() throws Exception {

        for (int offset = 0; offset < 60; offset++) {
            logger.debug("Test with offset {}", offset);

            String blobName = TestUtils.createRandomBlobName();
            String content =
                "123456789A123456123456789B123456123456789" +
                    "C123456789D123456789E12345";
            InputStream is = new ByteArrayInputStream(
                content.getBytes(StandardCharsets.UTF_8));

            Blob blob =
                makeBlob(blobName, is, content.length());
            encryptedBlobStore.putBlob(containerName, blob);

            var options = GetOptions.builder().startAt(offset).build();
            blob = encryptedBlobStore.getBlob(containerName, blobName, options);

            try (InputStream blobIs = blob.getPayload().openStream()) {
                var reader = new BufferedReader(new InputStreamReader(blobIs));
                String plaintext = reader.lines().collect(Collectors.joining());
                logger.debug("plaintext {}", plaintext);
                assertThat(plaintext).isEqualTo(content.substring(offset));
            }

            // RFC 7233: bytes=offset- should report bytes offset-(L-1)/L.
            long expectedEndRange = content.length() - 1L;
            assertThat(blob.getContentRange())
                .isEqualTo("bytes " + offset + "-" + expectedEndRange + "/" + content.length());
        }
    }

    @Test
    public void testReadTail() throws Exception {

        for (int length = 1; length < 60; length++) {
            logger.debug("Test with length {}", length);

            String blobName = TestUtils.createRandomBlobName();

            String content =
                "123456789A123456123456789B123456123456789C" +
                    "123456789D123456789E12345";
            InputStream is = new ByteArrayInputStream(
                content.getBytes(StandardCharsets.UTF_8));

            Blob blob =
                makeBlob(blobName, is, content.length());
            encryptedBlobStore.putBlob(containerName, blob);

            var options = GetOptions.builder().tail(length).build();
            blob = encryptedBlobStore.getBlob(containerName, blobName, options);

            try (InputStream blobIs = blob.getPayload().openStream()) {
                var reader = new BufferedReader(new InputStreamReader(blobIs));
                String plaintext = reader.lines().collect(Collectors.joining());
                logger.debug("plaintext {}", plaintext);
                assertThat(plaintext).isEqualTo(
                    content.substring(content.length() - length));
            }

            // RFC 7233: bytes=-N should report the actual byte range, not 0-N.
            long expectedStart = (long) content.length() - length;
            long expectedEnd = content.length() - 1L;
            assertThat(blob.getContentRange())
                .isEqualTo("bytes " + expectedStart + "-" + expectedEnd + "/" + content.length());
        }
    }

    @Test
    public void testReadPartialWithRandomEnd() throws Exception {

        for (int run = 0; run < 100; run++) {
            for (int offset = 0; offset < 50; offset++) {
                var rand = new Random();
                int end = offset + rand.nextInt(20) + 2;
                int size = end - offset + 1;

                logger.debug("Test with offset {} and end {} size {}",
                    offset, end, size);

                String blobName = TestUtils.createRandomBlobName();

                String content =
                    "123456789A123456-123456789B123456-123456789C123456-" +
                        "123456789D123456-123456789E123456";
                InputStream is = new ByteArrayInputStream(
                    content.getBytes(StandardCharsets.UTF_8));

                Blob blob = makeBlob(blobName, is,
                    content.length());
                encryptedBlobStore.putBlob(containerName, blob);

                var options = GetOptions.builder().range(offset, end).build();
                blob = encryptedBlobStore.getBlob(containerName, blobName,
                    options);

                try (InputStream blobIs = blob.getPayload().openStream()) {
                    var reader = new BufferedReader(
                        new InputStreamReader(blobIs));
                    String plaintext = reader.lines().collect(
                        Collectors.joining());
                    logger.debug("plaintext {}", plaintext);
                    assertThat(plaintext).hasSize(size);
                    assertThat(plaintext).isEqualTo(
                        content.substring(offset, end + 1));
                }

                assertThat(blob.getContentRange())
                    .isEqualTo("bytes " + offset + "-" + end + "/" + content.length());
            }
        }
    }

    @Test
    public void testReadOverLengthRange() throws Exception {
        String content =
            "123456789A123456-123456789B123456-123456789C123456-" +
                "123456789D123456-123456789E123456";
        int length = content.length();

        // An explicit range bytes=A-B whose end runs past the object returns
        // only the bytes up to the end; Content-Length and Content-Range must
        // report what is actually sent, not the over-large requested end.
        for (int offset : new int[] {0, 10, 40}) {
            String blobName = TestUtils.createRandomBlobName();
            InputStream is = new ByteArrayInputStream(
                content.getBytes(StandardCharsets.UTF_8));
            Blob blob = makeBlob(blobName, is, length);
            encryptedBlobStore.putBlob(containerName, blob);

            var options = GetOptions.builder()
                .range(offset, length + 1000)
                .build();
            blob = encryptedBlobStore.getBlob(containerName, blobName, options);

            try (InputStream blobIs = blob.getPayload().openStream()) {
                var reader = new BufferedReader(new InputStreamReader(blobIs));
                String plaintext = reader.lines().collect(Collectors.joining());
                assertThat(plaintext).isEqualTo(content.substring(offset));
            }

            assertThat(blob.getMetadata().getContentMetadata()
                .contentLength()).isEqualTo((long) length - offset);
            assertThat(blob.getContentRange())
                .isEqualTo("bytes " + offset + "-" + (length - 1) +
                    "/" + length);
        }
    }

    @Test
    public void testReadOverLengthTail() throws Exception {
        String content =
            "123456789A123456-123456789B123456-123456789C123456-" +
                "123456789D123456-123456789E123456";
        int length = content.length();

        // A suffix range bytes=-N whose N exceeds the object returns the whole
        // object with Content-Range starting at 0, not a negative offset.
        String blobName = TestUtils.createRandomBlobName();
        InputStream is = new ByteArrayInputStream(
            content.getBytes(StandardCharsets.UTF_8));
        Blob blob = makeBlob(blobName, is, length);
        encryptedBlobStore.putBlob(containerName, blob);

        var options = GetOptions.builder()
            .tail(length + 1000)
            .build();
        blob = encryptedBlobStore.getBlob(containerName, blobName, options);

        try (InputStream blobIs = blob.getPayload().openStream()) {
            var reader = new BufferedReader(new InputStreamReader(blobIs));
            String plaintext = reader.lines().collect(Collectors.joining());
            assertThat(plaintext).isEqualTo(content);
        }

        assertThat(blob.getMetadata().getContentMetadata().contentLength())
            .isEqualTo((long) length);
        assertThat(blob.getContentRange())
            .isEqualTo("bytes 0-" + (length - 1) + "/" + length);
    }

    @Test
    public void testMultipartReadPartial() throws Exception {

        for (int offset = 0; offset < 130; offset++) {
            logger.debug("Test with offset {}", offset);

            String blobName = TestUtils.createRandomBlobName();

            String content1 = "PART1-789A123456123456789B123456123456789C1234";
            String content2 =
                "PART2-789D123456123456789E123456123456789F123456";
            String content3 = "PART3-789G123456123456789H123456123456789I123";
            String content = content1 + content2 + content3;

            BlobMetadata blobMetadata = makeBlob(blobName,
                content.getBytes(StandardCharsets.UTF_8),
                content.length()).getMetadata();
            MultipartUpload mpu =
                encryptedBlobStore.initiateMultipartUpload(containerName,
                    blobMetadata, PutOptions.NONE);

            Payload payload1 = new ByteSourcePayload(ByteSource.wrap(content1.getBytes(StandardCharsets.UTF_8)));
            Payload payload2 = new ByteSourcePayload(ByteSource.wrap(content2.getBytes(StandardCharsets.UTF_8)));
            Payload payload3 = new ByteSourcePayload(ByteSource.wrap(content3.getBytes(StandardCharsets.UTF_8)));

            encryptedBlobStore.uploadMultipartPart(mpu, 1, payload1);
            encryptedBlobStore.uploadMultipartPart(mpu, 2, payload2);
            encryptedBlobStore.uploadMultipartPart(mpu, 3, payload3);

            List<MultipartPart> parts =
                encryptedBlobStore.listMultipartUpload(mpu);
            encryptedBlobStore.completeMultipartUpload(mpu, parts);

            var options = GetOptions.builder().startAt(offset).build();
            Blob blob =
                encryptedBlobStore.getBlob(containerName, blobName, options);

            try (InputStream blobIs = blob.getPayload().openStream()) {
                var reader = new BufferedReader(new InputStreamReader(blobIs));
                String plaintext = reader.lines().collect(Collectors.joining());
                logger.debug("plaintext {}", plaintext);
                assertThat(plaintext).isEqualTo(content.substring(offset));
            }
        }
    }

    @Test
    public void testMultipartReadTail() throws Exception {

        for (int length = 1; length < 130; length++) {
            logger.debug("Test with length {}", length);

            String blobName = TestUtils.createRandomBlobName();

            String content1 = "PART1-789A123456123456789B123456123456789C1234";
            String content2 =
                "PART2-789D123456123456789E123456123456789F123456";
            String content3 = "PART3-789G123456123456789H123456123456789I123";
            String content = content1 + content2 + content3;
            BlobMetadata blobMetadata = makeBlob(blobName,
                content.getBytes(StandardCharsets.UTF_8),
                content.length()).getMetadata();
            MultipartUpload mpu =
                encryptedBlobStore.initiateMultipartUpload(containerName,
                    blobMetadata, PutOptions.NONE);

            Payload payload1 = new ByteSourcePayload(ByteSource.wrap(content1.getBytes(StandardCharsets.UTF_8)));
            Payload payload2 = new ByteSourcePayload(ByteSource.wrap(content2.getBytes(StandardCharsets.UTF_8)));
            Payload payload3 = new ByteSourcePayload(ByteSource.wrap(content3.getBytes(StandardCharsets.UTF_8)));

            encryptedBlobStore.uploadMultipartPart(mpu, 1, payload1);
            encryptedBlobStore.uploadMultipartPart(mpu, 2, payload2);
            encryptedBlobStore.uploadMultipartPart(mpu, 3, payload3);

            List<MultipartPart> parts =
                encryptedBlobStore.listMultipartUpload(mpu);
            encryptedBlobStore.completeMultipartUpload(mpu, parts);

            var options = GetOptions.builder().tail(length).build();
            Blob blob =
                encryptedBlobStore.getBlob(containerName, blobName, options);

            try (InputStream blobIs = blob.getPayload().openStream()) {
                var reader = new BufferedReader(new InputStreamReader(blobIs));
                String plaintext = reader.lines().collect(Collectors.joining());
                logger.debug("plaintext {}", plaintext);
                assertThat(plaintext).isEqualTo(
                    content.substring(content.length() - length));
            }
        }
    }

    @Test
    public void testMultipartReadPartialWithRandomEnd() throws Exception {

        for (int run = 0; run < 100; run++) {
            // total len = 139
            for (int offset = 0; offset < 70; offset++) {
                var rand = new Random();
                int end = offset + rand.nextInt(60) + 2;
                int size = end - offset + 1;
                logger.debug("Test with offset {} and end {} size {}",
                    offset, end, size);

                String blobName = TestUtils.createRandomBlobName();

                String content1 =
                    "PART1-789A123456123456789B123456123456789C1234";
                String content2 =
                    "PART2-789D123456123456789E123456123456789F123456";
                String content3 =
                    "PART3-789G123456123456789H123456123456789I123";

                String content = content1 + content2 + content3;
                BlobMetadata blobMetadata =
                    makeBlob(blobName,
                        content.getBytes(StandardCharsets.UTF_8),
                        content.length()).getMetadata();
                MultipartUpload mpu =
                    encryptedBlobStore.initiateMultipartUpload(containerName,
                        blobMetadata, PutOptions.NONE);

                Payload payload1 = new ByteSourcePayload(ByteSource.wrap(content1.getBytes(StandardCharsets.UTF_8)));
                Payload payload2 = new ByteSourcePayload(ByteSource.wrap(content2.getBytes(StandardCharsets.UTF_8)));
                Payload payload3 = new ByteSourcePayload(ByteSource.wrap(content3.getBytes(StandardCharsets.UTF_8)));

                encryptedBlobStore.uploadMultipartPart(mpu, 1, payload1);
                encryptedBlobStore.uploadMultipartPart(mpu, 2, payload2);
                encryptedBlobStore.uploadMultipartPart(mpu, 3, payload3);

                List<MultipartPart> parts =
                    encryptedBlobStore.listMultipartUpload(mpu);
                encryptedBlobStore.completeMultipartUpload(mpu, parts);

                var options = GetOptions.builder().range(offset, end).build();
                Blob blob = encryptedBlobStore.getBlob(containerName, blobName,
                    options);

                try (InputStream blobIs = blob.getPayload().openStream()) {
                    var reader = new BufferedReader(
                        new InputStreamReader(blobIs));
                    String plaintext = reader.lines().collect(
                        Collectors.joining());
                    logger.debug("plaintext {}", plaintext);
                    assertThat(plaintext).isEqualTo(
                        content.substring(offset, end + 1));
                }
            }
        }
    }

    @Test
    public void testReadConditional() {
        String blobName = TestUtils.createRandomBlobName();
        String content = "Hello world.";
        InputStream is = new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8));

        Blob blob = makeBlob(blobName, is, content.length());
        encryptedBlobStore.putBlob(containerName, blob);

        GetOptions options = GetOptions.NONE;
        blob = encryptedBlobStore.getBlob(containerName, blobName, options);
        String etag = blob.getMetadata().getETag();

        GetOptions conditionalOptions = GetOptions.builder()
                .ifETagDoesntMatch(etag).build();
        var e = Assertions.assertThrows(HttpResponseException.class,
            () -> encryptedBlobStore.getBlob(containerName, blobName, conditionalOptions));
        assertThat(e.getResponse().statusCode()).isEqualTo(304);
    }

    @Test
    public void testReadDoubleZeroRange() throws IOException {
        String blobName = TestUtils.createRandomBlobName();
        String content = "Hello world.";
        InputStream is = new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8));

        Blob blob = makeBlob(blobName, is, content.length());
        encryptedBlobStore.putBlob(containerName, blob);

        GetOptions rangeOptions = GetOptions.builder()
                .range(0, 0).build();

        var result = encryptedBlobStore.getBlob(containerName, blobName, rangeOptions);
        assertThat(result.getPayload().openStream().readAllBytes().length).isEqualTo(1);

        assertThat(result.getContentRange())
            .isEqualTo("bytes 0-0/" + content.length());
    }
}
