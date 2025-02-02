/*
 * Copyright 2014-2025 Andrew Gaul <andrew@gaul.org>
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

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
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

import org.gaul.s3proxy.crypto.Constants;
import org.jclouds.ContextBuilder;
import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.BlobStoreContext;
import org.jclouds.blobstore.domain.Blob;
import org.jclouds.blobstore.domain.BlobAccess;
import org.jclouds.blobstore.domain.BlobMetadata;
import org.jclouds.blobstore.domain.MultipartPart;
import org.jclouds.blobstore.domain.MultipartUpload;
import org.jclouds.blobstore.domain.PageSet;
import org.jclouds.blobstore.domain.StorageMetadata;
import org.jclouds.blobstore.domain.StorageType;
import org.jclouds.blobstore.options.CopyOptions;
import org.jclouds.blobstore.options.GetOptions;
import org.jclouds.blobstore.options.ListContainerOptions;
import org.jclouds.blobstore.options.PutOptions;
import org.jclouds.io.Payload;
import org.jclouds.io.Payloads;
import org.jclouds.logging.slf4j.config.SLF4JLoggingModule;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@SuppressWarnings("UnstableApiUsage")
public final class EncryptedBlobStoreTest {
    private static final Logger logger =
        LoggerFactory.getLogger(EncryptedBlobStoreTest.class);

    private BlobStoreContext context;
    private BlobStore blobStore;
    private String containerName;
    private BlobStore encryptedBlobStore;

    private static Blob makeBlob(BlobStore blobStore, String blobName,
        InputStream is, long contentLength) {

        return blobStore.blobBuilder(blobName)
            .payload(is)
            .contentLength(contentLength)
            .build();
    }

    private static Blob makeBlob(BlobStore blobStore, String blobName,
        byte[] payload, long contentLength) {

        return blobStore.blobBuilder(blobName)
            .payload(payload)
            .contentLength(contentLength)
            .build();
    }

    private static Blob makeBlobWithContentType(BlobStore blobStore,
        String blobName,
        long contentLength,
        InputStream is,
        String contentType) {

        return blobStore.blobBuilder(blobName)
            .payload(is)
            .contentLength(contentLength)
            .contentType(contentType)
            .build();
    }

    @Before
    public void setUp() throws Exception {
        String password = "Password1234567!";
        String salt = "12345678";

        containerName = TestUtils.createRandomContainerName();

        //noinspection UnstableApiUsage
        context = ContextBuilder
            .newBuilder("transient")
            .credentials("identity", "credential")
            .modules(List.of(new SLF4JLoggingModule()))
            .build(BlobStoreContext.class);
        blobStore = context.getBlobStore();
        blobStore.createContainerInLocation(null, containerName);

        var properties = new Properties();
        properties.put(S3ProxyConstants.PROPERTY_ENCRYPTED_BLOBSTORE, "true");
        properties.put(S3ProxyConstants.PROPERTY_ENCRYPTED_BLOBSTORE_PASSWORD,
            password);
        properties.put(S3ProxyConstants.PROPERTY_ENCRYPTED_BLOBSTORE_SALT,
            salt);

        encryptedBlobStore =
            EncryptedBlobStore.newEncryptedBlobStore(blobStore, properties);
    }

    @After
    public void tearDown() throws Exception {
        if (context != null) {
            blobStore.deleteContainer(containerName);
            context.close();
        }
    }

    @Test
    public void testBlobNotExists() {

        String blobName = TestUtils.createRandomBlobName();
        Blob blob = encryptedBlobStore.getBlob(containerName, blobName);
        assertThat(blob).isNull();

        blob = encryptedBlobStore.getBlob(containerName, blobName,
            new GetOptions());
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
            Blob blob = makeBlob(blobStore, blobName, is, content.length());
            blobStore.putBlob(containerName, blob);
            blob = encryptedBlobStore.getBlob(containerName, blobName);

            InputStream blobIs = blob.getPayload().openStream();
            var r = new InputStreamReader(blobIs);
            var reader = new BufferedReader(r);
            String plaintext = reader.lines().collect(Collectors.joining());
            logger.debug("plaintext {}", plaintext);

            assertThat(content).isEqualTo(plaintext);

            var options = new GetOptions();
            blob = encryptedBlobStore.getBlob(containerName, blobName, options);

            blobIs = blob.getPayload().openStream();
            r = new InputStreamReader(blobIs);
            reader = new BufferedReader(r);
            plaintext = reader.lines().collect(Collectors.joining());
            logger.debug("plaintext {} with empty options ", plaintext);

            assertThat(content).isEqualTo(plaintext);
        }

        PageSet<? extends StorageMetadata> blobs =
            encryptedBlobStore.list(containerName, new ListContainerOptions());
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
                makeBlob(encryptedBlobStore, blobName, is, content.length());
            encryptedBlobStore.putBlob(containerName, blob);
        }

        PageSet<? extends StorageMetadata> blobs =
            encryptedBlobStore.list(containerName);
        for (StorageMetadata blob : blobs) {
            assertThat(blob.getSize()).isEqualTo(
                contentLengths.get(blob.getName()));
        }

        blobs =
            encryptedBlobStore.list(containerName, new ListContainerOptions());
        for (StorageMetadata blob : blobs) {
            assertThat(blob.getSize()).isEqualTo(
                contentLengths.get(blob.getName()));
            encryptedBlobStore.removeBlob(containerName, blob.getName());
        }

        blobs =
            encryptedBlobStore.list(containerName, new ListContainerOptions());
        assertThat(blobs.size()).isEqualTo(0);
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
        BlobMetadata blobMetadata = makeBlob(encryptedBlobStore, blobName,
            content.getBytes(StandardCharsets.UTF_8),
            content.length()).getMetadata();

        MultipartUpload mpu =
            encryptedBlobStore.initiateMultipartUpload(containerName,
                blobMetadata, new PutOptions());

        Payload payload1 = Payloads.newByteArrayPayload(
            contentParts[0].getBytes(StandardCharsets.UTF_8));
        Payload payload2 = Payloads.newByteArrayPayload(
            contentParts[1].getBytes(StandardCharsets.UTF_8));
        Payload payload3 = Payloads.newByteArrayPayload(
            contentParts[2].getBytes(StandardCharsets.UTF_8));

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

        var options = new ListContainerOptions();
        blobs = encryptedBlobStore.list(containerName, options.withDetails());
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
                Blob blob = makeBlob(blobStore, blobName, is, content.length());
                blobStore.putBlob(containerName, blob);

                var options = new GetOptions();
                int offset = rand.nextInt(content.length() - 1);
                logger.debug("content {} with offset {}", content, offset);

                options.startAt(offset);
                blob = encryptedBlobStore.getBlob(containerName, blobName,
                    options);

                InputStream blobIs = blob.getPayload().openStream();
                var r = new InputStreamReader(blobIs);
                var reader = new BufferedReader(r);
                String plaintext = reader.lines().collect(Collectors.joining());
                logger.debug("plaintext {} with offset {}", plaintext, offset);

                assertThat(plaintext).isEqualTo(content.substring(offset));

                options = new GetOptions();
                int tail = rand.nextInt(content.length());
                if (tail == 0) {
                    tail++;
                }
                logger.debug("content {} with tail {}", content, tail);

                options.tail(tail);
                blob = encryptedBlobStore.getBlob(containerName, blobName,
                    options);

                blobIs = blob.getPayload().openStream();
                r = new InputStreamReader(blobIs);
                reader = new BufferedReader(r);
                plaintext = reader.lines().collect(Collectors.joining());
                logger.debug("plaintext {} with tail {}", plaintext, tail);

                assertThat(plaintext).isEqualTo(
                    content.substring(content.length() - tail));

                options = new GetOptions();
                offset = 1;
                int end = content.length() - 2;
                logger.debug("content {} with range {}-{}", content, offset,
                    end);

                options.range(offset, end);
                blob = encryptedBlobStore.getBlob(containerName, blobName,
                    options);

                blobIs = blob.getPayload().openStream();
                r = new InputStreamReader(blobIs);
                reader = new BufferedReader(r);
                plaintext = reader.lines().collect(Collectors.joining());
                logger.debug("plaintext {} with range {}-{}", plaintext, offset,
                    end);

                assertThat(plaintext).isEqualTo(
                    content.substring(offset, end + 1));
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
            Blob blob = makeBlobWithContentType(encryptedBlobStore, blobName,
                content.length(), is, contentType);
            encryptedBlobStore.putBlob(containerName, blob);

            blob = encryptedBlobStore.getBlob(containerName, blobName);

            InputStream blobIs = blob.getPayload().openStream();
            var r = new InputStreamReader(blobIs);
            var reader = new BufferedReader(r);
            String plaintext = reader.lines().collect(Collectors.joining());
            logger.debug("plaintext {}", plaintext);

            assertThat(plaintext).isEqualTo(content);

            blob = blobStore.getBlob(containerName,
                blobName + Constants.S3_ENC_SUFFIX);
            blobIs = blob.getPayload().openStream();
            r = new InputStreamReader(blobIs);
            reader = new BufferedReader(r);
            String encrypted = reader.lines().collect(Collectors.joining());
            logger.debug("encrypted {}", encrypted);

            assertThat(content).isNotEqualTo(encrypted);

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
            Blob blob = makeBlobWithContentType(encryptedBlobStore, blobName,
                content.length(), is, contentType);
            var options = new PutOptions();
            encryptedBlobStore.putBlob(containerName, blob, options);

            blob = encryptedBlobStore.getBlob(containerName, blobName);

            InputStream blobIs = blob.getPayload().openStream();
            var r = new InputStreamReader(blobIs);
            var reader = new BufferedReader(r);
            String plaintext = reader.lines().collect(Collectors.joining());
            logger.debug("plaintext {}", plaintext);

            assertThat(content).isEqualTo(plaintext);

            blob = blobStore.getBlob(containerName,
                blobName + Constants.S3_ENC_SUFFIX);
            blobIs = blob.getPayload().openStream();
            r = new InputStreamReader(blobIs);
            reader = new BufferedReader(r);
            String encrypted = reader.lines().collect(Collectors.joining());
            logger.debug("encrypted {}", encrypted);

            assertThat(content).isNotEqualTo(encrypted);

            BlobMetadata metadata =
                encryptedBlobStore.blobMetadata(containerName,
                    blobName + Constants.S3_ENC_SUFFIX);
            assertThat(contentType).isEqualTo(
                metadata.getContentMetadata().getContentType());

            encryptedBlobStore.copyBlob(containerName, blobName,
                containerName, blobName + "-copy", CopyOptions.NONE);

            blob = blobStore.getBlob(containerName,
                blobName + Constants.S3_ENC_SUFFIX);
            blobIs = blob.getPayload().openStream();
            r = new InputStreamReader(blobIs);
            reader = new BufferedReader(r);
            encrypted = reader.lines().collect(Collectors.joining());
            logger.debug("encrypted {}", encrypted);

            assertThat(content).isNotEqualTo(encrypted);

            blob =
                encryptedBlobStore.getBlob(containerName, blobName + "-copy");
            blobIs = blob.getPayload().openStream();
            r = new InputStreamReader(blobIs);
            reader = new BufferedReader(r);
            plaintext = reader.lines().collect(Collectors.joining());
            logger.debug("plaintext {}", plaintext);

            assertThat(content).isEqualTo(plaintext);
        }
    }

    @Test
    public void testEncryptMultipartContent() throws Exception {
        String blobName = TestUtils.createRandomBlobName();

        String content1 = "123456789A123456123456789B123456123456789C1234";
        String content2 = "123456789D123456123456789E123456123456789F123456";
        String content3 = "123456789G123456123456789H123456123456789I123";

        String content = content1 + content2 + content3;
        BlobMetadata blobMetadata = makeBlob(encryptedBlobStore, blobName,
            content.getBytes(StandardCharsets.UTF_8),
            content.length()).getMetadata();
        MultipartUpload mpu =
            encryptedBlobStore.initiateMultipartUpload(containerName,
                blobMetadata, new PutOptions());

        Payload payload1 = Payloads.newByteArrayPayload(
            content1.getBytes(StandardCharsets.UTF_8));
        Payload payload2 = Payloads.newByteArrayPayload(
            content2.getBytes(StandardCharsets.UTF_8));
        Payload payload3 = Payloads.newByteArrayPayload(
            content3.getBytes(StandardCharsets.UTF_8));

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

        InputStream blobIs = blob.getPayload().openStream();
        var r = new InputStreamReader(blobIs);
        var reader = new BufferedReader(r);
        String plaintext = reader.lines().collect(Collectors.joining());
        logger.debug("plaintext {}", plaintext);
        assertThat(plaintext).isEqualTo(content);

        blob = blobStore.getBlob(containerName,
            blobName + Constants.S3_ENC_SUFFIX);
        blobIs = blob.getPayload().openStream();
        r = new InputStreamReader(blobIs);
        reader = new BufferedReader(r);
        String encrypted = reader.lines().collect(Collectors.joining());
        logger.debug("encrypted {}", encrypted);

        assertThat(content).isNotEqualTo(encrypted);
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
                makeBlob(encryptedBlobStore, blobName, is, content.length());
            encryptedBlobStore.putBlob(containerName, blob);

            var options = new GetOptions();
            options.startAt(offset);
            blob = encryptedBlobStore.getBlob(containerName, blobName, options);

            InputStream blobIs = blob.getPayload().openStream();
            var r = new InputStreamReader(blobIs);
            var reader = new BufferedReader(r);
            String plaintext = reader.lines().collect(Collectors.joining());
            logger.debug("plaintext {}", plaintext);

            assertThat(plaintext).isEqualTo(content.substring(offset));
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
                makeBlob(encryptedBlobStore, blobName, is, content.length());
            encryptedBlobStore.putBlob(containerName, blob);

            var options = new GetOptions();
            options.tail(length);
            blob = encryptedBlobStore.getBlob(containerName, blobName, options);

            InputStream blobIs = blob.getPayload().openStream();
            var r = new InputStreamReader(blobIs);
            var reader = new BufferedReader(r);
            String plaintext = reader.lines().collect(Collectors.joining());
            logger.debug("plaintext {}", plaintext);

            assertThat(plaintext).isEqualTo(
                content.substring(content.length() - length));
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

                Blob blob = makeBlob(encryptedBlobStore, blobName, is,
                    content.length());
                encryptedBlobStore.putBlob(containerName, blob);

                var options = new GetOptions();
                options.range(offset, end);
                blob = encryptedBlobStore.getBlob(containerName, blobName,
                    options);

                InputStream blobIs = blob.getPayload().openStream();
                var r = new InputStreamReader(blobIs);
                var reader = new BufferedReader(r);
                String plaintext = reader.lines().collect(Collectors.joining());
                logger.debug("plaintext {}", plaintext);

                assertThat(plaintext).hasSize(size);
                assertThat(plaintext).isEqualTo(
                    content.substring(offset, end + 1));
            }
        }
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

            BlobMetadata blobMetadata = makeBlob(encryptedBlobStore, blobName,
                content.getBytes(StandardCharsets.UTF_8),
                content.length()).getMetadata();
            MultipartUpload mpu =
                encryptedBlobStore.initiateMultipartUpload(containerName,
                    blobMetadata, new PutOptions());

            Payload payload1 = Payloads.newByteArrayPayload(
                content1.getBytes(StandardCharsets.UTF_8));
            Payload payload2 = Payloads.newByteArrayPayload(
                content2.getBytes(StandardCharsets.UTF_8));
            Payload payload3 = Payloads.newByteArrayPayload(
                content3.getBytes(StandardCharsets.UTF_8));

            encryptedBlobStore.uploadMultipartPart(mpu, 1, payload1);
            encryptedBlobStore.uploadMultipartPart(mpu, 2, payload2);
            encryptedBlobStore.uploadMultipartPart(mpu, 3, payload3);

            List<MultipartPart> parts =
                encryptedBlobStore.listMultipartUpload(mpu);
            encryptedBlobStore.completeMultipartUpload(mpu, parts);

            var options = new GetOptions();
            options.startAt(offset);
            Blob blob =
                encryptedBlobStore.getBlob(containerName, blobName, options);

            InputStream blobIs = blob.getPayload().openStream();
            var r = new InputStreamReader(blobIs);
            var reader = new BufferedReader(r);
            String plaintext = reader.lines().collect(Collectors.joining());
            logger.debug("plaintext {}", plaintext);

            assertThat(plaintext).isEqualTo(content.substring(offset));
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
            BlobMetadata blobMetadata = makeBlob(encryptedBlobStore, blobName,
                content.getBytes(StandardCharsets.UTF_8),
                content.length()).getMetadata();
            MultipartUpload mpu =
                encryptedBlobStore.initiateMultipartUpload(containerName,
                    blobMetadata, new PutOptions());

            Payload payload1 = Payloads.newByteArrayPayload(
                content1.getBytes(StandardCharsets.UTF_8));
            Payload payload2 = Payloads.newByteArrayPayload(
                content2.getBytes(StandardCharsets.UTF_8));
            Payload payload3 = Payloads.newByteArrayPayload(
                content3.getBytes(StandardCharsets.UTF_8));

            encryptedBlobStore.uploadMultipartPart(mpu, 1, payload1);
            encryptedBlobStore.uploadMultipartPart(mpu, 2, payload2);
            encryptedBlobStore.uploadMultipartPart(mpu, 3, payload3);

            List<MultipartPart> parts =
                encryptedBlobStore.listMultipartUpload(mpu);
            encryptedBlobStore.completeMultipartUpload(mpu, parts);

            var options = new GetOptions();
            options.tail(length);
            Blob blob =
                encryptedBlobStore.getBlob(containerName, blobName, options);

            InputStream blobIs = blob.getPayload().openStream();
            var r = new InputStreamReader(blobIs);
            var reader = new BufferedReader(r);
            String plaintext = reader.lines().collect(Collectors.joining());
            logger.debug("plaintext {}", plaintext);

            assertThat(plaintext).isEqualTo(
                content.substring(content.length() - length));
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
                    makeBlob(encryptedBlobStore, blobName,
                        content.getBytes(StandardCharsets.UTF_8),
                        content.length()).getMetadata();
                MultipartUpload mpu =
                    encryptedBlobStore.initiateMultipartUpload(containerName,
                        blobMetadata, new PutOptions());

                Payload payload1 = Payloads.newByteArrayPayload(
                    content1.getBytes(StandardCharsets.UTF_8));
                Payload payload2 = Payloads.newByteArrayPayload(
                    content2.getBytes(StandardCharsets.UTF_8));
                Payload payload3 = Payloads.newByteArrayPayload(
                    content3.getBytes(StandardCharsets.UTF_8));

                encryptedBlobStore.uploadMultipartPart(mpu, 1, payload1);
                encryptedBlobStore.uploadMultipartPart(mpu, 2, payload2);
                encryptedBlobStore.uploadMultipartPart(mpu, 3, payload3);

                List<MultipartPart> parts =
                    encryptedBlobStore.listMultipartUpload(mpu);
                encryptedBlobStore.completeMultipartUpload(mpu, parts);

                var options = new GetOptions();
                options.range(offset, end);
                Blob blob = encryptedBlobStore.getBlob(containerName, blobName,
                    options);

                InputStream blobIs = blob.getPayload().openStream();
                var r = new InputStreamReader(blobIs);
                var reader = new BufferedReader(r);
                String plaintext = reader.lines().collect(Collectors.joining());
                logger.debug("plaintext {}", plaintext);

                assertThat(plaintext).isEqualTo(
                    content.substring(offset, end + 1));
            }
        }
    }
}
