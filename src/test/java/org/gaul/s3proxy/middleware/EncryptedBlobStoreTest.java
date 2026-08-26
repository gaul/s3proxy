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
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Random;
import java.util.TreeSet;
import java.util.stream.Collectors;
import java.util.zip.CRC32;

import org.gaul.s3proxy.Quirks;
import org.gaul.s3proxy.S3ProxyConstants;
import org.gaul.s3proxy.TestUtils;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.ForwardingBlobStore;
import org.gaul.s3proxy.blobstore.SdkRequests;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.gaul.s3proxy.crypto.Constants;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.services.s3.model.CopyObjectRequest;
import software.amazon.awssdk.services.s3.model.Delete;
import software.amazon.awssdk.services.s3.model.DeleteObjectsRequest;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.s3.model.ObjectCannedACL;
import software.amazon.awssdk.services.s3.model.ObjectIdentifier;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.awssdk.services.s3.model.S3Object;
import software.amazon.awssdk.services.s3.model.UploadPartRequest;
import software.amazon.awssdk.services.s3.model.UploadPartResponse;

@SuppressWarnings("UnstableApiUsage")
@Execution(ExecutionMode.SAME_THREAD)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public final class EncryptedBlobStoreTest {
    private static final Logger logger =
        LoggerFactory.getLogger(EncryptedBlobStoreTest.class);
    /** The last part of an upload, which every backend lets be short. */
    private static final int LAST_PART_SIZE = 45;
    /**
     * Below this an object is swept offset by offset; above it only the
     * places the arithmetic turns are read.
     */
    private static final int SWEEPABLE_SIZE = 256;

    private BlobStore blobStore;
    private String containerName;
    private String provider;
    private BlobStore encryptedBlobStore;
    private Properties encryptionProperties;
    /**
     * What a part must weigh for the backend to take it anywhere but last.
     * S3 refuses one under 5 MB there; the stores that keep their own
     * multipart bookkeeping take any size, so the tests stay small and
     * quick wherever the backend lets them.
     */
    private int partSize;

    /** Bytes whose value names the offset they sit at. */
    private static byte[] filler(int offset, int length) {
        var bytes = new byte[length];
        for (int i = 0; i < length; ++i) {
            bytes[i] = (byte) ('a' + ((offset + i) % 26));
        }
        return bytes;
    }

    /** A multipart blob and the plaintext it was assembled from. */
    private static final class Multipart {
        private final String blobName;
        private final byte[] content;

        Multipart(String blobName, byte[] content) {
            this.blobName = blobName;
            this.content = content;
        }
    }

    private static GetObjectRequest rangeRequest(String container,
        String blobName, String range) {

        return GetObjectRequest.builder()
            .bucket(container)
            .key(blobName)
            .range(range)
            .build();
    }

    private static PutObjectRequest makeRequest(String containerName,
        String blobName, long contentLength) {

        return PutObjectRequest.builder()
            .bucket(containerName)
            .key(blobName)
            .contentLength(contentLength)
            .build();
    }

    /** Uploads a three part multipart blob and answers what it holds. */
    private Multipart uploadMultipartContent() {
        String blobName = TestUtils.createRandomBlobName();
        MultipartUpload mpu = encryptedBlobStore.initiateMultipartUpload(
            TestUtils.createRequest(containerName, blobName));

        var content = new ByteArrayOutputStream();
        int partNumber = 1;
        for (int size : new int[] {partSize, partSize, LAST_PART_SIZE}) {
            byte[] bytes = filler(content.size(), size);
            content.writeBytes(bytes);
            TestUtils.uploadPart(encryptedBlobStore, mpu, partNumber++,
                new ByteArrayInputStream(bytes), bytes.length);
        }

        encryptedBlobStore.completeMultipartUpload(mpu,
            TestUtils.completeRequest(mpu,
                encryptedBlobStore.listMultipartUpload(mpu)));
        return new Multipart(blobName, content.toByteArray());
    }

    /**
     * The offsets a ranged read is worth trying from.  A small object is
     * swept, since every offset is cheap and each one exercises a different
     * alignment; a large one is read where the arithmetic turns -- the two
     * ends and either side of a part boundary -- because a backend that
     * demands 5 MB parts makes the sweep unaffordable without making it any
     * more revealing.
     */
    private int[] readOffsets(int length) {
        var offsets = new TreeSet<Integer>();
        if (length <= SWEEPABLE_SIZE) {
            for (int offset = 0; offset < length; ++offset) {
                offsets.add(offset);
            }
        } else {
            int[] boundaries = {0, partSize, 2 * partSize, length};
            for (int boundary : boundaries) {
                for (int delta : new int[] {-17, -16, -1, 0, 1, 16, 17}) {
                    int offset = boundary + delta;
                    if (offset >= 0 && offset < length) {
                        offsets.add(offset);
                    }
                }
            }
        }
        return offsets.stream().mapToInt(Integer::intValue).toArray();
    }

    @BeforeAll
    public void setUpBlobStore() throws Exception {
        String password = "Password1234567!";
        String salt = "12345678";

        //noinspection UnstableApiUsage
        blobStore = TestUtils.createTestBlobStore();
        provider = TestUtils.testBlobStoreProvider();
        // The encrypted layer recovers decrypted sizes from user metadata or
        // stored ETag suffixes, neither of which sftp persists.
        assumeTrue(!Quirks.NO_PERSISTED_METADATA.contains(provider));
        partSize = (int) Math.max(blobStore.getMinimumMultipartPartSize(),
            LAST_PART_SIZE + 1);

        var properties = new Properties();
        properties.put(S3ProxyConstants.PROPERTY_ENCRYPTED_BLOBSTORE, "true");
        properties.put(S3ProxyConstants.PROPERTY_ENCRYPTED_BLOBSTORE_PASSWORD,
            password);
        properties.put(S3ProxyConstants.PROPERTY_ENCRYPTED_BLOBSTORE_SALT,
            salt);

        encryptionProperties = properties;
        encryptedBlobStore =
            EncryptedBlobStore.newEncryptedBlobStore(blobStore, properties);
    }

    @AfterAll
    public void tearDownBlobStore() throws Exception {
        if (blobStore != null) {
            blobStore.close();
        }
    }

    @BeforeEach
    public void setUp() throws Exception {
        containerName = TestUtils.createRandomContainerName();
        blobStore.createContainer(containerName);
    }

    @AfterEach
    public void tearDown() throws Exception {
        blobStore.deleteContainer(containerName);
    }

    /**
     * The checksum a caller asserts describes the plaintext, and the store
     * below is handed ciphertext.  A store that judges checksums would
     * refuse a write that is perfectly good, so neither an object nor a
     * part may carry one down -- the same reason the Content-MD5 is
     * dropped here.
     */
    @Test
    public void testEncryptedWriteDropsTheChecksum() throws Exception {

        var writes = new ArrayList<PutObjectRequest>();
        var parts = new ArrayList<UploadPartRequest>();
        BlobStore capturing = new ForwardingBlobStore(blobStore) {
            @Override
            public PutObjectResponse putBlob(PutObjectRequest request,
                InputStream payload) {

                writes.add(request);
                return super.putBlob(request, payload);
            }

            @Override
            public UploadPartResponse uploadMultipartPart(MultipartUpload mpu,
                UploadPartRequest request, InputStream is) {

                parts.add(request);
                return super.uploadMultipartPart(mpu, request, is);
            }
        };
        BlobStore encrypted = EncryptedBlobStore.newEncryptedBlobStore(
            capturing, encryptionProperties);

        byte[] content = filler(0, LAST_PART_SIZE);
        var crc32 = new CRC32();
        crc32.update(content);
        String checksum = Base64.getEncoder().encodeToString(
            ByteBuffer.allocate(4).putInt((int) crc32.getValue()).array());

        encrypted.putBlob(PutObjectRequest.builder()
                .bucket(containerName)
                .key(TestUtils.createRandomBlobName())
                .contentLength((long) content.length)
                .checksumCRC32(checksum)
                .build(),
            new ByteArrayInputStream(content));
        assertThat(writes).hasSize(1);
        assertThat(writes.get(0).checksumCRC32()).isNull();

        MultipartUpload mpu = encrypted.initiateMultipartUpload(
            TestUtils.createRequest(containerName,
                TestUtils.createRandomBlobName()));
        encrypted.uploadMultipartPart(mpu, UploadPartRequest.builder()
                .bucket(mpu.containerName())
                .key(mpu.blobName())
                .uploadId(mpu.id())
                .partNumber(1)
                .contentLength((long) content.length)
                .checksumCRC32(checksum)
                .build(),
            new ByteArrayInputStream(content));
        assertThat(parts).hasSize(1);
        assertThat(parts.get(0).checksumCRC32()).isNull();
        encrypted.abortMultipartUpload(mpu);
    }

    /**
     * An encrypted multipart object records each part's IV in a padding
     * block written after that part, so reading one means walking the
     * paddings backwards from the end of the object, a backend read apiece.
     * A client downloading a large object asks for it in ranged chunks, and
     * walking every part again for each chunk costs a round trip per part
     * per chunk -- minutes against a remote backend for an object of a few
     * hundred parts, which is what stalled #960.  The walk belongs to the
     * object, not to the request.
     */
    @Test
    public void testMultipartReadWalksThePartPaddingsOnce() throws Exception {
        int parts = 4;
        var reads = new java.util.concurrent.atomic.AtomicInteger();
        BlobStore counting = new ForwardingBlobStore(blobStore) {
            @Override
            public ResponseInputStream<GetObjectResponse> getBlob(
                GetObjectRequest request) {

                reads.incrementAndGet();
                return super.getBlob(request);
            }
        };
        BlobStore encrypted = EncryptedBlobStore.newEncryptedBlobStore(
            counting, encryptionProperties);

        String blobName = TestUtils.createRandomBlobName();
        MultipartUpload mpu = encrypted.initiateMultipartUpload(
            TestUtils.createRequest(containerName, blobName));
        var expected = new ByteArrayOutputStream();
        for (int i = 1; i <= parts; ++i) {
            byte[] bytes = filler(expected.size(),
                i == parts ? LAST_PART_SIZE : partSize);
            expected.writeBytes(bytes);
            TestUtils.uploadPart(encrypted, mpu, i,
                new ByteArrayInputStream(bytes), bytes.length);
        }
        encrypted.completeMultipartUpload(mpu, TestUtils.completeRequest(mpu,
            encrypted.listMultipartUpload(mpu)));

        try (var is = encrypted.getBlob(GetObjectRequest.builder()
                .bucket(containerName)
                .key(blobName)
                .build())) {
            assertThat(is.readAllBytes()).isEqualTo(expected.toByteArray());
        }

        // A byte apiece is enough to count by: the walk happens before any
        // of the object is read, so what it costs does not depend on how
        // much the request asked for.
        int chunks = 6;
        reads.set(0);
        for (int i = 0; i < chunks; ++i) {
            try (var is = encrypted.getBlob(rangeRequest(
                    containerName, blobName, "bytes=0-0"))) {
                assertThat(is.readAllBytes()).isEqualTo(
                    new byte[] {expected.toByteArray()[0]});
            }
        }

        // One walk of the paddings, then a single read of the data per
        // request.  Before the walk was remembered this was parts + 1 reads
        // every time, growing with the object rather than with the download.
        assertThat(reads.get()).isLessThanOrEqualTo(parts + chunks);

        // An object replaced under the same name is a different object, and
        // the paddings remembered for the first would decrypt it to rubbish.
        MultipartUpload replacement = encrypted.initiateMultipartUpload(
            TestUtils.createRequest(containerName, blobName));
        // One part, and a different length, so nothing about the walk
        // remembered for the first object would fit this one.
        byte[] replaced = filler(0, LAST_PART_SIZE + 7);
        TestUtils.uploadPart(encrypted, replacement, 1,
            new ByteArrayInputStream(replaced), replaced.length);
        encrypted.completeMultipartUpload(replacement, TestUtils.completeRequest(
            replacement, encrypted.listMultipartUpload(replacement)));

        try (var is = encrypted.getBlob(GetObjectRequest.builder()
                .bucket(containerName)
                .key(blobName)
                .build())) {
            assertThat(is.readAllBytes()).isEqualTo(replaced);
        }
    }

    @Test
    public void testBlobNotExists() {

        String blobName = TestUtils.createRandomBlobName();
        // neither the encrypted name nor the plaintext one is there, and
        // the wrapper answers that the way any read of an absent object does
        assertThatThrownBy(() -> encryptedBlobStore.getBlob(containerName,
                blobName)).isInstanceOf(NoSuchKeyException.class);
        assertThatThrownBy(() -> encryptedBlobStore.blobMetadata(containerName,
                blobName)).isInstanceOf(NoSuchKeyException.class);
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
            blobStore.putBlob(
                    makeRequest(containerName, blobName, content.length()),
                    is);
            var blob = encryptedBlobStore.getBlob(containerName, blobName);

            try (InputStream blobIs = blob) {
                var reader = new BufferedReader(new InputStreamReader(blobIs));
                String plaintext = reader.lines().collect(Collectors.joining());
                logger.debug("plaintext {}", plaintext);
                assertThat(content).isEqualTo(plaintext);
            }

            var got = encryptedBlobStore.getBlob(containerName, blobName);

            try (InputStream blobIs = got) {
                var reader = new BufferedReader(new InputStreamReader(blobIs));
                String plaintext = reader.lines().collect(Collectors.joining());
                logger.debug("plaintext {} with empty options ", plaintext);
                assertThat(content).isEqualTo(plaintext);
            }
        }

        var blobs = encryptedBlobStore.list(containerName);
        for (S3Object blob : blobs.contents()) {
            assertThat(blob.size()).isEqualTo(
                contentLengths.get(blob.key()));
        }

        assertThat(encryptedBlobStore.list().buckets()).isNotEmpty();
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
            encryptedBlobStore.putBlob(
                makeRequest(containerName, blobName, content.length()), is);
        }

        var blobs = encryptedBlobStore.list(containerName);
        for (S3Object blob : blobs.contents()) {
            assertThat(blob.size()).isEqualTo(
                contentLengths.get(blob.key()));
        }

        blobs =
            encryptedBlobStore.list(containerName);
        for (S3Object blob : blobs.contents()) {
            assertThat(blob.size()).isEqualTo(
                contentLengths.get(blob.key()));
            encryptedBlobStore.removeBlob(containerName, blob.key());
        }

        blobs =
            encryptedBlobStore.list(containerName);
        assertThat(blobs.contents()).isEmpty();
    }

    @Test
    public void testListEncryptedPagination() {
        var expected = new java.util.TreeMap<String, Long>();
        for (int i = 0; i < 5; i++) {
            String blobName = "blob-" + i;
            byte[] content = new byte[10 + i];
            java.util.Arrays.fill(content, (byte) 'c');
            expected.put(blobName, (long) content.length);
            encryptedBlobStore.putBlob(
                makeRequest(containerName, blobName, content.length),
                new ByteArrayInputStream(content));
        }

        // Page one blob at a time: the marker must advance so every blob is
        // returned exactly once, with its unencrypted size.
        var seen = new java.util.LinkedHashMap<String, Long>();
        String marker = null;
        for (int i = 0; i < expected.size() * 3; i++) {
            var page = encryptedBlobStore.list(ListObjectsV2Request.builder()
                .bucket(containerName)
                .maxKeys(1)
                .continuationToken(marker)
                .build());
            for (S3Object sm : page.contents()) {
                assertThat(seen).doesNotContainKey(sm.key());
                seen.put(sm.key(), sm.size());
            }
            marker = page.nextContinuationToken();
            if (marker == null) {
                break;
            }
        }

        assertThat(seen).isEqualTo(expected);
    }

    @Test
    public void testEncryptedEmptyBlob() throws Exception {
        String blobName = TestUtils.createRandomBlobName();
        encryptedBlobStore.putBlob(makeRequest(containerName, blobName, 0),
            new ByteArrayInputStream(new byte[0]));

        // An empty object is stored as a single 64-byte padding block.  HEAD
        // and the list view report zero; GET must also return zero bytes
        // rather than exposing the padding block.
        var metadata = encryptedBlobStore.blobMetadata(
            containerName, blobName);
        assertThat(metadata.contentLength()).isEqualTo(0L);

        var got = encryptedBlobStore.getBlob(containerName, blobName);
        try (InputStream is = got) {
            assertThat(is.readAllBytes()).isEmpty();
        }
        assertThat(got.response().contentLength())
            .isEqualTo(0L);

        var blobs = encryptedBlobStore.list(containerName);
        assertThat(blobs.contents().get(0).size()).isEqualTo(0L);
    }

    @Test
    public void testListEncryptedMultipart() {

        String blobName = TestUtils.createRandomBlobName();

        int[] partSizes = {partSize, partSize, LAST_PART_SIZE};
        long total = 0;
        MultipartUpload mpu = encryptedBlobStore.initiateMultipartUpload(
            TestUtils.createRequest(containerName, blobName));

        int partNumber = 1;
        for (int size : partSizes) {
            byte[] bytes = filler((int) total, size);
            total += size;
            TestUtils.uploadPart(encryptedBlobStore, mpu, partNumber++,
                new ByteArrayInputStream(bytes), bytes.length);
        }

        var parts = encryptedBlobStore.listMultipartUpload(mpu);

        int index = 0;
        for (var part : parts) {
            assertThat((long) partSizes[index]).isEqualTo(part.size());
            index++;
        }

        encryptedBlobStore.completeMultipartUpload(mpu,
            TestUtils.completeRequest(mpu, parts));

        var blobs = encryptedBlobStore.list(containerName);
        S3Object metadata = blobs.contents().get(0);
        assertThat(total).isEqualTo(metadata.size());

        assertThat(encryptedBlobStore.list().buckets()).isNotEmpty();

        // The batch delete reaches the encrypted name through the wrapper's
        // own single delete, which is what carries the suffix.
        encryptedBlobStore.removeBlobs(DeleteObjectsRequest.builder()
                .bucket(containerName)
                .delete(Delete.builder()
                        .objects(ObjectIdentifier.builder()
                                .key(blobName)
                                .build())
                        .build())
                .build());
        blobs = encryptedBlobStore.list(containerName);
        assertThat(blobs.contents()).isEmpty();
    }

    @Test
    public void testEncryptionMultipartUploadAbort() throws Exception {
        String blobName = TestUtils.createRandomBlobName();
        var content = "0123456789ABCDEF0123456789ABCDEF";
        MultipartUpload mpu = encryptedBlobStore.initiateMultipartUpload(
            TestUtils.createRequest(containerName, blobName));
        byte[] bytes = content.getBytes(StandardCharsets.UTF_8);
        var uploaded = TestUtils.uploadPart(encryptedBlobStore, mpu, 1,
            new ByteArrayInputStream(bytes), bytes.length);
        var completeRequest = SdkRequests.completeRequest(mpu,
            List.of(TestUtils.completedPart(1, uploaded)));

        encryptedBlobStore.abortMultipartUpload(mpu);

        // The abort removed the in-progress upload: nothing was committed and
        // no encrypted (.s3enc) backend blob was left behind, on either the
        // wrapper or the underlying delegate.
        assertThat(encryptedBlobStore.list(containerName).contents()).isEmpty();
        assertThat(blobStore.list(containerName).contents()).isEmpty();

        // The upload no longer exists, so completing it now fails rather than
        // resurrecting the object from a dangling upload.
        assertThatThrownBy(() ->
            encryptedBlobStore.completeMultipartUpload(mpu, completeRequest))
            .isInstanceOf(RuntimeException.class);
    }

    @Test
    public void testBlobNotEncryptedRanges() throws Exception {

        var tests = new String[] {
            "123456789A12345", // lower then the AES block
            "123456789A1234567", // one byte bigger then the AES block
            "123456789A123456123456789B123456123456789C" +
                "1234123456789A123456123456789B123456123456789C1234"
        };

        var blobNames = new HashMap<String, String>();
        for (String content : tests) {
            String blobName = TestUtils.createRandomBlobName();
            InputStream is = new ByteArrayInputStream(
                content.getBytes(StandardCharsets.UTF_8));
            blobStore.putBlob(
                makeRequest(containerName, blobName, content.length()), is);
            blobNames.put(content, blobName);
        }

        var rand = new Random();
        for (int run = 0; run < 20; run++) {
            for (String content : tests) {
                String blobName = blobNames.get(content);

                int offset = rand.nextInt(content.length() - 1);
                logger.debug("content {} with offset {}", content, offset);

                var blob = encryptedBlobStore.getBlob(rangeRequest(
                    containerName, blobName, "bytes=" + offset + "-"));

                try (InputStream blobIs = blob) {
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

                blob = encryptedBlobStore.getBlob(rangeRequest(
                    containerName, blobName, "bytes=-" + tail));

                try (InputStream blobIs = blob) {
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

                blob = encryptedBlobStore.getBlob(rangeRequest(
                    containerName, blobName,
                    "bytes=" + offset + "-" + end));

                try (InputStream blobIs = blob) {
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
            encryptedBlobStore.putBlob(
                makeRequest(containerName, blobName, content.length())
                    .toBuilder().contentType(contentType).build(), is);

            var blob = encryptedBlobStore.getBlob(containerName, blobName);

            try (InputStream blobIs = blob) {
                var reader = new BufferedReader(new InputStreamReader(blobIs));
                String plaintext = reader.lines().collect(Collectors.joining());
                logger.debug("plaintext {}", plaintext);
                assertThat(plaintext).isEqualTo(content);
            }

            blob = blobStore.getBlob(containerName,
                blobName + Constants.S3_ENC_SUFFIX);

            try (InputStream blobIs = blob) {
                var reader = new BufferedReader(new InputStreamReader(blobIs));
                String encrypted = reader.lines().collect(Collectors.joining());
                logger.debug("encrypted {}", encrypted);
                assertThat(content).isNotEqualTo(encrypted);
            }

            assertThat(encryptedBlobStore.blobExists(containerName,
                blobName)).isTrue();

            if (!Quirks.NO_BLOB_ACCESS_CONTROL.contains(provider)) {
                ObjectCannedACL access =
                    encryptedBlobStore.getBlobAccess(containerName, blobName);
                assertThat(access).isEqualTo(ObjectCannedACL.PRIVATE);

                encryptedBlobStore.setBlobAccess(containerName, blobName,
                    ObjectCannedACL.PUBLIC_READ);
                access = encryptedBlobStore.getBlobAccess(containerName,
                    blobName);
                assertThat(access).isEqualTo(ObjectCannedACL.PUBLIC_READ);
            }
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
            encryptedBlobStore.putBlob(
                makeRequest(containerName, blobName, content.length())
                    .toBuilder().contentType(contentType).build(), is);

            var blob = encryptedBlobStore.getBlob(containerName, blobName);

            try (InputStream blobIs = blob) {
                var reader = new BufferedReader(new InputStreamReader(blobIs));
                String plaintext = reader.lines().collect(Collectors.joining());
                logger.debug("plaintext {}", plaintext);
                assertThat(content).isEqualTo(plaintext);
            }

            blob = blobStore.getBlob(containerName,
                blobName + Constants.S3_ENC_SUFFIX);

            try (InputStream blobIs = blob) {
                var reader = new BufferedReader(new InputStreamReader(blobIs));
                String encrypted = reader.lines().collect(Collectors.joining());
                logger.debug("encrypted {}", encrypted);
                assertThat(content).isNotEqualTo(encrypted);
            }

            var metadata =
                encryptedBlobStore.blobMetadata(containerName,
                    blobName + Constants.S3_ENC_SUFFIX);
            assertThat(contentType).isEqualTo(
                metadata.contentType());

            encryptedBlobStore.copyBlob(CopyObjectRequest.builder()
                .sourceBucket(containerName).sourceKey(blobName)
                .destinationBucket(containerName)
                .destinationKey(blobName + "-copy")
                .build());

            blob = blobStore.getBlob(containerName,
                blobName + Constants.S3_ENC_SUFFIX);

            try (InputStream blobIs = blob) {
                var reader = new BufferedReader(new InputStreamReader(blobIs));
                String encrypted = reader.lines().collect(Collectors.joining());
                logger.debug("encrypted {}", encrypted);
                assertThat(content).isNotEqualTo(encrypted);
            }

            blob =
                encryptedBlobStore.getBlob(containerName, blobName + "-copy");

            try (InputStream blobIs = blob) {
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

        var content = new ByteArrayOutputStream();
        MultipartUpload mpu = encryptedBlobStore.initiateMultipartUpload(
            TestUtils.createRequest(containerName, blobName));

        int partNumber = 1;
        for (int size : new int[] {partSize, partSize, LAST_PART_SIZE}) {
            byte[] bytes = filler(content.size(), size);
            content.writeBytes(bytes);
            TestUtils.uploadPart(encryptedBlobStore, mpu, partNumber++,
                new ByteArrayInputStream(bytes), bytes.length);
        }

        var mpus =
            encryptedBlobStore.listMultipartUploads(containerName);
        assertThat(mpus.size()).isEqualTo(1);

        var parts = encryptedBlobStore.listMultipartUpload(mpu);
        assertThat(mpus.get(0).uploadId()).isEqualTo(mpu.id());

        encryptedBlobStore.completeMultipartUpload(mpu,
            TestUtils.completeRequest(mpu, parts));

        try (InputStream blobIs = encryptedBlobStore.getBlob(
                containerName, blobName)) {
            assertThat(blobIs.readAllBytes()).isEqualTo(content.toByteArray());
        }

        try (InputStream blobIs = blobStore.getBlob(containerName,
                blobName + Constants.S3_ENC_SUFFIX)) {
            assertThat(blobIs.readAllBytes()).isNotEqualTo(
                content.toByteArray());
        }
    }

    @Test
    public void testReadPartial() throws Exception {
        String blobName = TestUtils.createRandomBlobName();
        String content =
            "123456789A123456123456789B123456123456789" +
                "C123456789D123456789E12345";
        InputStream is = new ByteArrayInputStream(
            content.getBytes(StandardCharsets.UTF_8));
        encryptedBlobStore.putBlob(
            makeRequest(containerName, blobName, content.length()), is);

        for (int offset = 0; offset < 60; offset++) {
            logger.debug("Test with offset {}", offset);

            var blob = encryptedBlobStore.getBlob(rangeRequest(
                containerName, blobName, "bytes=" + offset + "-"));

            try (InputStream blobIs = blob) {
                var reader = new BufferedReader(new InputStreamReader(blobIs));
                String plaintext = reader.lines().collect(Collectors.joining());
                logger.debug("plaintext {}", plaintext);
                assertThat(plaintext).isEqualTo(content.substring(offset));
            }

            // RFC 7233: bytes=offset- should report bytes offset-(L-1)/L.
            long expectedEndRange = content.length() - 1L;
            assertThat(blob.response().contentRange())
                .isEqualTo("bytes " + offset + "-" + expectedEndRange + "/" + content.length());
        }
    }

    @Test
    public void testReadTail() throws Exception {
        String blobName = TestUtils.createRandomBlobName();
        String content =
            "123456789A123456123456789B123456123456789C" +
                "123456789D123456789E12345";
        InputStream is = new ByteArrayInputStream(
            content.getBytes(StandardCharsets.UTF_8));
        encryptedBlobStore.putBlob(
            makeRequest(containerName, blobName, content.length()), is);

        for (int length = 1; length < 60; length++) {
            logger.debug("Test with length {}", length);

            var blob = encryptedBlobStore.getBlob(rangeRequest(
                containerName, blobName, "bytes=-" + length));

            try (InputStream blobIs = blob) {
                var reader = new BufferedReader(new InputStreamReader(blobIs));
                String plaintext = reader.lines().collect(Collectors.joining());
                logger.debug("plaintext {}", plaintext);
                assertThat(plaintext).isEqualTo(
                    content.substring(content.length() - length));
            }

            // RFC 7233: bytes=-N should report the actual byte range, not 0-N.
            long expectedStart = (long) content.length() - length;
            long expectedEnd = content.length() - 1L;
            assertThat(blob.response().contentRange())
                .isEqualTo("bytes " + expectedStart + "-" + expectedEnd + "/" + content.length());
        }
    }

    @Test
    public void testReadPartialWithRandomEnd() throws Exception {

        String blobName = TestUtils.createRandomBlobName();
        String content =
            "123456789A123456-123456789B123456-123456789C123456-" +
                "123456789D123456-123456789E123456";
        InputStream is = new ByteArrayInputStream(
            content.getBytes(StandardCharsets.UTF_8));
        encryptedBlobStore.putBlob(
            makeRequest(containerName, blobName, content.length()), is);

        var rand = new Random();
        for (int offset = 0; offset < 50; offset++) {
            for (int sample = 0; sample < 3; sample++) {
                int end = offset + rand.nextInt(20) + 2;
                int size = end - offset + 1;

                logger.debug("Test with offset {} and end {} size {}",
                    offset, end, size);

                var blob = encryptedBlobStore.getBlob(rangeRequest(
                    containerName, blobName,
                    "bytes=" + offset + "-" + end));

                try (InputStream blobIs = blob) {
                    var reader = new BufferedReader(
                        new InputStreamReader(blobIs));
                    String plaintext = reader.lines().collect(
                        Collectors.joining());
                    logger.debug("plaintext {}", plaintext);
                    assertThat(plaintext).hasSize(size);
                    assertThat(plaintext).isEqualTo(
                        content.substring(offset, end + 1));
                }

                assertThat(blob.response().contentRange())
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
            encryptedBlobStore.putBlob(
                makeRequest(containerName, blobName, length), is);

            var got = encryptedBlobStore.getBlob(rangeRequest(
                containerName, blobName,
                "bytes=" + offset + "-" + (length + 1000)));

            try (InputStream blobIs = got) {
                var reader = new BufferedReader(new InputStreamReader(blobIs));
                String plaintext = reader.lines().collect(Collectors.joining());
                assertThat(plaintext).isEqualTo(content.substring(offset));
            }

            assertThat(got.response().contentLength())
                .isEqualTo((long) length - offset);
            assertThat(got.response().contentRange())
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
        encryptedBlobStore.putBlob(
            makeRequest(containerName, blobName, length), is);

        var got = encryptedBlobStore.getBlob(rangeRequest(
            containerName, blobName, "bytes=-" + (length + 1000)));

        try (InputStream blobIs = got) {
            var reader = new BufferedReader(new InputStreamReader(blobIs));
            String plaintext = reader.lines().collect(Collectors.joining());
            assertThat(plaintext).isEqualTo(content);
        }

        assertThat(got.response().contentLength())
            .isEqualTo((long) length);
        assertThat(got.response().contentRange())
            .isEqualTo("bytes 0-" + (length - 1) + "/" + length);
    }

    @Test
    public void testMultipartReadPartial() throws Exception {
        var multipart = uploadMultipartContent();
        byte[] content = multipart.content;

        for (int offset : readOffsets(content.length)) {
            logger.debug("Test with offset {}", offset);

            try (InputStream blobIs = encryptedBlobStore.getBlob(rangeRequest(
                    containerName, multipart.blobName,
                    "bytes=" + offset + "-"))) {
                assertThat(blobIs.readAllBytes()).isEqualTo(
                    Arrays.copyOfRange(content, offset, content.length));
            }
        }
    }

    @Test
    public void testMultipartReadTail() throws Exception {
        var multipart = uploadMultipartContent();
        byte[] content = multipart.content;

        // The same places the arithmetic turns, counted from the other end.
        for (int offset : readOffsets(content.length)) {
            int length = content.length - offset;
            if (length == 0) {
                continue;
            }
            logger.debug("Test with length {}", length);

            try (InputStream blobIs = encryptedBlobStore.getBlob(rangeRequest(
                    containerName, multipart.blobName, "bytes=-" + length))) {
                assertThat(blobIs.readAllBytes()).isEqualTo(
                    Arrays.copyOfRange(content, content.length - length,
                        content.length));
            }
        }
    }

    @Test
    public void testMultipartReadPartialWithRandomEnd() throws Exception {
        var multipart = uploadMultipartContent();
        byte[] content = multipart.content;

        var rand = new Random();
        for (int offset : readOffsets(content.length)) {
            if (offset + 2 >= content.length) {
                continue;
            }
            for (int sample = 0; sample < 3; sample++) {
                int end = Math.min(content.length - 1,
                    offset + rand.nextInt(60) + 2);
                logger.debug("Test with offset {} and end {} size {}",
                    offset, end, end - offset + 1);

                try (InputStream blobIs = encryptedBlobStore.getBlob(
                        rangeRequest(containerName, multipart.blobName,
                            "bytes=" + offset + "-" + end))) {
                    assertThat(blobIs.readAllBytes()).isEqualTo(
                        Arrays.copyOfRange(content, offset, end + 1));
                }
            }
        }
    }

    @Test
    public void testReadConditional() {
        String blobName = TestUtils.createRandomBlobName();
        String content = "Hello world.";
        InputStream is = new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8));

        encryptedBlobStore.putBlob(
            makeRequest(containerName, blobName, content.length()), is);

        var blob = encryptedBlobStore.getBlob(containerName, blobName);
        String etag = blob.response().eTag();

        var conditionalRequest = GetObjectRequest.builder()
                .bucket(containerName)
                .key(blobName)
                .ifNoneMatch(etag)
                .build();
        var e = Assertions.assertThrows(AwsServiceException.class,
            () -> encryptedBlobStore.getBlob(conditionalRequest));
        // The nio2 backends report If-None-Match misses as 304 directly while
        // the SDK backends report 412 and rely on the frontend remapping
        // GET and HEAD requests to 304.
        assertThat(e.statusCode()).isIn(304, 412);
    }

    @Test
    public void testReadDoubleZeroRange() throws IOException {
        String blobName = TestUtils.createRandomBlobName();
        String content = "Hello world.";
        InputStream is = new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8));

        encryptedBlobStore.putBlob(
            makeRequest(containerName, blobName, content.length()), is);

        var result = encryptedBlobStore.getBlob(rangeRequest(
                containerName, blobName, "bytes=0-0"));
        assertThat(result.readAllBytes().length).isEqualTo(1);

        assertThat(result.response().contentRange())
            .isEqualTo("bytes 0-0/" + content.length());
    }
}
