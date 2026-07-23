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

// SigV2 (AWS Signature Version 2) tests were removed in the AWS SDK v2
// migration: v2 has no public SigV2 path for S3.  The proxy still
// implements SigV2 and is exercised via the v1 jclouds backend.
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.nio.ByteBuffer;
import java.security.KeyManagementException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.UUID;
import java.util.zip.CRC32;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import com.google.common.collect.ImmutableList;
import com.google.common.hash.Hashing;
import com.google.common.io.ByteSource;

import org.assertj.core.api.Fail;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.Constants;
import org.gaul.s3proxy.blobstore.domain.Blob;
import org.gaul.s3proxy.blobstore.domain.BlobAccess;
import org.gaul.s3proxy.blobstore.domain.ContainerAccess;
import org.gaul.s3proxy.blobstore.options.CreateContainerOptions;
import org.gaul.s3proxy.blobstore.options.PutOptions;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.http.SdkHttpConfigurationOption;
import software.amazon.awssdk.http.apache5.Apache5HttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.model.ChecksumAlgorithm;
import software.amazon.awssdk.services.s3.model.ChecksumMode;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.CompletedMultipartUpload;
import software.amazon.awssdk.services.s3.model.CompletedPart;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.GetObjectAclResponse;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.Grant;
import software.amazon.awssdk.services.s3.model.Grantee;
import software.amazon.awssdk.services.s3.model.HeadObjectResponse;
import software.amazon.awssdk.services.s3.model.ListObjectsResponse;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Response;
import software.amazon.awssdk.services.s3.model.NoSuchBucketException;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.s3.model.ObjectCannedACL;
import software.amazon.awssdk.services.s3.model.ObjectIdentifier;
import software.amazon.awssdk.services.s3.model.Permission;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.services.s3.model.S3Object;
import software.amazon.awssdk.services.s3.model.StorageClass;
import software.amazon.awssdk.services.s3.model.Tagging;
import software.amazon.awssdk.services.s3.model.Type;
import software.amazon.awssdk.services.s3.model.UploadPartCopyResponse;
import software.amazon.awssdk.services.s3.model.UploadPartResponse;
import software.amazon.awssdk.services.s3.presigner.S3Presigner;
import software.amazon.awssdk.services.s3.presigner.model.GetObjectPresignRequest;
import software.amazon.awssdk.services.s3.presigner.model.PresignedGetObjectRequest;
import software.amazon.awssdk.utils.AttributeMap;

public final class AwsSdkTest {
    static {
        disableSslVerification();
    }

    private static final ByteSource BYTE_SOURCE = ByteSource.wrap(new byte[1]);
    private static final long MINIMUM_MULTIPART_SIZE = 5 * 1024 * 1024;
    private static final int MINIO_PORT = 9000;
    private static final int LOCALSTACK_PORT = 4566;
    private static final String ALL_USERS_GROUP =
            "http://acs.amazonaws.com/groups/global/AllUsers";

    private URI s3Endpoint;
    private URI s3EndpointUri;
    private S3Proxy s3Proxy;
    private BlobStore blobStore;
    private URI blobStoreEndpoint;
    private String blobStoreType;
    private String containerName;
    private AwsBasicCredentials awsCreds;
    private S3Client client;
    private String servicePath;

    @BeforeEach
    public void setUp() throws Exception {
        TestUtils.S3ProxyLaunchInfo info = TestUtils.startS3Proxy(
                System.getProperty("s3proxy.test.conf", "s3proxy.conf"));
        awsCreds = AwsBasicCredentials.create(info.getS3Identity(),
                info.getS3Credential());
        blobStore = info.getBlobStore();
        s3Proxy = info.getS3Proxy();
        s3Endpoint = info.getSecureEndpoint();
        servicePath = info.getServicePath();
        s3EndpointUri = URI.create(s3Endpoint.toString() + servicePath);
        client = buildClient(awsCreds);

        containerName = createRandomContainerName();
        info.getBlobStore().createContainer(containerName,
                CreateContainerOptions.NONE);

        blobStoreEndpoint = URI.create(info.getProperties().getProperty(
                Constants.PROPERTY_ENDPOINT, "http://stub"));
        blobStoreType = info.getProperties().getProperty(
                Constants.PROPERTY_PROVIDER, "");
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (client != null) {
            client.close();
        }
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
        if (blobStore != null) {
            blobStore.deleteContainer(containerName);
        }
    }

    private S3Client buildClient(AwsBasicCredentials creds) {
        return buildClient(StaticCredentialsProvider.create(creds));
    }

    private S3Client buildClient(AwsCredentialsProvider creds) {
        var attributeMap = AttributeMap.builder()
                .put(SdkHttpConfigurationOption.TRUST_ALL_CERTIFICATES, true)
                .build();
        return S3Client.builder()
                .credentialsProvider(creds)
                .region(Region.US_EAST_1)
                .endpointOverride(s3EndpointUri)
                .httpClient(Apache5HttpClient.builder()
                        .buildWithDefaults(attributeMap))
                .serviceConfiguration(S3Configuration.builder()
                        .pathStyleAccessEnabled(true)
                        .build())
                .build();
    }

    private S3Presigner buildPresigner() {
        return S3Presigner.builder()
                .credentialsProvider(StaticCredentialsProvider.create(awsCreds))
                .region(Region.US_EAST_1)
                .endpointOverride(s3EndpointUri)
                .serviceConfiguration(S3Configuration.builder()
                        .pathStyleAccessEnabled(true)
                        .build())
                .build();
    }

    private void putBlob(String bucket, String key, ByteSource source)
            throws Exception {
        client.putObject(b -> b.bucket(bucket).key(key),
                RequestBody.fromInputStream(source.openStream(),
                        source.size()));
    }

    @Test
    public void testAwsV4Signature() throws Exception {
        putBlob(containerName, "foo", BYTE_SOURCE);

        try (ResponseInputStream<GetObjectResponse> object = client.getObject(
                b -> b.bucket(containerName).key("foo"))) {
            assertThat(object.response().contentLength()).isEqualTo(
                    BYTE_SOURCE.size());
            try (InputStream expected = BYTE_SOURCE.openStream()) {
                assertThat((InputStream) object).hasSameContentAs(expected);
            }
        }
    }

    @Test
    public void testAwsV4SignatureChunkedSigned() throws Exception {
        // chunkedEncodingEnabled is true by default in v2.
        putBlob(containerName, "foo", BYTE_SOURCE);

        try (ResponseInputStream<GetObjectResponse> object = client.getObject(
                b -> b.bucket(containerName).key("foo"))) {
            assertThat(object.response().contentLength()).isEqualTo(
                    BYTE_SOURCE.size());
            try (InputStream expected = BYTE_SOURCE.openStream()) {
                assertThat((InputStream) object).hasSameContentAs(expected);
            }
        }
    }

    @Test
    public void testAwsV4SignatureNonChunked() throws Exception {
        client.close();
        var attributeMap = AttributeMap.builder()
                .put(SdkHttpConfigurationOption.TRUST_ALL_CERTIFICATES, true)
                .build();
        client = S3Client.builder()
                .credentialsProvider(StaticCredentialsProvider.create(awsCreds))
                .region(Region.US_EAST_1)
                .endpointOverride(s3EndpointUri)
                .httpClient(Apache5HttpClient.builder()
                        .buildWithDefaults(attributeMap))
                .serviceConfiguration(S3Configuration.builder()
                        .pathStyleAccessEnabled(true)
                        .chunkedEncodingEnabled(false)
                        .build())
                .build();

        putBlob(containerName, "foo", BYTE_SOURCE);

        try (ResponseInputStream<GetObjectResponse> object = client.getObject(
                b -> b.bucket(containerName).key("foo"))) {
            assertThat(object.response().contentLength()).isEqualTo(
                    BYTE_SOURCE.size());
            try (InputStream expected = BYTE_SOURCE.openStream()) {
                assertThat((InputStream) object).hasSameContentAs(expected);
            }
        }
    }

    // v1's withPayloadSigningEnabled(false) has no clean v2 SDK equivalent;
    // the UNSIGNED-PAYLOAD path is still exercised via the anonymous client
    // in AwsSdkAnonymousTest.

    @Test
    public void testAwsV4SignatureBadIdentity() throws Exception {
        client.close();
        client = buildClient(AwsBasicCredentials.create("bad-access-key",
                awsCreds.secretAccessKey()));

        try {
            putBlob(containerName, "foo", BYTE_SOURCE);
            Fail.failBecauseExceptionWasNotThrown(S3Exception.class);
        } catch (S3Exception e) {
            assertThat(e.awsErrorDetails().errorCode())
                    .isEqualTo("InvalidAccessKeyId");
        }
    }

    @Test
    public void testAwsV4SignatureBadCredential() throws Exception {
        client.close();
        client = buildClient(AwsBasicCredentials.create(
                awsCreds.accessKeyId(), "bad-secret-key"));

        try {
            putBlob(containerName, "foo", BYTE_SOURCE);
            Fail.failBecauseExceptionWasNotThrown(S3Exception.class);
        } catch (S3Exception e) {
            assertThat(e.awsErrorDetails().errorCode())
                    .isEqualTo("SignatureDoesNotMatch");
        }
    }

    @Test
    public void testAwsV4UrlSigning() throws Exception {
        String blobName = "foo";
        putBlob(containerName, blobName, BYTE_SOURCE);

        URI url;
        try (S3Presigner presigner = buildPresigner()) {
            PresignedGetObjectRequest presigned = presigner.presignGetObject(
                    GetObjectPresignRequest.builder()
                            .signatureDuration(Duration.ofHours(1))
                            .getObjectRequest(b -> b.bucket(containerName)
                                    .key(blobName))
                            .build());
            url = presigned.url().toURI();
        }

        try (InputStream actual = url.toURL().openStream();
                InputStream expected = BYTE_SOURCE.openStream()) {
            assertThat(actual).hasSameContentAs(expected);
        }
    }

    @ParameterizedTest
    @EnumSource(value = ChecksumAlgorithm.class,
            names = {"CRC32", "CRC32_C", "SHA1", "SHA256"})
    public void testPutObjectWithChecksumAlgorithm(ChecksumAlgorithm algorithm)
            throws Exception {
        var key = "testPutObjectChecksum-" + algorithm.toString();
        var byteSource = TestUtils.randomByteSource().slice(0, 1024);
        client.putObject(b -> b.bucket(containerName).key(key)
                        .checksumAlgorithm(algorithm),
                RequestBody.fromBytes(byteSource.read()));
    }

    @Test
    public void testPutObjectWithChecksumHeader() throws Exception {
        var key = "testPutObjectChecksumHeader";
        var byteSource = TestUtils.randomByteSource().slice(0, 1024);
        var content = byteSource.read();
        var crc32 = new CRC32();
        crc32.update(content);
        var checksum = Base64.getEncoder().encodeToString(
                ByteBuffer.allocate(4).putInt((int) crc32.getValue()).array());

        client.putObject(b -> b.bucket(containerName).key(key)
                        .checksumCRC32(checksum),
                RequestBody.fromBytes(content));

        try (InputStream actual = client.getObject(
                b -> b.bucket(containerName).key(key));
                InputStream expected = byteSource.openStream()) {
            assertThat(actual).hasSameContentAs(expected);
        }
    }

    @Test
    public void testPutObjectWithInvalidChecksumHeader() throws Exception {
        // A precomputed-checksum mismatch is detected mid-stream while the
        // body is forwarded to the backend, so it surfaces as a clean
        // BadDigest only on backends whose putBlob reads the payload once and
        // propagates the error.  Skip the one that cannot:
        // google-cloud-storage-sdk's Storage.createFrom() finalizes the
        // resumable upload on close, leaving a 0-byte object that is
        // indistinguishable on the wire from a legitimate empty-object PUT,
        // so the rejected key still exists afterwards.
        assumeTrue(!blobStoreType.equals("google-cloud-storage-sdk"));

        var key = "testPutObjectInvalidChecksumHeader";
        var content = TestUtils.randomByteSource().slice(0, 1024).read();
        var crc32 = new CRC32();
        crc32.update(content);
        // Corrupt the real checksum so it cannot match the body.
        var checksum = Base64.getEncoder().encodeToString(ByteBuffer.allocate(4)
                .putInt((int) crc32.getValue() ^ 1).array());

        try {
            client.putObject(b -> b.bucket(containerName).key(key)
                            .checksumCRC32(checksum),
                    RequestBody.fromBytes(content));
            Fail.failBecauseExceptionWasNotThrown(S3Exception.class);
        } catch (S3Exception e) {
            assertThat(e.awsErrorDetails().errorCode()).isEqualTo("BadDigest");
        }

        // The rejected upload must not be committed.
        try {
            client.getObject(b -> b.bucket(containerName).key(key));
            Fail.failBecauseExceptionWasNotThrown(S3Exception.class);
        } catch (S3Exception e) {
            assertThat(e.statusCode()).isEqualTo(404);
        }
    }

    @Test
    public void testPutObjectChecksumEchoAndHeadObject() throws Exception {
        var key = "testPutObjectChecksumEcho";
        var content = TestUtils.randomByteSource().slice(0, 1024).read();
        var checksum = Base64.getEncoder().encodeToString(
                Hashing.sha256().hashBytes(content).asBytes());

        PutObjectResponse putResponse = client.putObject(
                b -> b.bucket(containerName).key(key).checksumSHA256(checksum),
                RequestBody.fromBytes(content));
        assertThat(putResponse.checksumSHA256()).isEqualTo(checksum);

        // without x-amz-checksum-mode: ENABLED the checksum stays hidden
        HeadObjectResponse headResponse = client.headObject(
                b -> b.bucket(containerName).key(key));
        assertThat(headResponse.checksumSHA256()).isNull();

        headResponse = client.headObject(b -> b.bucket(containerName).key(key)
                .checksumMode(ChecksumMode.ENABLED));
        assertThat(headResponse.checksumSHA256()).isEqualTo(checksum);
        // the reserved persistence key must not leak as user metadata
        assertThat(headResponse.metadata()).isEmpty();
    }

    @Test
    public void testPutObjectMalformedChecksumHeader() throws Exception {
        var key = "testPutObjectMalformedChecksum";
        var content = TestUtils.randomByteSource().slice(0, 1024).read();
        try {
            client.putObject(b -> b.bucket(containerName).key(key)
                            .checksumSHA256("bad"),
                    RequestBody.fromBytes(content));
            Fail.failBecauseExceptionWasNotThrown(S3Exception.class);
        } catch (S3Exception e) {
            assertThat(e.statusCode()).isEqualTo(400);
            assertThat(e.awsErrorDetails().errorCode()).isEqualTo(
                    "InvalidRequest");
        }
    }

    @Test
    public void testMultipartUploadChecksum() throws Exception {
        var key = "testMultipartUploadChecksum";
        var content = TestUtils.randomByteSource().slice(0, 1024).read();
        var partChecksum = Base64.getEncoder().encodeToString(
                Hashing.sha256().hashBytes(content).asBytes());
        var compositeChecksum = Base64.getEncoder().encodeToString(
                Hashing.sha256().hashBytes(
                        Base64.getDecoder().decode(partChecksum)).asBytes()) +
                "-1";

        CreateMultipartUploadResponse createResponse =
                client.createMultipartUpload(b -> b.bucket(containerName)
                        .key(key)
                        .checksumAlgorithm(ChecksumAlgorithm.SHA256));
        assertThat(createResponse.checksumAlgorithm()).isEqualTo(
                ChecksumAlgorithm.SHA256);
        String uploadId = createResponse.uploadId();

        UploadPartResponse partResponse = client.uploadPart(b -> b
                        .bucket(containerName).key(key).uploadId(uploadId)
                        .partNumber(1)
                        .checksumSHA256(partChecksum),
                RequestBody.fromBytes(content));
        assertThat(partResponse.checksumSHA256()).isEqualTo(partChecksum);

        CompleteMultipartUploadResponse completeResponse =
                client.completeMultipartUpload(b -> b
                        .bucket(containerName).key(key).uploadId(uploadId)
                        .multipartUpload(CompletedMultipartUpload.builder()
                                .parts(CompletedPart.builder()
                                        .partNumber(1)
                                        .eTag(partResponse.eTag())
                                        .checksumSHA256(partChecksum)
                                        .build())
                                .build()));
        assertThat(completeResponse.checksumSHA256()).isEqualTo(
                compositeChecksum);

        // only MULTIPART_REQUIRES_STUB backends persist the composite for
        // later HeadObject requests
        if (Quirks.MULTIPART_REQUIRES_STUB.contains(blobStoreType)) {
            HeadObjectResponse headResponse = client.headObject(
                    b -> b.bucket(containerName).key(key)
                            .checksumMode(ChecksumMode.ENABLED));
            assertThat(headResponse.checksumSHA256()).isEqualTo(
                    compositeChecksum);
        }
    }

    @Test
    public void testMultipartCopy() throws Exception {
        assumeTrue(!blobStoreType.equals("openstack-swift-sdk"));
        assumeTrue(!blobStoreType.equals("azureblob-sdk"));

        String sourceBlobName = "testMultipartCopy-source";
        String targetBlobName = "testMultipartCopy-target";

        putBlob(containerName, sourceBlobName, BYTE_SOURCE);

        CreateMultipartUploadResponse initResult = client.createMultipartUpload(
                b -> b.bucket(containerName).key(targetBlobName));
        String uploadId = initResult.uploadId();

        long lastByte = BYTE_SOURCE.size() - 1;
        UploadPartCopyResponse copyResult = client.uploadPartCopy(b -> b
                .sourceBucket(containerName)
                .sourceKey(sourceBlobName)
                .destinationBucket(containerName)
                .destinationKey(targetBlobName)
                .uploadId(uploadId)
                .copySourceRange("bytes=0-" + lastByte)
                .partNumber(1));

        client.completeMultipartUpload(b -> b
                .bucket(containerName).key(targetBlobName).uploadId(uploadId)
                .multipartUpload(CompletedMultipartUpload.builder()
                        .parts(CompletedPart.builder()
                                .partNumber(1)
                                .eTag(copyResult.copyPartResult().eTag())
                                .build())
                        .build()));

        try (ResponseInputStream<GetObjectResponse> object = client.getObject(
                b -> b.bucket(containerName).key(targetBlobName))) {
            assertThat(object.response().contentLength()).isEqualTo(
                    BYTE_SOURCE.size());
            try (InputStream expected = BYTE_SOURCE.openStream()) {
                assertThat((InputStream) object).hasSameContentAs(expected);
            }
        }
    }

    @Test
    public void testMultipartCopyPreconditionFailed() throws Exception {
        assumeTrue(!blobStoreType.equals("openstack-swift-sdk"));
        assumeTrue(!blobStoreType.equals("azureblob-sdk"));

        String sourceBlobName = "testMultipartCopyPrecondition-source";
        String targetBlobName = "testMultipartCopyPrecondition-target";

        putBlob(containerName, sourceBlobName, BYTE_SOURCE);

        CreateMultipartUploadResponse initResult = client.createMultipartUpload(
                b -> b.bucket(containerName).key(targetBlobName));
        String uploadId = initResult.uploadId();

        long lastByte = BYTE_SOURCE.size() - 1;
        // A copy-source-if-match that cannot match the source ETag must fail
        // the precondition (and must not leak the opened source stream).
        try {
            client.uploadPartCopy(b -> b
                    .sourceBucket(containerName)
                    .sourceKey(sourceBlobName)
                    .destinationBucket(containerName)
                    .destinationKey(targetBlobName)
                    .uploadId(uploadId)
                    .copySourceIfMatch("\"00000000000000000000000000000000\"")
                    .copySourceRange("bytes=0-" + lastByte)
                    .partNumber(1));
            Fail.failBecauseExceptionWasNotThrown(S3Exception.class);
        } catch (S3Exception e) {
            assertThat(e.statusCode()).isEqualTo(412);
        }
    }

    @Test
    public void testBigMultipartUpload() throws Exception {
        String key = "multipart-upload";
        long partSize = MINIMUM_MULTIPART_SIZE;
        long size = partSize + 1;
        ByteSource byteSource = TestUtils.randomByteSource().slice(0, size);

        CreateMultipartUploadResponse initResponse = client.createMultipartUpload(
                b -> b.bucket(containerName).key(key));
        String uploadId = initResponse.uploadId();

        ByteSource byteSource1 = byteSource.slice(0, partSize);
        UploadPartResponse part1 = client.uploadPart(b -> b
                .bucket(containerName).key(key).uploadId(uploadId)
                .partNumber(1),
                RequestBody.fromInputStream(byteSource1.openStream(),
                        byteSource1.size()));

        ByteSource byteSource2 = byteSource.slice(partSize, size - partSize);
        UploadPartResponse part2 = client.uploadPart(b -> b
                .bucket(containerName).key(key).uploadId(uploadId)
                .partNumber(2),
                RequestBody.fromInputStream(byteSource2.openStream(),
                        byteSource2.size()));

        client.completeMultipartUpload(b -> b
                .bucket(containerName).key(key).uploadId(uploadId)
                .multipartUpload(CompletedMultipartUpload.builder()
                        .parts(
                                CompletedPart.builder().partNumber(1)
                                        .eTag(part1.eTag()).build(),
                                CompletedPart.builder().partNumber(2)
                                        .eTag(part2.eTag()).build())
                        .build()));

        try (ResponseInputStream<GetObjectResponse> object = client.getObject(
                b -> b.bucket(containerName).key(key))) {
            assertThat(object.response().contentLength()).isEqualTo(size);
            try (InputStream expected = byteSource.openStream()) {
                assertThat((InputStream) object).hasSameContentAs(expected);
            }
        }
    }

    @Test
    public void testMultipartUploadEtagPersisted() throws Exception {
        // The multipart ETag ("<md5>-<n>") that CompleteMultipartUpload
        // returns must be persisted, so a later HEAD reports the same ETag
        // rather than the MD5 of the assembled object.
        assumeTrue(blobStoreType.equals("filesystem-nio2") ||
                blobStoreType.equals("transient-nio2"));

        String key = "multipart-etag";
        long partSize = MINIMUM_MULTIPART_SIZE;
        long size = partSize + 1;
        ByteSource byteSource = TestUtils.randomByteSource().slice(0, size);

        CreateMultipartUploadResponse initResponse =
                client.createMultipartUpload(
                        b -> b.bucket(containerName).key(key));
        String uploadId = initResponse.uploadId();

        ByteSource byteSource1 = byteSource.slice(0, partSize);
        UploadPartResponse part1 = client.uploadPart(b -> b
                .bucket(containerName).key(key).uploadId(uploadId)
                .partNumber(1),
                RequestBody.fromInputStream(byteSource1.openStream(),
                        byteSource1.size()));
        ByteSource byteSource2 = byteSource.slice(partSize, size - partSize);
        UploadPartResponse part2 = client.uploadPart(b -> b
                .bucket(containerName).key(key).uploadId(uploadId)
                .partNumber(2),
                RequestBody.fromInputStream(byteSource2.openStream(),
                        byteSource2.size()));

        CompleteMultipartUploadResponse completeResponse =
                client.completeMultipartUpload(b -> b
                        .bucket(containerName).key(key).uploadId(uploadId)
                        .multipartUpload(CompletedMultipartUpload.builder()
                                .parts(
                                        CompletedPart.builder().partNumber(1)
                                                .eTag(part1.eTag()).build(),
                                        CompletedPart.builder().partNumber(2)
                                                .eTag(part2.eTag()).build())
                                .build()));
        assertThat(completeResponse.eTag()).contains("-2");

        // A later HEAD must report the same multipart ETag, not the MD5 of
        // the assembled object.
        HeadObjectResponse head = client.headObject(
                b -> b.bucket(containerName).key(key));
        assertThat(head.eTag()).isEqualTo(completeResponse.eTag());
        assertThat(head.eTag()).contains("-2");
    }

    @Test
    public void testAbortAfterCompleteKeepsObject() throws Exception {
        String key = "abort-after-complete";
        long partSize = MINIMUM_MULTIPART_SIZE;
        long size = partSize + 1;
        ByteSource byteSource = TestUtils.randomByteSource().slice(0, size);

        CreateMultipartUploadResponse initResponse =
                client.createMultipartUpload(
                        b -> b.bucket(containerName).key(key));
        String uploadId = initResponse.uploadId();

        ByteSource byteSource1 = byteSource.slice(0, partSize);
        UploadPartResponse part1 = client.uploadPart(b -> b
                .bucket(containerName).key(key).uploadId(uploadId)
                .partNumber(1),
                RequestBody.fromInputStream(byteSource1.openStream(),
                        byteSource1.size()));

        ByteSource byteSource2 = byteSource.slice(partSize, size - partSize);
        UploadPartResponse part2 = client.uploadPart(b -> b
                .bucket(containerName).key(key).uploadId(uploadId)
                .partNumber(2),
                RequestBody.fromInputStream(byteSource2.openStream(),
                        byteSource2.size()));

        client.completeMultipartUpload(b -> b
                .bucket(containerName).key(key).uploadId(uploadId)
                .multipartUpload(CompletedMultipartUpload.builder()
                        .parts(
                                CompletedPart.builder().partNumber(1)
                                        .eTag(part1.eTag()).build(),
                                CompletedPart.builder().partNumber(2)
                                        .eTag(part2.eTag()).build())
                        .build()));

        // A late or retried abort of the now-completed upload must not destroy
        // the object.  Backends report NoSuchUpload for a completed upload, but
        // the exact status is backend-specific; the invariant under test is
        // that the completed object survives regardless.
        try {
            client.abortMultipartUpload(b -> b.bucket(containerName).key(key)
                    .uploadId(uploadId));
        } catch (S3Exception e) {
            // expected on most backends; object survival is asserted below
        }

        try (ResponseInputStream<GetObjectResponse> object = client.getObject(
                b -> b.bucket(containerName).key(key))) {
            assertThat(object.response().contentLength()).isEqualTo(size);
            try (InputStream expected = byteSource.openStream()) {
                assertThat((InputStream) object).hasSameContentAs(expected);
            }
        }
    }

    @Test
    public void testMultipartUploadWithChecksum() throws Exception {
        String key = "multipart-upload-checksum";
        long partSize = MINIMUM_MULTIPART_SIZE;
        long size = partSize + 1;
        ByteSource byteSource = TestUtils.randomByteSource().slice(0, size);

        CreateMultipartUploadResponse initResponse =
                client.createMultipartUpload(
                        b -> b.bucket(containerName).key(key));
        String uploadId = initResponse.uploadId();

        ByteSource byteSource1 = byteSource.slice(0, partSize);
        byte[] content1 = byteSource1.read();
        String checksum1 = Base64.getEncoder().encodeToString(sha256(content1));
        UploadPartResponse part1 = client.uploadPart(b -> b
                .bucket(containerName).key(key).uploadId(uploadId)
                .partNumber(1).checksumSHA256(checksum1),
                RequestBody.fromBytes(content1));

        ByteSource byteSource2 = byteSource.slice(partSize, size - partSize);
        byte[] content2 = byteSource2.read();
        String checksum2 = Base64.getEncoder().encodeToString(sha256(content2));
        UploadPartResponse part2 = client.uploadPart(b -> b
                .bucket(containerName).key(key).uploadId(uploadId)
                .partNumber(2).checksumSHA256(checksum2),
                RequestBody.fromBytes(content2));

        // S3 returns the composite checksum: base64(SHA256(part checksums))-N.
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(Base64.getDecoder().decode(checksum1));
        md.update(Base64.getDecoder().decode(checksum2));
        String expected =
                Base64.getEncoder().encodeToString(md.digest()) + "-2";

        CompleteMultipartUploadResponse completeResponse =
                client.completeMultipartUpload(b -> b
                .bucket(containerName).key(key).uploadId(uploadId)
                .multipartUpload(CompletedMultipartUpload.builder()
                        .parts(
                                CompletedPart.builder().partNumber(1)
                                        .eTag(part1.eTag())
                                        .checksumSHA256(checksum1).build(),
                                CompletedPart.builder().partNumber(2)
                                        .eTag(part2.eTag())
                                        .checksumSHA256(checksum2).build())
                        .build()));

        assertThat(completeResponse.checksumSHA256()).isEqualTo(expected);
    }

    @Test
    public void testMultipartUploadMissingPartChecksum() throws Exception {
        String key = "multipart-upload-missing-checksum";
        long partSize = MINIMUM_MULTIPART_SIZE;
        long size = partSize + 1;
        ByteSource byteSource = TestUtils.randomByteSource().slice(0, size);

        CreateMultipartUploadResponse initResponse =
                client.createMultipartUpload(
                        b -> b.bucket(containerName).key(key));
        String uploadId = initResponse.uploadId();

        ByteSource byteSource1 = byteSource.slice(0, partSize);
        byte[] content1 = byteSource1.read();
        String checksum1 = Base64.getEncoder().encodeToString(sha256(content1));
        UploadPartResponse part1 = client.uploadPart(b -> b
                .bucket(containerName).key(key).uploadId(uploadId)
                .partNumber(1),
                RequestBody.fromBytes(content1));

        ByteSource byteSource2 = byteSource.slice(partSize, size - partSize);
        byte[] content2 = byteSource2.read();
        UploadPartResponse part2 = client.uploadPart(b -> b
                .bucket(containerName).key(key).uploadId(uploadId)
                .partNumber(2),
                RequestBody.fromBytes(content2));

        // Part 1 supplies a checksum but part 2 does not, so S3 rejects the
        // completion.
        try {
            client.completeMultipartUpload(b -> b
                    .bucket(containerName).key(key).uploadId(uploadId)
                    .multipartUpload(CompletedMultipartUpload.builder()
                            .parts(
                                    CompletedPart.builder().partNumber(1)
                                            .eTag(part1.eTag())
                                            .checksumSHA256(checksum1).build(),
                                    CompletedPart.builder().partNumber(2)
                                            .eTag(part2.eTag()).build())
                            .build()));
            Fail.failBecauseExceptionWasNotThrown(S3Exception.class);
        } catch (S3Exception e) {
            assertThat(e.statusCode()).isEqualTo(400);
        }
    }

    private static byte[] sha256(byte[] data) throws NoSuchAlgorithmException {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }

    @Test
    public void testMultipartUploadReplace() throws Exception {
        String key = "multipart-upload";
        long partSize = MINIMUM_MULTIPART_SIZE;
        long size = partSize + 1;
        ByteSource byteSource = TestUtils.randomByteSource().slice(0, size);

        // Create
        CreateMultipartUploadResponse initResponse1 =
                client.createMultipartUpload(
                        b -> b.bucket(containerName).key(key));
        String uploadId1 = initResponse1.uploadId();

        ByteSource byteSource1 = byteSource.slice(0, partSize);
        UploadPartResponse part1 = client.uploadPart(b -> b
                .bucket(containerName).key(key).uploadId(uploadId1)
                .partNumber(1),
                RequestBody.fromInputStream(byteSource1.openStream(),
                        byteSource1.size()));

        client.completeMultipartUpload(b -> b
                .bucket(containerName).key(key).uploadId(uploadId1)
                .multipartUpload(CompletedMultipartUpload.builder()
                        .parts(CompletedPart.builder().partNumber(1)
                                .eTag(part1.eTag()).build())
                        .build()));

        // Replace
        CreateMultipartUploadResponse initResponse2 =
                client.createMultipartUpload(
                        b -> b.bucket(containerName).key(key));
        String uploadId2 = initResponse2.uploadId();

        ByteSource byteSource2 = byteSource.slice(partSize, size - partSize);
        UploadPartResponse part2 = client.uploadPart(b -> b
                .bucket(containerName).key(key).uploadId(uploadId2)
                .partNumber(1),
                RequestBody.fromInputStream(byteSource2.openStream(),
                        byteSource2.size()));

        client.completeMultipartUpload(b -> b
                .bucket(containerName).key(key).uploadId(uploadId2)
                .multipartUpload(CompletedMultipartUpload.builder()
                        .parts(CompletedPart.builder().partNumber(1)
                                .eTag(part2.eTag()).build())
                        .build()));

        try (ResponseInputStream<GetObjectResponse> object = client.getObject(
                b -> b.bucket(containerName).key(key))) {
            assertThat(object.response().contentLength()).isEqualTo(
                    byteSource2.size());
            try (InputStream expected = byteSource2.openStream()) {
                assertThat((InputStream) object).hasSameContentAs(expected);
            }
        }
    }

    // TODO: testMultipartUploadConditionalCopy

    @Test
    public void testUpdateBlobXmlAcls() throws Exception {
        assumeTrue(!Quirks.NO_BLOB_ACCESS_CONTROL.contains(blobStoreType));
        assumeTrue(blobStoreEndpoint.getPort() != MINIO_PORT);

        String blobName = "testUpdateBlobXmlAcls-blob";
        putBlob(containerName, blobName, BYTE_SOURCE);

        GetObjectAclResponse acl = client.getObjectAcl(
                b -> b.bucket(containerName).key(blobName));

        var withRead = new ArrayList<>(acl.grants());
        withRead.add(Grant.builder()
                .grantee(Grantee.builder().type(Type.GROUP)
                        .uri(ALL_USERS_GROUP).build())
                .permission(Permission.READ)
                .build());
        client.putObjectAcl(b -> b.bucket(containerName).key(blobName)
                .accessControlPolicy(p -> p.owner(acl.owner())
                        .grants(withRead)));
        assertThat(client.getObjectAcl(
                b -> b.bucket(containerName).key(blobName)).grants())
                .containsExactlyInAnyOrderElementsOf(withRead);

        client.putObjectAcl(b -> b.bucket(containerName).key(blobName)
                .accessControlPolicy(p -> p.owner(acl.owner())
                        .grants(acl.grants())));
        assertThat(client.getObjectAcl(
                b -> b.bucket(containerName).key(blobName)).grants())
                .containsExactlyInAnyOrderElementsOf(acl.grants());

        var withWrite = new ArrayList<>(acl.grants());
        withWrite.add(Grant.builder()
                .grantee(Grantee.builder().type(Type.GROUP)
                        .uri(ALL_USERS_GROUP).build())
                .permission(Permission.WRITE)
                .build());
        try {
            client.putObjectAcl(b -> b.bucket(containerName).key(blobName)
                    .accessControlPolicy(p -> p.owner(acl.owner())
                            .grants(withWrite)));
            Fail.failBecauseExceptionWasNotThrown(S3Exception.class);
        } catch (S3Exception e) {
            assertThat(e.awsErrorDetails().errorCode())
                    .isEqualTo("NotImplemented");
        }
    }

    @Test
    public void testSetBlobAclMissingObjectSurfacesError() throws Exception {
        // A real ACL failure must surface rather than being swallowed as a
        // false success.  google-cloud-storage-sdk previously discarded every
        // StorageException from ACL operations; setting an ACL on a missing
        // object must return NoSuchKey, not report success.
        assumeTrue(blobStoreType.equals("google-cloud-storage-sdk"));

        try {
            client.putObjectAcl(b -> b.bucket(containerName).key("no-such-key")
                    .acl(ObjectCannedACL.PUBLIC_READ));
            Fail.failBecauseExceptionWasNotThrown(S3Exception.class);
        } catch (S3Exception e) {
            assertThat(e.statusCode()).isEqualTo(404);
        }
    }

    @Test
    public void testUnicodeObject() throws Exception {
        String blobName = "ŪņЇЌœđЗ/☺ unicode € rocks ™";
        putBlob(containerName, blobName, BYTE_SOURCE);

        HeadObjectResponse metadata = client.headObject(
                b -> b.bucket(containerName).key(blobName));
        assertThat(metadata).isNotNull();

        ListObjectsResponse listing = client.listObjects(
                b -> b.bucket(containerName));
        assertThat(listing.contents()).hasSize(1);
        assertThat(listing.contents().get(0).key()).isEqualTo(blobName);
    }

    @Test
    public void testSpecialCharacters() throws Exception {
        // TODO: fixed in jclouds 2.6.1
        assumeTrue(blobStoreEndpoint.getPort() != MINIO_PORT);
        assumeTrue(blobStoreEndpoint.getPort() != LOCALSTACK_PORT);

        String prefix = "special !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
        if (blobStoreType.equals("azureblob-sdk")) {
            prefix = prefix.replace("\\", "");
            // Avoid blob names that end with a dot (.), a forward slash (/), or
            // a sequence or combination of the two.
            prefix = prefix.replace("./", "/") + ".";
        }
        String blobName = prefix + "foo";
        putBlob(containerName, blobName, BYTE_SOURCE);

        String prefixForList = prefix;
        ListObjectsResponse listing = client.listObjects(
                b -> b.bucket(containerName).prefix(prefixForList));
        assertThat(listing.contents()).hasSize(1);
        assertThat(listing.contents().get(0).key()).isEqualTo(blobName);
    }

    @Test
    public void testAtomicMpuAbort() throws Exception {
        String key = "testAtomicMpuAbort";
        putBlob(containerName, key, BYTE_SOURCE);

        CreateMultipartUploadResponse initResponse = client.createMultipartUpload(
                b -> b.bucket(containerName).key(key));
        String uploadId = initResponse.uploadId();

        client.abortMultipartUpload(b -> b
                .bucket(containerName).key(key).uploadId(uploadId));

        try (ResponseInputStream<GetObjectResponse> object = client.getObject(
                b -> b.bucket(containerName).key(key))) {
            assertThat(object.response().contentLength()).isEqualTo(
                    BYTE_SOURCE.size());
            try (InputStream expected = BYTE_SOURCE.openStream()) {
                assertThat((InputStream) object).hasSameContentAs(expected);
            }
        }
    }

    @Test
    public void testMultipartStubHiddenFromList() throws Exception {
        // An in-progress multipart upload must not expose its internal stub
        // blob via ListObjects, matching S3 semantics where multipart
        // internals are not visible until the upload completes.  Only
        // MULTIPART_REQUIRES_STUB backends store the stub via S3ProxyHandler
        // and hide it from list(); the *-sdk backends track multipart state
        // internally.
        assumeTrue(Quirks.MULTIPART_REQUIRES_STUB.contains(blobStoreType));
        String key = UUID.randomUUID().toString();
        CreateMultipartUploadResponse initResponse =
                client.createMultipartUpload(
                        b -> b.bucket(containerName).key(key));
        String uploadId = initResponse.uploadId();

        ListObjectsResponse listing = client.listObjects(
                b -> b.bucket(containerName));
        assertThat(listing.contents()).isEmpty();

        ListObjectsV2Response listingV2 = client.listObjectsV2(
                b -> b.bucket(containerName));
        assertThat(listingV2.keyCount()).isEqualTo(0);
        assertThat(listingV2.contents()).isEmpty();

        client.abortMultipartUpload(b -> b
                .bucket(containerName).key(key).uploadId(uploadId));
    }

    @Test
    public void testListPaginationHidesMultipartSegments() throws Exception {
        // The Swift backend stores in-progress multipart segments and markers
        // under a reserved ".s3proxy-mpu/" prefix that list() hides.  These
        // sort before ordinary keys, so a whole listing page can consist
        // entirely of hidden objects; pagination must skip past them instead
        // of terminating early and hiding the real objects that follow.
        assumeTrue(blobStoreType.equals("openstack-swift-sdk"));

        String key = "multipart-in-progress";
        long partSize = MINIMUM_MULTIPART_SIZE;
        ByteSource part = TestUtils.randomByteSource().slice(0, partSize);
        CreateMultipartUploadResponse initResponse =
                client.createMultipartUpload(
                        b -> b.bucket(containerName).key(key));
        String uploadId = initResponse.uploadId();
        for (int partNumber = 1; partNumber <= 2; ++partNumber) {
            int number = partNumber;
            client.uploadPart(b -> b.bucket(containerName).key(key)
                    .uploadId(uploadId).partNumber(number),
                    RequestBody.fromInputStream(part.openStream(),
                            part.size()));
        }

        // Real objects that all sort after the hidden multipart internals.
        List<String> expected = List.of("obj-a", "obj-b", "obj-c");
        for (String name : expected) {
            putBlob(containerName, name, BYTE_SOURCE);
        }

        // Page one key at a time so early pages hold only hidden segments.
        List<String> seen = new ArrayList<>();
        String continuationToken = null;
        do {
            String token = continuationToken;
            ListObjectsV2Response listing = client.listObjectsV2(b -> {
                b.bucket(containerName).maxKeys(1);
                if (token != null) {
                    b.continuationToken(token);
                }
            });
            for (S3Object object : listing.contents()) {
                assertThat(object.key()).doesNotStartWith(".s3proxy-mpu");
                seen.add(object.key());
            }
            continuationToken = Boolean.TRUE.equals(listing.isTruncated()) ?
                    listing.nextContinuationToken() : null;
        } while (continuationToken != null);

        assertThat(seen).containsExactlyElementsOf(expected);

        client.abortMultipartUpload(b -> b
                .bucket(containerName).key(key).uploadId(uploadId));
    }

    @Test
    public void testOverrideResponseHeader() throws Exception {
        String blobName = "foo";
        putBlob(containerName, blobName, BYTE_SOURCE);

        String cacheControl = "no-cache";
        String contentDisposition = "attachment; filename=foo.html";
        String contentEncoding = "gzip";
        String contentLanguage = "en";
        String contentType = "text/html;charset=utf-8";
        String expires = "Wed, 13 Jul 2016 21:23:51 GMT";
        long expiresTime = 1468445031000L;

        try (ResponseInputStream<GetObjectResponse> object = client.getObject(
                b -> b.bucket(containerName).key(blobName)
                        .responseCacheControl(cacheControl)
                        .responseContentDisposition(contentDisposition)
                        .responseContentEncoding(contentEncoding)
                        .responseContentLanguage(contentLanguage)
                        .responseContentType(contentType)
                        .responseExpires(java.time.Instant.ofEpochMilli(
                                expiresTime)))) {
            assertThat((InputStream) object).isNotNull();
            object.transferTo(OutputStream.nullOutputStream());

            GetObjectResponse meta = object.response();
            assertThat(meta.cacheControl()).isEqualTo(cacheControl);
            assertThat(meta.contentDisposition()).isEqualTo(contentDisposition);
            assertThat(meta.contentEncoding()).isEqualTo(contentEncoding);
            assertThat(meta.contentLanguage()).isEqualTo(contentLanguage);
            assertThat(meta.contentType()).isEqualTo(contentType);
            assertThat(meta.expiresString()).isEqualTo(expires);
        }
    }

    @Test
    public void testDeleteMultipleObjectsEmpty() throws Exception {
        try {
            client.deleteObjects(b -> b.bucket(containerName)
                    .delete(d -> d.objects(List.of())));
            Fail.failBecauseExceptionWasNotThrown(S3Exception.class);
        } catch (S3Exception e) {
            assertThat(e.awsErrorDetails().errorCode())
                    .isEqualTo("MalformedXML");
        }
    }

    @Test
    public void testDeleteMultipleObjects() throws Exception {
        String blobName = "foo";

        // without quiet
        putBlob(containerName, blobName, BYTE_SOURCE);

        var result = client.deleteObjects(b -> b.bucket(containerName)
                .delete(d -> d.objects(
                        ObjectIdentifier.builder().key(blobName).build())));
        assertThat(result.deleted()).hasSize(1);
        assertThat(result.deleted().iterator().next().key()).isEqualTo(blobName);

        // with quiet
        putBlob(containerName, blobName, BYTE_SOURCE);

        result = client.deleteObjects(b -> b.bucket(containerName)
                .delete(d -> d.objects(
                        ObjectIdentifier.builder().key(blobName).build())
                        .quiet(true)));
        assertThat(result.deleted()).isEmpty();
    }

    @Test
    public void testPartNumberMarker() throws Exception {
        String blobName = "test-part-number-marker";
        CreateMultipartUploadResponse result = client.createMultipartUpload(
                b -> b.bucket(containerName).key(blobName));

        client.listParts(b -> b.bucket(containerName).key(blobName)
                .uploadId(result.uploadId()).partNumberMarker(0));

        try {
            client.listParts(b -> b.bucket(containerName).key(blobName)
                    .uploadId(result.uploadId()).partNumberMarker(1));
            Fail.failBecauseExceptionWasNotThrown(S3Exception.class);
        } catch (S3Exception e) {
            assertThat(e.awsErrorDetails().errorCode())
                    .isEqualTo("NotImplemented");
        } finally {
            client.abortMultipartUpload(b -> b.bucket(containerName)
                    .key(blobName).uploadId(result.uploadId()));
        }
    }

    @Test
    public void testHttpClient() throws Exception {
        // jclouds HttpClient is no longer available; skip this test
        assumeTrue(false);
    }

    @Test
    public void testListBuckets() throws Exception {
        var builder = ImmutableList.<String>builder();
        client.listBuckets().buckets()
                .forEach(b -> builder.add(b.name()));
        assertThat(builder.build()).contains(containerName);
    }

    @Test
    public void testContainerExists() throws Exception {
        client.headBucket(b -> b.bucket(containerName));
        try {
            client.headBucket(b -> b.bucket(createRandomContainerName()));
            Fail.failBecauseExceptionWasNotThrown(NoSuchBucketException.class);
        } catch (NoSuchBucketException e) {
            // expected
        } catch (S3Exception e) {
            // some backends return a generic 404 instead of NoSuchBucket
            assertThat(e.statusCode()).isEqualTo(404);
        }
    }

    @Test
    public void testContainerCreateDelete() throws Exception {
        assumeTrue(blobStoreEndpoint.getPort() != LOCALSTACK_PORT);
        // LocalStack in us-east-1 returns 200 OK for duplicate bucket creation (legacy S3 behavior)
        // https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateBucket.html
        assumeTrue(!blobStoreType.equals("aws-s3-sdk"));
        String containerName2 = createRandomContainerName();
        client.createBucket(b -> b.bucket(containerName2));
        try {
            client.createBucket(b -> b.bucket(containerName2));
            client.deleteBucket(b -> b.bucket(containerName2));
            Fail.failBecauseExceptionWasNotThrown(S3Exception.class);
        } catch (S3Exception e) {
            assertThat(e.awsErrorDetails().errorCode())
                    .isEqualTo("BucketAlreadyOwnedByYou");
        }
    }

    @Test
    public void testContainerDelete() throws Exception {
        client.headBucket(b -> b.bucket(containerName));
        client.deleteBucket(b -> b.bucket(containerName));
        try {
            client.headBucket(b -> b.bucket(containerName));
            Fail.failBecauseExceptionWasNotThrown(NoSuchBucketException.class);
        } catch (NoSuchBucketException e) {
            // expected
        } catch (S3Exception e) {
            assertThat(e.statusCode()).isEqualTo(404);
        }
    }

    private void putBlobAndCheckIt(String blobName) throws Exception {
        putBlob(containerName, blobName, BYTE_SOURCE);

        try (ResponseInputStream<GetObjectResponse> object = client.getObject(
                b -> b.bucket(containerName).key(blobName))) {
            try (InputStream expected = BYTE_SOURCE.openStream()) {
                assertThat((InputStream) object).hasSameContentAs(expected);
            }
        }
    }

    @Test
    public void testBlobPutGet() throws Exception {
        putBlobAndCheckIt("blob");
        putBlobAndCheckIt("blob%");
        putBlobAndCheckIt("blob%%");
    }

    @Test
    public void testBlobEscape() throws Exception {
        ListObjectsResponse listing = client.listObjects(
                b -> b.bucket(containerName));
        assertThat(listing.contents()).isEmpty();

        putBlobAndCheckIt("blob%");

        listing = client.listObjects(b -> b.bucket(containerName));
        assertThat(listing.contents()).hasSize(1);
        assertThat(listing.contents().iterator().next().key())
                .isEqualTo("blob%");
    }

    @Test
    public void testBlobList() throws Exception {
        ListObjectsResponse listing = client.listObjects(
                b -> b.bucket(containerName));
        assertThat(listing.contents()).isEmpty();

        var builder = ImmutableList.<String>builder();
        putBlob(containerName, "blob1", BYTE_SOURCE);
        listing = client.listObjects(b -> b.bucket(containerName));
        listing.contents().forEach(o -> builder.add(o.key()));
        assertThat(builder.build()).containsOnly("blob1");

        var builder2 = ImmutableList.<String>builder();
        putBlob(containerName, "blob2", BYTE_SOURCE);
        listing = client.listObjects(b -> b.bucket(containerName));
        listing.contents().forEach(o -> builder2.add(o.key()));
        assertThat(builder2.build()).containsOnly("blob1", "blob2");
    }

    @Test
    public void testBlobListRecursive() throws Exception {
        ListObjectsResponse listing = client.listObjects(
                b -> b.bucket(containerName));
        assertThat(listing.contents()).isEmpty();

        putBlob(containerName, "prefix/blob1", BYTE_SOURCE);
        putBlob(containerName, "prefix/blob2", BYTE_SOURCE);

        var builder = ImmutableList.<String>builder();
        listing = client.listObjects(b -> b.bucket(containerName)
                .delimiter("/"));
        assertThat(listing.contents()).isEmpty();
        listing.commonPrefixes().forEach(cp -> builder.add(cp.prefix()));
        assertThat(builder.build()).containsOnly("prefix/");

        var builder2 = ImmutableList.<String>builder();
        listing = client.listObjects(b -> b.bucket(containerName));
        listing.contents().forEach(o -> builder2.add(o.key()));
        assertThat(builder2.build()).containsOnly("prefix/blob1",
                "prefix/blob2");
        assertThat(listing.commonPrefixes()).isEmpty();
    }

    @Test
    public void testBlobListRecursiveImplicitMarker() throws Exception {
        assumeTrue(!Quirks.OPAQUE_MARKERS.contains(blobStoreType));

        ListObjectsResponse listing = client.listObjects(
                b -> b.bucket(containerName));
        assertThat(listing.contents()).isEmpty();

        putBlob(containerName, "blob1", BYTE_SOURCE);
        putBlob(containerName, "blob2", BYTE_SOURCE);

        listing = client.listObjects(b -> b.bucket(containerName).maxKeys(1));
        assertThat(listing.contents()).hasSize(1);
        assertThat(listing.contents().iterator().next().key()).isEqualTo("blob1");

        listing = client.listObjects(b -> b.bucket(containerName).maxKeys(1)
                .marker("blob1"));
        assertThat(listing.contents()).hasSize(1);
        assertThat(listing.contents().iterator().next().key()).isEqualTo("blob2");
    }

    @Test
    public void testBlobListV2() throws Exception {
        assumeTrue(!Quirks.OPAQUE_MARKERS.contains(blobStoreType));

        for (int i = 1; i < 5; ++i) {
            putBlob(containerName, String.valueOf(i), BYTE_SOURCE);
        }

        ListObjectsV2Response result = client.listObjectsV2(b -> b
                .bucket(containerName).maxKeys(1).startAfter("1"));
        assertThat(result.continuationToken()).isNullOrEmpty();
        assertThat(result.startAfter()).isEqualTo("1");
        if (blobStoreEndpoint.getPort() != MINIO_PORT) {
            // Minio returns "2[minio_cache:v2,return:]"
            assertThat(result.nextContinuationToken()).isEqualTo("2");
        }
        assertThat(result.isTruncated()).isTrue();
        assertThat(result.contents()).hasSize(1);
        assertThat(result.contents().get(0).key()).isEqualTo("2");

        String nextToken = result.nextContinuationToken();
        result = client.listObjectsV2(b -> b.bucket(containerName).maxKeys(1)
                .continuationToken(nextToken));
        if (blobStoreEndpoint.getPort() != MINIO_PORT) {
            // Minio returns "2[minio_cache:v2,return:]"
            assertThat(result.continuationToken()).isEqualTo("2");
            assertThat(result.nextContinuationToken()).isEqualTo("3");
        }
        assertThat(result.startAfter()).isNullOrEmpty();
        assertThat(result.isTruncated()).isTrue();
        assertThat(result.contents()).hasSize(1);
        assertThat(result.contents().get(0).key()).isEqualTo("3");

        String nextToken2 = result.nextContinuationToken();
        result = client.listObjectsV2(b -> b.bucket(containerName).maxKeys(1)
                .continuationToken(nextToken2));
        if (blobStoreEndpoint.getPort() != MINIO_PORT) {
            // Minio returns "3[minio_cache:v2,return:]"
            assertThat(result.continuationToken()).isEqualTo("3");
            assertThat(result.nextContinuationToken()).isNull();
        }
        assertThat(result.startAfter()).isNullOrEmpty();
        if (blobStoreEndpoint.getPort() != MINIO_PORT) {
            // TODO: why does this fail?
            assertThat(result.isTruncated()).isFalse();
        }
        assertThat(result.contents()).hasSize(1);
        assertThat(result.contents().get(0).key()).isEqualTo("4");
    }

    @Test
    public void testBlobMetadata() throws Exception {
        String blobName = "blob";
        putBlob(containerName, blobName, BYTE_SOURCE);

        HeadObjectResponse newMetadata = client.headObject(
                b -> b.bucket(containerName).key(blobName));
        assertThat(newMetadata.contentLength())
                .isEqualTo(BYTE_SOURCE.size());
    }

    @Test
    public void testBlobRemove() throws Exception {
        String blobName = "blob";
        putBlob(containerName, blobName, BYTE_SOURCE);
        assertThat(client.headObject(
                b -> b.bucket(containerName).key(blobName))).isNotNull();

        client.deleteObject(b -> b.bucket(containerName).key(blobName));
        try {
            client.headObject(b -> b.bucket(containerName).key(blobName));
            Fail.failBecauseExceptionWasNotThrown(NoSuchKeyException.class);
        } catch (NoSuchKeyException e) {
            // expected
        } catch (S3Exception e) {
            assertThat(e.statusCode()).isEqualTo(404);
        }

        client.deleteObject(b -> b.bucket(containerName).key(blobName));
    }

    @Test
    public void testDirectoryMarkerWithoutTrailingSlash() throws Exception {
        // Real S3 distinguishes "foo" from "foo/" as literal keys. The
        // nio2blob backends use POSIX paths and used to conflate them.
        assumeTrue(blobStoreType.equals("filesystem-nio2") ||
                blobStoreType.equals("transient-nio2"));

        String dirName = "testrun-7560";
        String marker = dirName + "/";
        client.putObject(b -> b.bucket(containerName).key(marker),
                RequestBody.empty());

        // sanity: HEAD/GET on the marker itself works
        assertThat(client.headObject(
                b -> b.bucket(containerName).key(marker))).isNotNull();

        // HEAD without trailing slash must 404
        try {
            client.headObject(b -> b.bucket(containerName).key(dirName));
            Fail.failBecauseExceptionWasNotThrown(NoSuchKeyException.class);
        } catch (NoSuchKeyException e) {
            // expected
        } catch (S3Exception e) {
            assertThat(e.statusCode()).isEqualTo(404);
        }

        // GET without trailing slash must 404
        try {
            client.getObject(b -> b.bucket(containerName).key(dirName));
            Fail.failBecauseExceptionWasNotThrown(NoSuchKeyException.class);
        } catch (NoSuchKeyException e) {
            // expected
        } catch (S3Exception e) {
            assertThat(e.statusCode()).isEqualTo(404);
        }

        // CopyObject with non-slash source must 404
        try {
            client.copyObject(b -> b.sourceBucket(containerName)
                    .sourceKey(dirName)
                    .destinationBucket(containerName)
                    .destinationKey("copy-dest"));
            Fail.failBecauseExceptionWasNotThrown(NoSuchKeyException.class);
        } catch (NoSuchKeyException e) {
            // expected
        } catch (S3Exception e) {
            assertThat(e.statusCode()).isEqualTo(404);
        }

        // DELETE without trailing slash must NOT remove the marker.
        // (S3 DeleteObject is idempotent, so the call itself succeeds.)
        client.deleteObject(b -> b.bucket(containerName).key(dirName));
        assertThat(client.headObject(
                b -> b.bucket(containerName).key(marker))).isNotNull();
    }

    @Test
    public void testDeleteDirectoryMarkerWithContents() throws Exception {
        // Deleting a directory-marker key whose directory still holds objects
        // must succeed and remove only the marker, not fail with 500 because
        // the underlying directory is non-empty.
        assumeTrue(blobStoreType.equals("filesystem-nio2") ||
                blobStoreType.equals("transient-nio2"));

        String marker = "testdir-9142/";
        client.putObject(b -> b.bucket(containerName).key(marker),
                RequestBody.empty());
        putBlob(containerName, marker + "child", BYTE_SOURCE);

        // Deleting the marker succeeds even though the directory is non-empty.
        client.deleteObject(b -> b.bucket(containerName).key(marker));

        // The marker object is gone...
        try {
            client.headObject(b -> b.bucket(containerName).key(marker));
            Fail.failBecauseExceptionWasNotThrown(NoSuchKeyException.class);
        } catch (NoSuchKeyException e) {
            // expected
        } catch (S3Exception e) {
            assertThat(e.statusCode()).isEqualTo(404);
        }

        // ...but the object beneath it remains.
        assertThat(client.headObject(
                b -> b.bucket(containerName).key(marker + "child")))
                .isNotNull();
    }

    @Test
    public void testDirectoryMarkerListMetadata() throws Exception {
        // Per the S3 API every <Contents> entry in a ListObjects(V1/V2)
        // response must carry <Size>, <LastModified> and <ETag>, even for a
        // "directory placeholder" key (one ending in "/"). The nio2 backends
        // used to omit them for such keys, so spec-abiding clients (e.g.
        // Hadoop's S3A connector) read a null/absent size and NPE.
        assumeTrue(blobStoreType.equals("filesystem-nio2") ||
                blobStoreType.equals("transient-nio2"));

        String marker = "dir-marker/";
        client.putObject(b -> b.bucket(containerName).key(marker),
                RequestBody.empty());

        // sanity: the server knows the marker's size via HEAD
        assertThat(client.headObject(
                b -> b.bucket(containerName).key(marker)).contentLength())
                .isEqualTo(0L);

        // ListObjectsV2 must report Size/LastModified/ETag for the marker.
        ListObjectsV2Response v2 = client.listObjectsV2(
                b -> b.bucket(containerName));
        S3Object v2Marker = v2.contents().stream()
                .filter(o -> o.key().equals(marker))
                .findFirst().orElse(null);
        assertThat(v2Marker).isNotNull();
        assertThat(v2Marker.size()).isEqualTo(0L);
        assertThat(v2Marker.lastModified()).isNotNull();
        assertThat(v2Marker.eTag()).isNotBlank();

        // ListObjects (v1) must do the same.
        ListObjectsResponse v1 = client.listObjects(
                b -> b.bucket(containerName));
        S3Object v1Marker = v1.contents().stream()
                .filter(o -> o.key().equals(marker))
                .findFirst().orElse(null);
        assertThat(v1Marker).isNotNull();
        assertThat(v1Marker.size()).isEqualTo(0L);
        assertThat(v1Marker.lastModified()).isNotNull();
        assertThat(v1Marker.eTag()).isNotBlank();
    }

    @Test
    public void testDirectoryMarkerListSelfPrefix() throws Exception {
        // Listing with a prefix equal to a directory-marker key
        // ("dir-marker/") must return that marker object itself, exactly as
        // real S3 returns keys >= prefix that start with the prefix. Hadoop
        // S3A's empty-directory probe (list prefix="<dir>/" delimiter="/")
        // relies on this; otherwise getFileStatus(<dir>) throws
        // FileNotFoundException, breaking HBase bulk load.
        assumeTrue(blobStoreType.equals("filesystem-nio2") ||
                blobStoreType.equals("transient-nio2"));

        String marker = "dir-marker/";
        client.putObject(b -> b.bucket(containerName).key(marker),
                RequestBody.empty());

        // The key equals the prefix, so its remainder after the prefix is
        // empty and it belongs in <Contents>, not <CommonPrefixes>.
        ListObjectsV2Response v2 = client.listObjectsV2(b -> b
                .bucket(containerName).prefix(marker).delimiter("/"));
        S3Object v2Self = v2.contents().stream()
                .filter(o -> o.key().equals(marker))
                .findFirst().orElse(null);
        assertThat(v2Self).isNotNull();
        assertThat(v2Self.size()).isEqualTo(0L);

        // ListObjects (v1) with the same prefix must do the same.
        ListObjectsResponse v1 = client.listObjects(b -> b
                .bucket(containerName).prefix(marker).delimiter("/"));
        S3Object v1Self = v1.contents().stream()
                .filter(o -> o.key().equals(marker))
                .findFirst().orElse(null);
        assertThat(v1Self).isNotNull();
        assertThat(v1Self.size()).isEqualTo(0L);
    }

    @Test
    public void testSlashKeyIsDistinctObject() throws Exception {
        // Real S3 accepts "/" as a legitimate object key distinct from the
        // bucket. In the nio2 backends "/" resolves to the filesystem root, so
        // it is stored under a reserved child rather than being munged onto
        // the container directory (which previously let DELETE/PUT of "/"
        // mutate the bucket). s3fs-fuse depends on this: touching the mount
        // point PUTs the bucket-root directory marker whose key is "/".
        //
        // Driven at the BlobStore layer: a key of "/" produces a "//" request
        // path whose empty segment the AWS SDK's SigV4 canonicalization signs
        // incompatibly (a client artifact, not a server behavior), so it 403s
        // before reaching the backend. The s3fs integration test covers the
        // end-to-end HTTP path with a client that signs "//" correctly.
        assumeTrue(blobStoreType.equals("filesystem-nio2") ||
                blobStoreType.equals("transient-nio2"));

        blobStore.putBlob(containerName, Blob.builder("sibling.txt")
                .payload(ByteSource.wrap(new byte[4])).build(),
                        PutOptions.NONE);

        // PUT key "/" as a 0-byte directory marker with user metadata,
        // mimicking an s3fs mount-point stamp.
        blobStore.putBlob(containerName, Blob.builder("/")
                .payload(ByteSource.empty())
                .userMetadata(Map.of("mode", "16832"))
                .build(), PutOptions.NONE);

        // The bucket and the unrelated object survive the PUT.
        assertThat(blobStore.containerExists(containerName)).isTrue();
        assertThat(blobStore.blobExists(containerName, "sibling.txt")).isTrue();

        // "/" round-trips as its own distinct 0-byte object with the metadata.
        var meta = blobStore.blobMetadata(containerName, "/");
        assertThat(meta).isNotNull();
        assertThat(meta.contentMetadata().contentLength()).isEqualTo(0L);
        assertThat(meta.userMetadata()).containsEntry("mode", "16832");

        // The reserved backing store is hidden: "/" is not enumerated.
        ListObjectsV2Response list = client.listObjectsV2(
                b -> b.bucket(containerName));
        assertThat(list.contents().stream().map(S3Object::key))
                .containsExactly("sibling.txt");

        // DELETE "/" removes only that object, never the bucket or the sibling.
        blobStore.removeBlob(containerName, "/");
        assertThat(blobStore.containerExists(containerName)).isTrue();
        assertThat(blobStore.blobExists(containerName, "sibling.txt")).isTrue();
        assertThat(blobStore.blobMetadata(containerName, "/")).isNull();
    }

    @Test
    public void testSlashKeyDeleteDoesNotDeleteEmptyBucket() throws Exception {
        // The original vulnerability: DELETE bucket/%2F ran
        // Files.delete(containerPath) and silently removed an empty bucket.
        // Removing key "/" must be an idempotent no-op on the empty bucket.
        assumeTrue(blobStoreType.equals("filesystem-nio2") ||
                blobStoreType.equals("transient-nio2"));

        blobStore.removeBlob(containerName, "/");
        assertThat(blobStore.containerExists(containerName)).isTrue();
    }

    @Test
    public void testSlashKeyAccessIsolatedFromContainer() throws Exception {
        // A blob ACL and a container ACL are both the OTHERS_READ POSIX bit on
        // their respective paths. If "/" aliased the container directory,
        // get/setBlobAccess("/") would read and write the bucket ACL. The
        // reserved backing store keeps the two independent.
        assumeTrue(blobStoreType.equals("filesystem-nio2") ||
                blobStoreType.equals("transient-nio2"));

        blobStore.putBlob(containerName, Blob.builder("/")
                .payload(ByteSource.empty()).build(), PutOptions.NONE);

        blobStore.setContainerAccess(containerName,
                ContainerAccess.PUBLIC_READ);
        // Skip on filesystems that cannot represent POSIX permissions; there
        // the ACL bit does not exist and there is nothing to isolate.
        assumeTrue(blobStore.getContainerAccess(containerName) ==
                ContainerAccess.PUBLIC_READ);

        // Making the "/" object private must not touch the bucket ACL.
        blobStore.setBlobAccess(containerName, "/", BlobAccess.PRIVATE);
        assertThat(blobStore.getContainerAccess(containerName))
                .isEqualTo(ContainerAccess.PUBLIC_READ);
        assertThat(blobStore.getBlobAccess(containerName, "/"))
                .isEqualTo(BlobAccess.PRIVATE);

        // And the reverse: bucket private, "/" object public.
        blobStore.setContainerAccess(containerName, ContainerAccess.PRIVATE);
        blobStore.setBlobAccess(containerName, "/", BlobAccess.PUBLIC_READ);
        assertThat(blobStore.getContainerAccess(containerName))
                .isEqualTo(ContainerAccess.PRIVATE);
        assertThat(blobStore.getBlobAccess(containerName, "/"))
                .isEqualTo(BlobAccess.PUBLIC_READ);
    }

    @Test
    public void testReservedSlashBlobNameRejected() throws Exception {
        // The reserved name backing "/" must not be addressable as an ordinary
        // key, or a client could interfere with the "/" object's storage.
        assumeTrue(blobStoreType.equals("filesystem-nio2") ||
                blobStoreType.equals("transient-nio2"));

        try {
            client.putObject(
                    b -> b.bucket(containerName).key(".s3proxy-slash"),
                    RequestBody.fromString("x"));
            Fail.failBecauseExceptionWasNotThrown(S3Exception.class);
        } catch (S3Exception e) {
            assertThat(e.statusCode()).isEqualTo(400);
        }
    }

    @Test
    public void testSinglepartUploadJettyCachedHeader() throws Exception {
        String blobName = "singlepart-upload-jetty-cached";
        String contentType = "text/plain";

        client.putObject(b -> b.bucket(containerName).key(blobName)
                        .contentType(contentType),
                RequestBody.fromInputStream(BYTE_SOURCE.openStream(),
                        BYTE_SOURCE.size()));

        try (ResponseInputStream<GetObjectResponse> object = client.getObject(
                b -> b.bucket(containerName).key(blobName))) {
            try (InputStream expected = BYTE_SOURCE.openStream()) {
                assertThat((InputStream) object).hasSameContentAs(expected);
            }
            assertThat(object.response().contentType()).isEqualTo(contentType);
        }
    }

    @Test
    public void testSinglepartUpload() throws Exception {
        String blobName = "singlepart-upload";
        String cacheControl = "max-age=3600";
        String contentDisposition = "attachment; filename=new.jpg";
        String contentEncoding = "gzip";
        String contentLanguage = "fr";
        String contentType = "audio/mp4";
        var userMetadata = Map.of(
                "key1", "value1",
                "key2", "value2");

        client.putObject(b -> {
            b.bucket(containerName).key(blobName).contentType(contentType)
                    .metadata(userMetadata);
            if (!Quirks.NO_CACHE_CONTROL_SUPPORT.contains(blobStoreType)) {
                b.cacheControl(cacheControl);
            }
            if (!Quirks.NO_CONTENT_DISPOSITION.contains(blobStoreType)) {
                b.contentDisposition(contentDisposition);
            }
            if (!Quirks.NO_CONTENT_ENCODING.contains(blobStoreType)) {
                b.contentEncoding(contentEncoding);
            }
            if (!Quirks.NO_CONTENT_LANGUAGE.contains(blobStoreType)) {
                b.contentLanguage(contentLanguage);
            }
        }, RequestBody.fromInputStream(BYTE_SOURCE.openStream(),
                BYTE_SOURCE.size()));

        try (ResponseInputStream<GetObjectResponse> object = client.getObject(
                b -> b.bucket(containerName).key(blobName))) {
            try (InputStream expected = BYTE_SOURCE.openStream()) {
                assertThat((InputStream) object).hasSameContentAs(expected);
            }
            GetObjectResponse meta = object.response();
            if (!Quirks.NO_CACHE_CONTROL_SUPPORT.contains(blobStoreType)) {
                assertThat(meta.cacheControl()).isEqualTo(cacheControl);
            }
            if (!Quirks.NO_CONTENT_DISPOSITION.contains(blobStoreType)) {
                assertThat(meta.contentDisposition()).isEqualTo(
                        contentDisposition);
            }
            if (!Quirks.NO_CONTENT_ENCODING.contains(blobStoreType)) {
                assertThat(meta.contentEncoding()).isEqualTo(contentEncoding);
            }
            if (!Quirks.NO_CONTENT_LANGUAGE.contains(blobStoreType)) {
                assertThat(meta.contentLanguage()).isEqualTo(contentLanguage);
            }
            assertThat(meta.contentType()).isEqualTo(contentType);
            assertThat(meta.metadata()).isEqualTo(userMetadata);
        }
    }

    // TODO: fails for GCS (jclouds not implemented)
    @Test
    public void testMultipartUpload() throws Exception {
        String blobName = "multipart-upload";
        String cacheControl = "max-age=3600";
        String contentDisposition = "attachment; filename=new.jpg";
        String contentEncoding = "gzip";
        String contentLanguage = "fr";
        String contentType = "audio/mp4";
        var userMetadata = Map.of(
                "key1", "value1",
                "key2", "value2");

        CreateMultipartUploadResponse result = client.createMultipartUpload(
                b -> {
                    b.bucket(containerName).key(blobName)
                            .contentType(contentType).metadata(userMetadata);
                    if (!Quirks.NO_CACHE_CONTROL_SUPPORT.contains(
                            blobStoreType)) {
                        b.cacheControl(cacheControl);
                    }
                    if (!Quirks.NO_CONTENT_DISPOSITION.contains(blobStoreType)) {
                        b.contentDisposition(contentDisposition);
                    }
                    if (!Quirks.NO_CONTENT_ENCODING.contains(blobStoreType)) {
                        b.contentEncoding(contentEncoding);
                    }
                    if (!Quirks.NO_CONTENT_LANGUAGE.contains(blobStoreType)) {
                        b.contentLanguage(contentLanguage);
                    }
                });

        ByteSource byteSource = TestUtils.randomByteSource().slice(
                0, MINIMUM_MULTIPART_SIZE + 1);
        ByteSource byteSource1 = byteSource.slice(0, MINIMUM_MULTIPART_SIZE);
        ByteSource byteSource2 = byteSource.slice(MINIMUM_MULTIPART_SIZE, 1);
        UploadPartResponse part1 = client.uploadPart(b -> b
                .bucket(containerName).key(blobName)
                .uploadId(result.uploadId()).partNumber(1),
                RequestBody.fromInputStream(byteSource1.openStream(),
                        byteSource1.size()));
        UploadPartResponse part2 = client.uploadPart(b -> b
                .bucket(containerName).key(blobName)
                .uploadId(result.uploadId()).partNumber(2),
                RequestBody.fromInputStream(byteSource2.openStream(),
                        byteSource2.size()));

        client.completeMultipartUpload(b -> b
                .bucket(containerName).key(blobName)
                .uploadId(result.uploadId())
                .multipartUpload(CompletedMultipartUpload.builder()
                        .parts(
                                CompletedPart.builder().partNumber(1)
                                        .eTag(part1.eTag()).build(),
                                CompletedPart.builder().partNumber(2)
                                        .eTag(part2.eTag()).build())
                        .build()));
        ListObjectsResponse listing = client.listObjects(
                b -> b.bucket(containerName));
        assertThat(listing.contents()).hasSize(1);

        try (ResponseInputStream<GetObjectResponse> object = client.getObject(
                b -> b.bucket(containerName).key(blobName))) {
            try (InputStream expected = byteSource.openStream()) {
                assertThat((InputStream) object).hasSameContentAs(expected);
            }
            GetObjectResponse meta = object.response();
            if (!Quirks.NO_CACHE_CONTROL_SUPPORT.contains(blobStoreType)) {
                assertThat(meta.cacheControl()).isEqualTo(cacheControl);
            }
            if (!Quirks.NO_CONTENT_DISPOSITION.contains(blobStoreType)) {
                assertThat(meta.contentDisposition()).isEqualTo(
                        contentDisposition);
            }
            if (!Quirks.NO_CONTENT_ENCODING.contains(blobStoreType)) {
                assertThat(meta.contentEncoding()).isEqualTo(contentEncoding);
            }
            if (!Quirks.NO_CONTENT_LANGUAGE.contains(blobStoreType)) {
                assertThat(meta.contentLanguage()).isEqualTo(contentLanguage);
            }
            assertThat(meta.contentType()).isEqualTo(contentType);
            assertThat(meta.metadata()).isEqualTo(userMetadata);
        }
    }

    // this test runs for several minutes
    @Disabled
    @Test
    public void testMaximumMultipartUpload() throws Exception {
        // skip with remote blobstores to avoid excessive run-times
        assumeTrue(blobStoreType.equals("filesystem-nio2") ||
                blobStoreType.equals("transient-nio2"));

        String blobName = "multipart-upload";
        int numParts = 32;
        long partSize = MINIMUM_MULTIPART_SIZE;
        ByteSource byteSource = TestUtils.randomByteSource().slice(
                0, partSize * numParts);

        CreateMultipartUploadResponse result = client.createMultipartUpload(
                b -> b.bucket(containerName).key(blobName));
        var parts = ImmutableList.<CompletedPart>builder();

        for (int i = 0; i < numParts; ++i) {
            ByteSource partByteSource = byteSource.slice(
                    i * partSize, partSize);
            int partNumber = i + 1;
            UploadPartResponse partResult = client.uploadPart(b -> b
                    .bucket(containerName).key(blobName)
                    .uploadId(result.uploadId()).partNumber(partNumber),
                    RequestBody.fromInputStream(partByteSource.openStream(),
                            partByteSource.size()));
            parts.add(CompletedPart.builder().partNumber(partNumber)
                    .eTag(partResult.eTag()).build());
        }

        client.completeMultipartUpload(b -> b
                .bucket(containerName).key(blobName)
                .uploadId(result.uploadId())
                .multipartUpload(CompletedMultipartUpload.builder()
                        .parts(parts.build()).build()));
        ListObjectsResponse listing = client.listObjects(
                b -> b.bucket(containerName));
        assertThat(listing.contents()).hasSize(1);

        try (ResponseInputStream<GetObjectResponse> object = client.getObject(
                b -> b.bucket(containerName).key(blobName))) {
            assertThat(object.response().contentLength()).isEqualTo(
                    partSize * numParts);
            try (InputStream expected = byteSource.openStream()) {
                assertThat((InputStream) object).hasSameContentAs(expected);
            }
        }
    }

    @Test
    public void testMultipartUploadAbort() throws Exception {
        // TODO: fixed in jclouds 2.6.1
        assumeTrue(blobStoreEndpoint.getPort() != MINIO_PORT);

        String blobName = "multipart-upload-abort";
        ByteSource byteSource = TestUtils.randomByteSource().slice(
                0, MINIMUM_MULTIPART_SIZE);

        CreateMultipartUploadResponse result = client.createMultipartUpload(
                b -> b.bucket(containerName).key(blobName));

        // TODO: google-cloud-storage and openstack-swift cannot list multipart
        // uploads
        var multipartListing = client.listMultipartUploads(
                b -> b.bucket(containerName));
        assertThat(multipartListing.uploads()).hasSize(1);

        var partListing = client.listParts(b -> b.bucket(containerName)
                .key(blobName).uploadId(result.uploadId()));
        assertThat(partListing.parts()).isEmpty();

        client.uploadPart(b -> b.bucket(containerName).key(blobName)
                        .uploadId(result.uploadId()).partNumber(1),
                RequestBody.fromInputStream(byteSource.openStream(),
                        byteSource.size()));

        multipartListing = client.listMultipartUploads(
                b -> b.bucket(containerName));
        assertThat(multipartListing.uploads()).hasSize(1);

        partListing = client.listParts(b -> b.bucket(containerName)
                .key(blobName).uploadId(result.uploadId()));
        assertThat(partListing.parts()).hasSize(1);

        client.abortMultipartUpload(b -> b.bucket(containerName).key(blobName)
                .uploadId(result.uploadId()));

        multipartListing = client.listMultipartUploads(
                b -> b.bucket(containerName));
        assertThat(multipartListing.uploads()).isEmpty();

        ListObjectsResponse listing = client.listObjects(
                b -> b.bucket(containerName));
        assertThat(listing.contents()).isEmpty();
    }

    @Test
    public void testCopyObjectPreserveMetadata() throws Exception {
        if (blobStoreType.equals("azureblob-sdk")) {
            // Azurite does not support copying blobs
            assumeTrue(!blobStoreEndpoint.getHost().equals("127.0.0.1"));
        }

        String fromName = "from-name";
        String toName = "to-name";
        String cacheControl = "max-age=3600";
        String contentDisposition = "attachment; filename=old.jpg";
        String contentEncoding = "gzip";
        String contentLanguage = "en";
        String contentType = "audio/ogg";
        var userMetadata = Map.of(
                "key1", "value1",
                "key2", "value2");

        client.putObject(b -> {
            b.bucket(containerName).key(fromName).contentType(contentType)
                    .metadata(userMetadata);
            if (!Quirks.NO_CACHE_CONTROL_SUPPORT.contains(blobStoreType)) {
                b.cacheControl(cacheControl);
            }
            if (!Quirks.NO_CONTENT_DISPOSITION.contains(blobStoreType)) {
                b.contentDisposition(contentDisposition);
            }
            if (!Quirks.NO_CONTENT_ENCODING.contains(blobStoreType)) {
                b.contentEncoding(contentEncoding);
            }
            if (!Quirks.NO_CONTENT_LANGUAGE.contains(blobStoreType)) {
                b.contentLanguage(contentLanguage);
            }
        }, RequestBody.fromInputStream(BYTE_SOURCE.openStream(),
                BYTE_SOURCE.size()));

        client.copyObject(b -> b.sourceBucket(containerName).sourceKey(fromName)
                .destinationBucket(containerName).destinationKey(toName));

        try (ResponseInputStream<GetObjectResponse> object = client.getObject(
                b -> b.bucket(containerName).key(toName))) {
            try (InputStream expected = BYTE_SOURCE.openStream()) {
                assertThat((InputStream) object).hasSameContentAs(expected);
            }
            GetObjectResponse meta = object.response();
            assertThat(meta.contentLength()).isEqualTo(BYTE_SOURCE.size());
            if (!Quirks.NO_CACHE_CONTROL_SUPPORT.contains(blobStoreType)) {
                assertThat(meta.cacheControl()).isEqualTo(cacheControl);
            }
            if (!Quirks.NO_CONTENT_DISPOSITION.contains(blobStoreType)) {
                assertThat(meta.contentDisposition()).isEqualTo(
                        contentDisposition);
            }
            if (!Quirks.NO_CONTENT_ENCODING.contains(blobStoreType)) {
                assertThat(meta.contentEncoding()).isEqualTo(contentEncoding);
            }
            if (!Quirks.NO_CONTENT_LANGUAGE.contains(blobStoreType)) {
                assertThat(meta.contentLanguage()).isEqualTo(contentLanguage);
            }
            assertThat(meta.contentType()).isEqualTo(contentType);
            assertThat(meta.metadata()).isEqualTo(userMetadata);
        }
    }

    @Test
    public void testCopyObjectReplaceMetadata() throws Exception {
        if (blobStoreType.equals("azureblob-sdk")) {
            // Azurite does not support copying blobs
            assumeTrue(!blobStoreEndpoint.getHost().equals("127.0.0.1"));
        }

        String fromName = "from-name";
        String toName = "to-name";

        client.putObject(b -> {
            b.bucket(containerName).key(fromName).contentType("audio/ogg")
                    .metadata(Map.of("key1", "value1", "key2", "value2"));
            if (!Quirks.NO_CACHE_CONTROL_SUPPORT.contains(blobStoreType)) {
                b.cacheControl("max-age=3600");
            }
            if (!Quirks.NO_CONTENT_DISPOSITION.contains(blobStoreType)) {
                b.contentDisposition("attachment; filename=old.jpg");
            }
            if (!Quirks.NO_CONTENT_ENCODING.contains(blobStoreType)) {
                b.contentEncoding("compress");
            }
            if (!Quirks.NO_CONTENT_LANGUAGE.contains(blobStoreType)) {
                b.contentLanguage("en");
            }
        }, RequestBody.fromInputStream(BYTE_SOURCE.openStream(),
                BYTE_SOURCE.size()));

        String cacheControl = "max-age=1800";
        String contentDisposition = "attachment; filename=new.jpg";
        String contentEncoding = "gzip";
        String contentLanguage = "fr";
        String contentType = "audio/mp4";
        var userMetadata = Map.of(
                "key3", "value3",
                "key4", "value4");
        client.copyObject(b -> {
            b.sourceBucket(containerName).sourceKey(fromName)
                    .destinationBucket(containerName).destinationKey(toName)
                    .metadataDirective(software.amazon.awssdk.services.s3.model
                            .MetadataDirective.REPLACE)
                    .contentType(contentType).metadata(userMetadata);
            if (!Quirks.NO_CACHE_CONTROL_SUPPORT.contains(blobStoreType)) {
                b.cacheControl(cacheControl);
            }
            if (!Quirks.NO_CONTENT_DISPOSITION.contains(blobStoreType)) {
                b.contentDisposition(contentDisposition);
            }
            if (!Quirks.NO_CONTENT_ENCODING.contains(blobStoreType)) {
                b.contentEncoding(contentEncoding);
            }
            if (!Quirks.NO_CONTENT_LANGUAGE.contains(blobStoreType)) {
                b.contentLanguage(contentLanguage);
            }
        });

        try (ResponseInputStream<GetObjectResponse> object = client.getObject(
                b -> b.bucket(containerName).key(toName))) {
            try (InputStream expected = BYTE_SOURCE.openStream()) {
                assertThat((InputStream) object).hasSameContentAs(expected);
            }
            GetObjectResponse meta = object.response();
            if (!Quirks.NO_CACHE_CONTROL_SUPPORT.contains(blobStoreType)) {
                assertThat(meta.cacheControl()).isEqualTo(cacheControl);
            }
            if (!Quirks.NO_CONTENT_DISPOSITION.contains(blobStoreType)) {
                assertThat(meta.contentDisposition()).isEqualTo(
                        contentDisposition);
            }
            if (!Quirks.NO_CONTENT_ENCODING.contains(blobStoreType)) {
                assertThat(meta.contentEncoding()).isEqualTo(contentEncoding);
            }
            if (!Quirks.NO_CONTENT_LANGUAGE.contains(blobStoreType)) {
                assertThat(meta.contentLanguage()).isEqualTo(contentLanguage);
            }
            assertThat(meta.contentType()).isEqualTo(contentType);
            assertThat(meta.metadata()).isEqualTo(userMetadata);
        }
    }

    @Test
    public void testConditionalGet() throws Exception {
        // TODO:
        assumeTrue(!blobStoreType.equals("google-cloud-storage-sdk"));

        String blobName = "blob-name";
        PutObjectResponse result = client.putObject(b -> b.bucket(containerName)
                        .key(blobName),
                RequestBody.fromInputStream(BYTE_SOURCE.openStream(),
                        BYTE_SOURCE.size()));

        try (ResponseInputStream<GetObjectResponse> object = client.getObject(
                b -> b.bucket(containerName).key(blobName)
                        .ifMatch(result.eTag()))) {
            assertThat((InputStream) object).isNotNull();
            object.transferTo(OutputStream.nullOutputStream());
        }

        try {
            client.getObject(b -> b.bucket(containerName).key(blobName)
                    .ifNoneMatch(result.eTag()));
            Fail.failBecauseExceptionWasNotThrown(S3Exception.class);
        } catch (S3Exception e) {
            // 304 Not Modified
            assertThat(e.statusCode()).isEqualTo(304);
        }
    }

    @Test
    public void testConditionalGetWildcard() throws Exception {
        // If-Match: * matches any existing object, so the GET succeeds;
        // If-None-Match: * also matches any existing object, so the GET is
        // 304 Not Modified.  Real S3 and Swift evaluate the wildcard natively;
        // google-cloud-storage-sdk, azureblob-sdk, and the nio2 backends
        // emulate the conditional inside s3proxy, which this also exercises.
        // LocalStack and MinIO do not implement the If-Match/If-None-Match "*"
        // wildcard, returning 412 where real S3 returns 200/304.
        assumeTrue(blobStoreEndpoint.getPort() != LOCALSTACK_PORT);
        assumeTrue(blobStoreEndpoint.getPort() != MINIO_PORT);

        String blobName = "blob-name";
        client.putObject(b -> b.bucket(containerName).key(blobName),
                RequestBody.fromInputStream(BYTE_SOURCE.openStream(),
                        BYTE_SOURCE.size()));

        // If-Match: * on an existing object succeeds.
        try (ResponseInputStream<GetObjectResponse> object = client.getObject(
                b -> b.bucket(containerName).key(blobName).ifMatch("*"))) {
            assertThat((InputStream) object).isNotNull();
            object.transferTo(OutputStream.nullOutputStream());
        }

        // If-None-Match: * on an existing object is 304 Not Modified.
        try {
            client.getObject(b -> b.bucket(containerName).key(blobName)
                    .ifNoneMatch("*"));
            Fail.failBecauseExceptionWasNotThrown(S3Exception.class);
        } catch (S3Exception e) {
            assertThat(e.statusCode()).isEqualTo(304);
        }
    }

    @Test
    public void testConditionalGetModifiedSince() throws Exception {
        // HTTP conditional dates have one-second granularity while backend
        // timestamps may carry sub-second precision.  A request whose
        // If-Modified-Since equals the object's own Last-Modified must be
        // treated as "not modified" (304), and If-Unmodified-Since with the
        // same value as "unmodified" (200).
        assumeTrue(blobStoreType.equals("google-cloud-storage-sdk") ||
                blobStoreType.equals("azureblob-sdk"));

        String blobName = "conditional-since";
        client.putObject(b -> b.bucket(containerName).key(blobName),
                RequestBody.fromInputStream(BYTE_SOURCE.openStream(),
                        BYTE_SOURCE.size()));
        HeadObjectResponse head = client.headObject(
                b -> b.bucket(containerName).key(blobName));
        Instant lastModified = head.lastModified();

        // If-Modified-Since == Last-Modified -> 304 Not Modified
        try {
            client.getObject(b -> b.bucket(containerName).key(blobName)
                    .ifModifiedSince(lastModified));
            Fail.failBecauseExceptionWasNotThrown(S3Exception.class);
        } catch (S3Exception e) {
            assertThat(e.statusCode()).isEqualTo(304);
        }

        // If-Unmodified-Since == Last-Modified -> 200 OK
        try (ResponseInputStream<GetObjectResponse> object = client.getObject(
                b -> b.bucket(containerName).key(blobName)
                        .ifUnmodifiedSince(lastModified))) {
            assertThat((InputStream) object).isNotNull();
            object.transferTo(OutputStream.nullOutputStream());
        }
    }

    @Test
    public void testStorageClass() throws Exception {
        // Minio only supports STANDARD and REDUCED_REDUNDANCY
        assumeTrue(blobStoreEndpoint.getPort() != MINIO_PORT);
        // TODO:
        assumeTrue(!blobStoreType.equals("google-cloud-storage-sdk"));
        // Swift does not support per-object storage classes
        assumeTrue(!blobStoreType.equals("openstack-swift-sdk"));
        String blobName = "test-storage-class";
        client.putObject(b -> b.bucket(containerName).key(blobName)
                        .storageClass(StorageClass.STANDARD_IA),
                RequestBody.fromInputStream(BYTE_SOURCE.openStream(),
                        BYTE_SOURCE.size()));
        HeadObjectResponse meta = client.headObject(
                b -> b.bucket(containerName).key(blobName));
        assertThat(meta.storageClassAsString()).isEqualTo("STANDARD_IA");

        // GET must report the storage class consistently with HEAD.  Scoped to
        // the SDK backends that map it; other backends carry the tier on
        // getBlob differently.
        if (blobStoreType.equals("aws-s3-sdk") ||
                blobStoreType.equals("azureblob-sdk")) {
            try (ResponseInputStream<GetObjectResponse> object =
                    client.getObject(b -> b.bucket(containerName)
                            .key(blobName))) {
                assertThat(object.response().storageClassAsString())
                        .isEqualTo("STANDARD_IA");
            }
        }
    }

    @Test
    public void testGetObjectRange() throws Exception {
        var blobName = "test-range";
        var byteSource = TestUtils.randomByteSource().slice(0, 1024);
        client.putObject(b -> b.bucket(containerName).key(blobName),
                RequestBody.fromInputStream(byteSource.openStream(),
                        byteSource.size()));

        try (ResponseInputStream<GetObjectResponse> object = client.getObject(
                b -> b.bucket(containerName).key(blobName)
                        .range("bytes=42-101"))) {
            assertThat(object.response().contentLength()).isEqualTo(
                    101 - 42 + 1);
            try (var expected = byteSource.slice(42, 101 - 42 + 1)
                    .openStream()) {
                assertThat((InputStream) object).hasSameContentAs(expected);
            }
        }
    }

    @Test
    public void testGetObjectSuffixRange() throws Exception {
        var blobName = "test-suffix-range";
        var byteSource = TestUtils.randomByteSource().slice(0, 1024);
        client.putObject(b -> b.bucket(containerName).key(blobName),
                RequestBody.fromInputStream(byteSource.openStream(),
                        byteSource.size()));

        // bytes=-100 returns the last 100 bytes of the object.
        try (ResponseInputStream<GetObjectResponse> object = client.getObject(
                b -> b.bucket(containerName).key(blobName)
                        .range("bytes=-100"))) {
            assertThat(object.response().contentLength()).isEqualTo(100);
            try (var expected = byteSource.slice(1024 - 100, 100)
                    .openStream()) {
                assertThat((InputStream) object).hasSameContentAs(expected);
            }
        }
    }

    @Test
    public void testGetObjectRangeExceedingLength() throws Exception {
        var blobName = "test-range-exceeding";
        var byteSource = TestUtils.randomByteSource().slice(0, 1024);
        client.putObject(b -> b.bucket(containerName).key(blobName),
                RequestBody.fromInputStream(byteSource.openStream(),
                        byteSource.size()));

        // A range whose end lies past the object returns only the bytes up to
        // the end of the object.  Content-Length and Content-Range must
        // reflect what is actually sent, not the over-large requested end;
        // otherwise the client stalls waiting for bytes that never come.
        try (ResponseInputStream<GetObjectResponse> object = client.getObject(
                b -> b.bucket(containerName).key(blobName)
                        .range("bytes=42-100000"))) {
            assertThat(object.response().contentLength()).isEqualTo(1024 - 42);
            assertThat(object.response().contentRange()).isEqualTo(
                    "bytes 42-1023/1024");
            try (var expected = byteSource.slice(42, 1024 - 42).openStream()) {
                assertThat((InputStream) object).hasSameContentAs(expected);
            }
        }
    }

    @Test
    public void testUnknownHeader() throws Exception {
        String blobName = "test-unknown-header";
        try {
            client.putObject(b -> b.bucket(containerName).key(blobName)
                            .tagging(Tagging.builder().tagSet(List.of())
                                    .build()),
                    RequestBody.fromInputStream(BYTE_SOURCE.openStream(),
                            BYTE_SOURCE.size()));
            Fail.failBecauseExceptionWasNotThrown(S3Exception.class);
        } catch (S3Exception e) {
            assertThat(e.awsErrorDetails().errorCode())
                    .isEqualTo("NotImplemented");
        }
    }

    @Test
    public void testGetBucketPolicy() throws Exception {
        try {
            client.getBucketPolicy(b -> b.bucket(containerName));
            Fail.failBecauseExceptionWasNotThrown(S3Exception.class);
        } catch (S3Exception e) {
            assertThat(e.awsErrorDetails().errorCode())
                    .isEqualTo("NoSuchPolicy");
        }
    }

    @Test
    public void testUnknownParameter() throws Exception {
        try {
            client.putBucketLogging(b -> b.bucket(containerName)
                    .bucketLoggingStatus(s -> { }));
            Fail.failBecauseExceptionWasNotThrown(S3Exception.class);
        } catch (S3Exception e) {
            assertThat(e.awsErrorDetails().errorCode())
                    .isEqualTo("NotImplemented");
        }
    }

    @Test
    public void testBlobStoreLocator() throws Exception {
        // Only the in-memory backend works without configuration.
        assumeTrue(blobStoreType.isEmpty() ||
                blobStoreType.equals("transient-nio2"));
        final BlobStore blobStore1 = blobStore;
        final BlobStore blobStore2 = TestUtils.createTransientBlobStore();
        s3Proxy.setBlobStoreLocator(new BlobStoreLocator() {
            @Override
            public @Nullable AccessGrant locateBlobStore(
                    String identity, String container, String blob) {
                if (identity.equals(awsCreds.accessKeyId())) {
                    return new AccessGrant(awsCreds.secretAccessKey(),
                            blobStore1);
                } else if (identity.equals("other-identity")) {
                    return new AccessGrant("credential", blobStore2);
                } else {
                    return null;
                }
            }
        });

        // check first access key
        var buckets = client.listBuckets().buckets();
        assertThat(buckets).hasSize(1);
        assertThat(buckets.get(0).name()).isEqualTo(containerName);

        // check second access key
        client.close();
        client = buildClient(AwsBasicCredentials.create("other-identity",
                "credential"));
        buckets = client.listBuckets().buckets();
        assertThat(buckets).isEmpty();

        // check invalid access key
        client.close();
        client = buildClient(AwsBasicCredentials.create("bad-identity",
                "credential"));
        try {
            client.listBuckets();
            Fail.failBecauseExceptionWasNotThrown(S3Exception.class);
        } catch (S3Exception e) {
            assertThat(e.awsErrorDetails().errorCode())
                    .isEqualTo("InvalidAccessKeyId");
        }
    }

    @Test
    public void testCopyRelativePath() throws Exception {
        assumeTrue(!blobStoreType.equals("azureblob-sdk"));
        try {
            client.copyObject(b -> b.sourceBucket(containerName)
                    .sourceKey("../evil.txt").destinationBucket(containerName)
                    .destinationKey("good.txt"));
            Fail.failBecauseExceptionWasNotThrown(AwsServiceException.class);
        } catch (AwsServiceException | SdkClientException e) {
            // expected
        }
    }

    @Test
    public void testDeleteRelativePath() throws Exception {
        try {
            client.deleteObject(b -> b.bucket(containerName)
                    .key("../evil.txt"));
            if (blobStoreType.equals("filesystem-nio2") ||
                    blobStoreType.equals("transient-nio2")) {
                Fail.failBecauseExceptionWasNotThrown(
                        AwsServiceException.class);
            }
        } catch (AwsServiceException | SdkClientException e) {
            // expected
        }
    }

    @Test
    public void testGetRelativePath() throws Exception {
        try {
            client.getObject(b -> b.bucket(containerName).key("../evil.txt"));
            Fail.failBecauseExceptionWasNotThrown(AwsServiceException.class);
        } catch (AwsServiceException | SdkClientException e) {
            // expected
        }
    }

    @Test
    public void testPutRelativePath() throws Exception {
        try {
            client.putObject(b -> b.bucket(containerName).key("../evil.txt"),
                    RequestBody.fromInputStream(BYTE_SOURCE.openStream(),
                            BYTE_SOURCE.size()));
            if (blobStoreType.equals("filesystem-nio2") ||
                    blobStoreType.equals("transient-nio2")) {
                Fail.failBecauseExceptionWasNotThrown(
                        AwsServiceException.class);
            }
        } catch (AwsServiceException | SdkClientException e) {
            // expected
        }
    }

    @Test
    public void testListRelativePath() throws Exception {
        try {
            client.listObjects(b -> b.bucket(containerName)
                    .prefix("../evil/"));
            if (blobStoreType.equals("filesystem-nio2") ||
                    blobStoreType.equals("transient-nio2")) {
                Fail.failBecauseExceptionWasNotThrown(
                        AwsServiceException.class);
            }
        } catch (AwsServiceException | SdkClientException e) {
            // expected
        }
    }

    private static final class NullX509TrustManager
            implements X509TrustManager {
        @Override
        @Nullable
        public X509Certificate[] getAcceptedIssuers() {
            return null;
        }

        @Override
        public void checkClientTrusted(X509Certificate[] certs,
                String authType) {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] certs,
                String authType) {
        }
    }

    static void disableSslVerification() {
        try {
            // Create a trust manager that does not validate certificate chains
            var trustAllCerts = new TrustManager[] {
                new NullX509TrustManager() };

            // Install the all-trusting trust manager
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(
                    sc.getSocketFactory());

            // Create all-trusting host name verifier
            var allHostsValid = new HostnameVerifier() {
                @Override
                public boolean verify(String hostname, SSLSession session) {
                    return true;
                }
            };

            // Install the all-trusting host verifier
            HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
        } catch (KeyManagementException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    static String createRandomContainerName() {
        return "s3proxy-" + new Random().nextInt(Integer.MAX_VALUE);
    }
}
