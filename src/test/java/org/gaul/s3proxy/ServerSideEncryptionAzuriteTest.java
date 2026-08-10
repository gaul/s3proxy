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
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.http.SdkHttpConfigurationOption;
import software.amazon.awssdk.http.apache5.Apache5HttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.services.s3.model.ServerSideEncryption;
import software.amazon.awssdk.utils.AttributeMap;

/**
 * Server-side encryption against the azureblob backend, exercised through
 * Azurite. Azure Blob always encrypts at rest, so AzureBlobStore acknowledges
 * SSE-S3 (AES256) on write and reports it on read for every object -- the way
 * S3 does with default bucket encryption -- while SSE-C and SSE-KMS, which the
 * backend cannot honor, are refused rather than silently ignored.
 *
 * Runs only when pointed at the azureblob backend
 * (-Ds3proxy.test.conf=s3proxy-azurite.conf), and is skipped otherwise so the
 * SSE-C/KMS refusals are not asserted against backends that implement them.
 */
public final class ServerSideEncryptionAzuriteTest {
    private static final String KEY = "sse-key";
    // A 32-byte SSE-C key and its MD5, so the handler's format vetting passes
    // and the request reaches AzureBlobStore, which is what refuses it.
    private static final byte[] CUSTOMER_KEY =
            "0123456789abcdef0123456789abcdef"
                    .getBytes(StandardCharsets.UTF_8);

    private S3Proxy s3Proxy;
    private S3Client client;
    private String containerName;

    @BeforeEach
    public void setUp() throws Exception {
        String conf = System.getProperty("s3proxy.test.conf", "");
        assumeTrue(conf.contains("azurite"),
                "runs only against the azureblob (Azurite) backend");

        TestUtils.S3ProxyLaunchInfo info = TestUtils.startS3Proxy(conf);
        s3Proxy = info.getS3Proxy();
        var creds = AwsBasicCredentials.create(
                info.getS3Identity(), info.getS3Credential());
        var endpoint = URI.create(
                info.getSecureEndpoint().toString() + info.getServicePath());
        var attributeMap = AttributeMap.builder()
                .put(SdkHttpConfigurationOption.TRUST_ALL_CERTIFICATES, true)
                .build();
        client = S3Client.builder()
                .credentialsProvider(StaticCredentialsProvider.create(creds))
                .region(Region.US_EAST_1)
                .endpointOverride(endpoint)
                .httpClient(Apache5HttpClient.builder()
                        .buildWithDefaults(attributeMap))
                .serviceConfiguration(S3Configuration.builder()
                        .pathStyleAccessEnabled(true)
                        .build())
                .build();
        containerName = TestUtils.createRandomContainerName();
        client.createBucket(b -> b.bucket(containerName));
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (client != null) {
            client.close();
        }
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
    }

    private static String base64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    @Test
    public void testSseS3AcceptedAndEchoed() throws Exception {
        PutObjectResponse put = client.putObject(b -> b
                        .bucket(containerName).key(KEY)
                        .serverSideEncryption(ServerSideEncryption.AES256),
                RequestBody.fromString("payload"));
        assertThat(put.serverSideEncryption())
                .isEqualTo(ServerSideEncryption.AES256);

        var head = client.headObject(b -> b.bucket(containerName).key(KEY));
        assertThat(head.serverSideEncryption())
                .isEqualTo(ServerSideEncryption.AES256);

        var get = client.getObjectAsBytes(
                b -> b.bucket(containerName).key(KEY));
        assertThat(get.response().serverSideEncryption())
                .isEqualTo(ServerSideEncryption.AES256);
    }

    @Test
    public void testReportsDefaultEncryption() throws Exception {
        // Ask for nothing: the object still rests under Azure's at-rest
        // default, reported as AES256 like S3 default bucket encryption.
        PutObjectResponse put = client.putObject(
                b -> b.bucket(containerName).key(KEY),
                RequestBody.fromString("payload"));
        assertThat(put.serverSideEncryption())
                .isEqualTo(ServerSideEncryption.AES256);

        var head = client.headObject(b -> b.bucket(containerName).key(KEY));
        assertThat(head.serverSideEncryption())
                .isEqualTo(ServerSideEncryption.AES256);
    }

    @Test
    public void testCustomerKeyRefused() throws Exception {
        String keyB64 = base64(CUSTOMER_KEY);
        String md5B64 = base64(
                MessageDigest.getInstance("MD5").digest(CUSTOMER_KEY));
        assertThatThrownBy(() -> client.putObject(b -> b
                        .bucket(containerName).key(KEY)
                        .sseCustomerAlgorithm("AES256")
                        .sseCustomerKey(keyB64)
                        .sseCustomerKeyMD5(md5B64),
                RequestBody.fromString("payload")))
                .isInstanceOfSatisfying(S3Exception.class,
                        e -> assertThat(e.statusCode()).isEqualTo(501));
    }

    @Test
    public void testKmsRefused() throws Exception {
        assertThatThrownBy(() -> client.putObject(b -> b
                        .bucket(containerName).key(KEY)
                        .serverSideEncryption(ServerSideEncryption.AWS_KMS)
                        .ssekmsKeyId("test-key-id"),
                RequestBody.fromString("payload")))
                .isInstanceOfSatisfying(S3Exception.class,
                        e -> assertThat(e.statusCode()).isEqualTo(501));
    }
}
