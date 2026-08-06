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

import java.net.URI;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.http.SdkHttpConfigurationOption;
import software.amazon.awssdk.http.apache5.Apache5HttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.model.CompletedMultipartUpload;
import software.amazon.awssdk.services.s3.model.CompletedPart;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.services.s3.model.ServerSideEncryption;
import software.amazon.awssdk.services.s3.model.UploadPartResponse;
import software.amazon.awssdk.utils.AttributeMap;

/**
 * Exercises the s3proxy.server-side-encryption policy end to end over HTTP:
 * how the proxy treats the x-amz-server-side-encryption request header under
 * each mode, and the SseMode parser.
 */
public final class ServerSideEncryptionTest {
    private static final String CONTAINER = "sse-test-container";
    private static final String KEY = "sse-test-key";

    private S3Proxy s3Proxy;
    private S3Client client;

    @AfterEach
    public void tearDown() throws Exception {
        if (client != null) {
            client.close();
        }
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
    }

    /** Start a proxy from the given conf, build a client, create the bucket. */
    private void launch(String configFile) throws Exception {
        TestUtils.S3ProxyLaunchInfo info = TestUtils.startS3Proxy(configFile);
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
        client.createBucket(b -> b.bucket(CONTAINER));
    }

    private PutObjectResponse putWithSse(ServerSideEncryption sse) {
        return client.putObject(b -> b
                        .bucket(CONTAINER).key(KEY).serverSideEncryption(sse),
                RequestBody.fromString("hello sse"));
    }

    /** The server-side-encryption value the proxy reports for KEY on HEAD. */
    private ServerSideEncryption headSse() {
        return client.headObject(b -> b.bucket(CONTAINER).key(KEY))
                .serverSideEncryption();
    }

    /** Assert that PUT with the given SSE mode is refused with 501. */
    private void assertPutRejectedWith501(ServerSideEncryption sse) {
        assertThatThrownBy(() -> putWithSse(sse))
                .isInstanceOfSatisfying(S3Exception.class,
                        e -> assertThat(e.statusCode()).isEqualTo(501));
    }

    private static void assertParses(String value,
            S3ProxyHandler.SseMode expected) {
        assertThat(S3ProxyHandler.SseMode.parse(value)).isEqualTo(expected);
    }

    @Test
    public void testSseS3AcceptedAndEchoedOnPutHeadGet() throws Exception {
        launch("s3proxy-sse-s3.conf");

        PutObjectResponse put = putWithSse(ServerSideEncryption.AES256);
        assertThat(put.serverSideEncryption())
                .isEqualTo(ServerSideEncryption.AES256);

        assertThat(headSse()).isEqualTo(ServerSideEncryption.AES256);

        GetObjectResponse get = client.getObjectAsBytes(
                b -> b.bucket(CONTAINER).key(KEY)).response();
        assertThat(get.serverSideEncryption())
                .isEqualTo(ServerSideEncryption.AES256);
    }

    @Test
    public void testSseS3EchoedOnCopy() throws Exception {
        launch("s3proxy-sse-s3.conf");
        putWithSse(ServerSideEncryption.AES256);

        var copy = client.copyObject(b -> b
                .sourceBucket(CONTAINER).sourceKey(KEY)
                .destinationBucket(CONTAINER).destinationKey(KEY + "-copy"));
        assertThat(copy.serverSideEncryption())
                .isEqualTo(ServerSideEncryption.AES256);
    }

    @Test
    public void testSseS3EchoedOnMultipartComplete() throws Exception {
        launch("s3proxy-sse-s3.conf");
        String mkey = KEY + "-mpu";

        CreateMultipartUploadResponse create = client.createMultipartUpload(
                b -> b.bucket(CONTAINER).key(mkey)
                        .serverSideEncryption(ServerSideEncryption.AES256));
        String uploadId = create.uploadId();

        UploadPartResponse part = client.uploadPart(
                b -> b.bucket(CONTAINER).key(mkey).uploadId(uploadId)
                        .partNumber(1),
                RequestBody.fromString("hello multipart sse"));

        CompletedPart cp = CompletedPart.builder()
                .partNumber(1).eTag(part.eTag()).build();
        var completed = client.completeMultipartUpload(
                b -> b.bucket(CONTAINER).key(mkey).uploadId(uploadId)
                        .multipartUpload(CompletedMultipartUpload.builder()
                                .parts(cp).build()));
        assertThat(completed.serverSideEncryption())
                .isEqualTo(ServerSideEncryption.AES256);
    }

    @Test
    public void testSseS3RejectsKms() throws Exception {
        launch("s3proxy-sse-s3.conf");
        assertPutRejectedWith501(ServerSideEncryption.AWS_KMS);
    }

    @Test
    public void testIgnoreAcceptsButDoesNotEcho() throws Exception {
        launch("s3proxy-sse-ignore.conf");

        PutObjectResponse put = putWithSse(ServerSideEncryption.AES256);
        assertThat(put.serverSideEncryption()).isNull();
        assertThat(headSse()).isNull();
    }

    @Test
    public void testRejectReturnsNotImplemented() throws Exception {
        launch("s3proxy-sse-reject.conf");
        assertPutRejectedWith501(ServerSideEncryption.AES256);
    }

    @Test
    public void testDefaultRejectsOnNonEncryptingBackend() throws Exception {
        // s3proxy.conf: transient backend, no SSE property, no encryption ->
        // the derived default must be reject (never claim encryption).
        launch("s3proxy.conf");
        assertPutRejectedWith501(ServerSideEncryption.AES256);
    }

    @Test
    public void testDefaultSseS3WhenEncryptedBlobStore() throws Exception {
        // s3proxy-encryption.conf: EncryptedBlobStore enabled, no SSE property
        // -> the proxy really encrypts, so the default derives to sse-s3.
        launch("s3proxy-encryption.conf");
        PutObjectResponse put = putWithSse(ServerSideEncryption.AES256);
        assertThat(put.serverSideEncryption())
                .isEqualTo(ServerSideEncryption.AES256);
        assertThat(headSse()).isEqualTo(ServerSideEncryption.AES256);
    }

    @Test
    public void testSseModeParse() {
        assertParses("sse-s3", S3ProxyHandler.SseMode.SSE_S3);
        assertParses("aes256", S3ProxyHandler.SseMode.SSE_S3);
        assertParses("ignore", S3ProxyHandler.SseMode.IGNORE);
        assertParses("reject", S3ProxyHandler.SseMode.REJECT);
        assertParses("", S3ProxyHandler.SseMode.REJECT);
        assertParses(null, S3ProxyHandler.SseMode.REJECT);
        assertThatThrownBy(() -> S3ProxyHandler.SseMode.parse("bogus"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
