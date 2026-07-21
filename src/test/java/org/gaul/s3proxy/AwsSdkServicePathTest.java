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

import java.io.InputStream;
import java.net.URI;
import java.time.Duration;

import com.google.common.io.ByteSource;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.options.CreateContainerOptions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.http.SdkHttpConfigurationOption;
import software.amazon.awssdk.http.apache5.Apache5HttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.presigner.S3Presigner;
import software.amazon.awssdk.services.s3.presigner.model.GetObjectPresignRequest;
import software.amazon.awssdk.services.s3.presigner.model.PresignedGetObjectRequest;
import software.amazon.awssdk.utils.AttributeMap;

/**
 * Exercise AWS V4 signatures when S3Proxy serves requests under a non-default
 * service path.  The signed URI must include the service path exactly once;
 * see <a href="https://github.com/gaul/s3proxy/issues/845">issue 845</a>.
 */
public final class AwsSdkServicePathTest {
    static {
        AwsSdkTest.disableSslVerification();
    }

    private static final ByteSource BYTE_SOURCE =
            ByteSource.wrap(new byte[1]);

    private S3Proxy s3Proxy;
    private BlobStore blobStore;
    private URI s3EndpointUri;
    private AwsBasicCredentials awsCreds;
    private S3Client client;
    private String containerName;

    @BeforeEach
    public void setUp() throws Exception {
        TestUtils.S3ProxyLaunchInfo info = TestUtils.startS3Proxy(
                "s3proxy-service-path.conf");
        awsCreds = AwsBasicCredentials.create(info.getS3Identity(),
                info.getS3Credential());
        blobStore = info.getBlobStore();
        s3Proxy = info.getS3Proxy();
        // service path is a non-empty prefix such as "/s3proxy"
        assertThat(info.getServicePath()).isNotEmpty();
        s3EndpointUri = URI.create(
                info.getSecureEndpoint().toString() + info.getServicePath());
        client = buildClient(true);

        containerName = AwsSdkTest.createRandomContainerName();
        info.getBlobStore().createContainer(containerName,
                CreateContainerOptions.NONE);
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

    private S3Client buildClient(boolean chunkedEncoding) {
        var attributeMap = AttributeMap.builder()
                .put(SdkHttpConfigurationOption.TRUST_ALL_CERTIFICATES, true)
                .build();
        return S3Client.builder()
                .credentialsProvider(StaticCredentialsProvider.create(awsCreds))
                .region(Region.US_EAST_1)
                .endpointOverride(s3EndpointUri)
                .httpClient(Apache5HttpClient.builder()
                        .buildWithDefaults(attributeMap))
                .serviceConfiguration(S3Configuration.builder()
                        .pathStyleAccessEnabled(true)
                        .chunkedEncodingEnabled(chunkedEncoding)
                        .build())
                .build();
    }

    private void putBlob(String key, ByteSource source) throws Exception {
        client.putObject(b -> b.bucket(containerName).key(key),
                RequestBody.fromInputStream(source.openStream(),
                        source.size()));
    }

    private void assertGetMatches(String key) throws Exception {
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
    public void testAwsV4Signature() throws Exception {
        // chunkedEncodingEnabled is true by default in v2.
        putBlob("foo", BYTE_SOURCE);
        assertGetMatches("foo");
    }

    @Test
    public void testAwsV4SignatureNonChunked() throws Exception {
        client.close();
        client = buildClient(false);
        putBlob("foo", BYTE_SOURCE);
        assertGetMatches("foo");
    }

    @Test
    public void testAwsV4UrlSigning() throws Exception {
        putBlob("foo", BYTE_SOURCE);

        URI url;
        try (S3Presigner presigner = S3Presigner.builder()
                .credentialsProvider(StaticCredentialsProvider.create(awsCreds))
                .region(Region.US_EAST_1)
                .endpointOverride(s3EndpointUri)
                .serviceConfiguration(S3Configuration.builder()
                        .pathStyleAccessEnabled(true)
                        .build())
                .build()) {
            PresignedGetObjectRequest presigned = presigner.presignGetObject(
                    GetObjectPresignRequest.builder()
                            .signatureDuration(Duration.ofHours(1))
                            .getObjectRequest(b -> b.bucket(containerName)
                                    .key("foo"))
                            .build());
            url = presigned.url().toURI();
        }

        try (InputStream actual = url.toURL().openStream();
                InputStream expected = BYTE_SOURCE.openStream()) {
            assertThat(actual).hasSameContentAs(expected);
        }
    }
}
