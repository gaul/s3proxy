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
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Random;

import com.google.common.io.ByteSource;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.options.CreateContainerOptions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.auth.credentials.AnonymousCredentialsProvider;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.http.SdkHttpConfigurationOption;
import software.amazon.awssdk.http.apache5.Apache5HttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.utils.AttributeMap;

public final class AwsSdkAnonymousTest {
    static {
        AwsSdkTest.disableSslVerification();
    }

    private static final ByteSource BYTE_SOURCE = ByteSource.wrap(new byte[1]);

    private URI s3Endpoint;
    private URI httpEndpoint;
    private URI s3EndpointUri;
    private S3Proxy s3Proxy;
    private BlobStore blobStore;
    private String containerName;
    private S3Client client;
    private String servicePath;

    @BeforeEach
    public void setUp() throws Exception {
        TestUtils.S3ProxyLaunchInfo info = TestUtils.startS3Proxy(
                "s3proxy-anonymous.conf");
        blobStore = info.getBlobStore();
        s3Proxy = info.getS3Proxy();
        httpEndpoint = info.getEndpoint();
        s3Endpoint = info.getSecureEndpoint();
        servicePath = info.getServicePath();
        s3EndpointUri = URI.create(s3Endpoint.toString() + servicePath);

        client = buildClient(AnonymousCredentialsProvider.create());

        containerName = createRandomContainerName();
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

    @Test
    public void testListBuckets() throws Exception {
        client.listBuckets();
    }

    @Test
    public void testAwsV4SignatureChunkedAnonymous() throws Exception {
        client.close();
        client = buildClient(AnonymousCredentialsProvider.create());

        client.putObject(b -> b.bucket(containerName).key("foo"),
                RequestBody.fromInputStream(BYTE_SOURCE.openStream(),
                        BYTE_SOURCE.size()));

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
    public void testAwsV4SignedChunkedPayloadTrailerAnonymous()
            throws Exception {
        // A client configured with (signing) credentials sends a signed,
        // chunked, checksum-trailer payload -- x-amz-content-sha256:
        // STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER -- over plain HTTP.
        // Even though the proxy uses authorization=none, it must decode the
        // aws-chunked framing instead of storing the chunk-signature and
        // checksum trailer lines verbatim.
        // Regression test for https://github.com/gaul/s3proxy/issues/922
        client.close();
        client = buildHttpClient(StaticCredentialsProvider.create(
                AwsBasicCredentials.create("dummy", "dummy")));

        byte[] content = "fileContent-none".getBytes(StandardCharsets.UTF_8);
        client.putObject(b -> b.bucket(containerName).key("foo"),
                RequestBody.fromBytes(content));

        try (ResponseInputStream<GetObjectResponse> object = client.getObject(
                b -> b.bucket(containerName).key("foo"))) {
            assertThat(object.response().contentLength())
                    .isEqualTo((long) content.length);
            assertThat(object.readAllBytes()).isEqualTo(content);
        }
    }

    @Test
    public void testHealthzEndpoint() throws Exception {
        URI baseUri = httpEndpoint != null ? httpEndpoint : s3Endpoint;
        String path = (servicePath == null ? "" : servicePath) + "/healthz";
        URI healthzUri = new URI(baseUri.getScheme(), baseUri.getUserInfo(),
                baseUri.getHost(), baseUri.getPort(), path,
                baseUri.getQuery(), baseUri.getFragment());

        HttpURLConnection connection =
                (HttpURLConnection) healthzUri.toURL().openConnection();
        connection.setRequestMethod("GET");

        assertThat(connection.getResponseCode()).isEqualTo(200);

        String body;
        try (InputStream stream = connection.getInputStream()) {
            body = new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        } finally {
            connection.disconnect();
        }

        assertThat(body).contains("\"status\":\"OK\"");
        assertThat(body).contains("\"gitHash\":\"");
        assertThat(body).contains("\"launchTime\":\"");
        assertThat(body).contains("\"currentTime\":\"");
        assertThat(body).startsWith("{").endsWith("}");
    }

    private S3Client buildClient(AwsCredentialsProvider credentialsProvider) {
        var attributeMap = AttributeMap.builder()
                .put(SdkHttpConfigurationOption.TRUST_ALL_CERTIFICATES, true)
                .build();
        return S3Client.builder()
                .credentialsProvider(credentialsProvider)
                .region(Region.US_EAST_1)
                .endpointOverride(s3EndpointUri)
                .httpClient(Apache5HttpClient.builder()
                        .buildWithDefaults(attributeMap))
                .serviceConfiguration(S3Configuration.builder()
                        .pathStyleAccessEnabled(true)
                        .build())
                .build();
    }

    private S3Client buildHttpClient(AwsCredentialsProvider creds) {
        URI httpUri = URI.create(httpEndpoint.toString() + servicePath);
        return S3Client.builder()
                .credentialsProvider(creds)
                .region(Region.US_EAST_1)
                .endpointOverride(httpUri)
                .httpClient(Apache5HttpClient.builder().build())
                .serviceConfiguration(S3Configuration.builder()
                        .pathStyleAccessEnabled(true)
                        .build())
                .build();
    }

    private static String createRandomContainerName() {
        return "s3proxy-" + new Random().nextInt(Integer.MAX_VALUE);
    }
}
