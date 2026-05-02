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

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Random;

import com.google.common.io.ByteSource;
import com.google.common.net.HttpHeaders;

import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpOptions;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.ssl.SSLContextBuilder;
import org.jclouds.blobstore.BlobStoreContext;
import org.jclouds.blobstore.domain.Blob;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.http.SdkHttpConfigurationOption;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.model.BucketCannedACL;
import software.amazon.awssdk.services.s3.presigner.S3Presigner;
import software.amazon.awssdk.services.s3.presigner.model.GetObjectPresignRequest;
import software.amazon.awssdk.utils.AttributeMap;

public final class CrossOriginResourceSharingResponseTest {
    static {
        AwsSdkTest.disableSslVerification();
    }

    private URI s3Endpoint;
    private URI s3EndpointUri;
    private S3Proxy s3Proxy;
    private BlobStoreContext context;
    private String containerName;
    private S3Client s3Client;
    private String servicePath;
    private CloseableHttpClient httpClient;
    private URI presignedGET;
    private URI publicGET;

    @Before
    public void setUp() throws Exception {
        TestUtils.S3ProxyLaunchInfo info = TestUtils.startS3Proxy(
                "s3proxy-cors.conf");
        var creds = AwsBasicCredentials.create(info.getS3Identity(),
                info.getS3Credential());
        var credsProvider = StaticCredentialsProvider.create(creds);
        context = info.getBlobStore().getContext();
        s3Proxy = info.getS3Proxy();
        s3Endpoint = info.getSecureEndpoint();
        servicePath = info.getServicePath();
        s3EndpointUri = URI.create(s3Endpoint.toString() + servicePath);

        var attributeMap = AttributeMap.builder()
                .put(SdkHttpConfigurationOption.TRUST_ALL_CERTIFICATES, true)
                .build();
        var serviceConfig = S3Configuration.builder()
                .pathStyleAccessEnabled(true)
                .build();
        s3Client = S3Client.builder()
                .credentialsProvider(credsProvider)
                .region(Region.US_EAST_1)
                .endpointOverride(s3EndpointUri)
                .httpClient(ApacheHttpClient.builder()
                        .buildWithDefaults(attributeMap))
                .serviceConfiguration(serviceConfig)
                .build();
        httpClient = getHttpClient();

        containerName = createRandomContainerName();
        info.getBlobStore().createContainerInLocation(null, containerName);

        s3Client.putBucketAcl(b -> b.bucket(containerName)
                .acl(BucketCannedACL.PUBLIC_READ));

        String blobName = "test";
        ByteSource payload = ByteSource.wrap("blob-content".getBytes(
                StandardCharsets.UTF_8));
        Blob blob = info.getBlobStore().blobBuilder(blobName)
                .payload(payload).contentLength(payload.size()).build();
        info.getBlobStore().putBlob(containerName, blob);

        try (S3Presigner presigner = S3Presigner.builder()
                .credentialsProvider(credsProvider)
                .region(Region.US_EAST_1)
                .endpointOverride(s3EndpointUri)
                .serviceConfiguration(serviceConfig)
                .build()) {
            presignedGET = presigner.presignGetObject(
                    GetObjectPresignRequest.builder()
                            .signatureDuration(Duration.ofHours(1))
                            .getObjectRequest(b -> b.bucket(containerName)
                                    .key(blobName))
                            .build()).url().toURI();
        }

        publicGET = URI.create(s3EndpointUri + "/" + containerName + "/" +
                blobName);
    }

    @After
    public void tearDown() throws Exception {
        if (s3Client != null) {
            s3Client.close();
        }
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
        if (context != null) {
            context.getBlobStore().deleteContainer(containerName);
            context.close();
        }
        if (httpClient != null) {
            httpClient.close();
        }
    }

    @Test
    public void testCorsPreflight() throws Exception {
        // Allowed origin and method
        var request = new HttpOptions(presignedGET);
        request.setHeader(HttpHeaders.ORIGIN, "https://example.com");
        request.setHeader(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "GET");
        HttpResponse response = httpClient.execute(request);
        assertThat(response.getStatusLine().getStatusCode())
                .isEqualTo(HttpStatus.SC_OK);
        assertThat(response.containsHeader(
                HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN)).isTrue();
        assertThat(response.getFirstHeader(
                HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN).getValue())
                .isEqualTo("https://example.com");
        assertThat(response.containsHeader(
                HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS)).isTrue();
        assertThat(response.getFirstHeader(
                HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS).getValue())
                .isEqualTo("GET, PUT");
        assertThat(response.getFirstHeader(
                HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS).getValue())
                .isEqualTo("ETag");

        // Allowed origin, method and header
        request.reset();
        request.setHeader(HttpHeaders.ORIGIN, "https://example.com");
        request.setHeader(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "GET");
        request.setHeader(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS, "Accept");
        response = httpClient.execute(request);
        assertThat(response.getStatusLine().getStatusCode())
                .isEqualTo(HttpStatus.SC_OK);
        assertThat(response.containsHeader(
                HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN)).isTrue();
        assertThat(response.getFirstHeader(
                HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN).getValue())
                .isEqualTo("https://example.com");
        assertThat(response.containsHeader(
                HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS)).isTrue();
        assertThat(response.getFirstHeader(
                HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS).getValue())
                .isEqualTo("GET, PUT");
        assertThat(response.containsHeader(
                HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS)).isTrue();
        assertThat(response.getFirstHeader(
                HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS).getValue())
                .isEqualTo("Accept");
        assertThat(response.getFirstHeader(
                HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS).getValue())
                .isEqualTo("ETag");

        // Allowed origin, method and header combination
        request.reset();
        request.setHeader(HttpHeaders.ORIGIN, "https://example.com");
        request.setHeader(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "GET");
        request.setHeader(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS,
                "Accept, Content-Type");
        response = httpClient.execute(request);
        assertThat(response.getStatusLine().getStatusCode())
                .isEqualTo(HttpStatus.SC_OK);
        assertThat(response.containsHeader(
                HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN)).isTrue();
        assertThat(response.getFirstHeader(
                HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN).getValue())
                .isEqualTo("https://example.com");
        assertThat(response.containsHeader(
                HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS)).isTrue();
        assertThat(response.getFirstHeader(
                HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS).getValue())
                .isEqualTo("GET, PUT");
        assertThat(response.containsHeader(
                HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS)).isTrue();
        assertThat(response.getFirstHeader(
                HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS).getValue())
                .isEqualTo("Accept, Content-Type");
        assertThat(response.getFirstHeader(
                HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS).getValue())
                .isEqualTo("ETag");
    }

    @Test
    public void testCorsPreflightPublicRead() throws Exception {
        // No CORS headers
        var request = new HttpOptions(publicGET);
        HttpResponse response = httpClient.execute(request);

        assertThat(response.getStatusLine().getStatusCode())
                .isEqualTo(HttpStatus.SC_BAD_REQUEST);

        // Not allowed method
        request.reset();
        request.setHeader(HttpHeaders.ORIGIN, "https://example.com");
        request.setHeader(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "PATCH");
        response = httpClient.execute(request);
        assertThat(response.getStatusLine().getStatusCode())
                .isEqualTo(HttpStatus.SC_BAD_REQUEST);

        // Allowed origin and method
        request.reset();
        request.setHeader(HttpHeaders.ORIGIN, "https://example.com");
        request.setHeader(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "GET");
        request.setHeader(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS,
                "Accept, Content-Type");
        response = httpClient.execute(request);
        assertThat(response.getStatusLine().getStatusCode())
                .isEqualTo(HttpStatus.SC_OK);
        assertThat(response.containsHeader(
                HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN)).isTrue();
        assertThat(response.getFirstHeader(
                HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN).getValue())
                .isEqualTo("https://example.com");
        assertThat(response.containsHeader(
                HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS)).isTrue();
        assertThat(response.getFirstHeader(
                HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS).getValue())
                .isEqualTo("GET, PUT");
        assertThat(response.containsHeader(
                HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS)).isTrue();
        assertThat(response.getFirstHeader(
                HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS).getValue())
                .isEqualTo("Accept, Content-Type");
        assertThat(response.getFirstHeader(
                HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS).getValue())
                .isEqualTo("ETag");
        assertThat(response.getFirstHeader(
                HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS))
                .isNull();
    }

    @Test
    public void testCorsActual() throws Exception {
        var request = new HttpGet(presignedGET);
        request.setHeader(HttpHeaders.ORIGIN, "https://example.com");
        HttpResponse response = httpClient.execute(request);
        assertThat(response.getStatusLine().getStatusCode())
                .isEqualTo(HttpStatus.SC_OK);
        assertThat(response.containsHeader(
                HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN)).isTrue();
        assertThat(response.getFirstHeader(
                HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN).getValue())
                .isEqualTo("https://example.com");
        assertThat(response.containsHeader(
                HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS)).isTrue();
        assertThat(response.getFirstHeader(
                HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS).getValue())
                    .isEqualTo("GET, PUT");
        assertThat(response.getFirstHeader(
                HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS).getValue())
                .isEqualTo("ETag");
    }

    @Test
    public void testNonCors() throws Exception {
        var request = new HttpGet(presignedGET);
        HttpResponse response = httpClient.execute(request);
        assertThat(response.getStatusLine().getStatusCode())
                .isEqualTo(HttpStatus.SC_OK);
        assertThat(response.containsHeader(
                HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN)).isFalse();
        assertThat(response.containsHeader(
                HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS)).isFalse();
    }

    private static String createRandomContainerName() {
        return "s3proxy-" + new Random().nextInt(Integer.MAX_VALUE);
    }

    private static CloseableHttpClient getHttpClient() throws
            KeyManagementException, NoSuchAlgorithmException,
            KeyStoreException {
        // Relax SSL Certificate check
        var sslContext = new SSLContextBuilder().loadTrustMaterial(
                null, new TrustStrategy() {
                    @Override
                    public boolean isTrusted(X509Certificate[] arg0,
                            String arg1) throws CertificateException {
                        return true;
                    }
                }).build();

        Registry<ConnectionSocketFactory> registry = RegistryBuilder
                .<ConnectionSocketFactory>create()
                .register("http", PlainConnectionSocketFactory.INSTANCE)
                .register("https", new SSLConnectionSocketFactory(sslContext,
                NoopHostnameVerifier.INSTANCE)).build();

        PoolingHttpClientConnectionManager connectionManager = new
                PoolingHttpClientConnectionManager(registry);

        return HttpClients.custom().setConnectionManager(connectionManager)
                .build();
    }
}
