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

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import com.amazonaws.HttpMethod;
import com.amazonaws.SDKGlobalConfiguration;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.client.builder.AwsClientBuilder.EndpointConfiguration;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.CannedAccessControlList;
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

public final class CrossOriginResourceSharingAllowAllResponseTest {
    static {
        System.setProperty(
                SDKGlobalConfiguration.DISABLE_CERT_CHECKING_SYSTEM_PROPERTY,
                "true");
        AwsSdkTest.disableSslVerification();
    }

    private URI s3Endpoint;
    private EndpointConfiguration s3EndpointConfig;
    private S3Proxy s3Proxy;
    private BlobStoreContext context;
    private String containerName;
    private AWSCredentials awsCreds;
    private AmazonS3 s3Client;
    private String servicePath;
    private CloseableHttpClient httpClient;
    private URI presignedGET;

    @Before
    public void setUp() throws Exception {
        TestUtils.S3ProxyLaunchInfo info = TestUtils.startS3Proxy(
                "s3proxy-cors-allow-all.conf");
        awsCreds = new BasicAWSCredentials(info.getS3Identity(),
                info.getS3Credential());
        context = info.getBlobStore().getContext();
        s3Proxy = info.getS3Proxy();
        s3Endpoint = info.getSecureEndpoint();
        servicePath = info.getServicePath();
        s3EndpointConfig = new EndpointConfiguration(
                s3Endpoint.toString() + servicePath, "us-east-1");
        s3Client = AmazonS3ClientBuilder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(awsCreds))
                .withEndpointConfiguration(s3EndpointConfig)
                .build();
        httpClient = getHttpClient();

        containerName = createRandomContainerName();
        info.getBlobStore().createContainerInLocation(null, containerName);

        s3Client.setBucketAcl(containerName,
                CannedAccessControlList.PublicRead);

        String blobName = "test";
        ByteSource payload = ByteSource.wrap("blob-content".getBytes(
                StandardCharsets.UTF_8));
        Blob blob = info.getBlobStore().blobBuilder(blobName)
                .payload(payload).contentLength(payload.size()).build();
        info.getBlobStore().putBlob(containerName, blob);

        var expiration = new Date(System.currentTimeMillis() +
                TimeUnit.HOURS.toMillis(1));
        presignedGET = s3Client.generatePresignedUrl(containerName, blobName,
                expiration, HttpMethod.GET).toURI();
    }

    @After
    public void tearDown() throws Exception {
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
        // Allowed origin, method and header combination
        var request = new HttpOptions(presignedGET);
        request.setHeader(HttpHeaders.ORIGIN, "https://example.com");
        request.setHeader(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "GET");
        request.setHeader(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS,
                "Accept, Content-Type");
        HttpResponse response = httpClient.execute(request);
        assertThat(response.getStatusLine().getStatusCode())
                .isEqualTo(HttpStatus.SC_OK);
        assertThat(response.containsHeader(
                HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN)).isTrue();
        assertThat(response.getFirstHeader(
                HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN).getValue())
                .isEqualTo("*");
        assertThat(response.containsHeader(
                HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS)).isTrue();
        assertThat(response.getFirstHeader(
                HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS).getValue())
                .isEqualTo("GET, HEAD, PUT, POST, DELETE");
        assertThat(response.containsHeader(
                HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS)).isTrue();
        assertThat(response.getFirstHeader(
                HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS).getValue())
                .isEqualTo("Accept, Content-Type");
        assertThat(response.containsHeader(
                HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS)).isTrue();
        assertThat(response.getFirstHeader(
                HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS).getValue())
                .isEqualTo("*");
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
                .isEqualTo("*");
        assertThat(response.containsHeader(
                HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS)).isTrue();
        assertThat(response.getFirstHeader(
                HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS).getValue())
                .isEqualTo("GET, HEAD, PUT, POST, DELETE");
        assertThat(response.containsHeader(
                HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS)).isTrue();
        assertThat(response.getFirstHeader(
                HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS).getValue())
                .isEqualTo("*");
    }

    @Test
    public void testNonCors() throws Exception {
        var request = new HttpGet(presignedGET);
        HttpResponse response = httpClient.execute(request);
        assertThat(response.getStatusLine().getStatusCode())
                .isEqualTo(HttpStatus.SC_OK);
        assertThat(response.containsHeader(
                HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN)).isFalse();
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
