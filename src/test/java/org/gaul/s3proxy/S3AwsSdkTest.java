/*
 * Copyright 2014-2015 Andrew Gaul <andrew@gaul.org>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.gaul.s3proxy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Properties;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import com.amazonaws.ClientConfiguration;
import com.amazonaws.HttpMethod;
import com.amazonaws.SDKGlobalConfiguration;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.model.AmazonS3Exception;
import com.amazonaws.services.s3.model.GeneratePresignedUrlRequest;
import com.amazonaws.services.s3.model.ObjectMetadata;
import com.google.common.base.Strings;
import com.google.common.base.Throwables;
import com.google.common.collect.ImmutableList;
import com.google.common.io.ByteSource;
import com.google.common.io.Resources;
import com.google.inject.Module;

import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.eclipse.jetty.util.component.AbstractLifeCycle;
import org.jclouds.Constants;
import org.jclouds.ContextBuilder;
import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.BlobStoreContext;
import org.jclouds.logging.slf4j.config.SLF4JLoggingModule;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public final class S3AwsSdkTest {
    static {
        System.setProperty(
                SDKGlobalConfiguration.DISABLE_CERT_CHECKING_SYSTEM_PROPERTY,
                "true");
        System.setProperty(
                SDKGlobalConfiguration.ENFORCE_S3_SIGV4_SYSTEM_PROPERTY,
                "true");
        disableSslVerification();
    }

    private static final ByteSource BYTE_SOURCE = ByteSource.wrap(new byte[1]);

    private URI s3Endpoint;
    private S3Proxy s3Proxy;
    private BlobStoreContext context;
    private String containerName;
    private BasicAWSCredentials awsCreds;

    @Before
    public void setUp() throws Exception {
        Properties s3ProxyProperties = new Properties();
        try (InputStream is = Resources.asByteSource(Resources.getResource(
                "s3proxy.conf")).openStream()) {
            s3ProxyProperties.load(is);
        }

        String provider = s3ProxyProperties.getProperty(
                Constants.PROPERTY_PROVIDER);
        String identity = s3ProxyProperties.getProperty(
                Constants.PROPERTY_IDENTITY);
        String credential = s3ProxyProperties.getProperty(
                Constants.PROPERTY_CREDENTIAL);
        String endpoint = s3ProxyProperties.getProperty(
                Constants.PROPERTY_ENDPOINT);
        String s3Identity = s3ProxyProperties.getProperty(
                S3ProxyConstants.PROPERTY_IDENTITY);
        String s3Credential = s3ProxyProperties.getProperty(
                S3ProxyConstants.PROPERTY_CREDENTIAL);
        awsCreds = new BasicAWSCredentials(s3Identity, s3Credential);
        s3Endpoint = new URI(s3ProxyProperties.getProperty(
                S3ProxyConstants.PROPERTY_ENDPOINT));
        String secureEndpoint = s3ProxyProperties.getProperty(
                S3ProxyConstants.PROPERTY_SECURE_ENDPOINT);
        String keyStorePath = s3ProxyProperties.getProperty(
                S3ProxyConstants.PROPERTY_KEYSTORE_PATH);
        String keyStorePassword = s3ProxyProperties.getProperty(
                S3ProxyConstants.PROPERTY_KEYSTORE_PASSWORD);
        String virtualHost = s3ProxyProperties.getProperty(
                S3ProxyConstants.PROPERTY_VIRTUAL_HOST);

        ContextBuilder builder = ContextBuilder
                .newBuilder(provider)
                .credentials(identity, credential)
                .modules(ImmutableList.<Module>of(new SLF4JLoggingModule()))
                .overrides(s3ProxyProperties);
        if (!Strings.isNullOrEmpty(endpoint)) {
            builder.endpoint(endpoint);
        }
        context = builder.build(BlobStoreContext.class);
        BlobStore blobStore = context.getBlobStore();
        containerName = createRandomContainerName();
        blobStore.createContainerInLocation(null, containerName);

        S3Proxy.Builder s3ProxyBuilder = S3Proxy.builder()
                .blobStore(blobStore)
                .endpoint(s3Endpoint);
        if (secureEndpoint != null) {
            s3ProxyBuilder.secureEndpoint(new URI(secureEndpoint));
        }
        if (s3Identity != null || s3Credential != null) {
            s3ProxyBuilder.awsAuthentication(s3Identity, s3Credential);
        }
        if (keyStorePath != null || keyStorePassword != null) {
            s3ProxyBuilder.keyStore(
                    Resources.getResource(keyStorePath).toString(),
                    keyStorePassword);
        }
        if (virtualHost != null) {
            s3ProxyBuilder.virtualHost(virtualHost);
        }
        s3Proxy = s3ProxyBuilder.build();
        s3Proxy.start();
        while (!s3Proxy.getState().equals(AbstractLifeCycle.STARTED)) {
            Thread.sleep(1);
        }

        // reset endpoint to handle zero port
        s3Endpoint = new URI("https", s3Endpoint.getUserInfo(),
                s3Endpoint.getHost(), s3Proxy.getSecurePort(), s3Endpoint.getPath(),
                s3Endpoint.getQuery(), s3Endpoint.getFragment());
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
    }

    @Test
    public void testAwsV2Signature() throws Exception {
        AmazonS3 client = new AmazonS3Client(awsCreds,
                new ClientConfiguration().withSignerOverride("S3SignerType"));
        client.setEndpoint(s3Endpoint.toString());
        client.putObject(containerName, "foo", BYTE_SOURCE.openStream(),
                new ObjectMetadata());
    }

    @Test
    public void testAwsV4Signature() throws Exception {
        final AmazonS3 client = new AmazonS3Client(awsCreds);
        client.setEndpoint(s3Endpoint.toString());

        Throwable thrown = catchThrowable(new ThrowingCallable() {
                @Override
                public void call() throws Exception {
                    client.putObject(containerName, "foo",
                            BYTE_SOURCE.openStream(), new ObjectMetadata());
                }
            });
        assertThat(thrown).isInstanceOf(AmazonS3Exception.class);
        ((AmazonS3Exception) thrown).getErrorCode().equals("InvalidArgument");
    }

    // TODO: cannot test with jclouds since S3BlobRequestSigner does not
    // implement the same logic as
    // AWSS3BlobRequestSigner.signForTemporaryAccess.
    @Test
    public void testUrlSigning() throws Exception {
        AmazonS3 client = new AmazonS3Client(awsCreds,
                new ClientConfiguration().withSignerOverride("S3SignerType"));
        client.setEndpoint(s3Endpoint.toString());

        String blobName = "foo";
        client.putObject(containerName, blobName, BYTE_SOURCE.openStream(),
                new ObjectMetadata());

        Date expiration = new Date(System.currentTimeMillis() +
                TimeUnit.HOURS.toMillis(1));
        GeneratePresignedUrlRequest request = new GeneratePresignedUrlRequest(
                containerName, blobName);
        request.setMethod(HttpMethod.GET);
        request.setExpiration(expiration);

        URL url = client.generatePresignedUrl(request);
        try (InputStream actual = url.openStream();
                InputStream expected = BYTE_SOURCE.openStream()) {
            assertThat(actual).hasContentEqualTo(expected);
        }
    }

    private static final class NullX509TrustManager
            implements X509TrustManager {
        @Override
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

    private static void disableSslVerification() {
        try {
            // Create a trust manager that does not validate certificate chains
            TrustManager[] trustAllCerts = new TrustManager[] {
                new NullX509TrustManager() };

            // Install the all-trusting trust manager
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(
                    sc.getSocketFactory());

            // Create all-trusting host name verifier
            HostnameVerifier allHostsValid = new HostnameVerifier() {
                public boolean verify(String hostname, SSLSession session) {
                    return true;
                }
            };

            // Install the all-trusting host verifier
            HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
        } catch (KeyManagementException | NoSuchAlgorithmException e) {
            throw Throwables.propagate(e);
        }
    }

    private static String createRandomContainerName() {
        return "s3proxy-" + new Random().nextInt(Integer.MAX_VALUE);
    }
}
