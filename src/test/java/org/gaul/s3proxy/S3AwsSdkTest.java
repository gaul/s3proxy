/*
 * Copyright 2014 Andrew Gaul <andrew@gaul.org>
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

import java.io.InputStream;
import java.net.URI;
import java.util.Properties;
import java.util.Random;

import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.model.AmazonS3Exception;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import com.google.common.io.Resources;
import com.google.inject.Module;

import org.eclipse.jetty.util.component.AbstractLifeCycle;
import org.jclouds.Constants;
import org.jclouds.ContextBuilder;
import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.BlobStoreContext;
import org.jclouds.logging.slf4j.config.SLF4JLoggingModule;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public final class S3AwsSdkTest {
    @Rule
    public ExpectedException thrown = ExpectedException.none();

    private URI s3Endpoint;
    private S3Proxy s3Proxy;
    private BlobStoreContext context;
    private BlobStoreContext s3Context;
    private BlobStore s3BlobStore;
    private String containerName;
    private String s3Identity;
    private String s3Credential;

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
        s3Identity = s3ProxyProperties.getProperty(
                S3ProxyConstants.PROPERTY_IDENTITY);
        s3Credential = s3ProxyProperties.getProperty(
                S3ProxyConstants.PROPERTY_CREDENTIAL);
        // The AWS client fails if certificate verification fails
        s3Endpoint = new URI(s3ProxyProperties.getProperty(
                S3ProxyConstants.PROPERTY_ENDPOINT).
                replaceAll("https", "http"));
        String keyStorePath = s3ProxyProperties.getProperty(
                S3ProxyConstants.PROPERTY_KEYSTORE_PATH);
        String keyStorePassword = s3ProxyProperties.getProperty(
                S3ProxyConstants.PROPERTY_KEYSTORE_PASSWORD);
        String forceMultiPartUpload = s3ProxyProperties.getProperty(
                S3ProxyConstants.PROPERTY_FORCE_MULTI_PART_UPLOAD);
        String virtualHost = s3ProxyProperties.getProperty(
                S3ProxyConstants.PROPERTY_VIRTUAL_HOST);

        Properties properties = new Properties();
        ContextBuilder builder = ContextBuilder
                .newBuilder(provider)
                .credentials(identity, credential)
                .modules(ImmutableList.<Module>of(new SLF4JLoggingModule()))
                .overrides(properties);
        if (!Strings.isNullOrEmpty(endpoint)) {
            builder.endpoint(endpoint);
        }
        context = builder.build(BlobStoreContext.class);
        BlobStore blobStore = context.getBlobStore();
        containerName = createRandomContainerName();
        blobStore.createContainerInLocation(null, containerName);

        S3Proxy.Builder s3ProxyBuilder = S3Proxy.builder()
                .blobStore(blobStore)
                .endpoint(s3Endpoint)
                .forceMultiPartUpload("true".equalsIgnoreCase(
                        forceMultiPartUpload));
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
        s3Endpoint = new URI(s3Endpoint.getScheme(), s3Endpoint.getUserInfo(),
                s3Endpoint.getHost(), s3Proxy.getPort(), s3Endpoint.getPath(),
                s3Endpoint.getQuery(), s3Endpoint.getFragment());

        Properties s3Properties = new Properties();
        s3Properties.setProperty(Constants.PROPERTY_TRUST_ALL_CERTS, "true");
        s3Context = ContextBuilder
                .newBuilder("s3")
                .credentials(s3Identity, s3Credential)
                .endpoint(s3Endpoint.toString())
                .overrides(s3Properties)
                .build(BlobStoreContext.class);
        s3BlobStore = s3Context.getBlobStore();
    }

    @After
    public void tearDown() throws Exception {
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
        if (s3Context != null) {
            s3Context.close();
        }
        if (context != null) {
            context.getBlobStore().deleteContainer(containerName);
            context.close();
        }
    }

    @Test
    public void testAwsV4Failure() throws Exception {
        BasicAWSCredentials awsCreds = new BasicAWSCredentials(s3Identity,
                s3Credential);
        AmazonS3 client = new AmazonS3Client(awsCreds);
        client.setEndpoint(s3Endpoint.toString());

        thrown.expect(AmazonS3Exception.class);
        thrown.expectMessage("Status Code: 400; Error Code: InvalidArgument");
        client.getObject(containerName, "foo");
    }

    private static String createRandomContainerName() {
        return "s3proxy-" + new Random().nextInt(Integer.MAX_VALUE);
    }
}
