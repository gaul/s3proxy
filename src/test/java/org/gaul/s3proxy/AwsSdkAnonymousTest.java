/*
 * Copyright 2014-2020 Andrew Gaul <andrew@gaul.org>
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
import java.util.Random;

import com.amazonaws.SDKGlobalConfiguration;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.AnonymousAWSCredentials;
import com.amazonaws.client.builder.AwsClientBuilder.EndpointConfiguration;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.internal.SkipMd5CheckStrategy;
import com.amazonaws.services.s3.model.ObjectMetadata;
import com.amazonaws.services.s3.model.S3Object;
import com.google.common.io.ByteSource;

import org.jclouds.blobstore.BlobStoreContext;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public final class AwsSdkAnonymousTest {
    static {
        System.setProperty(
                SDKGlobalConfiguration.DISABLE_CERT_CHECKING_SYSTEM_PROPERTY,
                "true");
        AwsSdkTest.disableSslVerification();
    }

    private static final ByteSource BYTE_SOURCE = ByteSource.wrap(new byte[1]);

    private URI s3Endpoint;
    private EndpointConfiguration s3EndpointConfig;
    private S3Proxy s3Proxy;
    private BlobStoreContext context;
    private String blobStoreType;
    private String containerName;
    private AWSCredentials awsCreds;
    private AmazonS3 client;
    private String servicePath;

    @Before
    public void setUp() throws Exception {
        TestUtils.S3ProxyLaunchInfo info = TestUtils.startS3Proxy(
                "s3proxy-anonymous.conf");
        awsCreds = new AnonymousAWSCredentials();
        context = info.getBlobStore().getContext();
        s3Proxy = info.getS3Proxy();
        s3Endpoint = info.getSecureEndpoint();
        servicePath = info.getServicePath();
        s3EndpointConfig = new EndpointConfiguration(
                s3Endpoint.toString() + servicePath, "us-east-1");
        client = AmazonS3ClientBuilder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(awsCreds))
                .withEndpointConfiguration(s3EndpointConfig)
                .build();

        containerName = createRandomContainerName();
        info.getBlobStore().createContainerInLocation(null, containerName);

        blobStoreType = context.unwrap().getProviderMetadata().getId();
        if (Quirks.OPAQUE_ETAG.contains(blobStoreType)) {
            System.setProperty(
                    SkipMd5CheckStrategy
                            .DISABLE_GET_OBJECT_MD5_VALIDATION_PROPERTY,
                    "true");
            System.setProperty(
                    SkipMd5CheckStrategy
                            .DISABLE_PUT_OBJECT_MD5_VALIDATION_PROPERTY,
                    "true");
        }
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
    public void testListBuckets() throws Exception {
        client.listBuckets();
    }

    @Test
    public void testAwsV4SignatureChunkedAnonymous() throws Exception {
        client = AmazonS3ClientBuilder.standard()
            .withChunkedEncodingDisabled(false)
            .withEndpointConfiguration(s3EndpointConfig)
            .build();

        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentLength(BYTE_SOURCE.size());
        client.putObject(containerName, "foo", BYTE_SOURCE.openStream(),
                metadata);

        S3Object object = client.getObject(containerName, "foo");
        assertThat(object.getObjectMetadata().getContentLength()).isEqualTo(
                BYTE_SOURCE.size());
        try (InputStream actual = object.getObjectContent();
            InputStream expected = BYTE_SOURCE.openStream()) {
            assertThat(actual).hasContentEqualTo(expected);
        }
    }

    private static String createRandomContainerName() {
        return "s3proxy-" + new Random().nextInt(Integer.MAX_VALUE);
    }
}
