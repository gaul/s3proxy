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

import org.jclouds.blobstore.BlobStoreContext;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.client.config.ClientOverrideConfiguration;
import software.amazon.awssdk.core.retry.RetryPolicy;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.http.SdkHttpConfigurationOption;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.utils.AttributeMap;

public final class AwsSdk2Test {
    private BlobStoreContext context;
    private S3Client s3Client;
    private String containerName;

    @Before
    public void setUp() throws Exception {
        var info = TestUtils.startS3Proxy(System.getProperty("s3proxy.test.conf", "s3proxy.conf"));
        context = info.getBlobStore().getContext();

        var attributeMap = AttributeMap.builder()
                .put(SdkHttpConfigurationOption.TRUST_ALL_CERTIFICATES, true)
                .build();
        s3Client = S3Client.builder()
                .credentialsProvider(
                        StaticCredentialsProvider.create(
                                AwsBasicCredentials.create(info.getS3Identity(), info.getS3Credential())))
                .region(Region.US_EAST_1)
                .endpointOverride(info.getSecureEndpoint())
                .httpClient(ApacheHttpClient.builder()
                        .buildWithDefaults(attributeMap))
                .overrideConfiguration(ClientOverrideConfiguration.builder()
                        .retryPolicy(RetryPolicy.builder()
                                .numRetries(0)
                                .build())
                        .build())
                .build();

        containerName = AwsSdkTest.createRandomContainerName();
        info.getBlobStore().createContainerInLocation(null, containerName);
    }

    @After
    public void tearDown() throws Exception {
        if (s3Client != null) {
            s3Client.close();
        }
        if (context != null) {
            context.getBlobStore().deleteContainer(containerName);
            context.close();
        }
    }

    @Test
    public void testPutObject() throws Exception {
        var key = "testPutObject";
        var byteSource = TestUtils.randomByteSource().slice(0, 1024);

        var putRequest = PutObjectRequest.builder()
                .bucket(containerName)
                .key(key)
                .build();

        s3Client.putObject(putRequest, RequestBody.fromBytes(byteSource.read()));
    }
}
