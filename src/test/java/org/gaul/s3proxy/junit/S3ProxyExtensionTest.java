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

package org.gaul.s3proxy.junit;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.Bucket;
import com.amazonaws.services.s3.model.S3ObjectSummary;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

/**
 * This is an example of how one would use the S3Proxy JUnit extension in a unit
 * test as opposed to a proper test of the S3ProxyExtension class.
 */
public class S3ProxyExtensionTest {

    @RegisterExtension
    static final S3ProxyExtension EXTENSION = S3ProxyExtension
            .builder()
            .withCredentials("access", "secret")
            .build();

    private static final String MY_TEST_BUCKET = "my-test-bucket";

    private AmazonS3 s3Client;

    @BeforeEach
    public final void setUp() throws Exception {
        s3Client = AmazonS3ClientBuilder
        .standard()
        .withCredentials(
            new AWSStaticCredentialsProvider(
                new BasicAWSCredentials(
                    EXTENSION.getAccessKey(), EXTENSION.getSecretKey())))
        .withEndpointConfiguration(
            new AwsClientBuilder.EndpointConfiguration(
                EXTENSION.getUri().toString(), Regions.US_EAST_1.getName()))
        .build();

        s3Client.createBucket(MY_TEST_BUCKET);
    }

    @Test
    public final void listBucket() {
        List<Bucket> buckets = s3Client.listBuckets();
        assertThat(buckets).hasSize(1);
        assertThat(buckets.get(0).getName())
                .isEqualTo(MY_TEST_BUCKET);
    }

    @Test
    public final void uploadFile() throws Exception {
        String testInput = "content";
        s3Client.putObject(MY_TEST_BUCKET, "file.txt", testInput);

        List<S3ObjectSummary> summaries = s3Client
                .listObjects(MY_TEST_BUCKET)
                .getObjectSummaries();
        assertThat(summaries).hasSize(1);
        assertThat(summaries.get(0).getKey()).isEqualTo("file.txt");
        assertThat(summaries.get(0).getSize()).isEqualTo(testInput.length());
    }

    @Test
    public final void doesBucketExistV2() {
        assertThat(s3Client.doesBucketExistV2(MY_TEST_BUCKET)).isTrue();

        // Issue #299
        assertThat(s3Client.doesBucketExistV2("nonexistingbucket")).isFalse();
    }

    @Test
    public final void createExtentionWithoutCredentials() {
        S3ProxyExtension extension = S3ProxyExtension
                .builder()
                .build();
        assertThat(extension.getAccessKey()).isNull();
        assertThat(extension.getSecretKey()).isNull();
        assertThat(extension.getUri()).isNull();
    }
}
