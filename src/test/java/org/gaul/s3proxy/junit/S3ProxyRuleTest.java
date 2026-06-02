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

package org.gaul.s3proxy.junit;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.http.apache5.Apache5HttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.model.Bucket;
import software.amazon.awssdk.services.s3.model.NoSuchBucketException;
import software.amazon.awssdk.services.s3.model.S3Object;

/**
 * This is an example of how one would use the S3Proxy JUnit rule in a unit
 * test as opposed to a proper test of the S3ProxyRule class.
 */
public class S3ProxyRuleTest {

    private static final String MY_TEST_BUCKET = "my-test-bucket";

    @Rule public TemporaryFolder temporaryFolder = new TemporaryFolder();
    @Rule public S3ProxyRule s3Proxy = S3ProxyRule
        .builder()
        .withCredentials("access", "secret")
        .build();

    private S3Client s3Client;

    @Before
    public final void setUp() throws Exception {
        s3Client = S3Client.builder()
            .credentialsProvider(StaticCredentialsProvider.create(
                AwsBasicCredentials.create(
                    s3Proxy.getAccessKey(), s3Proxy.getSecretKey())))
            .region(Region.US_EAST_1)
            .endpointOverride(s3Proxy.getUri())
            .httpClient(Apache5HttpClient.builder().build())
            .serviceConfiguration(S3Configuration.builder()
                .pathStyleAccessEnabled(true)
                .build())
            .build();

        s3Client.createBucket(b -> b.bucket(MY_TEST_BUCKET));
    }

    @After
    public final void tearDown() throws Exception {
        if (s3Client != null) {
            s3Client.close();
        }
    }

    @Test
    public final void listBucket() {
        List<Bucket> buckets = s3Client.listBuckets().buckets();
        assertThat(buckets).hasSize(1);
        assertThat(buckets.get(0).name())
            .isEqualTo(MY_TEST_BUCKET);
    }

    @Test
    public final void uploadFile() throws Exception {
        String testInput = "content";
        s3Client.putObject(b -> b.bucket(MY_TEST_BUCKET).key("file.txt"),
                RequestBody.fromString(testInput));

        List<S3Object> objects = s3Client.listObjectsV2(
                b -> b.bucket(MY_TEST_BUCKET)).contents();
        assertThat(objects).hasSize(1);
        assertThat(objects.get(0).key()).isEqualTo("file.txt");
        assertThat(objects.get(0).size()).isEqualTo(testInput.length());
    }

    @Test
    public final void doesBucketExist() {
        assertThat(bucketExists(MY_TEST_BUCKET)).isTrue();

        // Issue #299
        assertThat(bucketExists("nonexistingbucket")).isFalse();
    }

    @Test
    public final void createExtensionWithoutCredentials() {
        S3ProxyRule extension = S3ProxyRule
                .builder()
                .build();
        assertThat(extension.getAccessKey()).isNull();
        assertThat(extension.getSecretKey()).isNull();
        assertThat(extension.getUri()).isNull();
    }

    private boolean bucketExists(String bucket) {
        try {
            s3Client.headBucket(b -> b.bucket(bucket));
            return true;
        } catch (NoSuchBucketException e) {
            return false;
        }
    }
}
