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
import java.time.Duration;

import org.gaul.s3proxy.auth.AuthenticationType;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.model.ObjectIdentifier;

/**
 * A body whose digest the signature covers is read before the request is
 * authenticated, to its declared length.  Read no further, Jetty did not
 * count it finished, and the drain that runs once a response is written
 * waited its full idle time for more of a body that had all arrived: each
 * such request held its connection a second longer, and the next request on
 * it waited.  Over plain HTTP an SDK signs the body of every request that
 * has one, so s3-tests ran seven times slower.
 */
public final class SignedBodyDrainTest {
    private S3Proxy s3Proxy;
    private S3Client client;

    @BeforeEach
    public void setUp() throws Exception {
        s3Proxy = S3Proxy.builder()
                .stopTimeout(0)
                .blobStore(TestUtils.createTransientBlobStore())
                .awsAuthentication(AuthenticationType.AWS_V2_OR_V4,
                        "identity", "credential")
                .endpoint(URI.create("http://127.0.0.1:0"))
                .build();
        s3Proxy.start();
        while (!s3Proxy.getState().equals("STARTED")) {
            Thread.sleep(10);
        }
        client = S3Client.builder()
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create("identity", "credential")))
                .region(Region.US_EAST_1)
                .endpointOverride(URI.create(
                        "http://127.0.0.1:" + s3Proxy.getPort()))
                .serviceConfiguration(S3Configuration.builder()
                        .pathStyleAccessEnabled(true)
                        .build())
                .build();
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (client != null) {
            client.close();
        }
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
    }

    @Test
    public void testSignedBodiesDoNotHoldTheConnection() {
        String bucket = TestUtils.createRandomContainerName();
        client.createBucket(b -> b.bucket(bucket));
        // warm up the client and its connection
        deleteObjects(bucket);

        long start = System.nanoTime();
        for (int i = 0; i < 5; ++i) {
            deleteObjects(bucket);
        }
        // each held its connection for a second before the fix
        assertThat(Duration.ofNanos(System.nanoTime() - start))
                .isLessThan(Duration.ofSeconds(3));
    }

    private void deleteObjects(String bucket) {
        client.deleteObjects(b -> b.bucket(bucket).delete(d -> d.objects(
                ObjectIdentifier.builder().key("missing").build())));
    }
}
