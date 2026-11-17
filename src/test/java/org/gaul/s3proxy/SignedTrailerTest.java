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

import org.gaul.s3proxy.auth.AuthenticationType;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.model.ChecksumAlgorithm;
import software.amazon.awssdk.services.s3.model.ChecksumMode;

/**
 * An upload the SDK signs chunk by chunk, which it does over plain HTTP:
 * STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER, whose checksum trailer is
 * itself signed.  The SDK is the reference for how that signature is made,
 * so its upload passing is what says the verification here agrees with it.
 */
public final class SignedTrailerTest {
    private S3Proxy s3Proxy;
    private S3Client client;
    private String containerName;

    @BeforeEach
    public void setUp() throws Exception {
        BlobStore blobStore = TestUtils.createTransientBlobStore();
        containerName = TestUtils.createRandomContainerName();
        blobStore.createContainer(containerName);

        s3Proxy = S3Proxy.builder()
                .stopTimeout(0)
                .endpoint(URI.create("http://127.0.0.1:0"))
                .awsAuthentication(AuthenticationType.AWS_V4, "identity",
                        "credential")
                .blobStore(blobStore)
                .build();
        s3Proxy.start();

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
    public void testSignedTrailerUpload() throws Exception {
        byte[] content = TestUtils.randomByteSource().slice(0, 200_000)
                .read();
        var put = client.putObject(b -> b.bucket(containerName).key("key")
                .checksumAlgorithm(ChecksumAlgorithm.CRC32_C),
                RequestBody.fromBytes(content));
        assertThat(put.checksumCRC32C()).isNotNull();
        assertThat(client.headObject(b -> b.bucket(containerName).key("key")
                .checksumMode(ChecksumMode.ENABLED)).checksumCRC32C())
                .isEqualTo(put.checksumCRC32C());
    }
}
