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
import java.util.List;
import java.util.Random;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.http.SdkHttpConfigurationOption;
import software.amazon.awssdk.http.apache5.Apache5HttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.model.CompletedMultipartUpload;
import software.amazon.awssdk.services.s3.model.CompletedPart;
import software.amazon.awssdk.services.s3.model.UploadPartResponse;
import software.amazon.awssdk.utils.AttributeMap;

/**
 * A key that a single-part PUT accepts must work through a multipart upload
 * too.  The Azure backend used to record the destination of an in-progress
 * upload in a blob index tag, whose value admits only alphanumerics and
 * " +-.:=_/", so keys holding anything else -- and every non-ASCII key --
 * failed at CreateMultipartUpload while the same key stored fine in one part.
 */
public final class MultipartUploadKeyCharacterTest {
    /** Legal S3 keys that a blob index tag value cannot hold. */
    private static final List<String> KEYS = List.of(
            "report#2026.csv",
            "50%-off.png",
            "a&b?c=d.txt",
            "quarterly report (final).pdf",
            "résumé.pdf",
            "報告書.xlsx");

    private S3Proxy s3Proxy;
    private BlobStore blobStore;
    private S3Client client;
    private String containerName;

    @BeforeEach
    public void setUp() throws Exception {
        TestUtils.S3ProxyLaunchInfo info = TestUtils.startS3Proxy(
                System.getProperty("s3proxy.test.conf", "s3proxy.conf"));
        blobStore = info.getBlobStore();
        s3Proxy = info.getS3Proxy();

        var creds = AwsBasicCredentials.create(info.getS3Identity(),
                info.getS3Credential());
        var attributeMap = AttributeMap.builder()
                .put(SdkHttpConfigurationOption.TRUST_ALL_CERTIFICATES, true)
                .build();
        client = S3Client.builder()
                .credentialsProvider(StaticCredentialsProvider.create(creds))
                .region(Region.US_EAST_1)
                .endpointOverride(URI.create(
                        info.getSecureEndpoint().toString() +
                        info.getServicePath()))
                .httpClient(Apache5HttpClient.builder()
                        .buildWithDefaults(attributeMap))
                .serviceConfiguration(S3Configuration.builder()
                        .pathStyleAccessEnabled(true)
                        .build())
                .build();

        containerName = "container-" + new Random().nextInt(Integer.MAX_VALUE);
        blobStore.createContainer(containerName);
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (client != null) {
            client.close();
        }
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
        if (blobStore != null && containerName != null) {
            blobStore.deleteContainer(containerName);
        }
    }

    @Test
    public void testMultipartUploadRoundTripsKey() {
        for (String key : KEYS) {
            byte[] content = ("content of " + key).getBytes(
                    StandardCharsets.UTF_8);

            String uploadId = client.createMultipartUpload(
                    b -> b.bucket(containerName).key(key)).uploadId();

            UploadPartResponse part = client.uploadPart(
                    b -> b.bucket(containerName).key(key).uploadId(uploadId)
                            .partNumber(1),
                    RequestBody.fromBytes(content));

            client.completeMultipartUpload(b -> b
                    .bucket(containerName).key(key).uploadId(uploadId)
                    .multipartUpload(CompletedMultipartUpload.builder()
                            .parts(CompletedPart.builder().partNumber(1)
                                    .eTag(part.eTag()).build())
                            .build()));

            byte[] fetched = client.getObjectAsBytes(
                    b -> b.bucket(containerName).key(key)).asByteArray();
            assertThat(fetched).as("round trip of %s", key).isEqualTo(content);
        }
    }

    @Test
    public void testListMultipartUploadsReportsKey() {
        for (String key : KEYS) {
            String uploadId = client.createMultipartUpload(
                    b -> b.bucket(containerName).key(key)).uploadId();

            var keys = client.listMultipartUploads(
                    b -> b.bucket(containerName)).uploads().stream()
                    .map(u -> u.key()).toList();
            assertThat(keys).as("in-progress upload of %s", key).contains(key);

            client.abortMultipartUpload(b -> b.bucket(containerName).key(key)
                    .uploadId(uploadId));
        }
    }
}
