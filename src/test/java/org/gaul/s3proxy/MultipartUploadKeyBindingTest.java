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

import org.assertj.core.api.Assertions;
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
import software.amazon.awssdk.services.s3.model.CompletedPart;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.utils.AttributeMap;

/**
 * An upload id names an upload of one key.  Paired with another it names
 * nothing, as in S3: otherwise a request for one key could finish an upload
 * begun for another under its own name, with the ACL and metadata that
 * upload was given.  Runs on every backend, since the stub backends keep
 * the pairing themselves.
 */
public final class MultipartUploadKeyBindingTest {
    private S3Proxy s3Proxy;
    private BlobStore blobStore;
    private S3Client client;
    private String bucket;

    @BeforeEach
    public void setUp() throws Exception {
        TestUtils.S3ProxyLaunchInfo info = TestUtils.startS3Proxy(
                System.getProperty("s3proxy.test.conf", "s3proxy.conf"));
        s3Proxy = info.getS3Proxy();
        blobStore = info.getBlobStore();
        bucket = TestUtils.createRandomContainerName();
        blobStore.createContainer(bucket);
        client = S3Client.builder()
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create(info.getS3Identity(),
                                info.getS3Credential())))
                .region(Region.US_EAST_1)
                .endpointOverride(URI.create(info.getSecureEndpoint() +
                        info.getServicePath()))
                .httpClient(Apache5HttpClient.builder().buildWithDefaults(
                        AttributeMap.builder().put(SdkHttpConfigurationOption
                                .TRUST_ALL_CERTIFICATES, true).build()))
                .serviceConfiguration(S3Configuration.builder()
                        .pathStyleAccessEnabled(true).build())
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
        if (blobStore != null && bucket != null) {
            blobStore.deleteContainer(bucket);
        }
    }

    @Test
    public void testUploadIdDoesNotNameAnotherKey() {
        String uploadId = client.createMultipartUpload(b -> b.bucket(bucket)
                .key("a")).uploadId();
        assertNoSuchUpload(() -> client.uploadPart(b -> b.bucket(bucket)
                .key("b").uploadId(uploadId).partNumber(1),
                RequestBody.fromString("part")));
        assertNoSuchUpload(() -> client.listParts(b -> b.bucket(bucket)
                .key("b").uploadId(uploadId)));
        assertNoSuchUpload(() -> client.completeMultipartUpload(b -> b
                .bucket(bucket).key("b").uploadId(uploadId)
                .multipartUpload(m -> m.parts(CompletedPart.builder()
                        .partNumber(1).eTag("\"x\"").build()))));
        assertNoSuchUpload(() -> client.abortMultipartUpload(b -> b
                .bucket(bucket).key("b").uploadId(uploadId)));
        assertThat(blobStore.blobExists(bucket, "b")).isFalse();

        // the upload of the key it was begun for is untouched
        String etag = client.uploadPart(b -> b.bucket(bucket).key("a")
                .uploadId(uploadId).partNumber(1),
                RequestBody.fromString("part")).eTag();
        client.completeMultipartUpload(b -> b.bucket(bucket).key("a")
                .uploadId(uploadId).multipartUpload(m -> m.parts(
                        CompletedPart.builder().partNumber(1).eTag(etag)
                                .build())));
        assertThat(blobStore.blobExists(bucket, "a")).isTrue();
        blobStore.removeBlob(bucket, "a");
    }

    private static void assertNoSuchUpload(Runnable runnable) {
        S3Exception e = Assertions.catchThrowableOfType(S3Exception.class,
                runnable::run);
        assertThat(e).isNotNull();
        assertThat(e.statusCode()).isEqualTo(404);
    }
}
