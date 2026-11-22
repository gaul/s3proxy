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
import java.security.MessageDigest;
import java.util.HexFormat;

import org.assertj.core.api.Assertions;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.Constants;
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
    private boolean awsS3;
    private boolean miniStack;

    @BeforeEach
    public void setUp() throws Exception {
        TestUtils.S3ProxyLaunchInfo info = TestUtils.startS3Proxy(
                System.getProperty("s3proxy.test.conf", "s3proxy.conf"));
        s3Proxy = info.getS3Proxy();
        blobStore = info.getBlobStore();
        awsS3 = "aws-s3".equals(info.getProperties().getProperty(
                Constants.PROPERTY_PROVIDER));
        // the port MiniStack's lane publishes, as AwsSdkTest has it
        miniStack = awsS3 && URI.create(info.getProperties().getProperty(
                Constants.PROPERTY_ENDPOINT, "http://stub")).getPort() ==
                4567;
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
    public void testUploadIdDoesNotNameAnotherKey() throws Exception {
        String uploadId = client.createMultipartUpload(b -> b.bucket(bucket)
                .key("a")).uploadId();
        client.putObject(b -> b.bucket(bucket).key("source"),
                RequestBody.fromString("source"));
        assertNoSuchUpload(() -> client.uploadPart(b -> b.bucket(bucket)
                .key("b").uploadId(uploadId).partNumber(1),
                RequestBody.fromString("part")));
        // The aws-s3 store relays its backend's answer, and MiniStack
        // copies the part into the other key's upload where S3 answers
        // NoSuchUpload.
        if (!miniStack) {
            assertNoSuchUpload(() -> client.uploadPartCopy(b -> b
                    .sourceBucket(bucket).sourceKey("source")
                    .destinationBucket(bucket).destinationKey("b")
                    .uploadId(uploadId).partNumber(1)));
        }
        // aws-s3 lists no parts for an upload that is not open, which is
        // how the frontend tells a completion retried from a first one; see
        // AwsSdkTest.testPartOperationsWithoutCreate
        if (awsS3) {
            assertThat(client.listParts(b -> b.bucket(bucket).key("b")
                    .uploadId(uploadId)).parts()).isEmpty();
        } else {
            assertNoSuchUpload(() -> client.listParts(b -> b.bucket(bucket)
                    .key("b").uploadId(uploadId)));
        }
        assertNoSuchUpload(() -> client.completeMultipartUpload(b -> b
                .bucket(bucket).key("b").uploadId(uploadId)
                .multipartUpload(m -> m.parts(CompletedPart.builder()
                        .partNumber(1).eTag("\"x\"").build()))));
        assertNoSuchUpload(() -> client.abortMultipartUpload(b -> b
                .bucket(bucket).key("b").uploadId(uploadId)));
        assertThat(blobStore.blobExists(bucket, "b")).isFalse();
        // nor does an upload id spelled to end in the digest of the key the
        // upload was begun for, which is how the stub backends name the
        // record of it
        String spelled = uploadId + "." + HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(
                        "a".getBytes(StandardCharsets.UTF_8)));
        assertNoSuchUpload(() -> client.abortMultipartUpload(b -> b
                .bucket(bucket).key("b").uploadId(spelled)));

        // the upload of the key it was begun for is untouched, and holds
        // no part a refused request sent
        if (!miniStack) {
            assertThat(client.listParts(b -> b.bucket(bucket).key("a")
                    .uploadId(uploadId)).parts()).isEmpty();
        }
        String etag = client.uploadPart(b -> b.bucket(bucket).key("a")
                .uploadId(uploadId).partNumber(1),
                RequestBody.fromString("part")).eTag();
        client.completeMultipartUpload(b -> b.bucket(bucket).key("a")
                .uploadId(uploadId).multipartUpload(m -> m.parts(
                        CompletedPart.builder().partNumber(1).eTag(etag)
                                .build())));
        assertThat(blobStore.blobExists(bucket, "a")).isTrue();
        blobStore.removeBlob(bucket, "a");
        blobStore.removeBlob(bucket, "source");
    }

    private static void assertNoSuchUpload(Runnable runnable) {
        S3Exception e = Assertions.catchThrowableOfType(S3Exception.class,
                runnable::run);
        assertThat(e).isNotNull();
        assertThat(e.statusCode()).isEqualTo(404);
        assertThat(e.awsErrorDetails().errorCode()).isEqualTo("NoSuchUpload");
    }
}
