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
import java.util.List;

import org.assertj.core.api.Fail;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.ForwardingBlobStore;
import org.gaul.s3proxy.blobstore.domain.MultipartPart;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.gaul.s3proxy.blobstore.options.CreateContainerOptions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.model.CompletedMultipartUpload;
import software.amazon.awssdk.services.s3.model.CompletedPart;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.services.s3.model.UploadPartResponse;

public final class S3ProxyCompleteMultipartUploadErrorTest {
    private BlobStore blobStore;
    private S3Proxy s3Proxy;
    private S3Client client;
    private String containerName;

    @BeforeEach
    public void setUp() throws Exception {
        blobStore = TestUtils.createTransientBlobStore();
        containerName = TestUtils.createRandomContainerName();
        blobStore.createContainer(containerName, CreateContainerOptions.NONE);

        // Fail only completeMultipartUpload, so the upload succeeds up to the
        // point where the response has already been committed with 200.
        BlobStore failing = new ForwardingBlobStore(blobStore) {
            @Override
            public String completeMultipartUpload(MultipartUpload mpu,
                    List<MultipartPart> parts) {
                throw new RuntimeException("simulated late backend failure");
            }
        };

        s3Proxy = S3Proxy.builder()
                .endpoint(URI.create("http://127.0.0.1:0"))
                .blobStore(failing)
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
        if (blobStore != null) {
            blobStore.close();
        }
    }

    @Test
    public void testLateCompletionFailureReportsError() throws Exception {
        String key = "mpu-key";
        CreateMultipartUploadResponse init = client.createMultipartUpload(
                b -> b.bucket(containerName).key(key));
        String uploadId = init.uploadId();
        UploadPartResponse part = client.uploadPart(
                b -> b.bucket(containerName).key(key).uploadId(uploadId)
                        .partNumber(1),
                RequestBody.fromBytes(new byte[1]));

        // completeMultipartUpload fails in the backend after the 200 status
        // and XML prolog are already sent.  The client must still see an
        // error rather than a truncated success document.
        try {
            client.completeMultipartUpload(b -> b.bucket(containerName).key(key)
                    .uploadId(uploadId)
                    .multipartUpload(CompletedMultipartUpload.builder()
                            .parts(CompletedPart.builder().partNumber(1)
                                    .eTag(part.eTag()).build())
                            .build()));
            Fail.failBecauseExceptionWasNotThrown(S3Exception.class);
        } catch (S3Exception e) {
            assertThat(e.awsErrorDetails().errorCode()).isEqualTo(
                    "InternalError");
        }
    }
}
