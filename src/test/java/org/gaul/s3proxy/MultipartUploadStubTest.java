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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URI;
import java.nio.file.FileSystemException;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.ForwardingBlobStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.awssdk.services.s3.model.S3Exception;

/**
 * On the stores whose multipart uploads need a stub, an upload is two
 * records: the store's, which ListMultipartUploads shows and DeleteBucket
 * counts, and the stub the handler writes beside it.  A create that stores
 * the first and not the second must not leave an upload that no request can
 * end.
 */
public final class MultipartUploadStubTest {
    private static final String STUB_PREFIX = ".s3proxy-mpu-stub-";

    private BlobStore blobStore;
    private S3Proxy s3Proxy;
    private S3Client client;
    private String containerName;
    private volatile boolean failStub;

    @BeforeEach
    public void setUp() throws Exception {
        blobStore = TestUtils.createTransientBlobStore();
        containerName = TestUtils.createRandomContainerName();
        blobStore.createContainer(containerName);

        // What a file system does when the stub's attributes do not fit.
        BlobStore failing = new ForwardingBlobStore(blobStore) {
            @Override
            public PutObjectResponse putBlob(PutObjectRequest request,
                    InputStream payload) {
                if (failStub && request.key().startsWith(STUB_PREFIX)) {
                    throw new UncheckedIOException(new FileSystemException(
                            request.key(), null, "No space left on device"));
                }
                return super.putBlob(request, payload);
            }
        };

        s3Proxy = S3Proxy.builder()
                .stopTimeout(0)
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
    public void testCreateTakesUploadBackWhenStubCannotBeStored() {
        failStub = true;
        assertThatThrownBy(() -> client.createMultipartUpload(
                b -> b.bucket(containerName).key("key")))
                .isInstanceOfSatisfying(S3Exception.class,
                        e -> assertThat(e.statusCode()).isEqualTo(500));

        assertThat(client.listMultipartUploads(b -> b.bucket(containerName))
                .uploads()).isEmpty();
        client.deleteBucket(b -> b.bucket(containerName));
    }
}
