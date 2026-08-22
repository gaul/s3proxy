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

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.ForwardingBlobStore;
import org.gaul.s3proxy.blobstore.S3Exceptions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.model.BucketVersioningStatus;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.DeleteObjectResponse;
import software.amazon.awssdk.services.s3.model.ObjectIdentifier;

/**
 * DeleteObjects answers 200 carrying an Error element for each key it could
 * not delete, whatever the backing service said about that key.  Failing the
 * whole request instead would tell a client nothing was deleted while the
 * keys before the failing one already had been -- and which codes a service
 * uses is not something S3Proxy can know in advance: LocalStack refuses a
 * version it does not have with InvalidArgument where S3 says NoSuchVersion.
 */
public final class MultiDeletePartialFailureTest {
    /** Refuses one key the way a backend nobody anticipated might. */
    private static final class RefuseOneKey extends ForwardingBlobStore {
        private final String refusedKey;

        RefuseOneKey(BlobStore blobStore, String refusedKey) {
            super(blobStore);
            this.refusedKey = refusedKey;
        }

        @Override
        public boolean supportsVersioning() {
            return true;
        }

        @Override
        public DeleteObjectResponse removeBlob(DeleteObjectRequest request) {
            if (request.key().equals(refusedKey)) {
                throw S3Exceptions.invalidArgument(
                        "Invalid version id specified");
            }
            return delegate().removeBlob(request);
        }
    }

    private S3Proxy s3Proxy;
    private BlobStore blobStore;
    private S3Client client;
    private String containerName;

    @BeforeEach
    public void setUp() throws Exception {
        blobStore = new RefuseOneKey(TestUtils.createTransientBlobStore(),
                "refused");
        containerName = TestUtils.createRandomContainerName();

        s3Proxy = S3Proxy.builder()
                .stopTimeout(0)
                .endpoint(URI.create("http://127.0.0.1:0"))
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

        client.createBucket(b -> b.bucket(containerName));
        client.putBucketVersioning(b -> b.bucket(containerName)
                .versioningConfiguration(v -> v.status(
                        BucketVersioningStatus.ENABLED)));
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
    public void testOneRefusedKeyDoesNotFailTheRequest() {
        for (String key : new String[] {"first", "refused", "last"}) {
            client.putObject(b -> b.bucket(containerName).key(key),
                    RequestBody.fromString("content"));
        }

        var response = client.deleteObjects(b -> b.bucket(containerName)
                .delete(d -> d.objects(
                        ObjectIdentifier.builder().key("first").build(),
                        ObjectIdentifier.builder().key("refused").build(),
                        ObjectIdentifier.builder().key("last").build())));

        assertThat(response.deleted()).extracting(d -> d.key())
                .containsExactlyInAnyOrder("first", "last");
        assertThat(response.errors()).hasSize(1);
        var error = response.errors().get(0);
        assertThat(error.key()).isEqualTo("refused");
        assertThat(error.code()).isEqualTo("InvalidArgument");
        assertThat(error.message()).isEqualTo("Invalid version id specified");
    }
}
