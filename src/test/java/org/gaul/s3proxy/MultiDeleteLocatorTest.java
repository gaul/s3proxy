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

import java.net.URI;
import java.nio.charset.StandardCharsets;

import com.google.common.io.ByteSource;

import org.gaul.s3proxy.auth.AuthenticationType;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.model.DeleteObjectsResponse;
import software.amazon.awssdk.services.s3.model.ObjectIdentifier;
import software.amazon.awssdk.services.s3.model.S3Exception;

/**
 * DeleteObjects names its keys in the request body, where the request URI
 * names only the bucket.  What a {@link BlobStoreLocator} says about a key
 * must hold for them as it does for the key of a DELETE: a key it refuses
 * the identity is not deleted, and a key it places in another store is
 * deleted from that store.
 */
public final class MultiDeleteLocatorTest {
    private static final String IDENTITY = "alice";
    private static final String CREDENTIAL = "alice-secret";

    private S3Proxy s3Proxy;
    private BlobStore blobStore;
    private BlobStore archiveStore;
    private S3Client client;
    private String containerName;

    @BeforeEach
    public void setUp() throws Exception {
        blobStore = TestUtils.createTransientBlobStore();
        archiveStore = TestUtils.createTransientBlobStore();
        containerName = TestUtils.createRandomContainerName();
        blobStore.createContainer(containerName);
        archiveStore.createContainer(containerName);

        s3Proxy = S3Proxy.builder()
                .stopTimeout(0)
                .endpoint(URI.create("http://127.0.0.1:0"))
                .awsAuthentication(AuthenticationType.AWS_V2_OR_V4,
                        IDENTITY, CREDENTIAL)
                .blobStore(blobStore)
                .build();
        // alice may address the bucket and the keys under her own name.
        // Those under archive/ are hers as well, but another store has them.
        s3Proxy.setBlobStoreLocator((identity, container, blob) -> {
            if (!IDENTITY.equals(identity)) {
                return null;
            } else if (blob == null || blob.startsWith("alice/")) {
                return new AccessGrant(CREDENTIAL, blobStore);
            } else if (blob.startsWith("archive/")) {
                return new AccessGrant(CREDENTIAL, archiveStore);
            }
            return null;
        });
        s3Proxy.start();

        client = S3Client.builder()
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create(IDENTITY, CREDENTIAL)))
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
        if (archiveStore != null) {
            archiveStore.close();
        }
    }

    @Test
    public void testKeyTheLocatorRefusesIsNotDeleted() throws Exception {
        putBlob(blobStore, "alice/key");
        putBlob(blobStore, "bob/key");

        assertThatThrownBy(() -> deleteObjects("alice/key", "bob/key"))
                .isInstanceOfSatisfying(S3Exception.class, e -> {
                    assertThat(e.statusCode()).isEqualTo(403);
                    assertThat(e.awsErrorDetails().errorCode())
                            .isEqualTo("AccessDenied");
                });

        assertThat(blobStore.blobExists(containerName, "bob/key")).isTrue();
        // refused before any key is deleted
        assertThat(blobStore.blobExists(containerName, "alice/key")).isTrue();
    }

    @Test
    public void testKeyTheLocatorGrantsIsDeleted() throws Exception {
        putBlob(blobStore, "alice/key");

        var response = deleteObjects("alice/key");

        assertThat(response.deleted()).extracting(d -> d.key())
                .containsExactly("alice/key");
        assertThat(response.errors()).isEmpty();
        assertThat(blobStore.blobExists(containerName, "alice/key")).isFalse();
    }

    @Test
    public void testKeyIsDeletedFromTheStoreTheLocatorNames()
            throws Exception {
        putBlob(blobStore, "alice/key");
        putBlob(archiveStore, "archive/key");
        // the same name in the store the request itself was located in,
        // which the locator hands nobody
        putBlob(blobStore, "archive/key");

        var response = deleteObjects("alice/key", "archive/key");

        assertThat(response.deleted()).extracting(d -> d.key())
                .containsExactly("alice/key", "archive/key");
        assertThat(response.errors()).isEmpty();
        assertThat(blobStore.blobExists(containerName, "alice/key")).isFalse();
        assertThat(archiveStore.blobExists(containerName, "archive/key"))
                .isFalse();
        assertThat(blobStore.blobExists(containerName, "archive/key"))
                .isTrue();
    }

    private DeleteObjectsResponse deleteObjects(String... keys) {
        var objects = new ObjectIdentifier[keys.length];
        for (int i = 0; i < keys.length; ++i) {
            objects[i] = ObjectIdentifier.builder().key(keys[i]).build();
        }
        return client.deleteObjects(b -> b.bucket(containerName)
                .delete(d -> d.objects(objects)));
    }

    private void putBlob(BlobStore store, String key) throws Exception {
        TestUtils.putBlob(store, containerName, key,
                ByteSource.wrap(key.getBytes(StandardCharsets.UTF_8)));
    }
}
