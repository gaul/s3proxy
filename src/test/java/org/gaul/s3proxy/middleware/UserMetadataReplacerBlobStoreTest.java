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

package org.gaul.s3proxy.middleware;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import org.gaul.s3proxy.S3Proxy;
import org.gaul.s3proxy.TestUtils;
import org.gaul.s3proxy.auth.AuthenticationType;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.SdkRequests;
import org.gaul.s3proxy.checksum.FlexChecksum;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.CopyObjectRequest;
import software.amazon.awssdk.services.s3.model.MetadataDirective;

@SuppressWarnings("UnstableApiUsage")
public final class UserMetadataReplacerBlobStoreTest {
    private BlobStore blobStore;
    private String containerName;
    // TODO: better name?
    private BlobStore userMetadataReplacerBlobStore;

    @BeforeEach
    public void setUp() throws Exception {
        containerName = TestUtils.createRandomContainerName();

        //noinspection UnstableApiUsage
        blobStore = TestUtils.createTransientBlobStore();
        blobStore.createContainer(containerName);

        userMetadataReplacerBlobStore = UserMetadataReplacerBlobStore
                .newUserMetadataReplacerBlobStore(blobStore, "-", "_");
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (blobStore != null) {
            blobStore.deleteContainer(containerName);
        }
    }

    @Test
    public void testPutNewBlob() throws Exception {
        var blobName = TestUtils.createRandomBlobName();
        var content = TestUtils.randomByteSource().slice(0, 1024);
        userMetadataReplacerBlobStore.putBlob(
                TestUtils.putRequest(containerName, blobName, content)
                        .toBuilder()
                        .metadata(Map.of("my-key", "my-value-"))
                        .build(),
                content.openStream());

        // check underlying blobStore
        var userMetadata = blobStore.blobMetadata(containerName, blobName)
                .metadata();
        assertThat(userMetadata).hasSize(1);
        var entry = userMetadata.entrySet().iterator().next();
        assertThat(entry.getKey()).isEqualTo("my_key");
        assertThat(entry.getValue()).isEqualTo("my_value_");

        // check getBlob
        userMetadata = userMetadataReplacerBlobStore.getBlob(
                containerName, blobName)
                .response().metadata();
        assertThat(userMetadata).hasSize(1);
        entry = userMetadata.entrySet().iterator().next();
        assertThat(entry.getKey()).isEqualTo("my-key");
        assertThat(entry.getValue()).isEqualTo("my-value-");

        // check blobMetadata
        userMetadata = userMetadataReplacerBlobStore.blobMetadata(
                containerName, blobName).metadata();
        assertThat(userMetadata).hasSize(1);
        entry = userMetadata.entrySet().iterator().next();
        assertThat(entry.getKey()).isEqualTo("my-key");
        assertThat(entry.getValue()).isEqualTo("my-value-");
    }

    /** Two keys that become one after replacement are stored as one. */
    @Test
    public void testKeysThatCollideAfterReplacement() throws Exception {
        var blobName = TestUtils.createRandomBlobName();
        var content = TestUtils.randomByteSource().slice(0, 1024);
        userMetadataReplacerBlobStore.putBlob(
                TestUtils.putRequest(containerName, blobName, content)
                        .toBuilder()
                        .metadata(Map.of("my-key", "value", "my_key",
                                "value"))
                        .build(),
                content.openStream());

        assertThat(blobStore.blobMetadata(containerName, blobName)
                .metadata()).containsOnlyKeys("my_key");
    }

    @Test
    public void testCopyBlobReplaceMetadata() throws Exception {
        var fromName = TestUtils.createRandomBlobName();
        var toName = TestUtils.createRandomBlobName();
        var content = TestUtils.randomByteSource().slice(0, 1024);
        TestUtils.putBlob(userMetadataReplacerBlobStore, containerName,
                fromName, content);

        // A copy with a metadata-replace directive must munge the new
        // metadata into the backend the same way putBlob does.
        userMetadataReplacerBlobStore.copyBlob(CopyObjectRequest.builder()
                .sourceBucket(containerName).sourceKey(fromName)
                .destinationBucket(containerName).destinationKey(toName)
                .metadataDirective(MetadataDirective.REPLACE)
                .metadata(Map.of("my-key", "my-value-"))
                .build());

        // check underlying blobStore stores the munged form
        var backend = blobStore.blobMetadata(containerName, toName)
                .metadata();
        assertThat(backend).isEqualTo(Map.of("my_key", "my_value_"));

        // check getBlob reverses it
        var replaced = userMetadataReplacerBlobStore.getBlob(
                containerName, toName).response().metadata();
        assertThat(replaced).isEqualTo(Map.of("my-key", "my-value-"));
    }

    @Test
    public void testCopyBlobPreservesMetadata() throws Exception {
        var fromName = TestUtils.createRandomBlobName();
        var toName = TestUtils.createRandomBlobName();
        var content = TestUtils.randomByteSource().slice(0, 1024);
        userMetadataReplacerBlobStore.putBlob(
                TestUtils.putRequest(containerName, fromName, content)
                        .toBuilder()
                        .metadata(Map.of("my-key", "my-value-"))
                        .build(),
                content.openStream());

        // A copy without a replace directive carries the source's stored
        // (already-munged) metadata forward untouched; it must not be
        // re-munged or wiped.
        userMetadataReplacerBlobStore.copyBlob(CopyObjectRequest.builder()
                .sourceBucket(containerName).sourceKey(fromName)
                .destinationBucket(containerName).destinationKey(toName)
                .build());

        // backend still holds the single munged form
        assertThat(blobStore.blobMetadata(containerName, toName)
                .metadata()).isEqualTo(Map.of("my_key", "my_value_"));

        // getBlob reverses it
        assertThat(userMetadataReplacerBlobStore.getBlob(containerName, toName)
                .response().metadata())
                .isEqualTo(Map.of("my-key", "my-value-"));
    }

    @Test
    public void testChecksumMetadataIsNotMapped() throws Exception {
        // What S3ProxyHandler records under FlexChecksum.METADATA_PREFIX is
        // not user metadata: neither the name nor a composite's "-<parts>"
        // may change on the way to the backend or back.
        var blobName = TestUtils.createRandomBlobName();
        var content = TestUtils.randomByteSource().slice(0, 1024);
        var metadata = Map.of(
                FlexChecksum.SHA256.metadataKey(), "dmFsdWU=-2",
                "my-key", "my-value-");
        userMetadataReplacerBlobStore.putBlob(
                TestUtils.putRequest(containerName, blobName, content)
                        .toBuilder()
                        .metadata(metadata)
                        .build(),
                content.openStream());

        assertThat(blobStore.blobMetadata(containerName, blobName).metadata())
                .isEqualTo(Map.of(
                        FlexChecksum.SHA256.metadataKey(), "dmFsdWU=-2",
                        "my_key", "my_value_"));
        assertThat(userMetadataReplacerBlobStore.getBlob(
                containerName, blobName).response().metadata())
                .isEqualTo(metadata);
        assertThat(userMetadataReplacerBlobStore.blobMetadata(
                containerName, blobName).metadata())
                .isEqualTo(metadata);
    }

    @Test
    public void testUserMetadataIsNotMappedOntoChecksumMetadata()
            throws Exception {
        // S3ProxyHandler refuses s3proxy_checksum_* from a client and takes
        // it from the store for a checksum it validated, so no other name
        // may be mapped onto one in either direction.
        String forged = FlexChecksum.SHA256.metadataKey().replace('_', '-');
        var metadata = Map.of(forged, "dmFsdWU=");

        // hyphens stored as underscores: not written under the reserved name
        var blobName = TestUtils.createRandomBlobName();
        var content = TestUtils.randomByteSource().slice(0, 1024);
        userMetadataReplacerBlobStore.putBlob(
                TestUtils.putRequest(containerName, blobName, content)
                        .toBuilder()
                        .metadata(metadata)
                        .build(),
                content.openStream());
        assertThat(blobStore.blobMetadata(containerName, blobName).metadata())
                .isEqualTo(metadata);

        var copyName = TestUtils.createRandomBlobName();
        userMetadataReplacerBlobStore.copyBlob(CopyObjectRequest.builder()
                .sourceBucket(containerName).sourceKey(blobName)
                .destinationBucket(containerName).destinationKey(copyName)
                .metadataDirective(MetadataDirective.REPLACE)
                .metadata(metadata)
                .build());
        assertThat(blobStore.blobMetadata(containerName, copyName).metadata())
                .isEqualTo(metadata);

        var mpuName = TestUtils.createRandomBlobName();
        var mpu = userMetadataReplacerBlobStore.initiateMultipartUpload(
                TestUtils.createRequest(containerName, mpuName).toBuilder()
                        .metadata(metadata)
                        .build());
        var part = TestUtils.uploadPart(userMetadataReplacerBlobStore,
                mpu, 1, content.openStream(), content.size());
        userMetadataReplacerBlobStore.completeMultipartUpload(mpu,
                SdkRequests.completeRequest(mpu,
                        List.of(TestUtils.completedPart(1, part))));
        assertThat(blobStore.blobMetadata(containerName, mpuName).metadata())
                .isEqualTo(metadata);

        // underscores stored as hyphens: not read back as the reserved name
        var underscoreReplacerBlobStore = UserMetadataReplacerBlobStore
                .newUserMetadataReplacerBlobStore(blobStore, "_", "-");
        assertThat(underscoreReplacerBlobStore.getBlob(
                containerName, blobName).response().metadata())
                .isEqualTo(metadata);
        assertThat(underscoreReplacerBlobStore.blobMetadata(
                containerName, blobName).metadata())
                .isEqualTo(metadata);
    }

    /**
     * Through S3ProxyHandler, with underscores stored as hyphens: metadata a
     * client names s3proxy-checksum-sha256 comes back as the metadata it is
     * and not as the object's checksum, while a checksum the proxy compared
     * with the body is still reported.
     */
    @Test
    public void testClientMetadataIsNotReportedAsChecksum() throws Exception {
        byte[] content = "content".getBytes(StandardCharsets.UTF_8);
        String checksum = Base64.getEncoder().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(content));
        String forged = Base64.getEncoder().encodeToString(new byte[32]);
        var s3Proxy = S3Proxy.builder()
                .stopTimeout(0)
                .blobStore(UserMetadataReplacerBlobStore
                        .newUserMetadataReplacerBlobStore(blobStore, "_", "-"))
                .awsAuthentication(AuthenticationType.NONE, null, null)
                .endpoint(URI.create("http://127.0.0.1:0"))
                .build();
        s3Proxy.start();
        try {
            while (!s3Proxy.getState().equals("STARTED")) {
                Thread.sleep(10);
            }
            var httpClient = HttpClient.newHttpClient();
            var uri = URI.create("http://127.0.0.1:" + s3Proxy.getPort() +
                    "/" + containerName + "/" +
                    TestUtils.createRandomBlobName());
            var head = HttpRequest.newBuilder(uri)
                    .header("x-amz-checksum-mode", "ENABLED")
                    .method("HEAD", HttpRequest.BodyPublishers.noBody())
                    .build();

            var response = httpClient.send(HttpRequest.newBuilder(uri)
                    .header("x-amz-meta-s3proxy-checksum-sha256", forged)
                    .PUT(HttpRequest.BodyPublishers.ofByteArray(content))
                    .build(), HttpResponse.BodyHandlers.discarding());
            assertThat(response.statusCode()).isEqualTo(200);
            response = httpClient.send(head,
                    HttpResponse.BodyHandlers.discarding());
            assertThat(response.headers().firstValue("x-amz-checksum-sha256"))
                    .isEmpty();
            assertThat(response.headers().firstValue(
                    "x-amz-meta-s3proxy-checksum-sha256")).hasValue(forged);

            response = httpClient.send(HttpRequest.newBuilder(uri)
                    .header("x-amz-checksum-sha256", checksum)
                    .header("x-amz-meta-s3proxy-checksum-sha256", forged)
                    .PUT(HttpRequest.BodyPublishers.ofByteArray(content))
                    .build(), HttpResponse.BodyHandlers.discarding());
            assertThat(response.statusCode()).isEqualTo(200);
            response = httpClient.send(head,
                    HttpResponse.BodyHandlers.discarding());
            assertThat(response.headers().firstValue("x-amz-checksum-sha256"))
                    .hasValue(checksum);
            assertThat(response.headers().firstValue(
                    "x-amz-meta-s3proxy-checksum-sha256")).hasValue(forged);
        } finally {
            s3Proxy.stop();
        }
    }

    @Test
    public void testPutNewMultipartBlob() throws Exception {
        var blobName = TestUtils.createRandomBlobName();
        var content = TestUtils.randomByteSource().slice(0, 1024);
        var mpu = userMetadataReplacerBlobStore.initiateMultipartUpload(
                TestUtils.createRequest(containerName, blobName).toBuilder()
                        .metadata(Map.of("my-key", "my-value-"))
                        .build());
        var part = TestUtils.uploadPart(userMetadataReplacerBlobStore,
                mpu, 1, content.openStream(), content.size());
        userMetadataReplacerBlobStore.completeMultipartUpload(mpu,
                SdkRequests.completeRequest(mpu,
                        List.of(TestUtils.completedPart(1, part))));

        // check underlying blobStore
        var userMetadata = blobStore.blobMetadata(containerName, blobName)
                .metadata();
        assertThat(userMetadata).hasSize(1);
        var entry = userMetadata.entrySet().iterator().next();
        assertThat(entry.getKey()).isEqualTo("my_key");
        assertThat(entry.getValue()).isEqualTo("my_value_");

        // check getBlob
        userMetadata = userMetadataReplacerBlobStore.getBlob(
                containerName, blobName)
                .response().metadata();
        assertThat(userMetadata).hasSize(1);
        entry = userMetadata.entrySet().iterator().next();
        assertThat(entry.getKey()).isEqualTo("my-key");
        assertThat(entry.getValue()).isEqualTo("my-value-");

        // check blobMetadata
        userMetadata = userMetadataReplacerBlobStore.blobMetadata(
                containerName, blobName).metadata();
        assertThat(userMetadata).hasSize(1);
        entry = userMetadata.entrySet().iterator().next();
        assertThat(entry.getKey()).isEqualTo("my-key");
        assertThat(entry.getValue()).isEqualTo("my-value-");
    }
}
