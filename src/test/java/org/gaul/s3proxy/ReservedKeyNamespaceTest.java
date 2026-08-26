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
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.net.URI;
import java.nio.charset.StandardCharsets;
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
import software.amazon.awssdk.services.s3.model.Delete;
import software.amazon.awssdk.services.s3.model.ObjectIdentifier;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.utils.AttributeMap;

/**
 * S3Proxy keeps two name prefixes for itself on the stub backends: the store's
 * multipart parts ({@code .mpus-}) and the handler's stub carrying the
 * metadata, checksum and ACL that CompleteMultipartUpload gives the finished
 * object ({@code .s3proxy-mpu-stub-}).  Both are hidden from list(), and upload
 * ids are not secret -- ListMultipartUploads hands them out -- so a client able
 * to write either name decides what another client's in-flight upload
 * publishes, and leaves objects the bucket's owner can neither see nor delete.
 */
public final class ReservedKeyNamespaceTest {
    private static final String MULTIPART_PREFIX = ".mpus-";
    private static final String STUB_PREFIX = ".s3proxy-mpu-stub-";
    private static final byte[] CONTENT =
            "victim content".getBytes(StandardCharsets.UTF_8);

    private S3Proxy s3Proxy;
    private BlobStore blobStore;
    private S3Client client;
    private String containerName;
    private String uploadId;
    private String provider;

    @BeforeEach
    public void setUp() throws Exception {
        // These prefixes are the stub backends' own bookkeeping.  A store
        // that keeps its multipart state elsewhere has no such namespace to
        // defend, and so refuses nothing written to one.
        provider = TestUtils.testBlobStoreProvider();
        assumeTrue(Quirks.MULTIPART_REQUIRES_STUB.contains(provider));

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

        // An upload another client would like to interfere with, left in
        // flight for the duration of each test.
        uploadId = client.createMultipartUpload(b -> b
                .bucket(containerName).key("victim")
                .contentType("text/plain")).uploadId();
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

    /** The name of the file holding part one of the upload in flight. */
    private String partKey() {
        return MULTIPART_PREFIX + uploadId + "-victim-1";
    }

    private String stubKey() {
        return STUB_PREFIX + uploadId;
    }

    private static void assertRefused(
            org.assertj.core.api.ThrowableAssert.ThrowingCallable callable) {
        assertThatThrownBy(callable)
                .isInstanceOf(S3Exception.class)
                .satisfies(thrown -> {
                    var e = (S3Exception) thrown;
                    assertThat(e.statusCode()).isEqualTo(400);
                    assertThat(e.awsErrorDetails().errorCode())
                            .isEqualTo("InvalidArgument");
                });
    }

    @Test
    public void testPutIntoMultipartNamespaceIsRefused() {
        assertRefused(() -> client.putObject(
                b -> b.bucket(containerName).key(partKey()),
                RequestBody.fromString("attacker")));
    }

    @Test
    public void testPutOfMultipartStubIsRefused() {
        assertRefused(() -> client.putObject(
                b -> b.bucket(containerName).key(stubKey())
                        .contentType("text/attacker"),
                RequestBody.empty()));
    }

    @Test
    public void testDeleteOfReservedKeyIsRefused() {
        assertRefused(() -> client.deleteObject(
                b -> b.bucket(containerName).key(partKey())));
        assertRefused(() -> client.deleteObject(
                b -> b.bucket(containerName).key(stubKey())));
    }

    /** The keys arrive in the body here rather than the URI. */
    @Test
    public void testMultiDeleteOfReservedKeyIsRefused() {
        assertRefused(() -> client.deleteObjects(b -> b
                .bucket(containerName)
                .delete(Delete.builder()
                        .objects(ObjectIdentifier.builder()
                                .key(stubKey()).build())
                        .build())));
    }

    @Test
    public void testCopyOntoReservedKeyIsRefused() {
        client.putObject(b -> b.bucket(containerName).key("source"),
                RequestBody.fromBytes(CONTENT));
        assertRefused(() -> client.copyObject(b -> b
                .sourceBucket(containerName).sourceKey("source")
                .destinationBucket(containerName).destinationKey(partKey())));
    }

    /** The source names an object in a header rather than the URI. */
    @Test
    public void testCopyFromReservedKeyIsRefused() {
        assertRefused(() -> client.copyObject(b -> b
                .sourceBucket(containerName).sourceKey(stubKey())
                .destinationBucket(containerName).destinationKey("stolen")));
    }

    @Test
    public void testSetAclOnReservedKeyIsRefused() {
        assertRefused(() -> client.putObjectAcl(b -> b
                .bucket(containerName).key(partKey()).acl("public-read")));
    }

    /**
     * Completing an upload writes an object under the requested key, so a
     * reserved key must be refused where the upload starts.
     */
    @Test
    public void testInitiateWithReservedKeyIsRefused() {
        assertRefused(() -> client.createMultipartUpload(b -> b
                .bucket(containerName).key(MULTIPART_PREFIX + "sneaky")));
        assertRefused(() -> client.createMultipartUpload(b -> b
                .bucket(containerName).key(STUB_PREFIX + "sneaky")));
    }

    /**
     * Naming the prefix used to turn the filter off, which made these hidden
     * by default rather than hidden.
     */
    @Test
    public void testReservedKeysAreNotListable() {
        client.uploadPart(b -> b.bucket(containerName).key("victim")
                .uploadId(uploadId).partNumber(1),
                RequestBody.fromBytes(CONTENT));

        assertThat(client.listObjectsV2(b -> b.bucket(containerName)
                .prefix(MULTIPART_PREFIX)).contents()).isEmpty();
        assertThat(client.listObjectsV2(b -> b.bucket(containerName)
                .prefix(STUB_PREFIX)).contents()).isEmpty();
        assertThat(client.listObjectsV2(b -> b.bucket(containerName))
                .contents()).isEmpty();
    }

    /** What the refusals above protect: the upload publishes what it was given. */
    @Test
    public void testUploadInFlightIsUnaffected() {
        // The content type the upload was created with comes back from the
        // stub, which sftp has nowhere to keep.
        assumeTrue(!Quirks.NO_PERSISTED_METADATA.contains(provider));
        var part = client.uploadPart(b -> b.bucket(containerName).key("victim")
                .uploadId(uploadId).partNumber(1),
                RequestBody.fromBytes(CONTENT));
        client.completeMultipartUpload(b -> b
                .bucket(containerName).key("victim").uploadId(uploadId)
                .multipartUpload(CompletedMultipartUpload.builder()
                        .parts(CompletedPart.builder().partNumber(1)
                                .eTag(part.eTag()).build())
                        .build()));

        var got = client.getObjectAsBytes(
                b -> b.bucket(containerName).key("victim"));
        assertThat(got.asByteArray()).isEqualTo(CONTENT);
        assertThat(got.response().contentType()).isEqualTo("text/plain");
        assertThat(client.listObjectsV2(b -> b.bucket(containerName))
                .contents().stream().map(o -> o.key()))
                .containsExactly("victim");
    }
}
