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
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.util.Map;
import java.util.Optional;
import java.util.Random;

import com.google.common.collect.ImmutableMap;
import com.google.common.io.ByteSource;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.Constants;
import org.gaul.s3proxy.middleware.GlobBlobStoreLocator;
import org.gaul.s3proxy.middleware.GlobBlobStoreLocator.GlobTarget;
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
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.utils.AttributeMap;

/**
 * A bucket that a {@link BlobStoreLocator} refuses to hand to an identity must
 * stay unreachable through the copy-source header too, not only through the
 * request URI.
 */
public final class CopySourceAuthorizationTest {
    private static final String VICTIM_IDENTITY = "victim-identity";
    private static final String VICTIM_CREDENTIAL = "victim-credential";
    private static final String ATTACKER_IDENTITY = "attacker-identity";
    private static final String ATTACKER_CREDENTIAL = "attacker-credential";

    private S3Proxy s3Proxy;
    private BlobStore blobStore;
    private URI s3EndpointUri;
    private S3Client attackerClient;
    private String victimContainer;
    private String attackerContainer;

    @BeforeEach
    public void setUp() throws Exception {
        TestUtils.S3ProxyLaunchInfo info = TestUtils.startS3Proxy(
                System.getProperty("s3proxy.test.conf", "s3proxy.conf"));
        // Only the in-memory backend works without configuration.
        String blobStoreType = info.getProperties().getProperty(
                Constants.PROPERTY_PROVIDER, "");
        assumeTrue(blobStoreType.isEmpty() ||
                blobStoreType.equals("transient"));

        blobStore = info.getBlobStore();
        s3Proxy = info.getS3Proxy();
        s3EndpointUri = URI.create(info.getSecureEndpoint().toString() +
                info.getServicePath());

        victimContainer = "victim-" + new Random().nextInt(Integer.MAX_VALUE);
        attackerContainer = "attacker-" +
                new Random().nextInt(Integer.MAX_VALUE);
        blobStore.createContainer(victimContainer);
        blobStore.createContainer(attackerContainer);

        // Both identities are served by the same backing store but each owns
        // a disjoint set of buckets, so neither may read the other's.
        var credsMap = ImmutableMap.of(
                VICTIM_IDENTITY,
                new AccessGrant(VICTIM_CREDENTIAL, blobStore),
                ATTACKER_IDENTITY,
                new AccessGrant(ATTACKER_CREDENTIAL, blobStore));
        var globMap = Map.of(
                FileSystems.getDefault().getPathMatcher("glob:victim-*"),
                new GlobTarget(Optional.of(VICTIM_IDENTITY), blobStore),
                FileSystems.getDefault().getPathMatcher("glob:attacker-*"),
                new GlobTarget(Optional.of(ATTACKER_IDENTITY), blobStore));
        s3Proxy.setBlobStoreLocator(
                new GlobBlobStoreLocator(credsMap, globMap));

        attackerClient = buildClient(AwsBasicCredentials.create(
                ATTACKER_IDENTITY, ATTACKER_CREDENTIAL));
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (attackerClient != null) {
            attackerClient.close();
        }
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
        if (blobStore != null) {
            if (victimContainer != null) {
                blobStore.deleteContainer(victimContainer);
            }
            if (attackerContainer != null) {
                blobStore.deleteContainer(attackerContainer);
            }
        }
    }

    /** The attacker cannot read the victim bucket directly. */
    @Test
    public void testDirectGetIsDenied() {
        putSecret();

        assertThat(catchErrorCode(() -> attackerClient.getObject(
                b -> b.bucket(victimContainer).key("secret"))))
                .isNotNull();
    }

    /** Nor may it launder the same read through x-amz-copy-source. */
    @Test
    public void testCopyFromUnauthorizedSourceIsDenied() {
        putSecret();

        String errorCode = catchErrorCode(() -> attackerClient.copyObject(
                b -> b.sourceBucket(victimContainer).sourceKey("secret")
                        .destinationBucket(attackerContainer)
                        .destinationKey("loot")));
        assertThat(errorCode)
                .as("copy from a bucket the identity may not read must fail")
                .isNotNull();
        assertThat(blobStore.blobExists(attackerContainer, "loot")).isFalse();
    }

    /** Same for the multipart UploadPartCopy variant. */
    @Test
    public void testCopyPartFromUnauthorizedSourceIsDenied() {
        putSecret();

        String uploadId = attackerClient.createMultipartUpload(
                b -> b.bucket(attackerContainer).key("loot")).uploadId();
        String errorCode = catchErrorCode(() ->
                attackerClient.uploadPartCopy(
                        b -> b.sourceBucket(victimContainer)
                                .sourceKey("secret")
                                .destinationBucket(attackerContainer)
                                .destinationKey("loot")
                                .uploadId(uploadId).partNumber(1)));
        assertThat(errorCode)
                .as("UploadPartCopy from an unreadable bucket must fail")
                .isNotNull();
    }

    /** A copy within the identity's own buckets still works. */
    @Test
    public void testCopyFromAuthorizedSourceSucceeds() {
        attackerClient.putObject(
                b -> b.bucket(attackerContainer).key("mine"),
                RequestBody.fromString("mine"));

        attackerClient.copyObject(b -> b.sourceBucket(attackerContainer)
                .sourceKey("mine").destinationBucket(attackerContainer)
                .destinationKey("copy"));

        assertThat(blobStore.blobExists(attackerContainer, "copy")).isTrue();
    }

    private void putSecret() {
        ByteSource payload = ByteSource.wrap(
                "confidential".getBytes(StandardCharsets.UTF_8));
        try {
            TestUtils.putBlob(blobStore, victimContainer, "secret", payload);
        } catch (java.io.IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }

    private static String catchErrorCode(Runnable runnable) {
        try {
            runnable.run();
            return null;
        } catch (S3Exception e) {
            return e.awsErrorDetails().errorCode();
        }
    }

    private S3Client buildClient(AwsBasicCredentials creds) {
        var attributeMap = AttributeMap.builder()
                .put(SdkHttpConfigurationOption.TRUST_ALL_CERTIFICATES, true)
                .build();
        return S3Client.builder()
                .credentialsProvider(StaticCredentialsProvider.create(creds))
                .region(Region.US_EAST_1)
                .endpointOverride(s3EndpointUri)
                .httpClient(Apache5HttpClient.builder()
                        .buildWithDefaults(attributeMap))
                .serviceConfiguration(S3Configuration.builder()
                        .pathStyleAccessEnabled(true)
                        .build())
                .build();
    }
}
