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
import java.nio.file.FileSystems;
import java.nio.file.PathMatcher;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import org.gaul.s3proxy.auth.AuthenticationType;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.middleware.GlobBlobStoreLocator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.model.S3Exception;

/**
 * Two identities sharing one backend, separated only by the locator's bucket
 * globs.  Every operation that names a bucket in the request URI passes
 * through the locator, which refuses one belonging to the other identity.
 * ListBuckets names no bucket, so that check had nothing to ask about and the
 * listing reported every bucket the backend held -- one tenant reading the
 * other's bucket names, which is the whole of what the globs were separating.
 */
public final class ListBucketsTenantScopeTest {
    private static final String ALICE = "alice";
    private static final String ALICE_SECRET = "alice-credential";
    private static final String BOB = "bob";
    private static final String BOB_SECRET = "bob-credential";
    private static final String ALICE_BUCKET = "tenant-a-data";
    private static final String BOB_BUCKET = "tenant-b-secrets";
    /** Matches no glob, so the locator answers for the identity alone. */
    private static final String SHARED_BUCKET = "common-assets";

    private S3Proxy s3Proxy;
    private BlobStore blobStore;
    private URI endpoint;

    @BeforeEach
    public void setUp() throws Exception {
        blobStore = TestUtils.createTransientBlobStore();
        blobStore.createContainer(ALICE_BUCKET);
        blobStore.createContainer(BOB_BUCKET);
        blobStore.createContainer(SHARED_BUCKET);

        Map<String, AccessGrant> locator = new LinkedHashMap<>();
        locator.put(ALICE, new AccessGrant(ALICE_SECRET, blobStore));
        locator.put(BOB, new AccessGrant(BOB_SECRET, blobStore));
        Map<PathMatcher, GlobBlobStoreLocator.GlobTarget> globs =
                new LinkedHashMap<>();
        globs.put(glob("tenant-a-*"), new GlobBlobStoreLocator.GlobTarget(
                Optional.of(ALICE), blobStore));
        globs.put(glob("tenant-b-*"), new GlobBlobStoreLocator.GlobTarget(
                Optional.of(BOB), blobStore));

        s3Proxy = S3Proxy.builder()
                .stopTimeout(0)
                .blobStore(blobStore)
                .awsAuthentication(AuthenticationType.AWS_V2_OR_V4, ALICE,
                        ALICE_SECRET)
                .endpoint(URI.create("http://127.0.0.1:0"))
                .build();
        s3Proxy.setBlobStoreLocator(new GlobBlobStoreLocator(locator, globs));
        s3Proxy.start();
        while (!s3Proxy.getState().equals("STARTED")) {
            Thread.sleep(10);
        }
        endpoint = URI.create("http://127.0.0.1:" + s3Proxy.getPort());
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
    }

    /** A listing names only what its identity could have addressed. */
    @Test
    public void testListBucketsOmitsAnotherIdentitysBucket() {
        try (S3Client client = client(ALICE, ALICE_SECRET)) {
            assertThat(client.listBuckets().buckets().stream()
                    .map(b -> b.name()))
                    .containsExactlyInAnyOrder(ALICE_BUCKET, SHARED_BUCKET)
                    .doesNotContain(BOB_BUCKET);
        }
    }

    /** And the other identity sees its own, by the same rule. */
    @Test
    public void testEachIdentitySeesItsOwnBuckets() {
        try (S3Client client = client(BOB, BOB_SECRET)) {
            assertThat(client.listBuckets().buckets().stream()
                    .map(b -> b.name()))
                    .containsExactlyInAnyOrder(BOB_BUCKET, SHARED_BUCKET)
                    .doesNotContain(ALICE_BUCKET);
        }
    }

    /**
     * The listing agrees with what the bucket-addressed operations already
     * answered: a bucket it omits is one this identity cannot read.
     */
    @Test
    public void testOmittedBucketIsAlsoUnreadable() {
        try (S3Client client = client(ALICE, ALICE_SECRET)) {
            assertThatThrownBy(() -> client.headBucket(
                    b -> b.bucket(BOB_BUCKET)))
                    .isInstanceOf(S3Exception.class);
            assertThatThrownBy(() -> client.listObjectsV2(
                    b -> b.bucket(BOB_BUCKET)))
                    .isInstanceOf(S3Exception.class);
        }
    }

    /** A bucket the listing keeps is one the same identity can address. */
    @Test
    public void testListedBucketRemainsReadable() {
        try (S3Client client = client(ALICE, ALICE_SECRET)) {
            client.headBucket(b -> b.bucket(ALICE_BUCKET));
            client.listObjectsV2(b -> b.bucket(ALICE_BUCKET));
            client.headBucket(b -> b.bucket(SHARED_BUCKET));
        }
    }

    private static PathMatcher glob(String pattern) {
        return FileSystems.getDefault().getPathMatcher("glob:" + pattern);
    }

    private S3Client client(String identity, String credential) {
        return S3Client.builder()
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create(identity, credential)))
                .region(Region.US_EAST_1)
                .endpointOverride(endpoint)
                .serviceConfiguration(S3Configuration.builder()
                        .pathStyleAccessEnabled(true)
                        .build())
                .build();
    }
}
