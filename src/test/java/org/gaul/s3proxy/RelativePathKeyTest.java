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
import java.util.List;
import java.util.Random;

import com.google.common.io.ByteSource;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;

/**
 * A key holding a "." or ".." path segment is an ordinary S3 key, and a trap
 * for a backend that addresses objects through a URL path: the client of that
 * URL resolves the path it parses, removing the segment and, for "..", the one
 * before it, so the write leaves the container it was aimed at.  The
 * openstack-swift backend concatenated the name into the path, so "../evil.txt"
 * reached Swift as a container of the account to create, and
 * "../other/planted.txt" wrote into a container the request never named and
 * the caller was never authorized for -- answering 200 as it did.  The aws-s3,
 * google-cloud-storage and azureblob backends percent-encode their names and
 * were unaffected; the nio2 stores refuse what they cannot spell, and
 * openstack-swift now does the same, its okhttp connector reading even "%2E"
 * as a dot for that resolution.
 *
 * <p>So which backends store such a key and which refuse it differs, and this
 * asks after the invariant instead: the object never lands anywhere but the
 * container the request addressed.
 *
 * <p>Written against whichever backend s3proxy.test.conf selects, so a
 * backend that builds paths this way is caught wherever it is added.
 */
public final class RelativePathKeyTest {
    private static final String CONTENT = "payload";
    private static final String VICTIM_CONTENT = "victim-secret";

    private S3Proxy s3Proxy;
    private BlobStore blobStore;
    private S3Client client;
    private String container;
    private String other;
    /** The container name a "../" key would escape to, unique per run. */
    private String escaped;

    @BeforeEach
    public void setUp() throws Exception {
        TestUtils.S3ProxyLaunchInfo info = TestUtils.startS3Proxy(
                System.getProperty("s3proxy.test.conf", "s3proxy.conf"));
        s3Proxy = info.getS3Proxy();
        blobStore = info.getBlobStore();
        int suffix = new Random().nextInt(Integer.MAX_VALUE);
        container = "container-" + suffix;
        other = "other-" + suffix;
        escaped = "escaped-" + suffix;
        blobStore.createContainer(container);
        blobStore.createContainer(other);
        TestUtils.putBlob(blobStore, other, "secret.txt", ByteSource.wrap(
                VICTIM_CONTENT.getBytes(StandardCharsets.UTF_8)));

        client = S3Client.builder()
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create(info.getS3Identity(),
                                info.getS3Credential())))
                .region(Region.US_EAST_1)
                .endpointOverride(URI.create(info.getEndpoint() + "/"))
                .serviceConfiguration(S3Configuration.builder()
                        .pathStyleAccessEnabled(true)
                        .build())
                .build();
    }

    @AfterEach
    public void tearDown() throws Exception {
        // Leaving a container behind is how a stray one comes to outlive the
        // suite and trip a later test that counts them.
        if (client != null) {
            for (String bucket : List.of(container, other, escaped)) {
                try {
                    for (String key : keys(bucket)) {
                        client.deleteObject(b -> b.bucket(bucket).key(key));
                    }
                    client.deleteBucket(b -> b.bucket(bucket));
                } catch (SdkException e) {
                    // absent, which is the usual case for the escape target
                }
            }
            client.close();
        }
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
    }

    /**
     * The key the report used.  Whether a backend stores such a key or refuses
     * it is its own business -- the nio2 and openstack-swift stores refuse
     * what they cannot address, the rest store it literally -- so what is
     * asked here is the part none of them may get wrong: writing an object
     * creates no container, and the object is either absent or an object of
     * the container the request named.
     */
    @Test
    public void testDotDotKeyStaysInsideTheContainer() throws Exception {
        String key = "../" + escaped;

        boolean stored = put(container, key, CONTENT);

        // Named rather than counted: other tests run beside this one and the
        // account's containers are theirs to add to.
        assertThat(bucketNames()).doesNotContain(escaped);
        if (stored) {
            assertThat(keys(container)).containsExactly(key);
            assertThat(read(container, key)).isEqualTo(CONTENT);
        } else {
            assertThat(keys(container)).isEmpty();
        }
    }

    /**
     * A key naming another container is a key, not a route to it: the object
     * belongs to the container the request addressed.
     */
    @Test
    public void testDotDotKeyDoesNotReachAnotherContainer() throws Exception {
        String key = "../" + other + "/planted.txt";

        boolean stored = put(container, key, CONTENT);

        // The other container holds what it held, whatever became of the key.
        assertThat(keys(other)).containsExactly("secret.txt");
        assertThat(read(other, "secret.txt")).isEqualTo(VICTIM_CONTENT);
        if (stored) {
            assertThat(keys(container)).containsExactly(key);
            assertThat(read(container, key)).isEqualTo(CONTENT);
        }
    }

    /**
     * A single-dot segment resolves away too, so it is escaped as well.  What
     * the stores make of the key differs -- the nio2 ones normalise it to the
     * name a segment shorter, where S3 would keep it -- so this asks only what
     * every backend owes: the write does not leave the container, and the key
     * the client wrote reads back.
     */
    @Test
    public void testSingleDotKeyStaysInsideTheContainer() throws Exception {
        boolean stored = put(container, "./quiet.txt", CONTENT);

        assertThat(keys(other)).containsExactly("secret.txt");
        if (stored) {
            assertThat(read(container, "./quiet.txt")).isEqualTo(CONTENT);
        }
    }

    /**
     * A dot inside a segment is not a dot segment and needs no escaping, so
     * the ordinary case is unchanged.
     */
    @Test
    public void testOrdinaryDottedKeyRoundTrips() throws Exception {
        assertThat(put(container, "a/..b/c..d/report.txt", CONTENT)).isTrue();
        assertThat(read(container, "a/..b/c..d/report.txt"))
                .isEqualTo(CONTENT);
    }

    /** Writes the key, answering whether the store accepted it. */
    private boolean put(String bucket, String key, String content) {
        try {
            client.putObject(b -> b.bucket(bucket).key(key),
                    RequestBody.fromString(content));
            return true;
        } catch (SdkException e) {
            return false;
        }
    }

    private String read(String bucket, String key) {
        return client.getObjectAsBytes(b -> b.bucket(bucket).key(key))
                .asUtf8String();
    }

    private List<String> keys(String bucket) {
        return client.listObjectsV2(ListObjectsV2Request.builder()
                        .bucket(bucket).build())
                .contents().stream().map(object -> object.key()).sorted()
                .toList();
    }

    private List<String> bucketNames() {
        return client.listBuckets().buckets().stream()
                .map(bucket -> bucket.name()).sorted().toList();
    }
}
