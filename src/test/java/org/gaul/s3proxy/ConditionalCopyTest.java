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
import java.util.Random;

import org.gaul.s3proxy.auth.AuthenticationType;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.model.S3Exception;

/**
 * If-Match and If-None-Match on a CopyObject guard the destination, the way
 * they guard the key a put writes.  The proxy used to ignore them, so a copy
 * a caller had made conditional overwrote the destination regardless.
 *
 * <p>S3 takes an If-Match naming an ETag and If-None-Match: *, verified
 * against AWS: absent destination and If-Match is 404 NoSuchKey, a
 * destination whose ETag differs is 412, and If-None-Match: * is 412 once
 * the destination exists.  The nio2 stores also take the forms their put
 * takes, If-Match: * and an If-None-Match naming an ETag.
 */
public final class ConditionalCopyTest {
    private static final String SOURCE = "source";
    private static final String DEST = "dest";
    private static final String CONTENT = "content";
    private static final String OLD = "old";

    private S3Proxy s3Proxy;
    private S3Client client;
    private String containerName;
    private String sourceETag;

    @BeforeEach
    public void setUp() throws Exception {
        BlobStore blobStore = TestUtils.createTransientBlobStore();
        containerName = "container-" + new Random().nextInt(Integer.MAX_VALUE);
        blobStore.createContainer(containerName);

        s3Proxy = S3Proxy.builder()
                .stopTimeout(0)
                .blobStore(blobStore)
                .awsAuthentication(AuthenticationType.AWS_V2_OR_V4,
                        "identity", "credential")
                .endpoint(URI.create("http://127.0.0.1:0"))
                .build();
        s3Proxy.start();
        while (!s3Proxy.getState().equals("STARTED")) {
            Thread.sleep(10);
        }
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
        sourceETag = client.putObject(
                b -> b.bucket(containerName).key(SOURCE),
                RequestBody.fromString(CONTENT)).eTag();
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (client != null) {
            client.close();
        }
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
    }

    private void copy(String ifMatch, String ifNoneMatch) {
        client.copyObject(b -> b
                .sourceBucket(containerName).sourceKey(SOURCE)
                .destinationBucket(containerName).destinationKey(DEST)
                .ifMatch(ifMatch).ifNoneMatch(ifNoneMatch));
    }

    private void assertRefused(String ifMatch, String ifNoneMatch,
            int status, String code) {
        assertThatThrownBy(() -> copy(ifMatch, ifNoneMatch))
                .isInstanceOf(S3Exception.class)
                .satisfies(thrown -> {
                    var s3e = (S3Exception) thrown;
                    assertThat(s3e.statusCode()).isEqualTo(status);
                    assertThat(s3e.awsErrorDetails().errorCode())
                            .isEqualTo(code);
                });
    }

    private String putDest(String content) {
        return client.putObject(b -> b.bucket(containerName).key(DEST),
                RequestBody.fromString(content)).eTag();
    }

    private String readDest() {
        return client.getObjectAsBytes(
                b -> b.bucket(containerName).key(DEST)).asUtf8String();
    }

    @Test
    public void testIfMatchOnAbsentDestinationIsNoSuchKey() {
        assertRefused("\"0123456789abcdef0123456789abcdef\"", null,
                404, "NoSuchKey");
        assertRefused("*", null, 404, "NoSuchKey");
        assertThat(client.listObjectsV2(b -> b.bucket(containerName))
                .contents()).hasSize(1);
    }

    @Test
    public void testIfMatchComparesTheDestination() {
        String destETag = putDest(OLD);

        // the source's ETag is not the destination's
        assertRefused(sourceETag, null, 412, "PreconditionFailed");
        assertThat(readDest()).isEqualTo(OLD);

        copy(destETag, null);
        assertThat(readDest()).isEqualTo(CONTENT);
    }

    @Test
    public void testIfMatchWildcardNeedsADestination() {
        putDest(OLD);
        copy("*", null);
        assertThat(readDest()).isEqualTo(CONTENT);
    }

    @Test
    public void testIfNoneMatchWildcardCopiesOnlyOnce() {
        copy(null, "*");
        assertThat(readDest()).isEqualTo(CONTENT);

        putDest(OLD);
        assertRefused(null, "*", 412, "PreconditionFailed");
        assertThat(readDest()).isEqualTo(OLD);
    }

    @Test
    public void testIfNoneMatchComparesTheDestination() {
        String destETag = putDest(OLD);

        assertRefused(null, destETag, 412, "PreconditionFailed");
        assertThat(readDest()).isEqualTo(OLD);

        copy(null, sourceETag);
        assertThat(readDest()).isEqualTo(CONTENT);
    }

    /** The source conditions still apply, and to the source. */
    @Test
    public void testSourceAndDestinationConditionsTogether() {
        String destETag = putDest(OLD);

        assertThatThrownBy(() -> client.copyObject(b -> b
                .sourceBucket(containerName).sourceKey(SOURCE)
                .destinationBucket(containerName).destinationKey(DEST)
                .copySourceIfMatch(destETag)
                .ifMatch(destETag)))
                .isInstanceOf(S3Exception.class)
                .satisfies(thrown -> assertThat(
                        ((S3Exception) thrown).statusCode()).isEqualTo(412));
        assertThat(readDest()).isEqualTo(OLD);

        client.copyObject(b -> b
                .sourceBucket(containerName).sourceKey(SOURCE)
                .destinationBucket(containerName).destinationKey(DEST)
                .copySourceIfMatch(sourceETag)
                .ifMatch(destETag));
        assertThat(readDest()).isEqualTo(CONTENT);
    }
}
