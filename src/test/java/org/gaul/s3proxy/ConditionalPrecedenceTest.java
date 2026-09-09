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
import java.time.Instant;
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
import software.amazon.awssdk.services.s3.model.HeadObjectResponse;
import software.amazon.awssdk.services.s3.model.S3Exception;

/**
 * When a request carries both an if-match and an if-unmodified-since, S3
 * settles it on the stronger of the two: "If both of the If-Match and
 * If-Unmodified-Since headers are present in the request as follows, then
 * Amazon S3 returns the HTTP status code 200 OK and the data requested:
 * If-Match condition evaluates to true.  If-Unmodified-Since condition
 * evaluates to false."  The copy-source pair is documented the same way.
 * Each of the three places this is evaluated -- the metadata path a HEAD
 * takes, the store a GET goes through, and the copy source -- read the date
 * anyway, refusing a request S3 answers.
 */
public final class ConditionalPrecedenceTest {
    private static final String KEY = "object";
    private static final String CONTENT = "content";

    private S3Proxy s3Proxy;
    private S3Client client;
    private String containerName;

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
        client.putObject(b -> b.bucket(containerName).key(KEY),
                RequestBody.fromString(CONTENT));
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

    private HeadObjectResponse head() {
        return client.headObject(b -> b.bucket(containerName).key(KEY));
    }

    /** An hour before the object was written, so the date condition fails. */
    private Instant before() {
        return head().lastModified().minusSeconds(3600);
    }

    /** HEAD, which the frontend settles from the metadata it already read. */
    @Test
    public void testHeadIfMatchWinsOverIfUnmodifiedSince() {
        HeadObjectResponse response = client.headObject(b -> b
                .bucket(containerName).key(KEY)
                .ifMatch(head().eTag())
                .ifUnmodifiedSince(before()));
        assertThat(response.contentLength()).isEqualTo(CONTENT.length());
    }

    /** GET, which the store settles. */
    @Test
    public void testGetIfMatchWinsOverIfUnmodifiedSince() {
        var response = client.getObjectAsBytes(b -> b
                .bucket(containerName).key(KEY)
                .ifMatch(head().eTag())
                .ifUnmodifiedSince(before()));
        assertThat(response.asUtf8String()).isEqualTo(CONTENT);
    }

    /** And the copy source, which the frontend settles for itself. */
    @Test
    public void testCopyIfMatchWinsOverIfUnmodifiedSince() {
        client.copyObject(b -> b
                .sourceBucket(containerName).sourceKey(KEY)
                .destinationBucket(containerName).destinationKey("copy")
                .copySourceIfMatch(head().eTag())
                .copySourceIfUnmodifiedSince(before()));

        var copied = client.getObjectAsBytes(b -> b
                .bucket(containerName).key("copy"));
        assertThat(copied.asUtf8String()).isEqualTo(CONTENT);
    }

    /**
     * The date still settles a request that carries it alone, which is what
     * makes the cases above about precedence rather than about ignoring it.
     */
    @Test
    public void testIfUnmodifiedSinceAloneStillRefuses() {
        assertThatThrownBy(() -> client.headObject(b -> b
                .bucket(containerName).key(KEY)
                .ifUnmodifiedSince(before())))
                .isInstanceOf(S3Exception.class);
        assertThatThrownBy(() -> client.getObjectAsBytes(b -> b
                .bucket(containerName).key(KEY)
                .ifUnmodifiedSince(before())))
                .isInstanceOf(S3Exception.class);
    }

    /** An if-match that does not hold is still refused, date or no date. */
    @Test
    public void testFailingIfMatchStillRefuses() {
        assertThatThrownBy(() -> client.headObject(b -> b
                .bucket(containerName).key(KEY)
                .ifMatch("\"not-the-etag\"")
                .ifUnmodifiedSince(before())))
                .isInstanceOf(S3Exception.class);
        assertThatThrownBy(() -> client.getObjectAsBytes(b -> b
                .bucket(containerName).key(KEY)
                .ifMatch("\"not-the-etag\"")
                .ifUnmodifiedSince(before())))
                .isInstanceOf(S3Exception.class);
    }

    /**
     * The pairing S3 documents the other way round is unchanged: an
     * if-none-match that matches answers 304 whatever the date says.
     */
    @Test
    public void testIfNoneMatchStillAnswersNotModified() {
        assertThatThrownBy(() -> client.headObject(b -> b
                .bucket(containerName).key(KEY)
                .ifNoneMatch(head().eTag())
                .ifModifiedSince(before())))
                .isInstanceOf(S3Exception.class)
                .satisfies(e -> assertThat(((S3Exception) e).statusCode())
                        .isEqualTo(304));
    }
}
