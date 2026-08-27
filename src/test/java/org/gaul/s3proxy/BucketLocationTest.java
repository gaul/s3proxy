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
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.regex.Pattern;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.ForwardingBlobStore;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.BucketCannedACL;
import software.amazon.awssdk.services.s3.model.HeadBucketRequest;
import software.amazon.awssdk.services.s3.model.HeadBucketResponse;

/**
 * What GetBucketLocation answers, which used to be a constant: every bucket
 * on every backend read as us-east-1, and a bucket that did not exist read
 * that way too.  The region is the store's to know -- HeadBucket already
 * relays it -- and S3 spells us-east-1 as the empty constraint, which is
 * also the only honest answer for a backend with no regions.  See issue
 * #289.
 */
public final class BucketLocationTest {
    private static final Pattern CONSTRAINT = Pattern.compile(
            "<LocationConstraint[^>]*(?:/>|>(.*?)</LocationConstraint>)");

    private BlobStore blobStore;
    private S3Proxy s3Proxy;
    private String container;

    @AfterEach
    public void tearDown() throws Exception {
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
        if (blobStore != null) {
            blobStore.close();
        }
    }

    /** The complaint in the issue: a bucket elsewhere read as us-east-1. */
    @Test
    public void testReportsTheStoresRegion() throws Exception {
        setUpProxy("eu-west-1");

        HttpResponse<String> response = getLocation(container);

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(constraintOf(response.body())).isEqualTo("eu-west-1");
    }

    /** S3 has spelled its first region the empty constraint throughout. */
    @Test
    public void testUsEastOneIsTheEmptyConstraint() throws Exception {
        setUpProxy("us-east-1");

        HttpResponse<String> response = getLocation(container);

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(constraintOf(response.body())).isEmpty();
    }

    /** A backend with no regions names none, which reads the same way. */
    @Test
    public void testStoreWithoutRegionsAnswersEmpty() throws Exception {
        setUpProxy(null);

        HttpResponse<String> response = getLocation(container);

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(constraintOf(response.body())).isEmpty();
    }

    /**
     * The answer used to be 200 and an empty constraint for a bucket that
     * was never there, which told a client it had found one.
     */
    @Test
    public void testAbsentBucketIsNoSuchBucket() throws Exception {
        setUpProxy("eu-west-1");

        HttpResponse<String> response = getLocation(container + "-absent");

        assertThat(response.statusCode()).isEqualTo(404);
        assertThat(response.body()).contains("NoSuchBucket");
    }

    private void setUpProxy(@Nullable String region) throws Exception {
        blobStore = new RegionBlobStore(TestUtils.createTransientBlobStore(),
                region);
        container = TestUtils.createRandomContainerName();
        blobStore.createContainer(container);
        s3Proxy = S3Proxy.builder()
                .stopTimeout(0)
                .endpoint(URI.create("http://127.0.0.1:0"))
                .blobStore(blobStore)
                .build();
        s3Proxy.start();
    }

    private HttpResponse<String> getLocation(String bucket) throws Exception {
        return HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(URI.create(
                        "http://127.0.0.1:" + s3Proxy.getPort() + "/" +
                        bucket + "?location")).GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }

    /** The text of the LocationConstraint element, empty when it has none. */
    private static String constraintOf(String body) {
        var matcher = CONSTRAINT.matcher(body);
        assertThat(matcher.find()).describedAs(body).isTrue();
        String text = matcher.group(1);
        return text == null ? "" : text;
    }

    /**
     * Reports every bucket public-read, so the anonymous request reaches the
     * operation, and stamps the region onto HeadBucket's answer the way a
     * backend whose service has regions would.
     */
    private static final class RegionBlobStore extends ForwardingBlobStore {
        @Nullable
        private final String region;

        RegionBlobStore(BlobStore delegate, @Nullable String region) {
            super(delegate);
            this.region = region;
        }

        @Override
        public BucketCannedACL getContainerAccess(String container) {
            return BucketCannedACL.PUBLIC_READ;
        }

        @Override
        public HeadBucketResponse headBucket(HeadBucketRequest request) {
            HeadBucketResponse result = delegate().headBucket(request);
            return region == null ? result :
                    result.toBuilder().bucketRegion(region).build();
        }
    }
}
