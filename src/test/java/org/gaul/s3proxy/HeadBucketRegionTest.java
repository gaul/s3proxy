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

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.ForwardingBlobStore;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.BucketCannedACL;
import software.amazon.awssdk.services.s3.model.HeadBucketRequest;
import software.amazon.awssdk.services.s3.model.HeadBucketResponse;

/**
 * Covers what HeadBucket relays from the store: the bucketRegion a backend
 * with regions reports rides to the wire as x-amz-bucket-region, a store
 * without one adds no header, and a null response is the bucket's absence.
 */
public final class HeadBucketRegionTest {
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

    @Test
    public void testRelaysTheStoresBucketRegion() throws Exception {
        setUpProxy("us-west-2");

        HttpResponse<Void> response = headBucket(container);

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.headers().firstValue("x-amz-bucket-region"))
                .hasValue("us-west-2");
    }

    @Test
    public void testStoreWithoutRegionsAddsNoHeader() throws Exception {
        setUpProxy(null);

        HttpResponse<Void> response = headBucket(container);

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.headers().firstValue("x-amz-bucket-region"))
                .isEmpty();
    }

    @Test
    public void testNullResponseIsTheBucketsAbsence() throws Exception {
        setUpProxy("us-west-2");

        HttpResponse<Void> response = headBucket(container + "-absent");

        assertThat(response.statusCode()).isEqualTo(404);
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

    private HttpResponse<Void> headBucket(String bucket) throws Exception {
        return HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(URI.create(
                        "http://127.0.0.1:" + s3Proxy.getPort() + "/" +
                        bucket))
                        .method("HEAD", HttpRequest.BodyPublishers.noBody())
                        .build(),
                HttpResponse.BodyHandlers.discarding());
    }

    /**
     * Reports every bucket public-read, so the anonymous HEAD reaches the
     * existence probe, and stamps the region onto the delegate's answer
     * the way a backend whose service has regions would.
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
        @Nullable
        public HeadBucketResponse headBucket(HeadBucketRequest request) {
            HeadBucketResponse result = delegate().headBucket(request);
            if (result == null || region == null) {
                return result;
            }
            return result.toBuilder().bucketRegion(region).build();
        }
    }
}
