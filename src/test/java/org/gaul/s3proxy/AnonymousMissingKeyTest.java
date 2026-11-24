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
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Random;
import java.util.concurrent.CopyOnWriteArrayList;

import com.google.common.io.ByteSource;

import org.gaul.s3proxy.auth.AuthenticationType;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.ForwardingBlobStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.BucketCannedACL;
import software.amazon.awssdk.services.s3.model.ObjectCannedACL;

/**
 * S3 answers a read of a missing key NoSuchKey only to a caller who may list
 * the bucket, and AccessDenied to anyone else.  An anonymous read of a
 * private bucket answered 404 for a missing key and 403 for a present one, so
 * anyone could learn which keys the bucket held.  Once both answered 403,
 * the missing key still cost the store one more request than the present
 * one, and the time that took said the same thing.
 */
public final class AnonymousMissingKeyTest {
    private S3Proxy s3Proxy;
    private BlobStore blobStore;
    private String containerName;
    private String baseUri;
    private final HttpClient httpClient = HttpClient.newHttpClient();
    /** What deciding on a request asked of the store, in order. */
    private final List<String> accessChecks = new CopyOnWriteArrayList<>();

    @BeforeEach
    public void setUp() throws Exception {
        blobStore = TestUtils.createTransientBlobStore();
        containerName =
                "container-" + new Random().nextInt(Integer.MAX_VALUE);
        blobStore.createContainer(containerName);
        TestUtils.putBlob(blobStore, containerName, "present",
                ByteSource.wrap("private".getBytes(StandardCharsets.UTF_8)));

        // Stand in for a remote store, where each of these is a round trip.
        BlobStore recording = new ForwardingBlobStore(blobStore) {
            @Override
            public BucketCannedACL getContainerAccess(String container) {
                accessChecks.add("getContainerAccess");
                return super.getContainerAccess(container);
            }

            @Override
            public ObjectCannedACL getBlobAccess(String container,
                    String name) {
                accessChecks.add("getBlobAccess");
                return super.getBlobAccess(container, name);
            }
        };

        s3Proxy = S3Proxy.builder()
                .stopTimeout(0)
                .blobStore(recording)
                .awsAuthentication(AuthenticationType.AWS_V2_OR_V4,
                        "identity", "credential")
                .endpoint(URI.create("http://127.0.0.1:0"))
                .build();
        s3Proxy.start();
        while (!s3Proxy.getState().equals("STARTED")) {
            Thread.sleep(10);
        }
        baseUri = "http://127.0.0.1:" + s3Proxy.getPort() + "/";
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
    }

    /** A private bucket answers a missing key as it answers a present one. */
    @Test
    public void testPrivateBucketHidesWhichKeysExist() throws Exception {
        for (String method : new String[] {"GET", "HEAD"}) {
            HttpResponse<String> present = send(method, "present");
            HttpResponse<String> missing = send(method, "missing");
            assertThat(present.statusCode()).as(method).isEqualTo(403);
            assertThat(missing.statusCode()).as(method).isEqualTo(403);
            assertThat(missing.headers().firstValue("x-amz-delete-marker"))
                    .as(method).isEmpty();
        }
        assertThat(send("GET", "missing").body())
                .contains("<Code>AccessDenied</Code>");
    }

    /**
     * Refusing a present key asks the store what refusing a missing one
     * does.  One request fewer is one round trip sooner, which tells the two
     * apart as well as the status did.
     */
    @Test
    public void testPrivateBucketRefusesEitherKeyAtTheSameCost()
            throws Exception {
        for (String method : new String[] {"GET", "HEAD"}) {
            accessChecks.clear();
            assertThat(send(method, "present").statusCode()).as(method)
                    .isEqualTo(403);
            var present = List.copyOf(accessChecks);
            accessChecks.clear();
            assertThat(send(method, "missing").statusCode()).as(method)
                    .isEqualTo(403);
            assertThat(accessChecks).as(method).isNotEmpty()
                    .isEqualTo(present);
        }
    }

    /** A bucket anyone may list has no keys to hide, so S3 says NoSuchKey. */
    @Test
    public void testPublicReadBucketReportsMissingKey() throws Exception {
        blobStore.setContainerAccess(containerName,
                BucketCannedACL.PUBLIC_READ);
        assertThat(send("HEAD", "missing").statusCode()).isEqualTo(404);
        HttpResponse<String> response = send("GET", "missing");
        assertThat(response.statusCode()).isEqualTo(404);
        assertThat(response.body()).contains("<Code>NoSuchKey</Code>");
    }

    /** Which buckets exist is no secret in S3, so that still answers 404. */
    @Test
    public void testMissingBucketStillReportsNoSuchBucket() throws Exception {
        HttpResponse<String> response = httpClient.send(
                HttpRequest.newBuilder(URI.create(baseUri +
                        "no-such-bucket-" + containerName + "/key")).GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(404);
        assertThat(response.body()).contains("<Code>NoSuchBucket</Code>");
    }

    private HttpResponse<String> send(String method, String key)
            throws Exception {
        return httpClient.send(
                HttpRequest.newBuilder(URI.create(baseUri + containerName +
                        "/" + key))
                        .method(method, HttpRequest.BodyPublishers.noBody())
                        .build(),
                HttpResponse.BodyHandlers.ofString());
    }
}
