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

package org.gaul.s3proxy.gcloudsdk;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import com.google.common.base.Suppliers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.Credentials;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.BucketCannedACL;
import software.amazon.awssdk.services.s3.model.GetObjectAclRequest;
import software.amazon.awssdk.services.s3.model.NoSuchBucketException;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.s3.model.ObjectCannedACL;

/**
 * An anonymous read is refused alike whether its key is private or missing,
 * and the access of the key is what the refusal starts by asking for.  GCS
 * answers 404 for a missing key and for a missing bucket, and asking which
 * of them it was cost a missing key one more request than a private one, so
 * the time the refusal took said which keys a private bucket holds.  The
 * requests here go to a stand-in for GCS that holds one bucket, with one
 * object in it.
 */
public final class GCloudBlobAccessTest {
    private static final String BUCKET_PATH = "/storage/v1/b/bucket";
    private static final String OBJECT_PATH = BUCKET_PATH + "/o/present";

    private final List<String> requests = new CopyOnWriteArrayList<>();

    private HttpServer server;

    @BeforeEach
    public void setUp() throws IOException {
        server = HttpServer.create(new InetSocketAddress(
                InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", this::handle);
        server.start();
    }

    @AfterEach
    public void tearDown() {
        server.stop(0);
    }

    @Test
    public void testMissingKeyCostsTheRequestsOfAPrivateOne() {
        try (BlobStore blobStore = store()) {
            assertThat(blobStore.getBlobAccess("bucket", "present"))
                    .isEqualTo(ObjectCannedACL.PRIVATE);
            var present = List.copyOf(requests);
            requests.clear();

            assertThatThrownBy(() -> blobStore.getBlobAccess("bucket",
                    "missing"))
                    .isInstanceOf(NoSuchKeyException.class);
            // the bucket's public access prevention, then the ACL
            assertThat(requests).hasSameSizeAs(present).hasSize(2);
        }
    }

    /** Which the refusal of an anonymous read goes on to ask for. */
    @Test
    public void testContainerAccessReportsAMissingBucket() {
        try (BlobStore blobStore = store()) {
            assertThat(blobStore.getContainerAccess("bucket"))
                    .isEqualTo(BucketCannedACL.PRIVATE);
            assertThatThrownBy(() -> blobStore.getContainerAccess("other"))
                    .isInstanceOf(NoSuchBucketException.class);
        }
    }

    /** A caller who signed for the ACL is still told which is missing. */
    @Test
    public void testBlobAclTellsAMissingBucketFromAMissingKey() {
        try (BlobStore blobStore = store()) {
            assertThat(blobStore.getBlobAcl(acl("bucket", "present"))
                    .grants()).hasSize(1);
            assertThatThrownBy(() -> blobStore.getBlobAcl(
                    acl("bucket", "missing")))
                    .isInstanceOf(NoSuchKeyException.class);
            assertThatThrownBy(() -> blobStore.getBlobAcl(
                    acl("other", "present")))
                    .isInstanceOf(NoSuchBucketException.class);
        }
    }

    private static GetObjectAclRequest acl(String bucket, String key) {
        return GetObjectAclRequest.builder().bucket(bucket).key(key).build();
    }

    private BlobStore store() {
        return new GCloudBlobStore(Suppliers.ofInstance(
                new Credentials("project", /*credential=*/ "")),
                "http://127.0.0.1:" + server.getAddress().getPort());
    }

    /** Answers buckets.get and the two accessControls.list. */
    private void handle(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
        requests.add(exchange.getRequestMethod() + " " + path);
        int status = 200;
        String response;
        if (path.equals(BUCKET_PATH)) {
            response = "{\"kind\":\"storage#bucket\",\"id\":\"bucket\"," +
                    "\"name\":\"bucket\"}";
        } else if (path.equals(BUCKET_PATH + "/acl")) {
            response = "{\"kind\":\"storage#bucketAccessControls\"," +
                    "\"items\":[]}";
        } else if (path.equals(OBJECT_PATH + "/acl")) {
            response = "{\"kind\":\"storage#objectAccessControls\"," +
                    "\"items\":[]}";
        } else {
            status = 404;
            response = "{\"error\":{\"code\":404,\"message\":\"Not Found\"}}";
        }
        byte[] body = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type",
                "application/json; charset=UTF-8");
        exchange.sendResponseHeaders(status, body.length);
        try (var out = exchange.getResponseBody()) {
            out.write(body);
        }
    }
}
