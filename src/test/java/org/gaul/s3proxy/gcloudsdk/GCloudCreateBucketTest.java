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
import java.util.Set;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.stream.Collectors;

import com.google.common.base.Suppliers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.Credentials;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.BucketAlreadyExistsException;
import software.amazon.awssdk.services.s3.model.BucketAlreadyOwnedByYouException;

/**
 * Bucket names are one namespace for all of Google Cloud Storage, and
 * buckets.insert answers 409 for a name that is taken whoever took it.  The
 * stand-in here refuses every create so, and lists the project's own
 * buckets, which is what tells the two apart.
 */
public final class GCloudCreateBucketTest {
    private final Set<String> ownBuckets = new ConcurrentSkipListSet<>();
    private volatile boolean mayList = true;

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
    public void testCreateOwnBucketAgain() {
        ownBuckets.add("reports");
        try (BlobStore blobStore = store()) {
            assertThatThrownBy(() -> blobStore.createContainer("reports"))
                    .isInstanceOfSatisfying(
                            BucketAlreadyOwnedByYouException.class, e -> {
                                assertThat(e.statusCode()).isEqualTo(409);
                                assertThat(e.awsErrorDetails().errorCode())
                                        .isEqualTo("BucketAlreadyOwnedByYou");
                            });
        }
    }

    @Test
    public void testCreateBucketOfAnotherProject() {
        // shares the prefix the ownership check lists by
        ownBuckets.add("reports-2026");
        try (BlobStore blobStore = store()) {
            assertThatThrownBy(() -> blobStore.createContainer("reports"))
                    .isInstanceOfSatisfying(
                            BucketAlreadyExistsException.class, e -> {
                                assertThat(e.statusCode()).isEqualTo(409);
                                assertThat(e.awsErrorDetails().errorCode())
                                        .isEqualTo("BucketAlreadyExists");
                            });
        }
    }

    /** An account that cannot tell is not told the bucket is its own. */
    @Test
    public void testCreateTakenBucketWithoutListPermission() {
        ownBuckets.add("reports");
        mayList = false;
        try (BlobStore blobStore = store()) {
            assertThatThrownBy(() -> blobStore.createContainer("reports"))
                    .isInstanceOf(BucketAlreadyExistsException.class);
        }
    }

    private BlobStore store() {
        return new GCloudBlobStore(Suppliers.ofInstance(
                new Credentials("project", /*credential=*/ "")),
                "http://127.0.0.1:" + server.getAddress().getPort());
    }

    /** Answers buckets.insert and buckets.list. */
    private void handle(HttpExchange exchange) throws IOException {
        try (var in = exchange.getRequestBody()) {
            in.readAllBytes();
        }
        int status;
        String response;
        if (!exchange.getRequestURI().getPath().endsWith("/b")) {
            status = 404;
            response = error(status, "Not Found");
        } else if (exchange.getRequestMethod().equals("POST")) {
            status = 409;
            response = error(status, "conflict");
        } else if (!mayList) {
            status = 403;
            response = error(status, "forbidden");
        } else {
            status = 200;
            response = "{\"kind\":\"storage#buckets\",\"items\":[" +
                    ownBuckets.stream()
                            .map("{\"kind\":\"storage#bucket\",\"name\":\"%s\"}"
                                    ::formatted)
                            .collect(Collectors.joining(",")) + "]}";
        }
        byte[] body = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type",
                "application/json; charset=UTF-8");
        exchange.sendResponseHeaders(status, body.length);
        try (var out = exchange.getResponseBody()) {
            out.write(body);
        }
    }

    private static String error(int status, String reason) {
        return "{\"error\":{\"code\":%d,\"message\":\"%s\"}}".formatted(
                status, reason);
    }
}
