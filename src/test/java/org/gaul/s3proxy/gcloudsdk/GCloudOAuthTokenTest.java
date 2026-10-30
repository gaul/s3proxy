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

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import com.google.cloud.NoCredentials;
import com.google.common.base.Supplier;
import com.google.common.base.Suppliers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.Credentials;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * A Google credential ordinarily mints its own access tokens from a service
 * account key, which leaves a caller that already holds a token -- from a
 * workload identity exchange, say -- nowhere to put it.  A session token is
 * that place, and since nothing says how long it lasts the supplier is asked
 * again for each request rather than one answer being presented twice.
 * Naming neither a key nor a token leaves the tokens to application default
 * credentials, Workload Identity among them, except at an emulator, which
 * gets none.
 */
public final class GCloudOAuthTokenTest {
    private final List<String> authorizations =
            Collections.synchronizedList(new ArrayList<String>());

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

    /** The token the supplier holds is the bearer token that is presented. */
    @Test
    public void testRequestCarriesTheAccessToken() {
        Supplier<Credentials> creds = Suppliers.ofInstance(
                new Credentials("project", /*credential=*/ "", "token"));

        try (BlobStore blobStore = store(creds)) {
            blobStore.list();
        }

        assertThat(authorizations).containsExactly("Bearer token");
    }

    /** A token that expires gives way to its successor mid-flight. */
    @Test
    public void testAccessTokenFollowsTheSupplier() {
        var minted = new AtomicInteger();
        Supplier<Credentials> creds = () -> new Credentials("project",
                /*credential=*/ "", "token-" + minted.incrementAndGet());

        try (BlobStore blobStore = store(creds)) {
            blobStore.list();
            blobStore.list();
        }

        assertThat(authorizations).hasSize(2);
        assertThat(authorizations.get(0)).startsWith("Bearer token-");
        assertThat(authorizations.get(1))
                .isNotEqualTo(authorizations.get(0));
    }

    /**
     * Google's endpoints without a key defer to the SDK's lookup, the
     * regional and private ones still reached at the host they name.
     */
    @Test
    public void testNoKeyUsesApplicationDefaultCredentials() {
        Supplier<Credentials> creds = Suppliers.ofInstance(
                new Credentials("project", /*credential=*/ ""));

        for (String endpoint : List.of(
                "https://storage.googleapis.com",
                "https://storage.googleapis.com/",
                "https://storage.me-central2.rep.googleapis.com",
                "https://us-central1-storage.googleapis.com",
                "https://storage-xyz.p.googleapis.com")) {
            try (var blobStore = new GCloudBlobStore(creds, endpoint)) {
                assertThat(blobStore.options().getCredentials())
                        .as(endpoint)
                        .isNotSameAs(NoCredentials.getInstance());
                // The SDK reports its own default with a trailing slash.
                assertThat(blobStore.options().getHost()).startsWith(endpoint);
            }
        }
    }

    /** A host that only resembles Google's is taken for an emulator. */
    @Test
    public void testLookalikeHostGetsNoCredentials() {
        Supplier<Credentials> creds = Suppliers.ofInstance(
                new Credentials("project", /*credential=*/ ""));

        for (String endpoint : List.of(
                "https://storage.googleapis.com.example.com",
                "https://notgoogleapis.com",
                "http://storage.googleapis.com")) {
            try (var blobStore = new GCloudBlobStore(creds, endpoint)) {
                assertThat(blobStore.options().getCredentials())
                        .as(endpoint)
                        .isSameAs(NoCredentials.getInstance());
            }
        }
    }

    /** An emulator without a key is sent no credentials at all. */
    @Test
    public void testEmulatorGetsNoCredentials() {
        Supplier<Credentials> creds = Suppliers.ofInstance(
                new Credentials("project", /*credential=*/ ""));

        try (BlobStore blobStore = store(creds)) {
            blobStore.list();
        }

        assertThat(authorizations).containsExactly((String) null);
    }

    private BlobStore store(Supplier<Credentials> creds) {
        return new GCloudBlobStore(creds,
                "http://127.0.0.1:" + server.getAddress().getPort());
    }

    private void handle(HttpExchange exchange) throws IOException {
        authorizations.add(
                exchange.getRequestHeaders().getFirst("Authorization"));
        try (var in = exchange.getRequestBody()) {
            in.readAllBytes();
        }
        byte[] body = "{\"kind\":\"storage#buckets\",\"items\":[]}"
                .getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type",
                "application/json; charset=UTF-8");
        exchange.sendResponseHeaders(200, body.length);
        try (var out = exchange.getResponseBody()) {
            out.write(body);
        }
    }
}
