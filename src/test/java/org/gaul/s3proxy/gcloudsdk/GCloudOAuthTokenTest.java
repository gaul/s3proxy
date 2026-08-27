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
