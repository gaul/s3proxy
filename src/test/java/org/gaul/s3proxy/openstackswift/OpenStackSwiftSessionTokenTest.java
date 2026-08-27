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

package org.gaul.s3proxy.openstackswift;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

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
 * Keystone authenticates a caller who already holds a token by re-scoping it,
 * which spares a deployment minting them from also holding the password
 * behind them.  These watch what the store asks Keystone for: the answer is
 * refused here, since which method the request names is the whole question.
 */
public final class OpenStackSwiftSessionTokenTest {
    private final List<String> requests =
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

    /** A session token authenticates as a token, not as a password. */
    @Test
    public void testSessionTokenAuthenticatesAsAKeystoneToken() {
        try (BlobStore blobStore = keystoneStore(Suppliers.ofInstance(
                new Credentials("swift-user", "swift-password",
                        "keystone-token")))) {
            assertThat(catchThrowable(blobStore::list)).isNotNull();
        }

        assertThat(requests).hasSize(1);
        assertThat(requests.get(0)).contains("keystone-token");
        assertThat(requests.get(0)).doesNotContain("swift-password");
        assertThat(requests.get(0)).doesNotContain("swift-user");
    }

    /** Without one the password is what Keystone is asked to check. */
    @Test
    public void testAbsentSessionTokenAuthenticatesAsAPassword() {
        try (BlobStore blobStore = keystoneStore(Suppliers.ofInstance(
                new Credentials("swift-user", "swift-password")))) {
            assertThat(catchThrowable(blobStore::list)).isNotNull();
        }

        assertThat(requests).hasSize(1);
        assertThat(requests.get(0)).contains("swift-user");
        assertThat(requests.get(0)).contains("swift-password");
    }

    /**
     * Swift's own tempauth issues nothing a session token could name, and
     * the address it would have to be used against is not derivable, so the
     * configuration is refused rather than quietly ignored.
     */
    @Test
    public void testTempAuthRefusesASessionToken() {
        try (BlobStore blobStore = new OpenStackSwiftBlobStore(
                Suppliers.ofInstance(new Credentials("account:user", "key",
                        "token")),
                endpoint() + "/auth/v1.0", "account", "Default", "Default",
                /*region=*/ "")) {
            assertThatThrownBy(blobStore::list)
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Keystone token");
        }

        assertThat(requests).isEmpty();
    }

    private String endpoint() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    private BlobStore keystoneStore(Supplier<Credentials> creds) {
        return new OpenStackSwiftBlobStore(creds, endpoint() + "/v3",
                "project", "Default", "Default", /*region=*/ "");
    }

    private void handle(HttpExchange exchange) throws IOException {
        try (var in = exchange.getRequestBody()) {
            requests.add(new String(in.readAllBytes(),
                    StandardCharsets.UTF_8));
        }
        byte[] body = ("{\"error\": {\"code\": 401, \"message\":" +
                " \"request seen\"}}").getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type",
                "application/json");
        exchange.sendResponseHeaders(401, body.length);
        try (var out = exchange.getResponseBody()) {
            out.write(body);
        }
    }
}
