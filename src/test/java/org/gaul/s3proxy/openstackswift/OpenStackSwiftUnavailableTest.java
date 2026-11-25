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

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;

import com.google.common.base.Suppliers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.Credentials;
import org.gaul.s3proxy.blobstore.S3Exceptions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.awscore.exception.AwsServiceException;

/**
 * Swift throttling or unable to serve answers 429, 498 -- what its ratelimit
 * middleware sends unless configured otherwise -- or 502, 503 or 504.  Each
 * was passed on and became a 500 InternalError; S3 answers 503 SlowDown or
 * ServiceUnavailable, and SlowDown is what tells a client to back off.  A
 * stand-in answers tempauth and every other request with the status under
 * test.
 */
public final class OpenStackSwiftUnavailableTest {
    private static final String ACCOUNT = "/v1/AUTH_account";

    private HttpServer server;
    private volatile int status;

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
    public void testThrottledOrUnavailableIs503() {
        for (int throttled : new int[] {429, 498, 502, 503, 504}) {
            status = throttled;
            String expected = throttled == 429 || throttled == 498 ?
                    "SlowDown" : "ServiceUnavailable";
            try (BlobStore blobStore = store()) {
                assertThatThrownBy(() -> blobStore.createContainer(
                        "bucket"))
                        .as("%d", throttled)
                        .isInstanceOfSatisfying(AwsServiceException.class,
                                e -> {
                                    assertThat(e.statusCode())
                                            .isEqualTo(503);
                                    assertThat(S3Exceptions.errorCode(e))
                                            .isEqualTo(expected);
                                });
            }
        }
    }

    private BlobStore store() {
        return new OpenStackSwiftBlobStore(
                Suppliers.ofInstance(new Credentials("account:user", "key")),
                endpoint() + "/auth/v1.0", "account", "Default", "Default",
                /*region=*/ "");
    }

    private String endpoint() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    /** Answers tempauth, and every other request with the status. */
    private void handle(HttpExchange exchange) throws IOException {
        try (var in = exchange.getRequestBody()) {
            in.readAllBytes();
        }
        var headers = exchange.getResponseHeaders();
        if (exchange.getRequestURI().getPath().equals("/auth/v1.0")) {
            headers.set("X-Auth-Token", "token");
            headers.set("X-Storage-Url", endpoint() + ACCOUNT);
            exchange.sendResponseHeaders(200, -1);
        } else {
            headers.set("Content-Type", "text/plain");
            exchange.sendResponseHeaders(status, -1);
        }
        exchange.close();
    }
}
