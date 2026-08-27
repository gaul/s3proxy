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

package org.gaul.s3proxy.azureblob;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

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
 * A shared access signature is the Azure credential that expires, so these
 * watch the query string a request carries rather than what the service
 * answers -- which is refused here on purpose, since only what was signed is
 * in question.  Azure appends the signature per request from a credential the
 * pipeline holds, and S3Proxy refreshes that credential ahead of each call.
 */
public final class AzureSasCredentialTest {
    private final List<String> queries =
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

    /** The signature the supplier holds now is the one that is presented. */
    @Test
    public void testRequestCarriesTheSharedAccessSignature() {
        Supplier<Credentials> creds = Suppliers.ofInstance(new Credentials(
                /*identity=*/ "", /*credential=*/ "", "sv=2026-02-06&sig=abc"));

        try (BlobStore blobStore = store(creds)) {
            listRefusedByTheServer(blobStore);
        }

        assertThat(queries).hasSize(1);
        assertThat(queries.get(0)).contains("sig=abc");
    }

    /**
     * Azure hands a signature out with a leading question mark, which would
     * open a second query string were it appended as it came.
     */
    @Test
    public void testLeadingQuestionMarkIsNotAppendedAsWell() {
        Supplier<Credentials> creds = Suppliers.ofInstance(new Credentials(
                /*identity=*/ "", /*credential=*/ "", "?sig=abc"));

        try (BlobStore blobStore = store(creds)) {
            listRefusedByTheServer(blobStore);
        }

        assertThat(queries).hasSize(1);
        assertThat(queries.get(0)).doesNotContain("?");
        assertThat(queries.get(0)).contains("sig=abc");
    }

    /** A signature that expires gives way to its successor mid-flight. */
    @Test
    public void testSharedAccessSignatureFollowsTheSupplier() {
        var minted = new AtomicInteger();
        Supplier<Credentials> creds = () -> new Credentials(
                /*identity=*/ "", /*credential=*/ "",
                "sig=signature-" + minted.incrementAndGet());

        try (BlobStore blobStore = store(creds)) {
            listRefusedByTheServer(blobStore);
            listRefusedByTheServer(blobStore);
        }

        assertThat(queries).hasSize(2);
        assertThat(queries.get(0)).contains("sig=signature-");
        assertThat(queries.get(1)).isNotEqualTo(queries.get(0));
    }

    /**
     * Lists once, expecting the refusal the handler answers with: the
     * request is made for the sake of the query string it carries.
     */
    private static void listRefusedByTheServer(BlobStore blobStore) {
        assertThat(catchThrowable(blobStore::list)).isNotNull();
    }

    private BlobStore store(Supplier<Credentials> creds) {
        return new AzureBlobStore(creds, "http://127.0.0.1:" +
                server.getAddress().getPort() + "/devstoreaccount1");
    }

    private void handle(HttpExchange exchange) throws IOException {
        queries.add(exchange.getRequestURI().getQuery());
        try (var in = exchange.getRequestBody()) {
            in.readAllBytes();
        }
        byte[] body = ("<?xml version=\"1.0\" encoding=\"utf-8\"?><Error>" +
                "<Code>AuthenticationFailed</Code><Message>signature seen" +
                "</Message></Error>").getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("x-ms-error-code",
                "AuthenticationFailed");
        exchange.sendResponseHeaders(403, body.length);
        try (var out = exchange.getResponseBody()) {
            out.write(body);
        }
    }
}
