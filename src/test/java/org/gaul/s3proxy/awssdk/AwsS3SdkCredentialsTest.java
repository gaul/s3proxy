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

package org.gaul.s3proxy.awssdk;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicInteger;

import com.google.common.base.Supplier;
import com.google.common.base.Suppliers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import org.gaul.s3proxy.BlobStores;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.Credentials;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * What the store puts on the wire when its credentials expire.  Signing is
 * the only place a credential is observable, so these ask a listener what
 * arrived rather than the store what it holds: a supplier that answers
 * differently the second time must sign the second request differently, and a
 * session token must travel as the header S3 reads it from.
 */
public final class AwsS3SdkCredentialsTest {
    private static final String LIST_BUCKETS_RESULT =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
            "<ListAllMyBucketsResult" +
            " xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">" +
            "<Owner><ID>owner</ID><DisplayName>owner</DisplayName></Owner>" +
            "<Buckets/></ListAllMyBucketsResult>";

    private final List<String> authorizations =
            Collections.synchronizedList(new ArrayList<String>());
    private final List<String> sessionTokens =
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

    /**
     * A supplier is not a value: an assumed role hands out a new access key
     * id every time it is renewed, and the store must sign with the one it
     * holds now rather than the one it held when it was built.
     */
    @Test
    public void testEveryRequestResolvesCredentialsAgain() throws Exception {
        var minted = new AtomicInteger();
        Supplier<Credentials> creds = () -> new Credentials(
                "identity-" + minted.incrementAndGet(), "credential");

        try (BlobStore blobStore = store(creds)) {
            blobStore.list();
            blobStore.list();
        }

        assertThat(authorizations).hasSize(2);
        String first = accessKeyId(authorizations.get(0));
        String second = accessKeyId(authorizations.get(1));
        assertThat(first).startsWith("identity-");
        assertThat(second).isNotEqualTo(first);
    }

    /** A session token rides in its own header, not in the signature. */
    @Test
    public void testSessionTokenTravelsWithTheRequest() throws Exception {
        Supplier<Credentials> creds = Suppliers.ofInstance(new Credentials(
                "identity", "credential", "session-token"));

        try (BlobStore blobStore = store(creds)) {
            blobStore.list();
        }

        assertThat(sessionTokens).containsExactly("session-token");
    }

    /** The expiring half is re-read like the rest of the credential. */
    @Test
    public void testSessionTokenFollowsTheSupplier() throws Exception {
        var minted = new AtomicInteger();
        Supplier<Credentials> creds = () -> new Credentials("identity",
                "credential", "session-token-" + minted.incrementAndGet());

        try (BlobStore blobStore = store(creds)) {
            blobStore.list();
            blobStore.list();
        }

        assertThat(sessionTokens).hasSize(2);
        assertThat(sessionTokens.get(0)).startsWith("session-token-");
        assertThat(sessionTokens.get(1))
                .isNotEqualTo(sessionTokens.get(0));
    }

    /** A token named in the configuration reaches the wire unchanged. */
    @Test
    public void testConfiguredSessionTokenReachesTheBackend()
            throws Exception {
        var properties = new Properties();
        properties.setProperty("jclouds.identity", "identity");
        properties.setProperty("jclouds.credential", "credential");
        properties.setProperty("jclouds.session-token", "configured-token");
        properties.setProperty("jclouds.endpoint", endpoint());

        try (BlobStore blobStore = BlobStores.create("aws-s3", properties)) {
            blobStore.list();
        }

        assertThat(sessionTokens).containsExactly("configured-token");
    }

    private String endpoint() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    private BlobStore store(Supplier<Credentials> creds) {
        return new AwsS3SdkBlobStore(creds, endpoint(), "us-east-1",
                /*conditionalWrites=*/ "native",
                /*chunkedEncodingEnabled=*/ "true",
                /*stripETagQuotes=*/ "false");
    }

    private void handle(HttpExchange exchange) throws IOException {
        var headers = exchange.getRequestHeaders();
        authorizations.add(headers.getFirst("Authorization"));
        sessionTokens.add(headers.getFirst("x-amz-security-token"));
        try (var in = exchange.getRequestBody()) {
            in.readAllBytes();
        }
        byte[] body = LIST_BUCKETS_RESULT.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/xml");
        exchange.sendResponseHeaders(200, body.length);
        try (var out = exchange.getResponseBody()) {
            out.write(body);
        }
    }

    /**
     * The access key id a request signed with, which SigV4 spells at the head
     * of its scope: {@code Credential=<id>/<date>/<region>/s3/aws4_request}.
     */
    private static String accessKeyId(String authorization) {
        int begin = authorization.indexOf("Credential=") +
                "Credential=".length();
        return authorization.substring(begin,
                authorization.indexOf('/', begin));
    }
}
