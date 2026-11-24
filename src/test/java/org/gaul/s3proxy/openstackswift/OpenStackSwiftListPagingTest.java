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

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.TreeSet;

import com.google.common.base.Splitter;
import com.google.common.base.Suppliers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.Credentials;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.S3Object;

/**
 * The segments of a multipart upload in progress are objects of the
 * container, which Swift lists in its pages and a listing leaves out of its
 * answer.  What the store asks Swift for at a time is watched here, with a
 * stand-in for tempauth and the container listing.
 */
public final class OpenStackSwiftListPagingTest {
    private static final String ACCOUNT = "/v1/AUTH_account";

    private final TreeSet<String> names = new TreeSet<>();
    /** The limit of each listing asked for, in order. */
    private final List<Integer> limits =
            Collections.synchronizedList(new ArrayList<Integer>());

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
     * What a listing hides must not be read in pages as short as the
     * client's max-keys, a request to Swift for every two segments: only the
     * first page is as long as the answer needs.
     */
    @Test
    public void testListDoesNotPageHiddenSegmentsByMaxKeys() {
        for (int i = 0; i < 50; ++i) {
            names.add(".s3proxy-mpu/upload/%08d".formatted(i));
        }
        names.add("kept");
        names.add("last");
        try (BlobStore blobStore = store()) {
            var response = blobStore.list(ListObjectsV2Request.builder()
                    .bucket("bucket").maxKeys(1).build());

            assertThat(response.contents()).extracting(S3Object::key)
                    .containsExactly("kept");
            assertThat(response.nextContinuationToken()).isEqualTo("kept");
            assertThat(limits).containsExactly(2, 1001);

            limits.clear();
            response = blobStore.list(ListObjectsV2Request.builder()
                    .bucket("bucket").maxKeys(1).continuationToken("kept")
                    .build());

            assertThat(response.contents()).extracting(S3Object::key)
                    .containsExactly("last");
            assertThat(response.nextContinuationToken()).isNull();
            assertThat(limits).containsExactly(2);
        }
    }

    /** One page answers a listing that hides nothing. */
    @Test
    public void testListAsksForNoMoreThanItReturns() {
        for (int i = 0; i < 50; ++i) {
            names.add("key%02d".formatted(i));
        }
        try (BlobStore blobStore = store()) {
            var response = blobStore.list(ListObjectsV2Request.builder()
                    .bucket("bucket").maxKeys(2).startAfter("key10")
                    .build());

            assertThat(response.contents()).extracting(S3Object::key)
                    .containsExactly("key11", "key12");
            assertThat(response.nextContinuationToken()).isEqualTo("key12");
            assertThat(limits).containsExactly(3);
        }
    }

    private String endpoint() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    private BlobStore store() {
        return new OpenStackSwiftBlobStore(
                Suppliers.ofInstance(new Credentials("account:user", "key")),
                endpoint() + "/auth/v1.0", "account", "Default", "Default",
                /*region=*/ "");
    }

    /** Answers tempauth and the listing of any container. */
    private void handle(HttpExchange exchange) throws IOException {
        try (var in = exchange.getRequestBody()) {
            in.readAllBytes();
        }
        String path = exchange.getRequestURI().getPath();
        var headers = exchange.getResponseHeaders();
        if (path.equals("/auth/v1.0")) {
            headers.set("X-Auth-Token", "token");
            headers.set("X-Storage-Url", endpoint() + ACCOUNT);
            exchange.sendResponseHeaders(200, -1);
        } else if (!exchange.getRequestMethod().equals("GET")) {
            exchange.sendResponseHeaders(204, -1);
        } else {
            var query = new HashMap<String, String>();
            String rawQuery = exchange.getRequestURI().getRawQuery();
            for (String parameter : Splitter.on('&').split(rawQuery)) {
                int equals = parameter.indexOf('=');
                query.put(parameter.substring(0, equals), URLDecoder.decode(
                        parameter.substring(equals + 1),
                        StandardCharsets.UTF_8));
            }
            int limit = Integer.parseInt(
                    query.getOrDefault("limit", "10000"));
            limits.add(limit);
            String marker = query.get("marker");
            var objects = new ArrayList<String>();
            for (String name : marker == null ? names :
                    names.tailSet(marker, /*inclusive=*/ false)) {
                if (objects.size() == limit) {
                    break;
                }
                objects.add("""
                        {"name":"%s","bytes":0,\
                        "hash":"d41d8cd98f00b204e9800998ecf8427e",\
                        "content_type":"application/octet-stream",\
                        "last_modified":"2026-01-01T00:00:00.000000"}"""
                        .formatted(name));
            }
            byte[] body = ("[" + String.join(",", objects) + "]").getBytes(
                    StandardCharsets.UTF_8);
            headers.set("Content-Type", "application/json; charset=utf-8");
            exchange.sendResponseHeaders(200, body.length);
            try (var out = exchange.getResponseBody()) {
                out.write(body);
            }
        }
        exchange.close();
    }
}
