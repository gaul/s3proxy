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
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicInteger;

import com.google.common.base.Splitter;
import com.google.common.base.Suppliers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import org.assertj.core.groups.Tuple;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.Credentials;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.MultipartUpload;

/**
 * An upload's parts are objects named under its stub, and a listing of
 * the uploads has no use for them.  How many entries GCS sends back for it
 * is not something the emulator the other tests run against can tell, so
 * the listing is answered by a stand-in for objects.list that knows prefix
 * and delimiter.
 */
public final class GCloudMultipartListingTest {
    private static final String STUBS = ".s3proxy/stubs/";
    private static final int UPLOADS = 3;
    private static final int PARTS = 300;

    private final TreeSet<String> names = new TreeSet<>();
    /** The objects and common prefixes GCS was made to send. */
    private final AtomicInteger entriesSent = new AtomicInteger();

    private HttpServer server;

    @BeforeEach
    public void setUp() throws IOException {
        server = HttpServer.create(new InetSocketAddress(
                InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", this::handle);
        server.start();
        for (int u = 0; u < UPLOADS; ++u) {
            names.add(STUBS + "nonce" + u);
            for (int p = 1; p <= PARTS; ++p) {
                names.add(STUBS + "nonce" + u + "/part_%05d".formatted(p));
            }
        }
        names.add(STUBS + "nonce0/compose_0");
    }

    @AfterEach
    public void tearDown() {
        server.stop(0);
    }

    /** Each upload costs its stub and the prefix of its parts, no more. */
    @Test
    public void testListMultipartUploadsReadsNoParts() {
        try (BlobStore blobStore = store()) {
            assertThat(blobStore.listMultipartUploads("bucket"))
                    .extracting(MultipartUpload::uploadId,
                            MultipartUpload::key)
                    .containsExactly(
                            Tuple.tuple(STUBS + "nonce0", "key0"),
                            Tuple.tuple(STUBS + "nonce1", "key1"),
                            Tuple.tuple(STUBS + "nonce2", "key2"));
        }
        assertThat(entriesSent.get()).isLessThanOrEqualTo(2 * UPLOADS);
    }

    private BlobStore store() {
        return new GCloudBlobStore(Suppliers.ofInstance(
                new Credentials("project", /*credential=*/ "")),
                "http://127.0.0.1:" + server.getAddress().getPort());
    }

    /** Answers objects.list, in one page. */
    private void handle(HttpExchange exchange) throws IOException {
        Map<String, String> query = new HashMap<>();
        String rawQuery = exchange.getRequestURI().getRawQuery();
        if (rawQuery != null) {
            for (String parameter : Splitter.on('&').split(rawQuery)) {
                int equals = parameter.indexOf('=');
                query.put(parameter.substring(0, equals), URLDecoder.decode(
                        parameter.substring(equals + 1),
                        StandardCharsets.UTF_8));
            }
        }
        String prefix = query.getOrDefault("prefix", "");
        String delimiter = query.get("delimiter");
        var items = new StringBuilder();
        var prefixes = new TreeSet<String>();
        for (String name : names.tailSet(prefix)) {
            if (!name.startsWith(prefix)) {
                break;
            }
            int at = delimiter == null ? -1 :
                    name.indexOf(delimiter, prefix.length());
            if (at >= 0) {
                prefixes.add(name.substring(0, at + delimiter.length()));
                continue;
            }
            if (items.length() > 0) {
                items.append(',');
            }
            items.append("{\"kind\":\"storage#object\",\"bucket\":\"bucket\"," +
                    "\"name\":\"").append(name).append("\"," +
                    "\"generation\":\"1\",\"size\":\"0\"," +
                    "\"timeCreated\":\"2026-11-24T00:00:00.000Z\"");
            String rest = name.substring(STUBS.length());
            if (!rest.contains("/")) {
                items.append(",\"metadata\":{\"s3proxy_target_blob_name\":" +
                        "\"key").append(rest.substring("nonce".length()))
                        .append("\"}");
            }
            items.append('}');
            entriesSent.incrementAndGet();
        }
        entriesSent.addAndGet(prefixes.size());
        var response = new StringBuilder("{\"kind\":\"storage#objects\"," +
                "\"items\":[").append(items).append(']');
        if (!prefixes.isEmpty()) {
            response.append(",\"prefixes\":[");
            boolean first = true;
            for (String p : prefixes) {
                response.append(first ? "" : ",").append('"').append(p)
                        .append('"');
                first = false;
            }
            response.append(']');
        }
        response.append('}');
        byte[] body = response.toString().getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type",
                "application/json; charset=UTF-8");
        exchange.sendResponseHeaders(200, body.length);
        try (var out = exchange.getResponseBody()) {
            out.write(body);
        }
    }
}
