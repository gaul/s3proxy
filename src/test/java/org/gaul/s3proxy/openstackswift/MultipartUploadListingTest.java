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
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentSkipListMap;

import com.google.common.base.Splitter;
import com.google.common.base.Suppliers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.Credentials;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.ListMultipartUploadsRequest;

/**
 * The uploads of a bucket are found by their markers, which lay among the
 * segments: one for every part of every open upload and of every object
 * finished.  A listing of the uploads read all those names for each request,
 * which an anonymous client of a public-read bucket may send.  The markers
 * now lie apart, named by their upload's key, so that Swift lists them in
 * S3's order and a page of uploads is a page of Swift's listing.
 */
public final class MultipartUploadListingTest {
    private static final String CONTAINER = "container";
    private static final String ACCOUNT_PATH = "/v1/AUTH_account/";
    /** Swift's own limit on the names of a page. */
    private static final int SWIFT_PAGE_SIZE = 10_000;
    /** The MD5 of no content, which is all any object here has. */
    private static final String ETAG = "d41d8cd98f00b204e9800998ecf8427e";

    /** What Swift holds: the headers of each object, by its name. */
    private final Map<String, Map<String, String>> objects =
            new ConcurrentSkipListMap<>();
    /** How many names Swift answered each listing with. */
    private final List<Integer> pageSizes =
            Collections.synchronizedList(new ArrayList<Integer>());

    private HttpServer server;
    private BlobStore blobStore;

    @BeforeEach
    public void setUp() throws IOException {
        server = HttpServer.create(new InetSocketAddress(
                InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/auth/v1.0", this::authenticate);
        server.createContext(ACCOUNT_PATH, this::serve);
        server.start();
        blobStore = new OpenStackSwiftBlobStore(
                Suppliers.ofInstance(new Credentials("account:user", "key")),
                endpoint() + "/auth/v1.0", "account", "Default", "Default",
                /*region=*/ "");
    }

    @AfterEach
    public void tearDown() {
        blobStore.close();
        server.stop(0);
    }

    @Test
    public void testListingUploadsReadsNoSegments() {
        // the segments of uploads since finished, in the old layout and in
        // the present one, sorting ahead of every open upload and behind
        int segments = 2 * OpenStackSwiftBlobStore.LIST_PAGE_SIZE + 500;
        for (int part = 1; part <= segments; ++part) {
            for (String finished : List.of("!", "~", "p/!", "p/~")) {
                objects.put(String.format(Locale.ROOT,
                        ".s3proxy-mpu/%s/%05d", finished, part), Map.of());
            }
        }
        var first = initiate("first.mp4");
        var second = initiate("second.mp4");

        pageSizes.clear();
        var uploads = blobStore.listMultipartUploads(CONTAINER);

        assertThat(uploads).extracting(upload -> upload.key() + " " +
                upload.uploadId()).containsExactlyInAnyOrder(
                        "first.mp4 " + first.id(),
                        "second.mp4 " + second.id());
        assertThat(pageSizes.stream().mapToInt(Integer::intValue).sum())
                .isEqualTo(2);
    }

    /**
     * A page costs about the page, and a slash delimiter is folded by Swift
     * however many uploads its group holds; the page after a common prefix
     * starts past it.
     */
    @Test
    public void testPageOfUploadsReadsAboutThePage() {
        initiate("a");
        for (int i = 0; i < 50; ++i) {
            initiate("dir/%02d".formatted(i));
        }
        initiate("e");
        initiate("e");

        pageSizes.clear();
        var request = ListMultipartUploadsRequest.builder()
                .bucket(CONTAINER).delimiter("/").maxUploads(2);
        var first = blobStore.listMultipartUploads(request.build());
        assertThat(first.uploads()).extracting(u -> u.key())
                .containsExactly("a");
        assertThat(first.commonPrefixes()).extracting(p -> p.prefix())
                .containsExactly("dir/");
        assertThat(first.nextKeyMarker()).isEqualTo("dir/");
        // the page, one past it, and the long keys' markers
        assertThat(pageSizes.stream().mapToInt(Integer::intValue).sum())
                .isLessThanOrEqualTo(4);

        pageSizes.clear();
        var second = blobStore.listMultipartUploads(request
                .keyMarker(first.nextKeyMarker()).build());
        assertThat(second.uploads()).extracting(u -> u.key())
                .containsExactly("e", "e");
        assertThat(second.isTruncated()).isFalse();
        assertThat(pageSizes.stream().mapToInt(Integer::intValue).sum())
                .isLessThanOrEqualTo(4);

        var below = blobStore.listMultipartUploads(ListMultipartUploadsRequest
                .builder().bucket(CONTAINER).prefix("dir/").maxUploads(3)
                .build());
        assertThat(below.uploads()).extracting(u -> u.key())
                .containsExactly("dir/00", "dir/01", "dir/02");
    }

    private MultipartUpload initiate(String key) {
        return blobStore.initiateMultipartUpload(
                CreateMultipartUploadRequest.builder()
                        .bucket(CONTAINER)
                        .key(key)
                        .build());
    }

    private String endpoint() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    /** Swift's tempauth: a token, and the address of the account. */
    private void authenticate(HttpExchange exchange) throws IOException {
        exchange.getResponseHeaders().set("X-Auth-Token", "token");
        exchange.getResponseHeaders().set("X-Storage-Url",
                endpoint() + "/v1/AUTH_account");
        exchange.sendResponseHeaders(200, -1);
        exchange.close();
    }

    /** As much of Swift's object API as opening an upload asks of it. */
    private void serve(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath()
                .substring(ACCOUNT_PATH.length());
        exchange.getRequestBody().readAllBytes();
        if (!path.contains("/")) {
            list(exchange);
            return;
        }
        String name = path.substring(path.indexOf('/') + 1);
        if (exchange.getRequestMethod().equals("PUT")) {
            var stored = new TreeMap<String, String>();
            exchange.getRequestHeaders().forEach((header, values) -> {
                if (header.toLowerCase(Locale.ROOT)
                        .startsWith("x-object-meta-")) {
                    stored.put(header, values.get(0));
                }
            });
            objects.put(name, stored);
            exchange.getResponseHeaders().set("ETag", ETAG);
            exchange.sendResponseHeaders(201, -1);
        } else {
            var headers = objects.get(name);
            if (headers != null) {
                headers.forEach(exchange.getResponseHeaders()::set);
                exchange.getResponseHeaders().set("ETag", ETAG);
                exchange.getResponseHeaders().set("Last-Modified",
                        "Thu, 01 Jan 2026 00:00:00 GMT");
            }
            // no object has content here; a HEAD has to say so itself
            exchange.getResponseHeaders().set("Content-Length", "0");
            exchange.sendResponseHeaders(headers != null ? 200 : 404, -1);
        }
        exchange.close();
    }

    /**
     * A listing of the container: the names with a prefix, past a marker,
     * and no more of them than the limit asked for or Swift's own.
     */
    private void list(HttpExchange exchange) throws IOException {
        String prefix = "";
        String marker = "";
        String delimiter = null;
        int limit = SWIFT_PAGE_SIZE;
        for (String parameter : Splitter.on('&').split(
                exchange.getRequestURI().getRawQuery())) {
            String value = URLDecoder.decode(
                    parameter.substring(parameter.indexOf('=') + 1),
                    StandardCharsets.UTF_8);
            if (parameter.startsWith("prefix=")) {
                prefix = value;
            } else if (parameter.startsWith("marker=")) {
                marker = value;
            } else if (parameter.startsWith("limit=")) {
                limit = Math.min(limit, Integer.parseInt(value));
            } else if (parameter.startsWith("delimiter=")) {
                delimiter = value;
            }
        }
        var entries = new ArrayList<String>();
        String lastSubdir = null;
        for (String name : objects.keySet()) {
            if (entries.size() == limit) {
                break;
            }
            if (!name.startsWith(prefix) || name.compareTo(marker) <= 0) {
                continue;
            }
            int at = delimiter == null ? -1 :
                    name.indexOf(delimiter, prefix.length());
            if (at >= 0) {
                String subdir = name.substring(0, at + delimiter.length());
                // a subdir only once, and only past the marker, as Swift
                if (!subdir.equals(lastSubdir) &&
                        subdir.compareTo(marker) > 0) {
                    entries.add("{\"subdir\": \"" + subdir + "\"}");
                }
                lastSubdir = subdir;
                continue;
            }
            entries.add("{\"name\": \"" + name + "\", \"bytes\": 0," +
                    " \"hash\": \"" + ETAG + "\"," +
                    " \"content_type\": \"application/octet-stream\"," +
                    " \"last_modified\": \"2026-01-01T00:00:00.000000\"}");
        }
        pageSizes.add(entries.size());
        byte[] json = ("[" + String.join(",", entries) + "]")
                .getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, json.length);
        exchange.getResponseBody().write(json);
        exchange.close();
    }
}
