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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicInteger;

import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.google.common.base.Suppliers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.Credentials;
import org.gaul.s3proxy.blobstore.UploadNames;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.CommonPrefix;
import software.amazon.awssdk.services.s3.model.ListMultipartUploadsRequest;
import software.amazon.awssdk.services.s3.model.ListMultipartUploadsResponse;
import software.amazon.awssdk.services.s3.model.MultipartUpload;

/**
 * An upload's stub is named by its key and upload ID, so that GCS lists
 * the uploads in S3's order and a page of them is a page of GCS's listing.
 * How many entries GCS sends back is not something the emulator the other
 * tests run against can tell, so the listing is answered by a stand-in for
 * objects.list that knows prefix, delimiter, startOffset and maxResults.
 */
public final class GCloudMultipartListingTest {
    /** Stub names, with the key a long one keeps in its metadata. */
    private final TreeMap<String, String> stubs = new TreeMap<>();
    /** The objects and common prefixes GCS was made to send. */
    private final AtomicInteger entriesSent = new AtomicInteger();

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
     * Keys sort as S3 sorts them: a key before any longer key it begins,
     * and a space or a '!' after the key that stops short of it, which the
     * escaping of those characters in a stub's name has to keep.
     */
    @Test
    public void testUploadsListInKeyOrder() {
        for (String key : List.of("ab", "a/b", "a!b", "a b", "a")) {
            upload(key);
        }
        try (BlobStore blobStore = store()) {
            assertThat(keys(blobStore.listMultipartUploads(request()
                    .build()))).containsExactly("a", "a b", "a!b", "a/b",
                    "ab");
            assertThat(blobStore.listMultipartUploads("bucket"))
                    .extracting(MultipartUpload::key)
                    .containsExactlyInAnyOrder("a", "a b", "a!b", "a/b",
                            "ab");
        }
    }

    /** A page costs about the page, however many uploads follow it. */
    @Test
    public void testPageReadsAboutThePage() {
        for (int i = 0; i < 300; ++i) {
            upload("key%03d".formatted(i));
        }
        try (BlobStore blobStore = store()) {
            var first = blobStore.listMultipartUploads(request()
                    .maxUploads(10).build());
            assertThat(keys(first)).hasSize(10).startsWith("key000")
                    .endsWith("key009");
            assertThat(first.isTruncated()).isTrue();
            assertThat(entriesSent.get()).isLessThanOrEqualTo(12);

            entriesSent.set(0);
            var second = blobStore.listMultipartUploads(request()
                    .maxUploads(10).keyMarker(first.nextKeyMarker())
                    .uploadIdMarker(first.nextUploadIdMarker()).build());
            assertThat(keys(second)).hasSize(10).startsWith("key010")
                    .endsWith("key019");
            assertThat(entriesSent.get()).isLessThanOrEqualTo(12);
        }
    }

    /**
     * A slash folds a group of keys into one common prefix however many
     * uploads it holds, and the page after one resumes past the group.
     */
    @Test
    public void testDelimiterFoldsAndResumesPastAGroup() {
        upload("a");
        for (int i = 0; i < 50; ++i) {
            upload("dir/%02d".formatted(i));
        }
        upload("e");
        upload("e");
        try (BlobStore blobStore = store()) {
            var first = blobStore.listMultipartUploads(request()
                    .delimiter("/").maxUploads(2).build());
            assertThat(keys(first)).containsExactly("a", "dir/");
            assertThat(first.nextKeyMarker()).isEqualTo("dir/");
            assertThat(entriesSent.get()).isLessThanOrEqualTo(4);

            var second = blobStore.listMultipartUploads(request()
                    .delimiter("/").maxUploads(2)
                    .keyMarker(first.nextKeyMarker()).build());
            assertThat(keys(second)).containsExactly("e", "e");
            assertThat(second.isTruncated()).isFalse();

            var below = blobStore.listMultipartUploads(request()
                    .prefix("dir/").delimiter("/").maxUploads(3).build());
            assertThat(keys(below)).containsExactly("dir/00", "dir/01",
                    "dir/02");
        }
    }

    /** A key too long to name a stub by is merged in where it sorts. */
    @Test
    public void testLongKeyListsWhereItSorts() {
        String longKey = "m" + "x".repeat(1000);
        upload("a");
        upload(longKey);
        upload("z");
        assertThat(GCloudBlobStore.stubName(longKey,
                UploadNames.newUploadId(longKey))).doesNotContain(longKey);
        try (BlobStore blobStore = store()) {
            assertThat(keys(blobStore.listMultipartUploads(request()
                    .build()))).containsExactly("a", longKey, "z");
            assertThat(keys(blobStore.listMultipartUploads(request()
                    .maxUploads(1).keyMarker("a").build())))
                    .containsExactly(longKey);
        }
    }

    private void upload(String key) {
        stubs.put(GCloudBlobStore.stubName(key,
                UploadNames.newUploadId(key)), key);
    }

    private static ListMultipartUploadsRequest.Builder request() {
        return ListMultipartUploadsRequest.builder().bucket("bucket");
    }

    /** Uploads and common prefixes, in the order S3 lists them in. */
    private static List<String> keys(ListMultipartUploadsResponse page) {
        var keys = new TreeMap<String, String>();
        page.uploads().forEach(u -> keys.put(u.key() + "\0" + u.uploadId(),
                u.key()));
        page.commonPrefixes().stream().map(CommonPrefix::prefix)
                .forEach(p -> keys.put(p, p));
        return new ArrayList<>(keys.values());
    }

    private BlobStore store() {
        return new GCloudBlobStore(Suppliers.ofInstance(
                new Credentials("project", /*credential=*/ "")),
                "http://127.0.0.1:" + server.getAddress().getPort());
    }

    /** Answers objects.list, in pages of maxResults. */
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
        String delimiter = Strings.emptyToNull(query.get("delimiter"));
        String start = query.getOrDefault("startOffset", "");
        String after = query.get("pageToken");
        int maxResults = Integer.parseInt(
                query.getOrDefault("maxResults", "1000"));

        var items = new ArrayList<String>();
        var prefixes = new TreeSet<String>();
        String last = null;
        boolean more = false;
        String from = after != null ? after : start;
        for (var entry : stubs.tailMap(from, after == null).entrySet()) {
            String name = entry.getKey();
            if (!name.startsWith(prefix)) {
                continue;
            }
            int at = delimiter == null ? -1 :
                    name.indexOf(delimiter, prefix.length());
            String folded = at < 0 ? null :
                    name.substring(0, at + delimiter.length());
            if (folded != null && prefixes.contains(folded)) {
                last = name;
                continue;
            }
            if (items.size() + prefixes.size() == maxResults) {
                more = true;
                break;
            }
            if (folded != null) {
                prefixes.add(folded);
            } else {
                String metadata = name.contains("/l/") ?
                        ",\"metadata\":{\"s3proxy_target_blob_name\":\"" +
                        entry.getValue() + "\"}" : "";
                items.add("{\"kind\":\"storage#object\"," +
                        "\"bucket\":\"bucket\",\"name\":\"" + name +
                        "\",\"generation\":\"1\",\"size\":\"0\"," +
                        "\"timeCreated\":\"2026-11-24T00:00:00.000Z\"" +
                        metadata + "}");
            }
            last = name;
        }
        entriesSent.addAndGet(items.size() + prefixes.size());
        var response = new StringBuilder("{\"kind\":\"storage#objects\"," +
                "\"items\":[").append(String.join(",", items)).append(']');
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
        if (more && last != null) {
            response.append(",\"nextPageToken\":\"").append(last)
                    .append('"');
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
