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
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import com.google.common.base.Splitter;
import com.google.common.base.Suppliers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.Credentials;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.ListObjectVersionsRequest;
import software.amazon.awssdk.services.s3.model.ListObjectVersionsResponse;

/**
 * ListObjectVersions reads GCS's listing only as far as the page it
 * answers: it read every generation from the marker to the end of the
 * bucket, for every page, so paging through V versions cost O(V^2).
 * Answered by a stand-in for objects.list that knows generations, prefix,
 * delimiter, startOffset and pages, and counts the pages asked for.
 */
public final class GCloudVersionListingTest {
    /** Each name's generations, oldest first, as GCS lists them. */
    private final TreeMap<String, List<Long>> generations = new TreeMap<>();
    /** The "name#generation" of each delete marker. */
    private final Set<String> deleteMarkers = new HashSet<>();
    /** The maxResults of each page asked for, in order. */
    private final List<Integer> pageSizes =
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

    /** A page of two versions reads two GCS pages of 6000 versions. */
    @Test
    public void testListStopsOnceThePageIsSettled() {
        for (int i = 0; i < 2000; ++i) {
            generations.put("key%04d".formatted(i), List.of(1L, 2L, 3L));
        }
        try (BlobStore blobStore = store()) {
            var response = blobStore.listVersions(
                    ListObjectVersionsRequest.builder()
                            .bucket("bucket").maxKeys(2).build());

            assertThat(listed(response)).containsExactly(
                    "key0000#3 latest", "key0000#2");
            assertThat(response.isTruncated()).isTrue();
            assertThat(response.nextKeyMarker()).isEqualTo("key0000");
            assertThat(response.nextVersionIdMarker()).isEqualTo("2");
            assertThat(pageSizes).containsExactly(3, 1000);

            pageSizes.clear();
            response = blobStore.listVersions(
                    ListObjectVersionsRequest.builder()
                            .bucket("bucket").maxKeys(2)
                            .keyMarker("key1000").versionIdMarker("2")
                            .build());

            assertThat(listed(response)).containsExactly(
                    "key1000#1", "key1001#3 latest");
            assertThat(pageSizes).containsExactly(4, 1000);
        }
    }

    /** Paging through every version costs GCS pages in proportion. */
    @Test
    public void testPagingThroughIsLinear() {
        for (int i = 0; i < 2000; ++i) {
            generations.put("key%04d".formatted(i), List.of(1L, 2L, 3L));
        }
        try (BlobStore blobStore = store()) {
            var all = listAll(blobStore, 1000, /*delimiter=*/ null);

            assertThat(all).hasSize(6000);
            // 6 pages of the 6000 versions, each settled by a second GCS
            // page; reading to the end every time took 21
            assertThat(pageSizes).hasSizeLessThanOrEqualTo(13);
        }
    }

    /**
     * Whatever the page length, and wherever GCS's pages split a name's
     * generations, every version and common prefix is listed once, in
     * order, the newest of a name its latest.
     */
    @Test
    public void testEveryVersionAndPrefixOnce() {
        generations.put("a", List.of(1L, 2L, 3L));
        generations.put("b/x", List.of(4L));
        generations.put("b/y", List.of(5L, 6L));
        generations.put("c", List.of(7L, 8L, 9L, 10L, 11L));
        deleteMarkers.add("c#11");
        generations.put("d/z", List.of(12L));
        generations.put("e", List.of(13L));
        var flat = List.of("a#3 latest", "a#2", "a#1", "b/x#4 latest",
                "b/y#6 latest", "b/y#5", "c#11 latest marker", "c#10", "c#9",
                "c#8", "c#7", "d/z#12 latest", "e#13 latest");
        var folded = List.of("a#3 latest", "a#2", "a#1", "b/",
                "c#11 latest marker", "c#10", "c#9", "c#8", "c#7", "d/",
                "e#13 latest");
        try (BlobStore blobStore = store()) {
            for (int maxKeys = 1; maxKeys <= flat.size() + 1; ++maxKeys) {
                assertThat(listAll(blobStore, maxKeys, null))
                        .as("max-keys=%d", maxKeys)
                        .containsExactlyElementsOf(flat);
                assertThat(listAll(blobStore, maxKeys, "/"))
                        .as("max-keys=%d, delimiter", maxKeys)
                        .containsExactlyElementsOf(folded);
            }
        }
    }

    private static List<String> listAll(BlobStore blobStore, int maxKeys,
            @Nullable String delimiter) {
        var all = new ArrayList<String>();
        String keyMarker = null;
        String versionIdMarker = null;
        for (int pages = 0; pages < 1000; ++pages) {
            var response = blobStore.listVersions(
                    ListObjectVersionsRequest.builder()
                            .bucket("bucket").maxKeys(maxKeys)
                            .delimiter(delimiter).keyMarker(keyMarker)
                            .versionIdMarker(versionIdMarker).build());
            var page = listed(response);
            assertThat(page.size()).isLessThanOrEqualTo(maxKeys);
            all.addAll(page);
            if (!response.isTruncated()) {
                return all;
            }
            keyMarker = response.nextKeyMarker();
            versionIdMarker = response.nextVersionIdMarker();
        }
        throw new AssertionError("listing did not end");
    }

    /** A page's entries in name order, newest generation first. */
    private static List<String> listed(ListObjectVersionsResponse response) {
        var entries = new TreeMap<String, String>();
        for (var version : response.versions()) {
            entries.put(sortKey(version.key(), version.versionId()),
                    version.key() + "#" + version.versionId() +
                    (version.isLatest() ? " latest" : ""));
        }
        for (var marker : response.deleteMarkers()) {
            entries.put(sortKey(marker.key(), marker.versionId()),
                    marker.key() + "#" + marker.versionId() +
                    (marker.isLatest() ? " latest" : "") + " marker");
        }
        for (var prefix : response.commonPrefixes()) {
            entries.put(prefix.prefix(), prefix.prefix());
        }
        return new ArrayList<>(entries.values());
    }

    private static String sortKey(String key, String versionId) {
        // the newest first: generations are below a million here
        return key + "\0" + (1_000_000 - Long.parseLong(versionId));
    }

    private BlobStore store() {
        return new GCloudBlobStore(Suppliers.ofInstance(
                new Credentials("project", /*credential=*/ "")),
                "http://127.0.0.1:" + server.getAddress().getPort());
    }

    /** Answers objects.list. */
    private void handle(HttpExchange exchange) throws IOException {
        var query = new HashMap<String, String>();
        String rawQuery = exchange.getRequestURI().getRawQuery();
        if (rawQuery != null) {
            for (String parameter : Splitter.on('&').split(rawQuery)) {
                int equals = parameter.indexOf('=');
                query.put(parameter.substring(0, equals), URLDecoder.decode(
                        parameter.substring(equals + 1),
                        StandardCharsets.UTF_8));
            }
        }
        byte[] body = listing(query).getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type",
                "application/json; charset=UTF-8");
        exchange.sendResponseHeaders(200, body.length);
        try (var out = exchange.getResponseBody()) {
            out.write(body);
        }
    }

    private String listing(Map<String, String> query) {
        assertThat(query).containsEntry("versions", "true");
        String prefix = query.getOrDefault("prefix", "");
        String delimiter = query.get("delimiter");
        String startOffset = query.get("startOffset");
        // the whole listing: a common prefix once, or each generation of a
        // name, oldest first
        var entries = new ArrayList<String>();
        String lastPrefix = null;
        for (var entry : generations.entrySet()) {
            String name = entry.getKey();
            if (!name.startsWith(prefix) || (startOffset != null &&
                    name.compareTo(startOffset) < 0)) {
                continue;
            }
            int end = delimiter == null ? -1 :
                    name.indexOf(delimiter, prefix.length());
            if (end >= 0) {
                String commonPrefix =
                        name.substring(0, end + delimiter.length());
                if (!commonPrefix.equals(lastPrefix)) {
                    entries.add("/" + commonPrefix);
                    lastPrefix = commonPrefix;
                }
                continue;
            }
            for (long generation : entry.getValue()) {
                entries.add(name + "#" + generation);
            }
        }
        // one page of it: maxResults entries from the one pageToken names,
        // the objects among them apart from the common prefixes
        int maxResults = Integer.parseInt(
                query.getOrDefault("maxResults", "1000"));
        pageSizes.add(maxResults);
        int from = Integer.parseInt(query.getOrDefault("pageToken", "0"));
        int to = Math.min(entries.size(), from + maxResults);
        var items = new ArrayList<String>();
        var prefixes = new ArrayList<String>();
        for (String entry : entries.subList(from, to)) {
            if (entry.startsWith("/")) {
                prefixes.add("\"" + entry.substring(1) + "\"");
                continue;
            }
            int hash = entry.lastIndexOf('#');
            items.add("""
                    {"kind":"storage#object","bucket":"bucket",\
                    "name":"%s","generation":"%s","metageneration":"1",\
                    "size":"0","etag":"CAE=",\
                    "metadata":{"s3proxy_delete_marker":"%s"},\
                    "updated":"2026-01-01T00:00:00.000Z"}""".formatted(
                            entry.substring(0, hash),
                            entry.substring(hash + 1),
                            deleteMarkers.contains(entry)));
        }
        String nextPageToken = to < entries.size() ?
                ",\"nextPageToken\":\"" + to + "\"" : "";
        return "{\"kind\":\"storage#objects\",\"items\":[" +
                String.join(",", items) + "],\"prefixes\":[" +
                String.join(",", prefixes) + "]" + nextPageToken + "}";
    }
}
