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
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
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
 * A delete marker is an object of the bucket, which GCS lists in its pages
 * and a listing leaves out of its answer.  How many pages a listing asks GCS
 * for, and of what length, is not something the emulator the other tests run
 * against can tell, so the listings here are answered by a stand-in for
 * objects.list that knows prefix, delimiter, startOffset and pages.
 */
public final class GCloudListPagingTest {
    private final TreeSet<String> names = new TreeSet<>();
    /** Those of the names that are delete markers. */
    private final TreeSet<String> deleteMarkers = new TreeSet<>();
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

    /**
     * What a listing hides fills the pages GCS answers with, and must not
     * be read in pages as short as the client's max-keys: a request to GCS
     * for every delete marker is what an anonymous client of a public
     * bucket held a request thread with.
     */
    @Test
    public void testListDoesNotPageDeleteMarkersByMaxKeys() {
        for (int i = 0; i < 50; ++i) {
            names.add("deleted%02d".formatted(i));
            deleteMarkers.add("deleted%02d".formatted(i));
        }
        names.add("kept");
        names.add("last");
        try (BlobStore blobStore = store()) {
            var response = blobStore.list(ListObjectsV2Request.builder()
                    .bucket("bucket").maxKeys(1).build());

            assertThat(response.contents()).extracting(S3Object::key)
                    .containsExactly("kept");
            assertThat(response.nextContinuationToken()).isEqualTo("kept");
            assertThat(pageSizes).containsExactly(2, 1000);

            pageSizes.clear();
            response = blobStore.list(ListObjectsV2Request.builder()
                    .bucket("bucket").maxKeys(1).startAfter("deleted24")
                    .build());

            assertThat(response.contents()).extracting(S3Object::key)
                    .containsExactly("kept");
            assertThat(response.nextContinuationToken()).isEqualTo("kept");
            assertThat(pageSizes).containsExactly(3, 1000);

            pageSizes.clear();
            response = blobStore.list(ListObjectsV2Request.builder()
                    .bucket("bucket").maxKeys(1).continuationToken("kept")
                    .build());

            assertThat(response.contents()).extracting(S3Object::key)
                    .containsExactly("last");
            assertThat(response.nextContinuationToken()).isNull();
            assertThat(pageSizes).containsExactly(3);
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
                    .bucket("bucket").maxKeys(2).build());

            assertThat(response.contents()).extracting(S3Object::key)
                    .containsExactly("key00", "key01");
            assertThat(response.nextContinuationToken()).isEqualTo("key01");
            assertThat(pageSizes).containsExactly(3);

            pageSizes.clear();
            response = blobStore.list(ListObjectsV2Request.builder()
                    .bucket("bucket").maxKeys(2).startAfter("key10")
                    .build());

            assertThat(response.contents()).extracting(S3Object::key)
                    .containsExactly("key11", "key12");
            assertThat(response.nextContinuationToken()).isEqualTo("key12");
            assertThat(pageSizes).containsExactly(4);

            pageSizes.clear();
            response = blobStore.list(ListObjectsV2Request.builder()
                    .bucket("bucket").maxKeys(1000).build());

            assertThat(response.contents()).hasSize(50);
            assertThat(response.nextContinuationToken()).isNull();
            assertThat(pageSizes).containsExactly(1000);
        }
    }

    /**
     * GCS names the common prefixes of a page apart from its objects, and
     * a listing that ends within a page resumes after the last name it
     * returned: everything before that has to have been returned.
     */
    @Test
    public void testListReturnsEveryPrefixAndKeyOnce() {
        names.addAll(List.of("a", "b/key", "c", "d/key", "deleted", "e",
                "f/key", "g"));
        deleteMarkers.add("deleted");
        try (BlobStore blobStore = store()) {
            for (int maxKeys = 1; maxKeys <= 7; ++maxKeys) {
                var listed = new ArrayList<String>();
                String token = null;
                do {
                    var response = blobStore.list(
                            ListObjectsV2Request.builder()
                                    .bucket("bucket").delimiter("/")
                                    .maxKeys(maxKeys)
                                    .continuationToken(token).build());
                    response.contents().forEach(o -> listed.add(o.key()));
                    response.commonPrefixes().forEach(
                            p -> listed.add(p.prefix()));
                    token = response.nextContinuationToken();
                } while (token != null);
                assertThat(listed).as("max-keys=%d", maxKeys)
                        .containsExactlyInAnyOrder(
                                "a", "b/", "c", "d/", "e", "f/", "g");
            }
        }
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
        String prefix = query.getOrDefault("prefix", "");
        String delimiter = query.get("delimiter");
        String startOffset = query.get("startOffset");
        // the whole listing by name, and whether the name is a common prefix
        var entries = new TreeMap<String, Boolean>();
        for (String name : names) {
            if (!name.startsWith(prefix) || (startOffset != null &&
                    name.compareTo(startOffset) < 0)) {
                continue;
            }
            int end = delimiter == null ? -1 :
                    name.indexOf(delimiter, prefix.length());
            if (end >= 0) {
                entries.put(name.substring(0, end + delimiter.length()),
                        true);
            } else {
                entries.put(name, false);
            }
        }
        // one page of it: maxResults entries after the one pageToken names,
        // the objects among them apart from the common prefixes
        int maxResults = Integer.parseInt(
                query.getOrDefault("maxResults", "1000"));
        pageSizes.add(maxResults);
        String pageToken = query.get("pageToken");
        var items = new ArrayList<String>();
        var prefixes = new ArrayList<String>();
        String last = null;
        String nextPageToken = "";
        for (var entry : (pageToken == null ? entries :
                entries.tailMap(pageToken, /*inclusive=*/ false))
                .entrySet()) {
            if (items.size() + prefixes.size() == maxResults) {
                nextPageToken = ",\"nextPageToken\":\"" + last + "\"";
                break;
            }
            last = entry.getKey();
            if (entry.getValue()) {
                prefixes.add("\"" + last + "\"");
            } else {
                items.add("""
                        {"kind":"storage#object","bucket":"bucket",\
                        "name":"%s","generation":"1","metageneration":"1",\
                        "size":"0","etag":"CAE=",\
                        "metadata":{"s3proxy_delete_marker":"%s"},\
                        "updated":"2026-01-01T00:00:00.000Z"}""".formatted(
                                last, deleteMarkers.contains(last)));
            }
        }
        return "{\"kind\":\"storage#objects\",\"items\":[" +
                String.join(",", items) + "],\"prefixes\":[" +
                String.join(",", prefixes) + "]" + nextPageToken + "}";
    }
}
