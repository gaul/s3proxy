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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayInputStream;
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
import java.util.TreeSet;

import com.google.common.base.Splitter;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.Credentials;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.CopyObjectRequest;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.HeadObjectRequest;
import software.amazon.awssdk.services.s3.model.ListObjectVersionsRequest;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.s3.model.ObjectVersion;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.services.s3.model.S3Object;

/**
 * The stub of a multipart upload in progress is a blob of the container,
 * which Azure would serve and list as it does any other.  It carries the
 * metadata and headers of an upload that has published nothing yet, so a
 * client must neither read it as an object nor be handed it as a key.  The
 * requests here are answered by a stand-in for Get Blob, Get Blob Properties
 * and a List Blobs that knows prefix, delimiter, startFrom and maxresults.
 */
public final class AzureMultipartStubTest {
    private static final String STUB =
            ".s3proxy/stubs/11111111-2222-3333-4444-555555555555";

    private final TreeSet<String> names = new TreeSet<>();
    private final List<String> blobRequests =
            Collections.synchronizedList(new ArrayList<String>());

    private HttpServer server;

    @BeforeEach
    public void setUp() throws IOException {
        server = HttpServer.create(new InetSocketAddress(
                InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", this::handle);
        server.start();
        names.add(STUB);
        names.add("key");
    }

    @AfterEach
    public void tearDown() {
        server.stop(0);
    }

    /**
     * Azure grants read by container, so a public-read bucket would serve an
     * open upload's metadata to anyone.  A read of a stub answers as S3 does
     * for a key that holds nothing, without asking Azure for it.
     */
    @Test
    public void testReadsAnswerAStubAsAbsent() {
        for (boolean versioning : new boolean[] {false, true}) {
            try (BlobStore blobStore = store(versioning)) {
                assertAbsent(() -> blobStore.getBlob(
                        GetObjectRequest.builder()
                                .bucket("container").key(STUB).build()));
                assertAbsent(() -> blobStore.blobMetadata(
                        HeadObjectRequest.builder()
                                .bucket("container").key(STUB).build()));
                assertAbsent(() -> blobStore.copyBlob(
                        CopyObjectRequest.builder()
                                .sourceBucket("container").sourceKey(STUB)
                                .destinationBucket("container")
                                .destinationKey("copy").build()));
                assertThat(blobStore.blobExists("container", STUB)).isFalse();
            }
        }
        assertThat(blobRequests).isEmpty();
    }

    /**
     * Nor may a client write or delete a stub: completion publishes what the
     * stub says, and a write there would also be lost to its writer, since
     * reads and listings do not show it.  Refused without asking Azure.
     */
    @Test
    public void testWritesToAStubAreRefused() {
        for (boolean versioning : new boolean[] {false, true}) {
            try (BlobStore blobStore = store(versioning)) {
                assertRefused(() -> blobStore.putBlob(
                        PutObjectRequest.builder().bucket("container")
                                .key(STUB).contentLength(0L).build(),
                        new ByteArrayInputStream(new byte[0])));
                assertRefused(() -> blobStore.copyBlob(
                        CopyObjectRequest.builder()
                                .sourceBucket("container").sourceKey("key")
                                .destinationBucket("container")
                                .destinationKey(STUB).build()));
                assertRefused(() -> blobStore.removeBlob(
                        DeleteObjectRequest.builder()
                                .bucket("container").key(STUB).build()));
                assertRefused(() -> blobStore.initiateMultipartUpload(
                        CreateMultipartUploadRequest.builder()
                                .bucket("container").key(STUB).build()));
            }
        }
        assertThat(blobRequests).isEmpty();
    }

    private static void assertRefused(ThrowingCallable call) {
        assertThatThrownBy(call).isInstanceOfSatisfying(S3Exception.class,
                e -> assertThat(e.statusCode()).isEqualTo(400));
    }

    /** What the stand-in answers a read with, were one to reach it. */
    @Test
    public void testReadsAnswerAnObject() {
        try (BlobStore blobStore = store(/*versioning=*/ false)) {
            var head = blobStore.blobMetadata(HeadObjectRequest.builder()
                    .bucket("container").key("key").build());

            assertThat(head.metadata()).containsEntry("reviewer", "j.doe");
            assertThat(blobStore.blobExists("container", "key")).isTrue();
        }
    }

    @Test
    public void testListHidesStubs() {
        for (boolean versioning : new boolean[] {false, true}) {
            try (BlobStore blobStore = store(versioning)) {
                var response = blobStore.list(ListObjectsV2Request.builder()
                        .bucket("container").build());

                assertThat(response.contents()).extracting(S3Object::key)
                        .containsExactly("key");
                assertThat(response.isTruncated()).isFalse();
            }
        }
    }

    /** A page Azure filled with stubs is followed to the keys after it. */
    @Test
    public void testListDoesNotCountStubs() {
        for (boolean versioning : new boolean[] {false, true}) {
            try (BlobStore blobStore = store(versioning)) {
                var response = blobStore.list(ListObjectsV2Request.builder()
                        .bucket("container").maxKeys(1).build());

                assertThat(response.contents()).extracting(S3Object::key)
                        .containsExactly("key");
                assertThat(response.isTruncated()).isFalse();
            }
        }
    }

    /**
     * Nor is a page that holds only the group a delimiter folds the stubs
     * into, ".s3proxy/", which sorts ahead of most keys.  Handed on, it was
     * a page with neither Contents nor CommonPrefixes and a continuation
     * token, which a client that takes its next marker from the last key it
     * saw reads as the end of the bucket (#329).
     */
    @Test
    public void testListDoesNotCountAGroupOfStubs() {
        for (boolean versioning : new boolean[] {false, true}) {
            try (BlobStore blobStore = store(versioning)) {
                var response = blobStore.list(ListObjectsV2Request.builder()
                        .bucket("container").delimiter("/").maxKeys(1)
                        .build());

                assertThat(response.contents()).as("versioning %s", versioning)
                        .extracting(S3Object::key).containsExactly("key");
                assertThat(response.commonPrefixes()).isEmpty();
                assertThat(response.isTruncated()).isFalse();
            }
        }
    }

    @Test
    public void testListHidesStubsByPrefix() {
        for (boolean versioning : new boolean[] {false, true}) {
            try (BlobStore blobStore = store(versioning)) {
                var response = blobStore.list(ListObjectsV2Request.builder()
                        .bucket("container").prefix(".s3proxy/").build());

                assertThat(response.contents()).isEmpty();
            }
        }
    }

    /** Nor is a common prefix that lies within the stubs' own. */
    @Test
    public void testListHidesAGroupOfStubs() {
        for (boolean versioning : new boolean[] {false, true}) {
            try (BlobStore blobStore = store(versioning)) {
                var response = blobStore.list(ListObjectsV2Request.builder()
                        .bucket("container").prefix(".s3proxy/")
                        .delimiter("/").build());

                assertThat(response.commonPrefixes()).isEmpty();
                assertThat(response.contents()).isEmpty();
            }
        }
    }

    /** A client's own keys are listed, however close to the stubs. */
    @Test
    public void testListKeepsOtherKeys() {
        // A client's key that shares the group a delimiter folds the stubs
        // into is hidden with it from that listing, as an upload in progress
        // must not show as ".s3proxy/"; it is listed under the group's prefix.
        for (String own : new String[] {".s3proxy/mine", ".s3proxy/stubs0"}) {
            names.add(own);
            for (boolean versioning : new boolean[] {false, true}) {
                try (BlobStore blobStore = store(versioning)) {
                    var response = blobStore.list(ListObjectsV2Request.builder()
                            .bucket("container").prefix(".s3proxy/")
                            .delimiter("/").build());

                    assertThat(response.commonPrefixes()).isEmpty();
                    assertThat(response.contents()).extracting(S3Object::key)
                            .containsExactly(own);
                }
            }
            names.remove(own);
        }
    }

    @Test
    public void testListVersionsHidesStubs() {
        try (BlobStore blobStore = store(/*versioning=*/ true)) {
            var response = blobStore.listVersions(
                    ListObjectVersionsRequest.builder()
                            .bucket("container").build());

            assertThat(response.versions()).extracting(ObjectVersion::key)
                    .containsExactly("key");

            response = blobStore.listVersions(
                    ListObjectVersionsRequest.builder()
                            .bucket("container").prefix(".s3proxy/")
                            .delimiter("/").build());

            assertThat(response.commonPrefixes()).isEmpty();
            assertThat(response.versions()).isEmpty();
        }
    }

    private static void assertAbsent(ThrowingCallable call) {
        assertThatThrownBy(call).isInstanceOf(NoSuchKeyException.class);
    }

    private BlobStore store(boolean versioning) {
        return new AzureBlobStore(
                () -> new Credentials("", "", "sv=2026-02-06&sig=fake"),
                "http://127.0.0.1:" + server.getAddress().getPort() +
                        "/account",
                /*eTagMode=*/ "opaque", /*auth=*/ null, versioning);
    }

    /** Answers List Blobs, a page at a time, and a read of a blob. */
    private void handle(HttpExchange exchange) throws IOException {
        try (var in = exchange.getRequestBody()) {
            in.readAllBytes();
        }
        var query = new HashMap<String, String>();
        String rawQuery = exchange.getRequestURI().getRawQuery();
        if (rawQuery != null) {
            for (String parameter : Splitter.on('&').split(rawQuery)) {
                var pair = Splitter.on('=').limit(2).splitToList(parameter);
                query.put(pair.get(0), pair.size() < 2 ? "" :
                        URLDecoder.decode(pair.get(1),
                                StandardCharsets.UTF_8));
            }
        }
        var headers = exchange.getResponseHeaders();
        headers.set("x-ms-version", "2026-02-06");
        String path = exchange.getRequestURI().getPath();
        if (path.equals("/account/container") &&
                "list".equals(query.get("comp"))) {
            byte[] body = listing(query).getBytes(StandardCharsets.UTF_8);
            headers.set("Content-Type", "application/xml");
            exchange.sendResponseHeaders(200, body.length);
            try (var out = exchange.getResponseBody()) {
                out.write(body);
            }
            return;
        }
        blobRequests.add(exchange.getRequestMethod() + " " + path);
        String method = exchange.getRequestMethod();
        if (!path.startsWith("/account/container/") ||
                !names.contains(path.substring(
                        "/account/container/".length())) ||
                !(method.equals("GET") || method.equals("HEAD"))) {
            headers.set("x-ms-error-code", "BlobNotFound");
            exchange.sendResponseHeaders(404, -1);
            exchange.close();
            return;
        }
        headers.set("x-ms-blob-type", "BlockBlob");
        headers.set("x-ms-meta-reviewer", "j.doe");
        headers.set("Last-Modified", "Thu, 01 Jan 2026 00:00:00 GMT");
        headers.set("ETag", "\"0x1\"");
        headers.set("Content-Type", "application/octet-stream");
        if (method.equals("HEAD")) {
            headers.set("Content-Length", "0");
        }
        exchange.sendResponseHeaders(200, -1);
        exchange.close();
    }

    private String listing(Map<String, String> query) {
        String prefix = query.getOrDefault("prefix", "");
        String delimiter = query.get("delimiter");
        String marker = query.get("marker");
        String startFrom = query.get("startFrom");
        boolean versions = query.getOrDefault("include", "")
                .contains("versions");
        int maxResults = Integer.parseInt(
                query.getOrDefault("maxresults", "5000"));
        var entries = new StringBuilder();
        var prefixes = new TreeSet<String>();
        int count = 0;
        String nextMarker = "";
        for (String name : names) {
            if (!name.startsWith(prefix) ||
                    (startFrom != null && name.compareTo(startFrom) < 0) ||
                    (marker != null && !marker.isEmpty() &&
                            name.compareTo(marker) < 0)) {
                continue;
            }
            int end = delimiter == null ? -1 :
                    name.indexOf(delimiter, prefix.length());
            String group = end < 0 ? null :
                    name.substring(0, end + delimiter.length());
            if (group != null && prefixes.contains(group)) {
                continue;
            }
            if (count == maxResults) {
                nextMarker = name;
                break;
            }
            ++count;
            if (group != null) {
                prefixes.add(group);
                entries.append("<BlobPrefix><Name>").append(group)
                        .append("</Name></BlobPrefix>");
                continue;
            }
            entries.append("<Blob><Name>").append(name).append("</Name>");
            if (versions) {
                entries.append("<VersionId>2026-01-01T00:00:00.0000000Z" +
                        "</VersionId><IsCurrentVersion>true" +
                        "</IsCurrentVersion>");
            }
            entries.append("<Properties><Last-Modified>" +
                    "Thu, 01 Jan 2026 00:00:00 GMT</Last-Modified>" +
                    "<Etag>0x1</Etag><Content-Length>0</Content-Length>" +
                    "<BlobType>BlockBlob</BlobType></Properties></Blob>");
        }
        return "<?xml version=\"1.0\" encoding=\"utf-8\"?>" +
                "<EnumerationResults ContainerName=\"container\"><Blobs>" +
                entries + "</Blobs><NextMarker>" + nextMarker +
                "</NextMarker></EnumerationResults>";
    }
}
