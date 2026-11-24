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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.Pattern;

import com.google.cloud.storage.StorageException;
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

/**
 * An upload's parts are objects of the bucket, and completing or aborting
 * it removes every one of them.  How many requests that takes is not
 * something the emulator the other tests run against can tell, so the
 * requests here are answered by a stand-in for objects.get, objects.list
 * and the batch endpoint.
 */
public final class GCloudMultipartCleanupTest {
    private static final String STUB = ".s3proxy/stubs/nonce";
    private static final int PARTS = 250;
    private static final Pattern DELETE_LINE = Pattern.compile(
            "^DELETE \\S*/storage/v1/b/bucket/o/(\\S+?)\\?(\\S*)",
            Pattern.MULTILINE);

    /** The objects deleted one request apiece. */
    private final List<String> singleDeletes = new CopyOnWriteArrayList<>();
    /** The objects each batch named, with their generation. */
    private final List<List<String>> batches = new CopyOnWriteArrayList<>();
    /** What the batch answers for one of the objects, if not 204. */
    private volatile String refusedName;
    private volatile int refusedStatus;

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
     * The parts go in batches of a hundred, each removed by its own
     * generation, so that a versioned bucket keeps no archived copy.  One
     * already gone is no failure.
     */
    @Test
    public void testAbortDeletesThePartsInBatches() {
        refusedName = partName(7);
        refusedStatus = 404;
        try (BlobStore blobStore = store()) {
            blobStore.abortMultipartUpload(upload());
        }

        assertThat(singleDeletes).isEmpty();
        assertThat(batches).extracting(List::size)
                .containsExactly(100, 100, PARTS + 1 - 200);
        var expected = new ArrayList<String>();
        for (int i = 0; i < PARTS; ++i) {
            expected.add(partName(i) + "@" + (1000 + i));
        }
        expected.add(STUB + "@1");
        assertThat(batches.stream().flatMap(List::stream))
                .containsExactlyInAnyOrderElementsOf(expected);
    }

    /** A part the store could not remove fails the request. */
    @Test
    public void testAbortReportsARefusedDelete() {
        refusedName = partName(150);
        refusedStatus = 403;
        try (BlobStore blobStore = store()) {
            assertThatThrownBy(() ->
                    blobStore.abortMultipartUpload(upload()))
                    .isInstanceOfSatisfying(StorageException.class,
                            e -> assertThat(e.getCode()).isEqualTo(403));
        }
    }

    private static String partName(int i) {
        return STUB + "/part-%05d".formatted(i);
    }

    private static MultipartUpload upload() {
        return new MultipartUpload(STUB, CreateMultipartUploadRequest
                .builder().bucket("bucket").key("target").build());
    }

    private BlobStore store() {
        return new GCloudBlobStore(Suppliers.ofInstance(
                new Credentials("project", /*credential=*/ "")),
                "http://127.0.0.1:" + server.getAddress().getPort());
    }

    private void handle(HttpExchange exchange) throws IOException {
        String method = exchange.getRequestMethod();
        String path = URLDecoder.decode(exchange.getRequestURI().getRawPath(),
                StandardCharsets.UTF_8);
        String query = exchange.getRequestURI().getRawQuery();
        if (method.equals("POST") && path.endsWith("/batch/storage/v1")) {
            answerBatch(exchange);
            return;
        }
        int status = 200;
        String response;
        if (method.equals("DELETE")) {
            singleDeletes.add(path);
            status = 204;
            response = "";
        } else if (path.equals("/storage/v1/b/bucket/o/" + STUB)) {
            response = object(STUB, 1).replace("}",
                    ",\"metadata\":{\"s3proxy_target_blob_name\":" +
                    "\"target\"}}");
        } else if (path.equals("/storage/v1/b/bucket/o") && query != null &&
                query.contains("versions=true")) {
            var items = new StringBuilder();
            for (int i = 0; i < PARTS; ++i) {
                items.append(object(partName(i), 1000 + i)).append(',');
            }
            items.append(object(STUB, 1));
            response = "{\"kind\":\"storage#objects\",\"items\":[" + items +
                    "]}";
        } else {
            status = 404;
            response = "{\"error\":{\"code\":404,\"message\":\"Not Found\"}}";
        }
        byte[] body = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type",
                "application/json; charset=UTF-8");
        exchange.sendResponseHeaders(status, status == 204 ? -1 :
                body.length);
        try (var out = exchange.getResponseBody()) {
            out.write(body);
        }
    }

    private static String object(String name, long generation) {
        return "{\"kind\":\"storage#object\",\"bucket\":\"bucket\"," +
                "\"name\":\"" + name + "\",\"generation\":\"" + generation +
                "\",\"size\":\"0\"}";
    }

    /** Answers each delete in a batch, in the order they were asked. */
    private void answerBatch(HttpExchange exchange) throws IOException {
        String request = new String(exchange.getRequestBody().readAllBytes(),
                StandardCharsets.UTF_8);
        var names = new ArrayList<String>();
        var statuses = new ArrayList<Integer>();
        var matcher = DELETE_LINE.matcher(request);
        while (matcher.find()) {
            String name = URLDecoder.decode(matcher.group(1),
                    StandardCharsets.UTF_8);
            var generation = Pattern.compile("generation=(\\d+)")
                    .matcher(matcher.group(2));
            names.add(name + "@" +
                    (generation.find() ? generation.group(1) : "none"));
            statuses.add(name.equals(refusedName) ? refusedStatus : 204);
        }
        batches.add(names);

        String boundary = "batch_boundary";
        var response = new StringBuilder();
        for (int i = 0; i < statuses.size(); ++i) {
            int status = statuses.get(i);
            String body = status == 204 ? "" :
                    "{\"error\":{\"code\":" + status +
                    ",\"message\":\"refused\"}}";
            response.append("--").append(boundary).append("\r\n")
                    .append("Content-Type: application/http\r\n")
                    .append("Content-ID: <response-").append(i + 1)
                    .append(">\r\n\r\n")
                    .append("HTTP/1.1 ").append(status)
                    .append(status == 204 ? " No Content" : " Error")
                    .append("\r\n")
                    .append("Content-Type: application/json\r\n")
                    .append("Content-Length: ").append(body.length())
                    .append("\r\n\r\n")
                    .append(body).append("\r\n");
        }
        response.append("--").append(boundary).append("--\r\n");
        byte[] bytes = response.toString().getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type",
                "multipart/mixed; boundary=" + boundary);
        exchange.sendResponseHeaders(200, bytes.length);
        try (var out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }
}
