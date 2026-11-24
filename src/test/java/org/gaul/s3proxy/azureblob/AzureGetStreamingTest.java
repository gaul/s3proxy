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

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import java.util.concurrent.Executors;

import com.google.common.base.Splitter;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.Credentials;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.StorageClass;

/**
 * A GET is one Get Blob, its body streamed: it used to be read in 4 MiB
 * blocks, a request for each, and with a Get Blob Properties besides for
 * the access tier, which Get Blob reports but the SDK's model of its
 * headers leaves out.  Answered by a stand-in for Get Blob and Get Blob
 * Properties that counts what it is asked.
 */
public final class AzureGetStreamingTest {
    /** Five of the 4 MiB blocks the store used to read. */
    private static final byte[] CONTENT = new byte[20 * 1024 * 1024];

    static {
        new Random(42).nextBytes(CONTENT);
    }

    private final List<String> requests =
            Collections.synchronizedList(new ArrayList<String>());
    /** The tier Get Blob reports, or none from a server that omits it. */
    private volatile @Nullable String tier = "Cool";

    private HttpServer server;

    @BeforeEach
    public void setUp() throws IOException {
        server = HttpServer.create(new InetSocketAddress(
                InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", this::handle);
        // a request at a time would hold the lookup of the tier behind the
        // body of the download it is made while
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
    }

    @AfterEach
    public void tearDown() {
        server.stop(0);
    }

    @Test
    public void testGetIsOneRequest() throws Exception {
        try (BlobStore blobStore = store();
             var stream = blobStore.getBlob(GetObjectRequest.builder()
                     .bucket("container").key("blob").build())) {
            assertThat(stream.response().contentLength())
                    .isEqualTo(CONTENT.length);
            assertThat(stream.response().storageClass())
                    .isEqualTo(StorageClass.STANDARD_IA);
            assertThat(stream.readAllBytes()).isEqualTo(CONTENT);
        }
        assertThat(requests).containsExactly("GET");
    }

    @Test
    public void testRangeIsOneRequest() throws Exception {
        try (BlobStore blobStore = store();
             var stream = blobStore.getBlob(GetObjectRequest.builder()
                     .bucket("container").key("blob")
                     .range("bytes=10-5000009").build())) {
            assertThat(stream.response().contentLength())
                    .isEqualTo(5_000_000L);
            assertThat(stream.response().contentRange())
                    .isEqualTo("bytes 10-5000009/" + CONTENT.length);
            assertThat(stream.readAllBytes()).isEqualTo(
                    Arrays.copyOfRange(CONTENT, 10, 5_000_010));
        }
        assertThat(requests).containsExactly("GET");
    }

    /** Where Get Blob sends no tier, it is asked for after all. */
    @Test
    public void testTierAskedForOnlyWhereMissing() throws Exception {
        tier = null;
        try (BlobStore blobStore = store();
             var stream = blobStore.getBlob(GetObjectRequest.builder()
                     .bucket("container").key("blob").build())) {
            assertThat(stream.response().storageClass())
                    .isEqualTo(StorageClass.STANDARD_IA);
            stream.readAllBytes();
        }
        assertThat(requests).containsExactly("GET", "HEAD");
    }

    private BlobStore store() {
        return new AzureBlobStore(
                () -> new Credentials("", "", "sv=2026-02-06&sig=fake"),
                "http://127.0.0.1:" + server.getAddress().getPort() +
                        "/account",
                /*eTagMode=*/ "opaque", /*auth=*/ null,
                /*versioning=*/ false);
    }

    private void handle(HttpExchange exchange) throws IOException {
        String method = exchange.getRequestMethod();
        requests.add(method);
        exchange.getRequestBody().readAllBytes();
        var headers = exchange.getResponseHeaders();
        headers.set("x-ms-version", "2026-02-06");
        headers.set("x-ms-blob-type", "BlockBlob");
        headers.set("ETag", "\"0x1\"");
        headers.set("Last-Modified", "Thu, 01 Jan 2026 00:00:00 GMT");
        headers.set("Content-Type", "application/octet-stream");
        if (method.equals("HEAD")) {
            // Get Blob Properties always reports the tier
            headers.set("x-ms-access-tier", "Cool");
            headers.set("Content-Length", Integer.toString(CONTENT.length));
            exchange.sendResponseHeaders(200, -1);
            exchange.close();
            return;
        }
        if (tier != null) {
            headers.set("x-ms-access-tier", tier);
        }
        int first = 0;
        int last = CONTENT.length - 1;
        int status = 200;
        String range = exchange.getRequestHeaders().getFirst("x-ms-range");
        if (range != null) {
            var bounds = Splitter.on('-').splitToList(
                    range.substring("bytes=".length()));
            first = Integer.parseInt(bounds.get(0));
            if (bounds.size() > 1 && !bounds.get(1).isEmpty()) {
                last = Math.min(last, Integer.parseInt(bounds.get(1)));
            }
            status = 206;
            headers.set("Content-Range", "bytes " + first + "-" + last +
                    "/" + CONTENT.length);
        }
        int length = last - first + 1;
        exchange.sendResponseHeaders(status, length);
        try (var out = exchange.getResponseBody()) {
            out.write(CONTENT, first, length);
        }
    }
}
