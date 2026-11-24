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
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.Credentials;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * What the service behind the store sends for a read that is given up on,
 * e.g., when the client of a GET has hung up.  The service here is a listener
 * that answers a read with as many bytes as the key says and reports how many
 * of them it got rid of, and over which connection.
 */
public final class AwsS3SdkAbandonedReadTest {
    private static final String CONTAINER = "container";
    private static final long LARGE = 1L << 30;

    /** One answered read: the bytes sent for it and the client's port. */
    private record Served(long sent, int port) {
    }

    private final BlockingQueue<Served> served = new LinkedBlockingQueue<>();

    private HttpServer server;
    private BlobStore store;

    @BeforeEach
    public void setUp() throws IOException {
        server = HttpServer.create(new InetSocketAddress(
                InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", this::handle);
        server.start();
        store = new AwsS3SdkBlobStore(
                () -> new Credentials("identity", "credential"),
                "http://127.0.0.1:" + server.getAddress().getPort(),
                "us-east-1",
                /*conditionalWrites=*/ "native",
                /*chunkedEncodingEnabled=*/ "true",
                /*stripETagQuotes=*/ "false");
    }

    @AfterEach
    public void tearDown() {
        store.close();
        server.stop(0);
    }

    /** The rest of a large object is not fetched for nobody. */
    @Test
    public void testAbandonedReadStopsTheTransfer() throws Exception {
        try (var blob = store.getBlob(CONTAINER, Long.toString(LARGE))) {
            assertThat(blob.readNBytes(1000)).hasSize(1000);
        }
        assertThat(served().sent()).isLessThan(LARGE);
    }

    /** Nor is all of one that nobody began to read. */
    @Test
    public void testUnreadStopsTheTransfer() throws Exception {
        store.getBlob(CONTAINER, Long.toString(LARGE)).close();
        assertThat(served().sent()).isLessThan(LARGE);
    }

    /** Giving up a read gives its connection up too, not just the body. */
    @Test
    public void testAbandonedReadsLeakNoConnection() throws Exception {
        // more than the SDK client's pool holds
        for (int i = 0; i < 64; ++i) {
            store.getBlob(CONTAINER, Long.toString(1L << 20)).close();
            served();
        }
        try (var blob = store.getBlob(CONTAINER, "2000")) {
            assertThat(blob.readAllBytes()).hasSize(2000);
        }
        assertThat(served().sent()).isEqualTo(2000);
    }

    /** A short remainder is read, which keeps the connection for reuse. */
    @Test
    public void testShortRemainderKeepsTheConnection() throws Exception {
        try (var blob = store.getBlob(CONTAINER, "2000")) {
            assertThat(blob.readNBytes(1000)).hasSize(1000);
        }
        Served first = served();
        assertThat(first.sent()).isEqualTo(2000);

        store.getBlob(CONTAINER, "2000").close();
        assertThat(served().port()).isEqualTo(first.port());
    }

    /** A read that reached its end was never given up on. */
    @Test
    public void testFinishedReadKeepsTheConnection() throws Exception {
        try (var blob = store.getBlob(CONTAINER, "2000")) {
            assertThat(blob.readAllBytes()).hasSize(2000);
        }
        Served first = served();

        store.getBlob(CONTAINER, "2000").close();
        assertThat(served().port()).isEqualTo(first.port());
    }

    private Served served() throws InterruptedException {
        Served next = served.poll(60, TimeUnit.SECONDS);
        assertThat(next).isNotNull();
        return next;
    }

    /** Answers a read of /container/N with N bytes, or as many as go out. */
    private void handle(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
        long size = Long.parseLong(path.substring(path.lastIndexOf('/') + 1));
        byte[] chunk = new byte[64 * 1024];
        long sent = 0;
        try {
            exchange.sendResponseHeaders(200, size);
            try (var out = exchange.getResponseBody()) {
                while (sent < size) {
                    int count = (int) Math.min(chunk.length, size - sent);
                    out.write(chunk, 0, count);
                    sent += count;
                }
            }
        } catch (IOException ioe) {
            // the store hung up
        } finally {
            served.add(new Served(sent, exchange.getRemoteAddress().getPort()));
        }
    }
}
