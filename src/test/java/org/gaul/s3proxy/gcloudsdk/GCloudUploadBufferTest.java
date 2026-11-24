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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.management.ManagementFactory;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;

import com.google.common.base.Splitter;
import com.google.common.base.Suppliers;
import com.sun.management.ThreadMXBean;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.Credentials;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.UploadPartRequest;

/**
 * The SDK buffers the chunk of an upload twice, and the chunk is sized by
 * the Content-Length the client declares.  A client declares what it likes
 * and sends what it likes, so what is checked here is that a body costs the
 * store what has arrived of it: the emulator the other tests run against is
 * only ever sent bodies as long as they were declared to be.
 */
public final class GCloudUploadBufferTest {
    private static final ThreadMXBean THREADS =
            (ThreadMXBean) ManagementFactory.getThreadMXBean();
    private static final String UPLOAD_ID =
            ".s3proxy/stubs/11111111-2222-3333-4444-555555555555";
    private static final String PART_NAME = UPLOAD_ID + "/part_00001";
    private static final MultipartUpload UPLOAD = new MultipartUpload(
            UPLOAD_ID, CreateMultipartUploadRequest.builder()
                    .bucket("bucket").key("key").build());
    // above the 15 MiB of the largest chunk, which it is therefore given
    private static final long DECLARED_SIZE = 16_000_000;
    // the smallest chunk, which a body declared to be shorter is given
    private static final int CHUNK_SIZE = 256 * 1024;
    // Far below one buffer of the largest chunk, and far above what a
    // request to the store allocates besides.
    private static final long ALLOCATION_LIMIT = 1024 * 1024;

    private final Map<String, ByteArrayOutputStream> sessions =
            new ConcurrentHashMap<>();
    private final Map<String, byte[]> objects = new ConcurrentHashMap<>();
    /** The size of each request that carried part of an upload. */
    private final List<Integer> chunks =
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

    @Test
    public void testPutBlobBuffersNothingForALengthOnlyDeclared() {
        var body = new StalledInputStream();
        try (BlobStore blobStore = store()) {
            // loads the classes of an upload, which allocates too
            blobStore.putBlob(put(5), stream("hello"));

            long before = THREADS.getCurrentThreadAllocatedBytes();
            blobStore.putBlob(put(DECLARED_SIZE), body);

            assertThat(body.allocatedWhenStalled - before)
                    .isBetween(0L, ALLOCATION_LIMIT);
        }

        assertThat(objects.get("key")).asString(StandardCharsets.UTF_8)
                .isEqualTo("x");
    }

    @Test
    public void testUploadPartBuffersNothingForALengthOnlyDeclared() {
        var body = new StalledInputStream();
        try (BlobStore blobStore = store()) {
            blobStore.uploadMultipartPart(UPLOAD, part(5), stream("hello"));

            long before = THREADS.getCurrentThreadAllocatedBytes();
            blobStore.uploadMultipartPart(UPLOAD, part(DECLARED_SIZE), body);

            assertThat(body.allocatedWhenStalled - before)
                    .isBetween(0L, ALLOCATION_LIMIT);
        }

        assertThat(objects.get(PART_NAME)).asString(StandardCharsets.UTF_8)
                .isEqualTo("x");
    }

    @Test
    public void testPutBlobStoresABodyShorterThanItsChunk() {
        byte[] body = body(CHUNK_SIZE - 1);
        try (BlobStore blobStore = store()) {
            blobStore.putBlob(put(body.length), new ByteArrayInputStream(body));
        }

        assertThat(objects.get("key")).isEqualTo(body);
        assertThat(chunks).containsExactly(body.length);
    }

    /**
     * The chunk received ahead of the SDK is sent as the chunk it is, and
     * the rest of the body after it.  The body is declared shorter than it
     * is so that it takes several of the smallest chunk, not of the largest.
     */
    @Test
    public void testPutBlobStoresABodyOfSeveralChunks() {
        byte[] body = body(2 * CHUNK_SIZE + 5);
        try (BlobStore blobStore = store()) {
            blobStore.putBlob(put(5), new ByteArrayInputStream(body));
        }

        assertThat(objects.get("key")).isEqualTo(body);
    }

    /** The part's ETag is of the whole body, the chunk received ahead too. */
    @Test
    public void testUploadPartStoresABodyOfSeveralChunks() throws Exception {
        byte[] body = body(2 * CHUNK_SIZE + 5);
        try (BlobStore blobStore = store()) {
            var response = blobStore.uploadMultipartPart(UPLOAD, part(5),
                    new ByteArrayInputStream(body));

            assertThat(response.eTag()).isEqualTo(HexFormat.of().formatHex(
                    MessageDigest.getInstance("MD5").digest(body)));
        }

        assertThat(objects.get(PART_NAME)).isEqualTo(body);
    }

    private BlobStore store() {
        return new GCloudBlobStore(Suppliers.ofInstance(
                new Credentials("project", /*credential=*/ "")),
                "http://127.0.0.1:" + server.getAddress().getPort());
    }

    private static PutObjectRequest put(long contentLength) {
        return PutObjectRequest.builder()
                .bucket("bucket").key("key")
                .contentLength(contentLength).build();
    }

    private static UploadPartRequest part(long contentLength) {
        return UploadPartRequest.builder()
                .bucket("bucket").key("key").uploadId(UPLOAD_ID)
                .partNumber(1).contentLength(contentLength).build();
    }

    private static InputStream stream(String body) {
        return new ByteArrayInputStream(
                body.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] body(int size) {
        byte[] body = new byte[size];
        new Random(0).nextBytes(body);
        return body;
    }

    /**
     * A body that its client declared more of than it sent.  One byte
     * arrives, and the read for the next one is where a client keeps the
     * request waiting for as long as it likes: what the reading thread has
     * allocated by then is what such a request holds.  Here that read ends
     * the body instead.
     */
    private static final class StalledInputStream extends InputStream {
        private boolean arrived;
        private long allocatedWhenStalled = -1;

        @Override
        public int read() {
            byte[] b = new byte[1];
            return read(b, 0, 1) == -1 ? -1 : b[0] & 0xff;
        }

        @Override
        public int read(byte[] b, int off, int len) {
            if (len == 0) {
                return 0;
            }
            if (!arrived) {
                arrived = true;
                b[off] = 'x';
                return 1;
            }
            if (allocatedWhenStalled == -1) {
                allocatedWhenStalled =
                        THREADS.getCurrentThreadAllocatedBytes();
            }
            return -1;
        }
    }

    private void handle(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
        String query = exchange.getRequestURI().getQuery();
        byte[] request;
        try (var in = exchange.getRequestBody()) {
            request = in.readAllBytes();
        }
        int status = 200;
        String response;
        if (path.startsWith("/upload/") &&
                exchange.getRequestMethod().equals("POST")) {
            // the start of a resumable upload
            String session = Integer.toString(sessions.size());
            sessions.put(session, new ByteArrayOutputStream());
            exchange.getResponseHeaders().set("Location",
                    "http://127.0.0.1:" + server.getAddress().getPort() +
                    path + "?" + query + "&upload_id=" + session);
            response = "";
        } else if (path.startsWith("/upload/")) {
            var received = sessions.get(parameter(query, "upload_id"));
            received.write(request);
            chunks.add(request.length);
            // "bytes 0-9/*" continues an upload, and "bytes 0-9/10" states
            // its total size, which is what makes an object of it
            if (exchange.getRequestHeaders().getFirst("Content-Range")
                    .endsWith("/*")) {
                status = 308;
                exchange.getResponseHeaders().set("Range",
                        "bytes=0-" + (received.size() - 1));
                response = "";
            } else {
                String name = parameter(query, "name");
                objects.put(name, received.toByteArray());
                response = object(name, received.size());
            }
        } else if (path.endsWith("/o/" + UPLOAD_ID)) {
            response = object(UPLOAD_ID, 0);
        } else {
            response = "{\"kind\":\"storage#bucket\",\"name\":\"bucket\"}";
        }
        byte[] body = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type",
                "application/json; charset=UTF-8");
        exchange.sendResponseHeaders(status, body.length == 0 ? -1 :
                body.length);
        try (var out = exchange.getResponseBody()) {
            out.write(body);
        }
    }

    private static String parameter(String query, String name) {
        for (String parameter : Splitter.on('&').split(query)) {
            if (parameter.startsWith(name + "=")) {
                return parameter.substring(name.length() + 1);
            }
        }
        throw new IllegalArgumentException(query);
    }

    private static String object(String name, int size) {
        return """
                {"kind":"storage#object","bucket":"bucket","name":"%s",\
                "generation":"1","metageneration":"1","size":"%d",\
                "etag":"CAE=",\
                "metadata":{"s3proxy_target_blob_name":"key"},\
                "updated":"2026-01-01T00:00:00.000Z"}""".formatted(
                        name, size);
    }
}
