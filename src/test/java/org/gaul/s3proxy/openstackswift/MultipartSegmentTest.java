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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentSkipListMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.google.common.base.Suppliers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.Credentials;
import org.gaul.s3proxy.blobstore.SdkRequests;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.CompletedPart;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.Part;
import software.amazon.awssdk.services.s3.model.UploadPartRequest;

/**
 * A finished object is the segments its manifest names, so a part upload
 * that ends after the completion must not write over one of them: every
 * upload of a part has a segment of its own, and the listing and the
 * completion choose among them.  The store runs against a stand-in that
 * does of Swift what a multipart upload uses, and that, as Swift does,
 * refuses to serve an object whose segment is no longer the one its
 * manifest recorded.
 */
public final class MultipartSegmentTest {
    private static final String CONTAINER = "container";
    private static final String KEY = "object";
    private static final String ACCOUNT = "/v1/AUTH_test";
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final DateTimeFormatter LISTED = DateTimeFormatter
            .ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSSSS", Locale.ROOT)
            .withZone(ZoneOffset.UTC);

    /**
     * What the stand-in keeps of an object.  The content is its bytes as
     * ISO 8859-1, which the text this test stores reads as itself in.
     */
    private record Stored(String content, String eTag, Instant lastModified,
            boolean isManifest, Map<String, String> metadata) {
    }

    // "container/name" to the object; sorted, as a listing is
    private final Map<String, Stored> objects = new ConcurrentSkipListMap<>();
    // one second later for each object written, so that the order of two
    // writes never rests on how fast the test ran
    private final AtomicLong clock = new AtomicLong();

    private HttpServer server;
    private ExecutorService executor;
    private BlobStore blobStore;

    @BeforeEach
    public void setUp() throws IOException {
        executor = Executors.newCachedThreadPool();
        server = HttpServer.create(new InetSocketAddress(
                InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", this::handle);
        server.setExecutor(executor);
        server.start();
        String endpoint = "http://127.0.0.1:" + server.getAddress().getPort();
        blobStore = new OpenStackSwiftBlobStore(
                Suppliers.ofInstance(new Credentials("test:tester",
                        "testing")),
                endpoint + "/auth/v1.0", "test", "Default", "Default",
                /*region=*/ "");
        blobStore.createContainer(CONTAINER);
    }

    @AfterEach
    public void tearDown() {
        blobStore.close();
        server.stop(0);
        executor.shutdownNow();
    }

    /**
     * The sender of a part decides when its body ends.  One who begins it
     * while the upload is open and ends it after the completion wrote over
     * the segment the finished object's manifest names.
     */
    @Test
    public void testPartEndingAfterCompletionLeavesTheObject()
            throws Exception {
        MultipartUpload mpu = initiate();
        String approved = uploadPart(mpu, 1, "approved");

        var body = new StalledBody("other content");
        var late = executor.submit(() -> blobStore.uploadMultipartPart(mpu,
                partRequest(mpu, 1, body.length()), body));
        try {
            // reading the body, so past the check that the upload is open
            assertThat(body.awaitStalled()).isTrue();

            complete(mpu, completed(1, approved));
            assertThat(read()).isEqualTo("approved");
        } finally {
            body.release();
        }
        late.get(30, TimeUnit.SECONDS);

        assertThat(segmentsOfObject()).containsExactly("approved");
        assertThat(read()).isEqualTo("approved");
    }

    /** As in S3, a part uploaded again replaces the one before it. */
    @Test
    public void testPartUploadedAgainReplacesTheFirst() throws Exception {
        MultipartUpload mpu = initiate();
        uploadPart(mpu, 1, "first");
        String second = uploadPart(mpu, 1, "the second");
        String other = uploadPart(mpu, 2, "|other");

        List<Part> parts = blobStore.listMultipartUpload(mpu);
        assertThat(parts).extracting(Part::partNumber).containsExactly(1, 2);
        assertThat(parts).extracting(Part::eTag)
                .containsExactly(second, other);
        assertThat(parts.get(0).size()).isEqualTo("the second".length());

        complete(mpu, completed(1, second), completed(2, other));
        assertThat(read()).isEqualTo("the second|other");
    }

    /**
     * The frontend checks the ETag a completion states against the part it
     * lists, and a part uploaded again may arrive between that and the
     * completion.  The object is made of what was checked.
     */
    @Test
    public void testCompletionNamesThePartItsETagStates() throws Exception {
        MultipartUpload mpu = initiate();
        String first = uploadPart(mpu, 1, "first");
        uploadPart(mpu, 1, "the second");

        complete(mpu, completed(1, first));
        assertThat(read()).isEqualTo("first");
    }

    /**
     * An upload begun when a part's segment was named by its number alone
     * still holds such segments, and completes with them.
     */
    @Test
    public void testSegmentNamedByPartNumberAlone() throws Exception {
        MultipartUpload mpu = initiate();
        String prefix = CONTAINER + "/.s3proxy-mpu/p/" + mpu.id() + "/";
        Stored old = stored("old".getBytes(StandardCharsets.UTF_8),
                /*isManifest=*/ false, Map.of());
        objects.put(prefix + "00001", old);
        String added = uploadPart(mpu, 2, "|added");

        assertThat(blobStore.listMultipartUpload(mpu))
                .extracting(Part::partNumber).containsExactly(1, 2);
        assertThat(blobStore.listMultipartUpload(mpu))
                .extracting(Part::eTag).containsExactly(old.eTag(), added);

        complete(mpu, completed(1, old.eTag()), completed(2, added));
        assertThat(read()).isEqualTo("old|added");

        // and a part uploaded again replaces such a segment too
        MultipartUpload again = initiate();
        prefix = CONTAINER + "/.s3proxy-mpu/p/" + again.id() + "/";
        objects.put(prefix + "00001", stored(
                "old".getBytes(StandardCharsets.UTF_8),
                /*isManifest=*/ false, Map.of()));
        String replaced = uploadPart(again, 1, "replaced");
        assertThat(blobStore.listMultipartUpload(again))
                .extracting(Part::eTag).containsExactly(replaced);
        complete(again, completed(1, replaced));
        assertThat(read()).isEqualTo("replaced");
    }

    /**
     * A part's body whose last byte is not to be had until the test lets
     * go of it.
     */
    private static final class StalledBody extends InputStream {
        private final CountDownLatch stalled = new CountDownLatch(1);
        private final CountDownLatch released = new CountDownLatch(1);
        private final byte[] content;
        private int position;

        StalledBody(String content) {
            this.content = content.getBytes(StandardCharsets.UTF_8);
        }

        long length() {
            return content.length;
        }

        /** Whether all but the last byte has been read. */
        boolean awaitStalled() throws InterruptedException {
            return stalled.await(30, TimeUnit.SECONDS);
        }

        void release() {
            released.countDown();
        }

        @Override
        public int read(byte[] buffer, int offset, int length)
                throws IOException {
            // a byte at a time, so that the last is asked for by itself
            int next = length == 0 ? 0 : read();
            if (next == -1 || length == 0) {
                return next;
            }
            buffer[offset] = (byte) next;
            return 1;
        }

        @Override
        public int read() throws IOException {
            if (position == content.length) {
                return -1;
            }
            if (position == content.length - 1) {
                stalled.countDown();
                try {
                    if (!released.await(60, TimeUnit.SECONDS)) {
                        throw new IOException("never released");
                    }
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    throw new InterruptedIOException();
                }
            }
            return content[position++] & 0xFF;
        }
    }

    private MultipartUpload initiate() {
        return blobStore.initiateMultipartUpload(
                CreateMultipartUploadRequest.builder()
                        .bucket(CONTAINER).key(KEY).build());
    }

    private static UploadPartRequest partRequest(MultipartUpload mpu,
            int partNumber, long length) {
        return UploadPartRequest.builder()
                .bucket(CONTAINER).key(KEY).uploadId(mpu.id())
                .partNumber(partNumber).contentLength(length).build();
    }

    /** Uploads a part and returns its ETag. */
    private String uploadPart(MultipartUpload mpu, int partNumber,
            String content) {
        byte[] bytes = content.getBytes(StandardCharsets.UTF_8);
        return blobStore.uploadMultipartPart(mpu,
                partRequest(mpu, partNumber, bytes.length),
                new ByteArrayInputStream(bytes)).eTag();
    }

    private static CompletedPart completed(int partNumber, String eTag) {
        return CompletedPart.builder().partNumber(partNumber).eTag(eTag)
                .build();
    }

    private void complete(MultipartUpload mpu, CompletedPart... parts) {
        blobStore.completeMultipartUpload(mpu,
                SdkRequests.completeRequest(mpu, List.of(parts)));
    }

    private String read() throws IOException {
        try (var is = blobStore.getBlob(CONTAINER, KEY)) {
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    /** What the segments the object's manifest names hold now. */
    private List<String> segmentsOfObject() throws IOException {
        var segments = new ArrayList<String>();
        Stored manifest = objects.get(CONTAINER + "/" + KEY);
        assertThat(manifest.isManifest()).isTrue();
        for (var entry : MAPPER.readTree(manifest.content())) {
            segments.add(objects.get(entry.get("path").asText()).content());
        }
        return segments;
    }

    private Stored stored(byte[] content, boolean isManifest,
            Map<String, String> metadata) {
        String eTag;
        try {
            eTag = HexFormat.of().formatHex(
                    MessageDigest.getInstance("MD5").digest(content));
        } catch (NoSuchAlgorithmException nsae) {
            throw new IllegalStateException(nsae);
        }
        return new Stored(new String(content, StandardCharsets.ISO_8859_1),
                eTag, Instant.ofEpochSecond(clock.incrementAndGet()),
                isManifest, metadata);
    }

    /**
     * The content of an object: its own, or for a manifest that of its
     * segments, and null when one of them is not as the manifest has it.
     */
    @Nullable
    private String contentOf(Stored object) throws IOException {
        if (!object.isManifest()) {
            return object.content();
        }
        var content = new StringBuilder();
        for (var entry : MAPPER.readTree(object.content())) {
            Stored segment = objects.get(entry.get("path").asText());
            if (segment == null ||
                    !segment.eTag().equals(entry.get("etag").asText()) ||
                    segment.content().length() !=
                            entry.get("size_bytes").asLong()) {
                return null;
            }
            content.append(segment.content());
        }
        return content.toString();
    }

    private void handle(HttpExchange exchange) throws IOException {
        try (exchange) {
            byte[] body = exchange.getRequestBody().readAllBytes();
            String path = exchange.getRequestURI().getPath();
            if (path.equals("/auth/v1.0")) {
                exchange.getResponseHeaders().set("X-Auth-Token", "token");
                exchange.getResponseHeaders().set("X-Storage-Url",
                        "http://" + exchange.getRequestHeaders()
                                .getFirst("Host") + ACCOUNT);
                respond(exchange, 200, new byte[0]);
                return;
            }
            // "container", or "container/name"
            String name = path.substring(ACCOUNT.length() + 1);
            var query = new TreeMap<String, String>();
            for (String parameter : Splitter.on('&').split(
                    Strings.nullToEmpty(
                            exchange.getRequestURI().getQuery()))) {
                int equals = parameter.indexOf('=');
                if (equals != -1) {
                    query.put(parameter.substring(0, equals),
                            parameter.substring(equals + 1));
                }
            }
            if (name.indexOf('/') == -1) {
                handleContainer(exchange, name, query);
            } else {
                handleObject(exchange, name, query, body);
            }
        }
    }

    private void handleContainer(HttpExchange exchange, String container,
            Map<String, String> query) throws IOException {
        if (!exchange.getRequestMethod().equals("GET")) {
            respond(exchange, 201, new byte[0]);
            return;
        }
        String prefix = container + "/" + query.getOrDefault("prefix", "");
        String marker = container + "/" + query.getOrDefault("marker", "");
        var listing = new ArrayList<Map<String, Object>>();
        for (var entry : objects.entrySet()) {
            if (entry.getKey().startsWith(prefix) &&
                    entry.getKey().compareTo(marker) > 0) {
                listing.add(Map.of(
                        "name", entry.getKey().substring(
                                container.length() + 1),
                        "hash", entry.getValue().eTag(),
                        "bytes", entry.getValue().content().length(),
                        "content_type", "application/octet-stream",
                        "last_modified", LISTED.format(
                                entry.getValue().lastModified())));
            }
        }
        exchange.getResponseHeaders().set("Content-Type",
                "application/json");
        respond(exchange, 200, MAPPER.writeValueAsBytes(listing));
    }

    private void handleObject(HttpExchange exchange, String name,
            Map<String, String> query, byte[] body) throws IOException {
        String method = exchange.getRequestMethod();
        if (method.equals("PUT")) {
            boolean isManifest = "put".equals(
                    query.get("multipart-manifest"));
            var metadata = new TreeMap<String, String>();
            exchange.getRequestHeaders().forEach((header, values) -> {
                if (header.toLowerCase(Locale.ROOT).startsWith(
                        "x-object-meta-")) {
                    metadata.put(header, values.get(0));
                }
            });
            Stored object = stored(body, isManifest, metadata);
            if (contentOf(object) == null) {
                respond(exchange, 400, new byte[0]);
                return;
            }
            objects.put(name, object);
            exchange.getResponseHeaders().set("ETag", object.eTag());
            respond(exchange, 201, new byte[0]);
            return;
        }
        if (method.equals("DELETE")) {
            respond(exchange, objects.remove(name) != null ? 204 : 404,
                    new byte[0]);
            return;
        }
        Stored object = objects.get(name);
        if (object == null) {
            respond(exchange, 404, new byte[0]);
            return;
        }
        String content = "get".equals(query.get("multipart-manifest")) ?
                object.content() : contentOf(object);
        if (content == null) {
            respond(exchange, 409, new byte[0]);
            return;
        }
        var headers = exchange.getResponseHeaders();
        headers.set("ETag", object.eTag());
        headers.set("Content-Type", "application/octet-stream");
        headers.set("Last-Modified", DateTimeFormatter.RFC_1123_DATE_TIME
                .format(object.lastModified().atOffset(ZoneOffset.UTC)));
        if (object.isManifest()) {
            headers.set("X-Static-Large-Object", "True");
        }
        object.metadata().forEach(headers::set);
        respond(exchange, 200,
                content.getBytes(StandardCharsets.ISO_8859_1));
    }

    private static void respond(HttpExchange exchange, int status,
            byte[] body) throws IOException {
        if (exchange.getRequestMethod().equals("HEAD")) {
            exchange.getResponseHeaders().set("Content-Length",
                    Integer.toString(body.length));
            exchange.sendResponseHeaders(status, -1);
            return;
        }
        exchange.sendResponseHeaders(status, body.length == 0 ? -1 :
                body.length);
        try (var out = exchange.getResponseBody()) {
            out.write(body);
        }
    }
}
