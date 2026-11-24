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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.SequenceInputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import com.google.common.base.Suppliers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.Credentials;
import org.gaul.s3proxy.blobstore.UploadNames;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.services.s3.model.UploadPartRequest;

/**
 * The frontend refuses a body by failing the read that shows it to be wrong:
 * a digest that does not match what was signed, a chunk signature, a client
 * that went away.  GCS makes an object of a resumable upload when it is sent
 * the chunk that states the total size, so a payload that fails must never
 * be followed by that chunk.  The emulator the other tests run against is
 * only ever sent payloads that can be read, so what a failed one leaves
 * behind is checked here.
 */
public final class GCloudRefusedPayloadTest {
    private static final String UPLOAD_ID =
            UploadNames.newUploadId("key");
    private static final String STUB =
            GCloudBlobStore.stubName("key", UPLOAD_ID);
    private static final String PART = GCloudBlobStore.partName(UPLOAD_ID, 1);
    private static final String OBJECT = """
            {"kind":"storage#object","bucket":"bucket","name":"%s",\
            "generation":"1","metageneration":"1","size":"%d",\
            "etag":"CAE=","md5Hash":"xvmCfRHTDFg+uRtCA6yhcQ==",\
            "metadata":{"s3proxy_target_blob_name":"key"},\
            "updated":"2026-01-01T00:00:00.000Z"}""";
    /** The md5Hash above in hex, which the store reports as the ETag. */
    private static final String ETAG = "c6f9827d11d30c583eb91b4203aca171";
    // More than is read ahead of a payload that declares a few bytes, so
    // that the rest of it is streamed.
    private static final int LONG = 600 * 1024;
    // A length to declare, whatever is sent: too much to be read ahead.
    private static final long LARGE = 8L * 1024 * 1024;

    /** The name and the bytes received of each resumable upload. */
    private final Map<String, Map.Entry<String, ByteArrayOutputStream>>
            sessions = new ConcurrentHashMap<>();
    private final Map<String, byte[]> objects = new ConcurrentHashMap<>();
    /** The status GCS answers the chunk that states the total size with. */
    private volatile int commitStatus = 200;

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
    public void testPutStoresAPayloadReadToItsEnd() {
        try (BlobStore blobStore = store()) {
            var response = blobStore.putBlob(put(9L), payload("version 1"));

            assertThat(response.eTag()).isEqualTo(ETAG);
        }

        assertThat(objects.get("key")).isEqualTo(bytes("version 1"));
    }

    @Test
    public void testPutStoresAnEmptyPayload() {
        try (BlobStore blobStore = store()) {
            blobStore.putBlob(put(0L), payload(""));
        }

        assertThat(objects.get("key")).isEmpty();
    }

    @Test
    public void testPutKeepsTheObjectWhenThePayloadIsRefused() {
        try (BlobStore blobStore = store()) {
            blobStore.putBlob(put(9L), payload("version 1"));

            assertThatThrownBy(() -> blobStore.putBlob(put(7L),
                    refused(bytes("forged"))))
                    .hasRootCauseMessage("refused");
        }

        assertThat(objects.get("key")).isEqualTo(bytes("version 1"));
    }

    @Test
    public void testPutStoresNothingWhenTheFirstReadIsRefused() {
        try (BlobStore blobStore = store()) {
            assertThatThrownBy(() -> blobStore.putBlob(put(7L),
                    refused(new byte[0])))
                    .hasRootCauseMessage("refused");
        }

        assertThat(objects).isEmpty();
    }

    /** A payload may go on past the length its request declared. */
    @Test
    public void testPutStoresAPayloadLongerThanDeclared() {
        try (BlobStore blobStore = store()) {
            blobStore.putBlob(put(9L), new ByteArrayInputStream(
                    new byte[LONG]));
        }

        assertThat(objects.get("key")).isEqualTo(new byte[LONG]);
    }

    @Test
    public void testPutKeepsTheObjectWhenALongerPayloadIsRefused() {
        try (BlobStore blobStore = store()) {
            blobStore.putBlob(put(9L), payload("version 1"));

            assertThatThrownBy(() -> blobStore.putBlob(put(9L),
                    refused(new byte[LONG])))
                    .hasRootCauseMessage("refused");
        }

        assertThat(objects.get("key")).isEqualTo(bytes("version 1"));
    }

    @Test
    public void testPutStoresALargePayload() {
        try (BlobStore blobStore = store()) {
            var response = blobStore.putBlob(put(LARGE),
                    payload("version 1"));

            assertThat(response.eTag()).isEqualTo(ETAG);
        }

        assertThat(objects.get("key")).isEqualTo(bytes("version 1"));
    }

    @Test
    public void testPutKeepsTheObjectWhenALargePayloadIsRefused() {
        try (BlobStore blobStore = store()) {
            blobStore.putBlob(put(9L), payload("version 1"));

            assertThatThrownBy(() -> blobStore.putBlob(put(LARGE),
                    refused(bytes("forged"))))
                    .hasRootCauseMessage("refused");
        }

        assertThat(objects.get("key")).isEqualTo(bytes("version 1"));
    }

    @Test
    public void testPutKeepsTheObjectWhenAPayloadOfNoLengthIsRefused() {
        try (BlobStore blobStore = store()) {
            blobStore.putBlob(put(/*contentLength=*/ null),
                    payload("version 1"));

            assertThatThrownBy(() -> blobStore.putBlob(
                    put(/*contentLength=*/ null), refused(bytes("forged"))))
                    .hasRootCauseMessage("refused");
        }

        assertThat(objects.get("key")).isEqualTo(bytes("version 1"));
    }

    /** What GCS refuses is still answered as what S3 calls it. */
    @Test
    public void testPutReportsAPreconditionGcsRefuses() {
        commitStatus = 412;
        try (BlobStore blobStore = store()) {
            for (Long contentLength : new Long[] {9L, LARGE}) {
                assertThatThrownBy(() -> blobStore.putBlob(
                        put(contentLength), payload("version 1")))
                        .isInstanceOfSatisfying(S3Exception.class, e ->
                                assertThat(e.statusCode()).isEqualTo(412));
            }
        }

        assertThat(objects).isEmpty();
    }

    @Test
    public void testPartKeepsThePartWhenThePayloadIsRefused() {
        try (BlobStore blobStore = store()) {
            blobStore.uploadMultipartPart(upload(), part(9L),
                    payload("version 1"));
            assertThat(objects.get(PART)).isEqualTo(bytes("version 1"));

            for (long contentLength : new long[] {7L, LARGE}) {
                assertThatThrownBy(() -> blobStore.uploadMultipartPart(
                        upload(), part(contentLength),
                        refused(bytes("forged"))))
                        .hasRootCauseMessage("refused");
            }
        }

        assertThat(objects.get(PART)).isEqualTo(bytes("version 1"));
    }

    @Test
    public void testPartStoresALargePayload() {
        try (BlobStore blobStore = store()) {
            blobStore.uploadMultipartPart(upload(), part(LARGE),
                    payload("version 1"));
        }

        assertThat(objects.get(PART)).isEqualTo(bytes("version 1"));
    }

    /** Yields a body, then fails as a validating stream does. */
    private static InputStream refused(byte[] body) {
        return new SequenceInputStream(new ByteArrayInputStream(body),
                new InputStream() {
                    @Override
                    public int read() throws IOException {
                        throw new IOException("refused");
                    }

                    @Override
                    public int read(byte[] b, int off, int len)
                            throws IOException {
                        throw new IOException("refused");
                    }
                });
    }

    private static InputStream payload(String body) {
        return new ByteArrayInputStream(bytes(body));
    }

    private static byte[] bytes(String string) {
        return string.getBytes(StandardCharsets.UTF_8);
    }

    private static PutObjectRequest put(@Nullable Long contentLength) {
        return PutObjectRequest.builder().bucket("bucket").key("key")
                .contentLength(contentLength).build();
    }

    private static MultipartUpload upload() {
        return new MultipartUpload(UPLOAD_ID,
                CreateMultipartUploadRequest.builder().bucket("bucket")
                        .key("key").build());
    }

    private static UploadPartRequest part(long contentLength) {
        return UploadPartRequest.builder().bucket("bucket").key("key")
                .uploadId(UPLOAD_ID).partNumber(1)
                .contentLength(contentLength).build();
    }

    private BlobStore store() {
        return new GCloudBlobStore(Suppliers.ofInstance(
                new Credentials("project", /*credential=*/ "")),
                "http://127.0.0.1:" + server.getAddress().getPort());
    }

    private void handle(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
        byte[] request;
        try (var in = exchange.getRequestBody()) {
            request = in.readAllBytes();
        }
        if (path.startsWith("/upload/")) {
            // Opens a resumable session, whose chunks are PUT to Location.
            String query = exchange.getRequestURI().getQuery();
            String name = query.substring(query.indexOf("name=") + 5)
                    .replaceFirst("&.*", "");
            String session = "/session/" + sessions.size();
            sessions.put(session, Map.entry(name,
                    new ByteArrayOutputStream()));
            exchange.getResponseHeaders().set("Location", "http://127.0.0.1:" +
                    server.getAddress().getPort() + session);
            exchange.sendResponseHeaders(200, -1);
            exchange.close();
            return;
        }
        int status = 200;
        String response;
        if (path.startsWith("/session/")) {
            String name = sessions.get(path).getKey();
            var received = sessions.get(path).getValue();
            received.write(request);
            if (exchange.getRequestHeaders().getFirst("Content-Range")
                    .endsWith("/*")) {
                // Not the last chunk: acknowledges what has arrived.
                exchange.getResponseHeaders().set("Range",
                        "bytes=0-" + (received.size() - 1));
                exchange.sendResponseHeaders(308, -1);
                exchange.close();
                return;
            }
            status = commitStatus;
            if (status == 200) {
                objects.put(name, received.toByteArray());
            }
            response = OBJECT.formatted(name, received.size());
        } else if (path.contains("/o/")) {
            response = OBJECT.formatted(STUB, 0);
        } else {
            response = "{\"kind\":\"storage#bucket\",\"name\":\"bucket\"}";
        }
        byte[] body = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type",
                "application/json; charset=UTF-8");
        exchange.sendResponseHeaders(status, body.length);
        try (var out = exchange.getResponseBody()) {
            out.write(body);
        }
    }
}
