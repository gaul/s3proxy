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
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;

import com.google.cloud.storage.StorageException;
import com.google.common.base.Suppliers;
import com.google.common.base.Throwables;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.Credentials;
import org.gaul.s3proxy.blobstore.UploadNames;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.services.s3.model.UploadPartRequest;

/**
 * GCS takes the bytes of a resumable upload from whoever names its session
 * URI, without a credential, and a refusal that asks to be retried -- the 429
 * for a second write of one object within a second, or a 5xx -- leaves the
 * session open.  The SDK's account of a refused request quotes that URI, and
 * an error the store does not translate reaches the log at the default
 * level, so what is checked here is that nothing a refused upload throws
 * names the session.  The emulator the other tests run against refuses no
 * upload.
 */
public final class GCloudRefusedUploadTest {
    private static final String UPLOAD_ID =
            UploadNames.newUploadId("key");
    private static final String STUB =
            GCloudBlobStore.stubName("key", UPLOAD_ID);
    // more than the 256 KiB chunk a small Content-Length is given, so that
    // the refused request is not the one that states the total size
    private static final int SEVERAL_CHUNKS = 600 * 1024;

    private final AtomicInteger sessions = new AtomicInteger();
    /** The status that answers a request to a session. */
    private volatile int refusal;

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

    /** An error that is not translated keeps its status and no more. */
    @Test
    public void testPutBlobRefusalDoesNotNameTheSession() {
        refusal = 429;
        try (BlobStore blobStore = store()) {
            assertThatThrownBy(() -> blobStore.putBlob(put(), stream("hello")))
                    // GCS's 429 is S3's SlowDown
                    .isInstanceOfSatisfying(S3Exception.class,
                            s3e -> assertThat(s3e.statusCode()).isEqualTo(503))
                    .satisfies(GCloudRefusedUploadTest::assertNamesNoSession);
        }

        assertThat(sessions).hasValue(1);
    }

    /**
     * A request before the last one is refused from the channel's write,
     * which wraps the SDK's exception in an IOException.
     */
    @Test
    public void testPutBlobRefusedChunkDoesNotNameTheSession() {
        refusal = 503;
        try (BlobStore blobStore = store()) {
            assertThatThrownBy(() -> blobStore.putBlob(put(),
                    new ByteArrayInputStream(new byte[SEVERAL_CHUNKS])))
                    .hasRootCauseInstanceOf(StorageException.class)
                    .satisfies(GCloudRefusedUploadTest::assertNamesNoSession)
                    .rootCause().hasMessageContaining("503");
        }

        assertThat(sessions).hasValue(1);
    }

    /** A translated refusal keeps the SDK's exception as its cause. */
    @Test
    public void testPutBlobTranslatedRefusalDoesNotNameTheSession() {
        refusal = 412;
        try (BlobStore blobStore = store()) {
            assertThatThrownBy(() -> blobStore.putBlob(put(), stream("hello")))
                    .isInstanceOfSatisfying(S3Exception.class,
                            s3e -> assertThat(s3e.statusCode()).isEqualTo(412))
                    .satisfies(GCloudRefusedUploadTest::assertNamesNoSession);
        }

        assertThat(sessions).hasValue(1);
    }

    @Test
    public void testUploadPartRefusalDoesNotNameTheSession() {
        var mpu = new MultipartUpload(UPLOAD_ID,
                CreateMultipartUploadRequest.builder()
                        .bucket("bucket").key("key").build());
        var request = UploadPartRequest.builder()
                .bucket("bucket").key("key").uploadId(UPLOAD_ID)
                .partNumber(1).contentLength(5L).build();
        refusal = 429;
        try (BlobStore blobStore = store()) {
            assertThatThrownBy(() -> blobStore.uploadMultipartPart(
                    mpu, request, stream("hello")))
                    // GCS's 429 is S3's SlowDown
                    .isInstanceOfSatisfying(S3Exception.class,
                            s3e -> assertThat(s3e.statusCode()).isEqualTo(503))
                    .satisfies(GCloudRefusedUploadTest::assertNamesNoSession);
            assertThatThrownBy(() -> blobStore.uploadMultipartPart(
                    mpu, request,
                    new ByteArrayInputStream(new byte[SEVERAL_CHUNKS])))
                    .hasRootCauseInstanceOf(StorageException.class)
                    .satisfies(GCloudRefusedUploadTest::assertNamesNoSession);
        }

        assertThat(sessions).hasValue(2);
    }

    /** Nothing an error is logged with: messages, causes and suppressed. */
    private static void assertNamesNoSession(Throwable thrown) {
        assertThat(Throwables.getStackTraceAsString(thrown))
                .doesNotContain("upload_id");
    }

    private BlobStore store() {
        return new GCloudBlobStore(Suppliers.ofInstance(
                new Credentials("project", /*credential=*/ "")),
                "http://127.0.0.1:" + server.getAddress().getPort());
    }

    private static PutObjectRequest put() {
        return PutObjectRequest.builder()
                .bucket("bucket").key("key").contentLength(5L).build();
    }

    private static InputStream stream(String body) {
        return new ByteArrayInputStream(
                body.getBytes(StandardCharsets.UTF_8));
    }

    private void handle(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
        String query = exchange.getRequestURI().getQuery();
        try (var in = exchange.getRequestBody()) {
            in.readAllBytes();
        }
        int status = 200;
        String response = "";
        if (path.startsWith("/upload/") &&
                exchange.getRequestMethod().equals("POST")) {
            // the start of a resumable upload
            exchange.getResponseHeaders().set("Location",
                    "http://127.0.0.1:" + server.getAddress().getPort() +
                    path + "?" + query + "&upload_id=" +
                    sessions.incrementAndGet());
        } else if (path.startsWith("/upload/")) {
            status = refusal;
            response = "{\"error\":{\"code\":%d,\"message\":\"Refused\"}}"
                    .formatted(refusal);
        } else if (path.endsWith("/o/" + STUB)) {
            // the stub that stands for a multipart upload in progress
            response = """
                    {"kind":"storage#object","bucket":"bucket","name":"%s",\
                    "generation":"1","metageneration":"1","size":"0",\
                    "etag":"CAE=",\
                    "metadata":{"s3proxy_target_blob_name":"key"},\
                    "updated":"2026-01-01T00:00:00.000Z"}""".formatted(
                            STUB);
        } else {
            status = 404;
            response = "{\"error\":{\"code\":404,\"message\":\"Not Found\"}}";
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
}
