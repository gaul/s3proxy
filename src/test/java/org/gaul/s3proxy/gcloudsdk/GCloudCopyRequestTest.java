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
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPInputStream;

import com.google.common.base.Suppliers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.Credentials;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.CopyObjectRequest;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.MetadataDirective;
import software.amazon.awssdk.services.s3.model.UploadPartCopyRequest;

/**
 * GCS copies an object's metadata from the source only when the rewrite
 * request describes no target; any description at all, even one of nothing
 * but a name, stands as the whole of the copy's metadata.  The emulator the
 * other tests run against merges the two instead, so what is sent is
 * checked here.
 */
public final class GCloudCopyRequestTest {
    private static final String OBJECT = """
            {"kind":"storage#object","bucket":"bucket","name":"%s",\
            "generation":"1","metageneration":"1","size":"1",\
            "etag":"CAE=","md5Hash":"xvmCfRHTDFg+uRtCA6yhcQ==",\
            "contentType":"text/plain","metadata":{"color":"red"},\
            "updated":"2026-01-01T00:00:00.000Z"}""";

    private final List<String> rewrites =
            Collections.synchronizedList(new ArrayList<String>());

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

    /** A plain copy describes no target, leaving it the source's. */
    @Test
    public void testCopyLeavesTheMetadataToTheSource() {
        try (BlobStore blobStore = store()) {
            blobStore.copyBlob(CopyObjectRequest.builder()
                    .sourceBucket("bucket").sourceKey("from")
                    .destinationBucket("bucket").destinationKey("to")
                    .build());
        }

        assertThat(rewrites).containsExactly("");
    }

    /** A replacing copy describes the target in full. */
    @Test
    public void testReplaceDescribesTheTarget() {
        try (BlobStore blobStore = store()) {
            blobStore.copyBlob(CopyObjectRequest.builder()
                    .sourceBucket("bucket").sourceKey("from")
                    .destinationBucket("bucket").destinationKey("to")
                    .metadataDirective(MetadataDirective.REPLACE)
                    .contentType("image/png")
                    .metadata(Map.of("color", "blue"))
                    .build());
        }

        assertThat(rewrites).hasSize(1);
        assertThat(rewrites.get(0)).contains("image/png").contains("blue");
    }

    /**
     * A composite object has no MD5 to give a part copied from it an ETag,
     * so the store declines the server-side copy and the caller streams it.
     */
    @Test
    public void testPartCopyFromACompositeSourceIsNotServerSide() {
        var mpu = new MultipartUpload("upload",
                CreateMultipartUploadRequest.builder()
                        .bucket("bucket").key("to").build());
        try (BlobStore blobStore = store()) {
            assertThatThrownBy(() -> blobStore.copyMultipartPart(mpu,
                    UploadPartCopyRequest.builder()
                            .sourceBucket("bucket").sourceKey("composite")
                            .destinationBucket("bucket").destinationKey("to")
                            .uploadId("upload").partNumber(1).build()))
                    .isInstanceOf(UnsupportedOperationException.class);
        }

        assertThat(rewrites).isEmpty();
    }

    private BlobStore store() {
        return new GCloudBlobStore(Suppliers.ofInstance(
                new Credentials("project", /*credential=*/ "")),
                "http://127.0.0.1:" + server.getAddress().getPort());
    }

    private void handle(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
        String request;
        boolean gzip = "gzip".equals(exchange.getRequestHeaders().getFirst(
                "Content-Encoding"));
        try (var raw = exchange.getRequestBody();
             var in = gzip ? new GZIPInputStream(raw) : raw) {
            request = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
        String response;
        if (path.contains("/rewriteTo/")) {
            rewrites.add(request);
            response = "{\"kind\":\"storage#rewriteResponse\"," +
                    "\"done\":true,\"totalBytesRewritten\":\"1\"," +
                    "\"objectSize\":\"1\",\"resource\":" +
                    OBJECT.formatted("to") + "}";
        } else if (path.contains("/o/composite")) {
            // as GCS reports one: a component count and no md5Hash
            response = OBJECT.formatted("composite").replace(
                    "\"md5Hash\":\"xvmCfRHTDFg+uRtCA6yhcQ==\",",
                    "\"componentCount\":2,");
        } else if (path.contains("/o/")) {
            response = OBJECT.formatted("from");
        } else {
            response = "{\"kind\":\"storage#bucket\",\"name\":\"bucket\"}";
        }
        byte[] body = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type",
                "application/json; charset=UTF-8");
        exchange.sendResponseHeaders(200, body.length);
        try (var out = exchange.getResponseBody()) {
            out.write(body);
        }
    }
}
