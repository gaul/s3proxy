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
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

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
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.UploadPartCopyRequest;

/**
 * A backend that holds its ETags unquoted is sent every ETag condition
 * unquoted.  What arrives is asked of a listener, since no emulator has the
 * fault the option is for.
 */
public final class AwsS3SdkStripETagQuotesTest {
    private static final String QUOTED = "\"0123456789abcdef\"";
    private static final String BARE = "0123456789abcdef";

    /** The last value seen of each condition header, by lowercase name. */
    private final Map<String, String> conditions = new ConcurrentHashMap<>();

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
    public void testConditionalDelete() {
        try (BlobStore blobStore = store()) {
            blobStore.removeBlob(DeleteObjectRequest.builder()
                    .bucket("bucket").key("key").ifMatch(QUOTED).build());
        }
        assertThat(conditions).containsEntry("if-match", BARE);
    }

    @Test
    public void testCopySourceConditions() {
        try (BlobStore blobStore = store()) {
            blobStore.copyBlob(CopyObjectRequest.builder()
                    .sourceBucket("bucket").sourceKey("from")
                    .destinationBucket("bucket").destinationKey("to")
                    .copySourceIfMatch(QUOTED)
                    .copySourceIfNoneMatch(QUOTED)
                    .build());
        }
        assertThat(conditions)
                .containsEntry("x-amz-copy-source-if-match", BARE)
                .containsEntry("x-amz-copy-source-if-none-match", BARE);
    }

    @Test
    public void testPartCopySourceConditions() {
        var mpu = new MultipartUpload("upload",
                CreateMultipartUploadRequest.builder()
                        .bucket("bucket").key("to").build());
        try (BlobStore blobStore = store()) {
            blobStore.copyMultipartPart(mpu, UploadPartCopyRequest.builder()
                    .sourceBucket("bucket").sourceKey("from")
                    .destinationBucket("bucket").destinationKey("to")
                    .uploadId("upload").partNumber(1)
                    .copySourceIfMatch(QUOTED)
                    .build());
        }
        assertThat(conditions)
                .containsEntry("x-amz-copy-source-if-match", BARE);
    }

    private BlobStore store() {
        return new AwsS3SdkBlobStore(Suppliers.ofInstance(
                new Credentials("identity", "credential")),
                "http://127.0.0.1:" + server.getAddress().getPort(),
                "us-east-1", /*conditionalWrites=*/ "native",
                /*chunkedEncodingEnabled=*/ "true",
                /*stripETagQuotes=*/ "true");
    }

    private void handle(HttpExchange exchange) throws IOException {
        var headers = exchange.getRequestHeaders();
        for (String name : List.of("If-Match",
                "x-amz-copy-source-if-match",
                "x-amz-copy-source-if-none-match")) {
            String value = headers.getFirst(name);
            if (value != null) {
                conditions.put(name.toLowerCase(), value);
            }
        }
        try (var in = exchange.getRequestBody()) {
            in.readAllBytes();
        }
        if (exchange.getRequestMethod().equals("DELETE")) {
            exchange.sendResponseHeaders(204, -1);
            exchange.close();
            return;
        }
        String query = exchange.getRequestURI().getQuery();
        String element = query != null && query.contains("partNumber") ?
                "CopyPartResult" : "CopyObjectResult";
        byte[] body = ("<?xml version=\"1.0\" encoding=\"UTF-8\"?><" +
                element + "><ETag>" + BARE + "</ETag><LastModified>" +
                "2026-01-01T00:00:00.000Z</LastModified></" + element + ">")
                .getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/xml");
        exchange.sendResponseHeaders(200, body.length);
        try (var out = exchange.getResponseBody()) {
            out.write(body);
        }
    }
}
