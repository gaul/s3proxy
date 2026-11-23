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
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.google.common.base.Suppliers;
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
import software.amazon.awssdk.services.s3.model.Delete;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.DeleteObjectsRequest;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.ObjectCannedACL;
import software.amazon.awssdk.services.s3.model.ObjectIdentifier;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.S3Exception;

/**
 * The store keeps a multipart upload's stub, parts and intermediate
 * composes as objects of the client's own bucket under {@code
 * .s3proxy/stubs/}, and completes the upload as the stub's metadata says:
 * target key, headers, user metadata and ACL.  Upload IDs are the stubs'
 * names and ListMultipartUploads hands them out, so a client able to write
 * one -- anyone, in a public-read-write bucket -- decided what another
 * client's upload published, a private upload made public-read included.
 * No write may name a key there, and none reaches GCS.
 */
public final class GCloudReservedKeyTest {
    private static final String STUB =
            ".s3proxy/stubs/11111111-2222-3333-4444-555555555555";
    private static final String PART = STUB + "/part_00001";
    private static final String OBJECT = """
            {"kind":"storage#object","bucket":"bucket","name":"%s",\
            "generation":"1","metageneration":"1","size":"0",\
            "etag":"CAE=","updated":"2026-01-01T00:00:00.000Z"}""";

    /** What the fake GCS was asked, as "METHOD path?query". */
    private final List<String> requests =
            Collections.synchronizedList(new ArrayList<String>());

    /** The names the fake GCS lists in the bucket. */
    private volatile List<String> listing = List.of();

    private HttpServer server;
    private BlobStore blobStore;

    @BeforeEach
    public void setUp() throws IOException {
        server = HttpServer.create(new InetSocketAddress(
                InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", this::handle);
        server.start();
        blobStore = new GCloudBlobStore(Suppliers.ofInstance(
                new Credentials("project", /*credential=*/ "")),
                "http://127.0.0.1:" + server.getAddress().getPort());
    }

    @AfterEach
    public void tearDown() throws Exception {
        blobStore.close();
        server.stop(0);
    }

    @Test
    public void testPutBlobIsRefused() {
        for (String key : List.of(STUB, PART)) {
            assertRefused(() -> blobStore.putBlob(PutObjectRequest.builder()
                    .bucket("bucket").key(key).contentLength(0L)
                    .metadata(Map.of(
                            "s3proxy_target_blob_name", "victim",
                            "s3proxy_blob_access", "PUBLIC_READ"))
                    .build(), InputStream.nullInputStream()));
        }
        assertThat(requests).isEmpty();
    }

    @Test
    public void testCopyOntoIsRefused() {
        assertRefused(() -> blobStore.copyBlob(CopyObjectRequest.builder()
                .sourceBucket("bucket").sourceKey("source")
                .destinationBucket("bucket").destinationKey(STUB)
                .build()));
        assertThat(requests).isEmpty();
    }

    @Test
    public void testRemoveBlobIsRefused() {
        for (String key : List.of(STUB, PART)) {
            assertRefused(() -> blobStore.removeBlob(
                    DeleteObjectRequest.builder()
                            .bucket("bucket").key(key).build()));
        }
        assertThat(requests).isEmpty();
    }

    /** The batch names its keys to GCS itself; the others still go. */
    @Test
    public void testRemoveBlobsIsRefused() {
        var response = blobStore.removeBlobs(DeleteObjectsRequest.builder()
                .bucket("bucket")
                .delete(Delete.builder().objects(
                        ObjectIdentifier.builder().key("key").build(),
                        ObjectIdentifier.builder().key(STUB).build())
                        .build())
                .build());

        assertThat(response.deleted()).extracting(d -> d.key())
                .containsExactly("key");
        assertThat(response.errors()).singleElement().satisfies(error -> {
            assertThat(error.key()).isEqualTo(STUB);
            assertThat(error.code()).isEqualTo("InvalidArgument");
        });
        assertThat(requests).anyMatch(r -> r.startsWith("DELETE ") &&
                r.contains("/o/key"));
        assertThat(requests).noneMatch(r -> r.contains("stubs") ||
                r.contains("batch"));
    }

    @Test
    public void testSetBlobAccessIsRefused() {
        assertRefused(() -> blobStore.setBlobAccess("bucket", PART,
                ObjectCannedACL.PUBLIC_READ));
        assertRefused(() -> blobStore.setBlobAccess("bucket", PART,
                ObjectCannedACL.PUBLIC_READ, /*versionId=*/ null));
        assertThat(requests).isEmpty();
    }

    /** The listing shows the bookkeeping, which is left where it is. */
    @Test
    public void testClearContainerLeavesTheBookkeeping() {
        listing = List.of("key", STUB, PART);

        blobStore.clearContainer(ListObjectsV2Request.builder()
                .bucket("bucket").build());

        assertThat(requests).filteredOn(r -> r.startsWith("DELETE "))
                .singleElement().satisfies(
                        r -> assertThat(r).contains("/o/key"));
    }

    /** Completing the upload would write the object under that key. */
    @Test
    public void testInitiateMultipartUploadIsRefused() {
        assertRefused(() -> blobStore.initiateMultipartUpload(
                CreateMultipartUploadRequest.builder()
                        .bucket("bucket").key(STUB).build()));
        assertThat(requests).isEmpty();
    }

    private static void assertRefused(ThrowingCallable callable) {
        assertThatThrownBy(callable)
                .isInstanceOfSatisfying(S3Exception.class, e -> {
                    assertThat(e.statusCode()).isEqualTo(400);
                    assertThat(e.awsErrorDetails().errorCode())
                            .isEqualTo("InvalidArgument");
                });
    }

    private void handle(HttpExchange exchange) throws IOException {
        try (var in = exchange.getRequestBody()) {
            in.readAllBytes();
        }
        var uri = exchange.getRequestURI();
        requests.add(exchange.getRequestMethod() + " " + uri.getRawPath() +
                (uri.getRawQuery() == null ? "" : "?" + uri.getRawQuery()));
        int status = 404;
        String response =
                "{\"error\":{\"code\":404,\"message\":\"Not Found\"}}";
        if (exchange.getRequestMethod().equals("GET") &&
                uri.getPath().endsWith("/b/bucket")) {
            // an unversioned bucket
            status = 200;
            response = "{\"kind\":\"storage#bucket\",\"name\":\"bucket\"}";
        } else if (exchange.getRequestMethod().equals("GET") &&
                uri.getPath().endsWith("/b/bucket/o")) {
            status = 200;
            response = "{\"kind\":\"storage#objects\",\"items\":[" +
                    listing.stream().map(OBJECT::formatted)
                            .collect(Collectors.joining(",")) + "]}";
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
