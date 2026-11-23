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
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.google.common.base.Suppliers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.Credentials;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.CompletedMultipartUpload;
import software.amazon.awssdk.services.s3.model.CompletedPart;
import software.amazon.awssdk.services.s3.model.CopyObjectRequest;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.ObjectCannedACL;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.UploadPartRequest;

/**
 * GCS gives an object written without an ACL its bucket's default object
 * ACL, which may grant allUsers, where S3 gives it a private one.  The
 * emulator the other tests run against has no default object ACLs, so what
 * is checked here is that every write names the ACL it means -- other than
 * to a bucket with uniform bucket-level access, which refuses any.
 */
public final class GCloudObjectAclTest {
    private static final String UPLOAD_ID =
            ".s3proxy/stubs/11111111-2222-3333-4444-555555555555";

    private final List<String> requests =
            Collections.synchronizedList(new ArrayList<String>());
    private boolean uniformAccess;
    private boolean aclRemovalFails;

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
    public void testPutBlobNamesAPrivateAcl() {
        try (BlobStore blobStore = store()) {
            blobStore.putBlob(put().build(), body());
        }

        assertThat(sent("POST /upload/")).hasSize(1).allMatch(
                r -> r.contains("predefinedAcl=projectPrivate"));
    }

    @Test
    public void testPutBlobNamesThePublicAcl() {
        try (BlobStore blobStore = store()) {
            blobStore.putBlob(put().acl(ObjectCannedACL.PUBLIC_READ).build(),
                    body());
        }

        assertThat(sent("POST /upload/")).hasSize(1).allMatch(
                r -> r.contains("predefinedAcl=publicRead"));
    }

    @Test
    public void testPutBlobNamesNoAclUnderUniformAccess() {
        uniformAccess = true;
        try (BlobStore blobStore = store()) {
            blobStore.putBlob(put().build(), body());
        }

        assertThat(sent("POST /upload/")).hasSize(1).noneMatch(
                r -> r.contains("predefinedAcl"));
    }

    @Test
    public void testCopyBlobNamesAPrivateAcl() {
        try (BlobStore blobStore = store()) {
            blobStore.copyBlob(copy());
        }

        assertThat(sent("POST /storage/v1/b/bucket/o/from/rewriteTo/"))
                .hasSize(1).allMatch(r -> r.contains(
                        "destinationPredefinedAcl=projectPrivate"));
    }

    @Test
    public void testCopyBlobNamesNoAclUnderUniformAccess() {
        uniformAccess = true;
        try (BlobStore blobStore = store()) {
            blobStore.copyBlob(copy());
        }

        assertThat(sent("POST /storage/v1/b/bucket/o/from/rewriteTo/"))
                .hasSize(1).noneMatch(r -> r.contains("PredefinedAcl"));
    }

    /** A single part is copied onto the key. */
    @Test
    public void testCompletionOfOnePartNamesAPrivateAcl() {
        try (BlobStore blobStore = store()) {
            complete(blobStore, 1);
        }

        assertThat(sent("POST /storage/v1/b/bucket/o/" + UPLOAD_ID +
                "/part_00001/rewriteTo/")).hasSize(1).allMatch(r -> r.contains(
                        "destinationPredefinedAcl=projectPrivate"));
    }

    /**
     * Several are composed, which cannot name an ACL, so the grant a
     * default object ACL may have made is taken away afterwards.
     */
    @Test
    public void testCompletionOfSeveralPartsRemovesThePublicGrant() {
        try (BlobStore blobStore = store()) {
            complete(blobStore, 2);
        }

        assertThat(sent("POST /storage/v1/b/bucket/o/key/compose"))
                .hasSize(1);
        assertThat(sent("DELETE /storage/v1/b/bucket/o/key/acl/allUsers"))
                .hasSize(1);
    }

    @Test
    public void testCompletionOfSeveralPartsAsksForNoAclUnderUniformAccess() {
        uniformAccess = true;
        try (BlobStore blobStore = store()) {
            complete(blobStore, 2);
        }

        assertThat(sent("POST /storage/v1/b/bucket/o/key/compose"))
                .hasSize(1);
        assertThat(requests).noneMatch(r -> r.contains("/acl"));
    }

    /**
     * An upload's stub and parts are the store's own objects, but they hold
     * the upload's metadata and content, so the bucket's default ACL must
     * not make them public either.
     */
    @Test
    public void testUploadBookkeepingNamesAPrivateAcl() {
        try (BlobStore blobStore = store()) {
            blobStore.initiateMultipartUpload(CreateMultipartUploadRequest
                    .builder().bucket("bucket").key("key").build());
            blobStore.uploadMultipartPart(mpu(), UploadPartRequest.builder()
                    .bucket("bucket").key("key").uploadId(UPLOAD_ID)
                    .partNumber(1).contentLength(5L).build(), body());
        }

        assertThat(sent("POST /upload/")).hasSize(2).allMatch(
                r -> r.contains("predefinedAcl=projectPrivate"));
    }

    /**
     * Where the public grant cannot be taken off a composed object, the
     * object goes rather than stay public; the parts stay to complete again.
     */
    @Test
    public void testCompletionRemovesAnObjectItCannotMakePrivate() {
        aclRemovalFails = true;
        try (BlobStore blobStore = store()) {
            assertThatThrownBy(() -> complete(blobStore, 2))
                    .isInstanceOf(RuntimeException.class);
        }

        assertThat(sent("DELETE /storage/v1/b/bucket/o/key?")).hasSize(1);
        assertThat(sent("DELETE /storage/v1/b/bucket/o/" + UPLOAD_ID))
                .isEmpty();
    }

    private List<String> sent(String prefix) {
        return requests.stream().filter(r -> r.startsWith(prefix)).toList();
    }

    private static PutObjectRequest.Builder put() {
        return PutObjectRequest.builder()
                .bucket("bucket").key("key").contentLength(5L);
    }

    private static ByteArrayInputStream body() {
        return new ByteArrayInputStream(
                "hello".getBytes(StandardCharsets.UTF_8));
    }

    private static CopyObjectRequest copy() {
        return CopyObjectRequest.builder()
                .sourceBucket("bucket").sourceKey("from")
                .destinationBucket("bucket").destinationKey("key")
                .build();
    }

    private static MultipartUpload mpu() {
        return new MultipartUpload(UPLOAD_ID,
                CreateMultipartUploadRequest.builder()
                        .bucket("bucket").key("key").build());
    }

    private static void complete(BlobStore blobStore, int partCount) {
        var mpu = mpu();
        var parts = new ArrayList<CompletedPart>();
        for (int i = 1; i <= partCount; ++i) {
            parts.add(CompletedPart.builder().partNumber(i).build());
        }
        blobStore.completeMultipartUpload(mpu,
                CompleteMultipartUploadRequest.builder()
                        .bucket("bucket").key("key").uploadId(UPLOAD_ID)
                        .multipartUpload(CompletedMultipartUpload.builder()
                                .parts(parts).build())
                        .build());
    }

    private BlobStore store() {
        return new GCloudBlobStore(Suppliers.ofInstance(
                new Credentials("project", /*credential=*/ "")),
                "http://127.0.0.1:" + server.getAddress().getPort());
    }

    private void handle(HttpExchange exchange) throws IOException {
        String method = exchange.getRequestMethod();
        String path = exchange.getRequestURI().getPath();
        String query = exchange.getRequestURI().getQuery();
        requests.add(method + " " + path + "?" + query);
        try (var in = exchange.getRequestBody()) {
            in.readAllBytes();
        }
        int status = 200;
        String response = "";
        if (path.startsWith("/upload/") && method.equals("POST") &&
                query.contains("uploadType=multipart")) {
            // a small object sent whole, as a stub is
            response = object(UPLOAD_ID);
        } else if (path.startsWith("/upload/") && method.equals("POST")) {
            // the start of a resumable upload, whose session is its URL
            exchange.getResponseHeaders().set("Location",
                    "http://127.0.0.1:" + server.getAddress().getPort() +
                    path + "?" + query + "&upload_id=1");
        } else if (path.startsWith("/upload/")) {
            response = object("key");
        } else if (path.equals("/storage/v1/b/bucket")) {
            response = "{\"kind\":\"storage#bucket\",\"name\":\"bucket\"," +
                    "\"iamConfiguration\":{\"uniformBucketLevelAccess\":" +
                    "{\"enabled\":" + uniformAccess + "}}}";
        } else if (path.equals("/storage/v1/b/bucket/o")) {
            // the upload's bookkeeping, which a completion lists to remove
            response = "{\"kind\":\"storage#objects\"}";
        } else if (path.contains("/rewriteTo/")) {
            response = "{\"kind\":\"storage#rewriteResponse\"," +
                    "\"done\":true,\"totalBytesRewritten\":\"5\"," +
                    "\"objectSize\":\"5\",\"resource\":" + object("key") +
                    "}";
        } else if (path.endsWith("/compose")) {
            response = object("key");
        } else if (path.endsWith("/acl/allUsers")) {
            status = aclRemovalFails ? 503 : 204;
            if (aclRemovalFails) {
                response = "{\"error\":{\"code\":503,\"message\":\"down\"}}";
            }
        } else if (path.endsWith("/o/" + UPLOAD_ID)) {
            response = object(UPLOAD_ID);
        } else {
            response = object(path.substring(path.lastIndexOf('/') + 1));
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

    private static String object(String name) {
        return """
                {"kind":"storage#object","bucket":"bucket","name":"%s",\
                "generation":"1","metageneration":"1","size":"5",\
                "etag":"CAE=",\
                "metadata":{"s3proxy_target_blob_name":"key"},\
                "updated":"2026-01-01T00:00:00.000Z"}""".formatted(name);
    }
}
