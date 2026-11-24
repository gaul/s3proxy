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

package org.gaul.s3proxy.nio2blob;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.concurrent.CompletableFuture;

import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.CompletedMultipartUpload;
import software.amazon.awssdk.services.s3.model.CompletedPart;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.ObjectCannedACL;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.UploadPartRequest;

/**
 * The access a multipart upload asks for belongs to the object it assembles,
 * and not to one that replaces that object while the completion is still
 * removing the upload's parts.
 */
public final class Nio2MultipartAccessTest {
    private static final String CONTAINER = "container";
    private static final byte[] DATA = "data".getBytes(StandardCharsets.UTF_8);

    @TempDir
    private Path root;
    private FilesystemNio2BlobStore blobStore;

    @BeforeEach
    public void setUp() {
        blobStore = new FilesystemNio2BlobStore(root.toString());
        blobStore.createContainer(CONTAINER);
    }

    private MultipartUpload upload(String key, ObjectCannedACL access,
            int parts) {
        return upload(key, access, parts, DATA);
    }

    private MultipartUpload upload(String key, ObjectCannedACL access,
            int parts, byte[] data) {
        var mpu = blobStore.initiateMultipartUpload(
                CreateMultipartUploadRequest.builder()
                        .bucket(CONTAINER).key(key).acl(access).build());
        for (int i = 1; i <= parts; ++i) {
            blobStore.uploadMultipartPart(mpu, UploadPartRequest.builder()
                    .bucket(CONTAINER).key(key).uploadId(mpu.id())
                    .partNumber(i).contentLength((long) data.length).build(),
                    new ByteArrayInputStream(data));
        }
        return mpu;
    }

    /** Completes an upload, listing only its first part. */
    private void complete(MultipartUpload mpu) {
        blobStore.completeMultipartUpload(mpu,
                CompleteMultipartUploadRequest.builder()
                        .bucket(CONTAINER).key(mpu.blobName())
                        .uploadId(mpu.id())
                        .multipartUpload(CompletedMultipartUpload.builder()
                                .parts(CompletedPart.builder()
                                        .partNumber(1).build())
                                .build())
                        .build());
    }

    /** Writes an empty object, which is all a marker can hold. */
    private void put(String key, ObjectCannedACL access) {
        blobStore.putBlob(PutObjectRequest.builder()
                .bucket(CONTAINER).key(key)
                .contentLength(0L).acl(access).build(),
                new ByteArrayInputStream(new byte[0]));
    }

    @Test
    public void testReplacementKeepsItsAccess() throws Exception {
        // Every part is removed, listed in the completion or not, so these
        // are what keeps the completion busy after it has published the
        // object.
        var mpu = upload("blob", ObjectCannedACL.PUBLIC_READ, 500);

        var completion = CompletableFuture.runAsync(() -> complete(mpu));
        while (!blobStore.blobExists(CONTAINER, "blob")) {
            assertThat(completion).isNotCompletedExceptionally();
        }
        // published with its access, not given it later
        assertThat(blobStore.getBlobAccess(CONTAINER, "blob")).isEqualTo(
                ObjectCannedACL.PUBLIC_READ);

        put("blob", ObjectCannedACL.PRIVATE);
        completion.join();

        assertThat(blobStore.getBlobAccess(CONTAINER, "blob")).isEqualTo(
                ObjectCannedACL.PRIVATE);
    }

    @Test
    public void testCompletedUploadHasItsAccess() throws Exception {
        var mpu = upload("public", ObjectCannedACL.PUBLIC_READ, 1);
        complete(mpu);
        assertThat(blobStore.getBlobAccess(CONTAINER, "public")).isEqualTo(
                ObjectCannedACL.PUBLIC_READ);

        mpu = upload("private", ObjectCannedACL.PRIVATE, 1);
        complete(mpu);
        assertThat(blobStore.getBlobAccess(CONTAINER, "private")).isEqualTo(
                ObjectCannedACL.PRIVATE);
    }

    // A directory marker is not renamed into place like other objects, and
    // the directory it makes starts out with whatever mode the umask allows.
    @Test
    public void testDirectoryMarkerHasItsAccess() throws Exception {
        var mpu = upload("uploaded/", ObjectCannedACL.PRIVATE, 1,
                new byte[0]);
        complete(mpu);
        assertThat(blobStore.getBlobAccess(CONTAINER, "uploaded/")).isEqualTo(
                ObjectCannedACL.PRIVATE);

        put("put/", ObjectCannedACL.PUBLIC_READ);
        assertThat(blobStore.getBlobAccess(CONTAINER, "put/")).isEqualTo(
                ObjectCannedACL.PUBLIC_READ);
        put("put/", ObjectCannedACL.PRIVATE);
        assertThat(blobStore.getBlobAccess(CONTAINER, "put/")).isEqualTo(
                ObjectCannedACL.PRIVATE);
    }
}
