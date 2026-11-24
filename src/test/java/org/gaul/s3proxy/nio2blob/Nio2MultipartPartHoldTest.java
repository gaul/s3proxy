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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.gaul.s3proxy.blobstore.S3Exceptions;
import org.gaul.s3proxy.blobstore.SdkRequests;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import software.amazon.awssdk.services.s3.model.CompletedPart;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.services.s3.model.UploadPartRequest;

/**
 * A completion judges the parts of an upload -- their ETags, and their
 * content where it asserts a checksum -- and the store then assembles them
 * by name.  A part replaced in between was published under the verdict
 * reached on its predecessor, so the completion holds the parts as they are
 * and a part that arrives meanwhile waits.
 */
public final class Nio2MultipartPartHoldTest {
    private static final String CONTAINER = "container";

    @TempDir
    private Path root;
    private FilesystemNio2BlobStore blobStore;
    private ExecutorService executor;

    @BeforeEach
    public void setUp() {
        blobStore = new FilesystemNio2BlobStore(root.toString());
        blobStore.createContainer(CONTAINER);
        executor = Executors.newSingleThreadExecutor();
    }

    @AfterEach
    public void tearDown() {
        executor.shutdownNow();
    }

    @Test
    public void testPartWaitsWhileTheUploadIsHeld() throws Exception {
        var mpu = blobStore.initiateMultipartUpload(
                CreateMultipartUploadRequest.builder()
                        .bucket(CONTAINER).key("blob").build());
        uploadPart(mpu, "approved");

        var hold = blobStore.holdMultipartParts(mpu.id());
        var replacing = executor.submit(() -> uploadPart(mpu, "replaced"));
        assertThatThrownBy(() -> replacing.get(500, TimeUnit.MILLISECONDS))
                .isInstanceOf(TimeoutException.class);
        assertThat(readPart(mpu)).isEqualTo("approved");

        // a completion that is refused leaves the upload open, and the part
        // takes its place
        hold.close();
        replacing.get(30, TimeUnit.SECONDS);
        assertThat(readPart(mpu)).isEqualTo("replaced");
    }

    @Test
    public void testPartOfAnUploadCompletedMeanwhileIsRefused()
            throws Exception {
        var mpu = blobStore.initiateMultipartUpload(
                CreateMultipartUploadRequest.builder()
                        .bucket(CONTAINER).key("blob").build());
        String eTag = uploadPart(mpu, "approved");

        var hold = blobStore.holdMultipartParts(mpu.id());
        var replacing = executor.submit(() -> uploadPart(mpu, "replaced"));
        assertThatThrownBy(() -> replacing.get(500, TimeUnit.MILLISECONDS))
                .isInstanceOf(TimeoutException.class);
        blobStore.completeMultipartUpload(mpu, SdkRequests.completeRequest(
                mpu, List.of(CompletedPart.builder()
                        .partNumber(1).eTag(eTag).build())));
        hold.close();

        assertThatThrownBy(() -> replacing.get(30, TimeUnit.SECONDS))
                .isInstanceOf(ExecutionException.class)
                .cause()
                .isInstanceOf(S3Exception.class)
                .matches(e -> S3Exceptions.errorCode((S3Exception) e)
                        .equals("NoSuchUpload"));
        try (var blob = blobStore.getBlob(CONTAINER, "blob")) {
            assertThat(new String(blob.readAllBytes(),
                    StandardCharsets.UTF_8))
                    .isEqualTo("approved");
        }
        // and leaves nothing of itself behind
        try (var files = Files.list(root.resolve(CONTAINER))) {
            assertThat(files.map(path -> path.getFileName().toString()))
                    .containsExactly("blob");
        }
    }

    private String uploadPart(MultipartUpload mpu, String content) {
        byte[] bytes = content.getBytes(StandardCharsets.UTF_8);
        return blobStore.uploadMultipartPart(mpu, UploadPartRequest.builder()
                .bucket(CONTAINER).key(mpu.blobName()).uploadId(mpu.id())
                .partNumber(1).contentLength((long) bytes.length).build(),
                new ByteArrayInputStream(bytes)).eTag();
    }

    private String readPart(MultipartUpload mpu) throws Exception {
        try (var part = blobStore.getMultipartPart(mpu, 1)) {
            return new String(part.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
