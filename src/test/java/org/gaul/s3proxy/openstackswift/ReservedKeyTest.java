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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayInputStream;

import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.S3Exceptions;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.CopyObjectRequest;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.MetadataDirective;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.S3Exception;

/**
 * The store keeps an upload's marker and segments as objects of the
 * client's own container, under names list() hides.  Swift grants read by
 * container, so in a public-read one a name was all that stood between
 * anyone and the parts of an upload not completed -- and the name is the
 * upload ID, which ListMultipartUploads tells.  These ask for such names as
 * a client does.  The store is given nothing to reach Swift with, so an
 * answer is one it gave without asking.
 */
public final class ReservedKeyTest {
    private static final String CONTAINER = "container";
    private static final String UPLOAD_ID =
            "0b0e6a2c-6d0c-4a4c-9d5e-2f1f4a8f5c11";
    private static final String SEGMENT =
            ".s3proxy-mpu/" + UPLOAD_ID + "/00001";
    private static final String MARKER =
            ".s3proxy-mpu/" + UPLOAD_ID + "/.meta";

    private BlobStore blobStore;

    @BeforeEach
    public void setUp() {
        blobStore = new OpenStackSwiftBlobStore(() -> {
            throw new IllegalStateException("the store asked Swift");
        }, "http://127.0.0.1:1/v3", "project", "Default", "Default",
                /*region=*/ "");
    }

    @AfterEach
    public void tearDown() {
        blobStore.close();
    }

    @Test
    public void testReservedNames() {
        assertThat(OpenStackSwiftBlobStore.isReserved(SEGMENT)).isTrue();
        assertThat(OpenStackSwiftBlobStore.isReserved(MARKER)).isTrue();
        assertThat(OpenStackSwiftBlobStore.isReserved(".s3proxy-mpu/"))
                .isTrue();
        // a client's own keys, however like them
        assertThat(OpenStackSwiftBlobStore.isReserved(".s3proxy-mpu"))
                .isFalse();
        assertThat(OpenStackSwiftBlobStore.isReserved(".s3proxy-mpu-stub-x"))
                .isFalse();
        assertThat(OpenStackSwiftBlobStore.isReserved("a/.s3proxy-mpu/b"))
                .isFalse();
    }

    @Test
    public void testReadsFindNothing() {
        for (String key : new String[] {SEGMENT, MARKER}) {
            assertThatThrownBy(() -> blobStore.getBlob(CONTAINER, key))
                    .as(key).isInstanceOf(NoSuchKeyException.class);
            assertThatThrownBy(() -> blobStore.getBlob(
                    GetObjectRequest.builder().bucket(CONTAINER).key(key)
                            .range("bytes=0-0").build()))
                    .as(key).isInstanceOf(NoSuchKeyException.class);
            assertThatThrownBy(() -> blobStore.blobMetadata(CONTAINER, key))
                    .as(key).isInstanceOf(NoSuchKeyException.class);
            assertThat(blobStore.blobMetadataIfPresent(CONTAINER, key))
                    .as(key).isNull();
            assertThat(blobStore.blobExists(CONTAINER, key)).as(key)
                    .isFalse();
        }
    }

    /** Nor is a segment read by copying it to a name that is served. */
    @Test
    public void testCopySourceFindsNothing() {
        var copy = copyOf(SEGMENT, "copy");
        assertThatThrownBy(() -> blobStore.copyBlob(copy.build()))
                .isInstanceOf(NoSuchKeyException.class);
        assertThatThrownBy(() -> blobStore.copyBlob(copy.copy()
                .metadataDirective(MetadataDirective.REPLACE).build()))
                .isInstanceOf(NoSuchKeyException.class);
        assertThatThrownBy(() -> blobStore.copyBlob(copy.copy()
                .copySourceIfMatch("*").build()))
                .isInstanceOf(NoSuchKeyException.class);
    }

    @Test
    public void testWritesAreRefused() {
        assertRefused(() -> blobStore.putBlob(PutObjectRequest.builder()
                .bucket(CONTAINER).key(SEGMENT).contentLength(0L).build(),
                new ByteArrayInputStream(new byte[0])));
        assertRefused(() -> blobStore.copyBlob(
                copyOf("object", SEGMENT).build()));
        assertRefused(() -> blobStore.removeBlob(CONTAINER, SEGMENT));
        assertRefused(() -> blobStore.removeBlob(CONTAINER, MARKER));
    }

    /**
     * An upload publishes under the key its completion names, which is a
     * client's as much as the one it was created with.
     */
    @Test
    public void testUploadsAreRefused() {
        var create = CreateMultipartUploadRequest.builder()
                .bucket(CONTAINER).key(SEGMENT).build();
        assertRefused(() -> blobStore.initiateMultipartUpload(create));
        assertRefused(() -> blobStore.completeMultipartUpload(
                new MultipartUpload(UPLOAD_ID, create),
                CompleteMultipartUploadRequest.builder()
                        .bucket(CONTAINER).key(SEGMENT).uploadId(UPLOAD_ID)
                        .build()));
    }

    private static CopyObjectRequest.Builder copyOf(String from, String to) {
        return CopyObjectRequest.builder()
                .sourceBucket(CONTAINER).sourceKey(from)
                .destinationBucket(CONTAINER).destinationKey(to);
    }

    private static void assertRefused(ThrowingCallable call) {
        assertThatThrownBy(call)
                .isInstanceOfSatisfying(S3Exception.class, se -> {
                    assertThat(se.statusCode()).isEqualTo(400);
                    assertThat(S3Exceptions.errorCode(se))
                            .isEqualTo("InvalidArgument");
                });
    }
}
