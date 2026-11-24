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
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import org.gaul.s3proxy.S3ProxyConstants;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.SdkRequests;
import org.gaul.s3proxy.middleware.EncryptedBlobStore;
import org.gaul.s3proxy.middleware.Middlewares;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.services.s3.model.BucketVersioningStatus;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.HeadObjectRequest;
import software.amazon.awssdk.services.s3.model.ObjectCannedACL;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

/**
 * An unsigned read is answered only from an object that is public-read.
 * The frontend asks for the object's access and then reads the object, two
 * calls that each resolve the key, and a put between them replaces a public
 * object with a private one whose content the read then serves.  The read
 * therefore carries {@link SdkRequests#ONLY_IF_PUBLIC_READ}, and the store
 * judges the file it opens.
 */
public final class Nio2OnlyIfPublicReadTest {
    private static final String CONTAINER = "container";
    private static final String KEY = "myobj";

    private TransientNio2BlobStore store;

    @BeforeEach
    public void setUp() {
        store = new TransientNio2BlobStore();
        store.createContainer(CONTAINER);
    }

    private String write(BlobStore blobStore, String content,
            ObjectCannedACL acl) {
        byte[] bytes = content.getBytes(StandardCharsets.UTF_8);
        return blobStore.putBlob(PutObjectRequest.builder()
                        .bucket(CONTAINER).key(KEY)
                        .contentLength((long) bytes.length)
                        .acl(acl)
                        .build(),
                new ByteArrayInputStream(bytes)).versionId();
    }

    private static GetObjectRequest.Builder publicRead() {
        return GetObjectRequest.builder()
                .bucket(CONTAINER).key(KEY)
                .overrideConfiguration(SdkRequests.ONLY_IF_PUBLIC_READ);
    }

    private static String read(BlobStore blobStore, GetObjectRequest request)
            throws IOException {
        try (var blob = blobStore.getBlob(request)) {
            return new String(blob.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static void assertForbidden(Runnable read) {
        assertThatThrownBy(read::run)
                .isInstanceOfSatisfying(AwsServiceException.class,
                        ase -> assertThat(ase.statusCode()).isEqualTo(403));
    }

    @Test
    public void testPublicObject() throws Exception {
        write(store, "public", ObjectCannedACL.PUBLIC_READ);

        assertThat(read(store, publicRead().build())).isEqualTo("public");
        assertThat(store.blobMetadata(HeadObjectRequest.builder()
                .bucket(CONTAINER).key(KEY)
                .overrideConfiguration(SdkRequests.ONLY_IF_PUBLIC_READ)
                .build()).contentLength()).isEqualTo(6);
    }

    @Test
    public void testPrivateObject() throws Exception {
        write(store, "private", ObjectCannedACL.PRIVATE);

        assertForbidden(() -> store.getBlob(publicRead().build()));
        assertForbidden(() -> store.blobMetadata(HeadObjectRequest.builder()
                .bucket(CONTAINER).key(KEY)
                .overrideConfiguration(SdkRequests.ONLY_IF_PUBLIC_READ)
                .build()));
        // a condition is not answered with the ETag of what may not be read
        assertForbidden(() -> store.getBlob(publicRead()
                .ifNoneMatch("*").build()));

        // every other read is its caller's to judge
        assertThat(read(store, GetObjectRequest.builder()
                .bucket(CONTAINER).key(KEY).build())).isEqualTo("private");
        assertThat(SdkRequests.onlyIfPublicRead(GetObjectRequest.builder()
                .bucket(CONTAINER).key(KEY).build())).isFalse();
    }

    /** The version read is the one judged, not the current one. */
    @Test
    public void testPrivateVersionOfPublicObject() throws Exception {
        store.putBucketVersioning(CONTAINER, BucketVersioningStatus.ENABLED);
        String privateVersion = write(store, "private",
                ObjectCannedACL.PRIVATE);
        String publicVersion = write(store, "public",
                ObjectCannedACL.PUBLIC_READ);

        assertThat(read(store, publicRead().build())).isEqualTo("public");
        assertThat(read(store, publicRead().versionId(publicVersion).build()))
                .isEqualTo("public");
        assertForbidden(() -> store.getBlob(publicRead()
                .versionId(privateVersion).build()));
    }

    /** A middleware that rewrites the request keeps what rides on it. */
    @Test
    public void testThroughMiddleware() throws Exception {
        var properties = new Properties();
        properties.setProperty(S3ProxyConstants.PROPERTY_PREFIX_BLOBSTORE +
                "." + CONTAINER, "prefix/");
        BlobStore prefixed = Middlewares.wrap(store, properties,
                unused -> {
                    throw new AssertionError();
                });

        write(prefixed, "private", ObjectCannedACL.PRIVATE);
        assertForbidden(() -> prefixed.getBlob(publicRead().build()));

        write(prefixed, "public", ObjectCannedACL.PUBLIC_READ);
        assertThat(read(prefixed, publicRead().build())).isEqualTo("public");
    }

    /** As does the encrypting one, whose HEAD builds a request of its own. */
    @Test
    public void testThroughEncryption() throws Exception {
        var properties = new Properties();
        properties.setProperty(
                S3ProxyConstants.PROPERTY_ENCRYPTED_BLOBSTORE_PASSWORD,
                "password");
        properties.setProperty(
                S3ProxyConstants.PROPERTY_ENCRYPTED_BLOBSTORE_SALT, "salt");
        BlobStore encrypted = EncryptedBlobStore.newEncryptedBlobStore(store,
                properties);
        var head = HeadObjectRequest.builder()
                .bucket(CONTAINER).key(KEY)
                .overrideConfiguration(SdkRequests.ONLY_IF_PUBLIC_READ)
                .build();

        write(encrypted, "private", ObjectCannedACL.PRIVATE);
        assertForbidden(() -> encrypted.getBlob(publicRead().build()));
        assertForbidden(() -> encrypted.blobMetadata(head));

        write(encrypted, "public", ObjectCannedACL.PUBLIC_READ);
        assertThat(read(encrypted, publicRead().build())).isEqualTo("public");
        assertThat(encrypted.blobMetadata(head).contentLength()).isEqualTo(6);
    }

    /**
     * The owner replaces a public object with a private one and back while
     * readers keep asking for a public one: whatever a reader is given was
     * public, however the two interleave.
     */
    @Test
    public void testReadRacingOverwrite() throws Exception {
        write(store, "public", ObjectCannedACL.PUBLIC_READ);

        String leaked = null;
        var failure = new AtomicReference<Throwable>();
        var stop = new AtomicBoolean();
        var writer = new Thread(() -> {
            try {
                while (!stop.get()) {
                    write(store, "private", ObjectCannedACL.PRIVATE);
                    write(store, "public", ObjectCannedACL.PUBLIC_READ);
                }
            } catch (RuntimeException re) {
                failure.compareAndSet(null, re);
            }
        });

        writer.start();
        long deadline = System.nanoTime() + 2_000_000_000L;
        int reads = 0;
        try {
            while (System.nanoTime() < deadline && leaked == null) {
                try {
                    String content = read(store, publicRead().build());
                    if (!content.equals("public")) {
                        leaked = content;
                    }
                    ++reads;
                } catch (AwsServiceException ase) {
                    // the private object was there, and said so
                    assertThat(ase.statusCode()).isEqualTo(403);
                }
            }
        } finally {
            stop.set(true);
            writer.join();
        }

        assertThat(failure.get()).isNull();
        assertThat(leaked).isNull();
        assertThat(reads).isGreaterThan(0);
    }
}
