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
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;

import com.google.common.jimfs.Configuration;
import com.google.common.jimfs.Jimfs;

import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.gaul.s3proxy.S3Proxy;
import org.gaul.s3proxy.auth.AuthenticationType;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

import software.amazon.awssdk.services.s3.model.HeadObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.services.s3.model.S3Object;

/**
 * A filesystem reports a name that is too long only once it has found the
 * directories above it, so a key holding one failed under a prefix that
 * holds objects and was merely absent under one that does not -- which told
 * an anonymous reader of a private bucket which prefixes are in use.  Such a
 * key is refused before the filesystem is asked.
 */
public final class Nio2KeySegmentLengthTest {
    private static final String CONTAINER = "container";
    private static final byte[] CONTENT = "content".getBytes(
            StandardCharsets.UTF_8);
    private static final String TOO_LONG = "k".repeat(256);

    @TempDir
    private Path root;
    private FilesystemNio2BlobStore blobStore;

    @BeforeEach
    public void setUp() {
        blobStore = new FilesystemNio2BlobStore(root.toString());
        blobStore.createContainer(CONTAINER);
        put(blobStore, "present/blob");
    }

    @Test
    public void testOverlongSegmentAnswersTheSameUnderAnyPrefix() {
        for (String key : List.of("present/" + TOO_LONG,
                "absent/" + TOO_LONG, TOO_LONG, TOO_LONG + "/blob",
                "present/" + TOO_LONG + "/")) {
            assertRefused(key, () -> blobStore.getBlobAccess(CONTAINER, key));
            assertRefused(key, () -> blobStore.blobMetadata(
                    HeadObjectRequest.builder().bucket(CONTAINER).key(key)
                            .build()));
            assertRefused(key, () -> put(blobStore, key));
            assertRefused(key, () -> blobStore.removeBlob(CONTAINER, key));
        }
        assertThat(keys(blobStore)).containsExactly("present/blob");
    }

    @Test
    public void testLongestNameIsStored() {
        String key = "present/" + "k".repeat(255);
        put(blobStore, key);
        assertThat(keys(blobStore)).containsExactly("present/blob", key);
    }

    /** A name is counted in bytes, of which these characters take two. */
    @Test
    @DisabledOnOs(OS.WINDOWS)
    public void testSegmentIsCountedInBytes() {
        String key = "present/" + "é".repeat(128);
        assertRefused(key, () -> put(blobStore, key));
        assertRefused(key, () -> blobStore.getBlobAccess(CONTAINER, key));
    }

    /**
     * Windows counts UTF-16 code units instead, so it keeps the name above
     * and one twice as long.  Jimfs stands in for it, as in
     * {@link Nio2WindowsKeyTest}.
     */
    @Test
    public void testSegmentIsCountedInCharactersOnWindows() throws Exception {
        try (var windows = Jimfs.newFileSystem(Configuration.windows()
                .toBuilder()
                .setAttributeViews("basic", "user")
                .setWorkingDirectory("C:\\")
                .build())) {
            var store = new AbstractNio2BlobStore(windows.getPath("C:\\")) {
            };
            store.createContainer(CONTAINER);
            String longest = "é".repeat(255);
            put(store, longest);
            assertThat(keys(store)).containsExactly(longest);

            String key = "é".repeat(256);
            assertRefused(key, () -> put(store, key));
        }
    }

    /**
     * Where it told: an unsigned read of a private bucket, which is refused
     * whatever the bucket holds.  This one answered 500 under a prefix that
     * holds objects and AccessDenied under one that does not.
     */
    @Test
    public void testAnonymousReadDoesNotTellPrefixesApart() throws Exception {
        var s3Proxy = S3Proxy.builder()
                .stopTimeout(0)
                .blobStore(blobStore)
                .awsAuthentication(AuthenticationType.AWS_V2_OR_V4,
                        "identity", "credential")
                .endpoint(URI.create("http://127.0.0.1:0"))
                .build();
        s3Proxy.start();
        try {
            while (!s3Proxy.getState().equals("STARTED")) {
                Thread.sleep(10);
            }
            var baseUri = "http://127.0.0.1:" + s3Proxy.getPort() + "/" +
                    CONTAINER + "/";
            var httpClient = HttpClient.newHttpClient();
            for (String method : new String[] {"GET", "HEAD"}) {
                assertThat(send(httpClient, method, baseUri + "present/blob"))
                        .as(method).isEqualTo(403);
                int present = send(httpClient, method, baseUri + "present/" +
                        TOO_LONG);
                int absent = send(httpClient, method, baseUri + "absent/" +
                        TOO_LONG);
                assertThat(present).as(method).isEqualTo(absent)
                        .isEqualTo(400);
            }
        } finally {
            s3Proxy.stop();
        }
    }

    /** Jimfs has no limit to run into, so that store keeps what S3 does. */
    @Test
    public void testTransientStoreKeepsOverlongSegment() {
        var transientStore = new TransientNio2BlobStore();
        transientStore.createContainer(CONTAINER);
        put(transientStore, TOO_LONG);
        assertThat(keys(transientStore)).containsExactly(TOO_LONG);
    }

    private static int send(HttpClient httpClient, String method, String uri)
            throws Exception {
        return httpClient.send(
                HttpRequest.newBuilder(URI.create(uri))
                        .method(method, HttpRequest.BodyPublishers.noBody())
                        .build(),
                HttpResponse.BodyHandlers.discarding()).statusCode();
    }

    private static void assertRefused(String key, ThrowingCallable call) {
        assertThatThrownBy(call).as(key)
                .isInstanceOfSatisfying(S3Exception.class, e ->
                        assertThat(e.statusCode()).isEqualTo(400));
    }

    private static void put(BlobStore store, String key) {
        store.putBlob(PutObjectRequest.builder()
                .bucket(CONTAINER).key(key)
                .contentLength((long) CONTENT.length).build(),
                new ByteArrayInputStream(CONTENT));
    }

    private static List<String> keys(BlobStore store) {
        return store.list(CONTAINER).contents().stream()
                .map(S3Object::key).toList();
    }
}
