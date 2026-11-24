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
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import com.google.common.jimfs.Configuration;
import com.google.common.jimfs.Jimfs;
import com.google.common.jimfs.PathNormalization;

import org.gaul.s3proxy.blobstore.S3Exceptions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.services.s3.model.S3Object;

/**
 * The filesystem store where a name is found in any case, as on APFS, NTFS
 * and ext4 with casefold; a Jimfs configured that way walks the same code.
 * The names the store keeps for itself in a container were compared with a
 * key as strings, so {@code .S3PROXY-TMP/x} was a client's key to the check
 * and the store's own file {@code .s3proxy-tmp/x} to the filesystem.
 */
public final class Nio2CaseInsensitiveKeyTest {
    private static final String CONTAINER = "container";
    private static final byte[] CONTENT = "content".getBytes(
            StandardCharsets.UTF_8);
    private static final byte[] OTHER = "another".getBytes(
            StandardCharsets.UTF_8);

    private FileSystem caseInsensitive;
    private AbstractNio2BlobStore store;

    /** A store over whatever filesystem it is handed. */
    private static final class Nio2Store extends AbstractNio2BlobStore {
        Nio2Store(Path root) {
            super(root);
        }
    }

    @BeforeEach
    public void setUp() {
        caseInsensitive = Jimfs.newFileSystem(Configuration.unix().toBuilder()
                .setNameCanonicalNormalization(PathNormalization.NFD,
                        PathNormalization.CASE_FOLD_ASCII)
                .setAttributeViews("posix", "user")
                .setWorkingDirectory("/")
                .build());
        store = new Nio2Store(caseInsensitive.getPath("/"));
        store.createContainer(CONTAINER);
    }

    @AfterEach
    public void tearDown() throws IOException {
        caseInsensitive.close();
    }

    /**
     * A write in progress is a file under {@code .s3proxy-tmp}.  Another
     * client that put the same name in capitals replaced that file, and the
     * first write then published the other's bytes as its own.
     */
    @Test
    public void testWriteInFlightIsNotReplaced() throws Exception {
        var temporary = caseInsensitive.getPath("/", CONTAINER,
                ".s3proxy-tmp");
        var refused = new ArrayList<S3Exception>();
        InputStream payload = new FilterInputStream(
                new ByteArrayInputStream(CONTENT)) {
            private boolean tried;

            @Override
            public int read(byte[] b, int off, int len) throws IOException {
                if (!tried) {
                    tried = true;
                    String name;
                    try (var files = Files.list(temporary)) {
                        name = files.findFirst().orElseThrow().getFileName()
                                .toString();
                    }
                    try {
                        put(".S3PROXY-TMP/" + name,
                                new ByteArrayInputStream(OTHER));
                    } catch (S3Exception e) {
                        refused.add(e);
                    }
                }
                return super.read(b, off, len);
            }
        };

        put("blob", payload);

        assertThat(refused).hasSize(1);
        assertThat(S3Exceptions.errorCode(refused.get(0)))
                .isEqualTo("InvalidArgument");
        try (var blob = store.getBlob(CONTAINER, "blob")) {
            assertThat(blob.readAllBytes()).isEqualTo(CONTENT);
        }
        assertThat(keys()).containsExactly("blob");
    }

    /**
     * Capitals are the plainest other spelling and not the only one: a
     * filesystem that folds case may also skip a soft hyphen or a
     * zero-width space, and read a long s or a ligature as its letters.
     */
    @Test
    public void testReservedNameInAnySpellingIsRefused() {
        for (String key : List.of(
                ".S3PROXY-TMP", ".S3PROXY-TMP/blob", ".s3Proxy-Tmp/blob",
                ".S3PROXY-VERSIONS", ".S3PROXY-VERSIONS/blob",
                ".S3PROXY-SLASH", ".S3PROXY-SLASH/blob",
                ".MPUS-blob", ".Mpus-dir/blob",
                ".s3proxy-\u00adtmp/blob", ".s3proxy\u200b-tmp/blob",
                ".\u017f3proxy-tmp/blob", ".mpu\u017f-blob",
                ".mp\u00adus-blob")) {
            assertThatThrownBy(() -> put(key,
                    new ByteArrayInputStream(CONTENT)))
                    .describedAs("put of key %s", key)
                    .isInstanceOfSatisfying(S3Exception.class, e ->
                            assertThat(e.statusCode()).isEqualTo(400));
            assertThatThrownBy(() -> store.removeBlob(CONTAINER, key))
                    .describedAs("delete of key %s", key)
                    .isInstanceOfSatisfying(S3Exception.class, e ->
                            assertThat(e.statusCode()).isEqualTo(400));
        }
        assertThat(keys()).isEmpty();
    }

    /** Below the container the same names are keys like any other. */
    @Test
    public void testOtherKeysAreStillStored() {
        var stored = List.of(".S3PROXY-TMPX", ".mpus", "a/.S3PROXY-TMP/blob",
                "b/.MPUS-blob", "s3proxy-tmp/blob", "\u00fcber/blob");
        for (String key : stored) {
            put(key, new ByteArrayInputStream(CONTENT));
        }
        assertThat(keys()).containsExactlyInAnyOrderElementsOf(stored);
    }

    private void put(String key, InputStream payload) {
        store.putBlob(PutObjectRequest.builder()
                .bucket(CONTAINER).key(key)
                .contentLength((long) CONTENT.length).build(), payload);
    }

    private List<String> keys() {
        return store.list(CONTAINER).contents().stream()
                .map(S3Object::key).toList();
    }
}
