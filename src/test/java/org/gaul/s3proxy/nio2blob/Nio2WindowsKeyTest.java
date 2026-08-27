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

import java.io.IOException;
import java.nio.file.FileSystem;
import java.nio.file.Path;

import com.google.common.io.ByteSource;
import com.google.common.jimfs.Configuration;
import com.google.common.jimfs.Jimfs;

import org.gaul.s3proxy.TestUtils;
import org.gaul.s3proxy.blobstore.S3Exceptions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.s3.model.S3Exception;

/**
 * The filesystem store on Windows, which java.nio.file makes reachable from
 * anywhere: the store speaks Path, so a Jimfs configured Windows-style walks
 * the same code a Windows deployment does.  A key is a byte string to S3 and
 * a path to this store, and the two part company wherever the filesystem
 * spells its separator differently.  See issue #282.
 */
public final class Nio2WindowsKeyTest {
    private static final String CONTAINER = "container";

    private FileSystem windows;
    private AbstractNio2BlobStore store;

    /** A store over whatever filesystem it is handed. */
    private static final class Nio2Store extends AbstractNio2BlobStore {
        Nio2Store(Path root) {
            super(root);
        }
    }

    @BeforeEach
    public void setUp() {
        windows = Jimfs.newFileSystem(Configuration.windows().toBuilder()
                .setAttributeViews("basic", "user")
                .setWorkingDirectory("C:\\")
                .build());
        store = new Nio2Store(windows.getPath("C:\\"));
        store.createContainer(CONTAINER);
    }

    @AfterEach
    public void tearDown() throws IOException {
        windows.close();
    }

    /**
     * What the issue reported: a folder key came back spelled with the
     * separator the host happened to use.  Every key a listing answers with
     * is spelled the way S3 spells it, whatever the filesystem underneath.
     */
    @Test
    public void testListedKeysUseForwardSlashes() throws IOException {
        put("test/");
        put("dir/sub/file.txt");

        assertThat(keys(ListObjectsV2Request.builder().bucket(CONTAINER)
                .build())).containsExactly("dir/sub/file.txt", "test/");

        var delimited = store.list(ListObjectsV2Request.builder()
                .bucket(CONTAINER).delimiter("/").build());
        assertThat(delimited.commonPrefixes().stream()
                .map(p -> p.prefix()).toList())
                .containsExactly("dir/", "test/");
    }

    /**
     * A backslash is a separator here and cannot be part of a name, so the
     * key would come back as {@code back/slash.txt} and answer for whoever
     * wrote that key instead.  Both halves of that are refused at once.
     */
    @Test
    public void testKeyHoldingTheSeparatorIsRefused() {
        assertThatThrownBy(() -> put("back\\slash.txt"))
                .isInstanceOf(S3Exception.class)
                .matches(e -> S3Exceptions.errorCode((S3Exception) e)
                        .equals("InvalidArgument"))
                .hasMessageContaining("path separator");

        // no object was left under the key the caller did not write
        assertThatThrownBy(() -> store.blobMetadata(CONTAINER,
                "back/slash.txt")).isInstanceOf(NoSuchKeyException.class);
        assertThat(keys(ListObjectsV2Request.builder().bucket(CONTAINER)
                .build())).isEmpty();
    }

    /** Reading one is refused too, or it would answer for another key. */
    @Test
    public void testReadingAKeyHoldingTheSeparatorIsRefused()
            throws IOException {
        put("back/slash.txt");

        assertThatThrownBy(() -> store.blobMetadata(CONTAINER,
                "back\\slash.txt")).isInstanceOf(S3Exception.class);
        assertThatThrownBy(() -> store.getBlob(CONTAINER, "back\\slash.txt"))
                .isInstanceOf(S3Exception.class);
    }

    /** An upload names its object up front, so it is refused up front. */
    @Test
    public void testMultipartUploadOfSuchAKeyIsRefused() {
        assertThatThrownBy(() -> store.initiateMultipartUpload(
                CreateMultipartUploadRequest.builder()
                        .bucket(CONTAINER)
                        .key("back\\slash.bin")
                        .build()))
                .isInstanceOf(S3Exception.class);
    }

    /**
     * Matching a prefix holding the separator would answer with keys that do
     * not begin with it, since the store would read it as a directory.
     */
    @Test
    public void testPrefixHoldingTheSeparatorIsRefused() throws IOException {
        put("back/slash.txt");

        assertThatThrownBy(() -> store.list(ListObjectsV2Request.builder()
                .bucket(CONTAINER).prefix("back\\").build()))
                .isInstanceOf(S3Exception.class)
                .hasMessageContaining("path separator");
        // the same listing by the prefix S3 would use still answers
        assertThat(keys(ListObjectsV2Request.builder().bucket(CONTAINER)
                .prefix("back/").build())).containsExactly("back/slash.txt");
    }

    /**
     * Where the separator is "/" a backslash is an ordinary character in a
     * name, and the store goes on storing it as S3 does.
     */
    @Test
    public void testUnixKeepsABackslashInTheKey() throws IOException {
        try (var unix = Jimfs.newFileSystem(Configuration.unix().toBuilder()
                .setAttributeViews("posix", "user")
                .setWorkingDirectory("/")
                .build())) {
            var unixStore = new Nio2Store(unix.getPath("/"));
            unixStore.createContainer(CONTAINER);
            TestUtils.putBlob(unixStore, CONTAINER, "back\\slash.txt",
                    ByteSource.wrap(new byte[] {1, 2, 3}));

            assertThat(unixStore.blobMetadata(CONTAINER, "back\\slash.txt")
                    .contentLength()).isEqualTo(3);
            assertThat(unixStore.list(ListObjectsV2Request.builder()
                    .bucket(CONTAINER).build()).contents().stream()
                    .map(o -> o.key()).toList())
                    .containsExactly("back\\slash.txt");
        }
    }

    /**
     * Windows forbids these in a name outright, where S3 takes them.  Before
     * this each raised InvalidPathException out of Path.resolve, which
     * reached the caller as a 500: a fault laid at S3Proxy's door for a
     * request that was never going to work.
     */
    @Test
    public void testKeyWindowsCannotSpellIsRefused() {
        for (String key : new String[] {
            "co:lon.txt", "sta*r.txt", "qu?stion.txt", "less<than.txt",
            "pipe|d.txt", "quo\"te.txt", "trailing "}) {
            assertThatThrownBy(() -> put(key))
                    .describedAs("key %s", key)
                    .isInstanceOf(S3Exception.class)
                    .matches(e -> S3Exceptions.errorCode((S3Exception) e)
                            .equals("InvalidArgument"))
                    .hasMessageContaining("cannot store");
        }
    }

    /** Reading and listing answer the same way, not with a 500 either. */
    @Test
    public void testReadingAndListingSuchAKeyAreRefused() {
        assertThatThrownBy(() -> store.blobMetadata(CONTAINER, "co:lon.txt"))
                .isInstanceOf(S3Exception.class)
                .hasMessageContaining("cannot store");
        assertThatThrownBy(() -> store.list(ListObjectsV2Request.builder()
                .bucket(CONTAINER).prefix("co:lon").build()))
                .isInstanceOf(S3Exception.class)
                .hasMessageContaining("cannot store");
    }

    /**
     * The same refusal where the host is not Windows: no filesystem takes a
     * NUL, and S3 takes one in a key like any other byte.
     */
    @Test
    public void testKeyNoFilesystemCanSpellIsRefused(@TempDir Path temp) {
        var real = new FilesystemNio2BlobStore(temp.toString());
        real.createContainer(CONTAINER);

        assertThatThrownBy(() -> TestUtils.putBlob(real, CONTAINER,
                "nul" + (char) 0 + "key.txt", ByteSource.empty()))
                .isInstanceOf(S3Exception.class)
                .matches(e -> S3Exceptions.errorCode((S3Exception) e)
                        .equals("InvalidArgument"))
                .hasMessageContaining("cannot store");
    }

    private void put(String key) throws IOException {
        TestUtils.putBlob(store, CONTAINER, key,
                ByteSource.wrap(new byte[0]));
    }

    private java.util.List<String> keys(ListObjectsV2Request request) {
        return store.list(request).contents().stream()
                .map(o -> o.key()).toList();
    }
}
