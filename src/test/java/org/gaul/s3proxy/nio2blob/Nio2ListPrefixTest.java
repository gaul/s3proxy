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
import java.nio.file.Path;
import java.util.List;

import com.google.common.io.ByteSource;

import org.gaul.s3proxy.TestUtils;
import org.gaul.s3proxy.blobstore.S3Exceptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.S3Exception;

/**
 * A listing walks the directory its prefix names, so that directory has to
 * be the one the prefix spells and has to lie inside the container.  With a
 * ".." in it the prefix {@code ../<container>} normalized back into the
 * container it was asked of, and so passed the check made of it, while the
 * walk started one directory up: at the store's root, with every other
 * container under it.  An absolute prefix started there without a dot.
 */
public final class Nio2ListPrefixTest {
    private static final String CONTAINER = "container";
    /** Begins with the other's name, as an absolute prefix needs it to. */
    private static final String SIMILAR = "container-internal";
    private static final String OTHER = "other";

    @TempDir
    private Path root;
    private AbstractNio2BlobStore store;

    @BeforeEach
    public void setUp() throws IOException {
        use(new FilesystemNio2BlobStore(root.toString()));
    }

    @Test
    public void testPrefixDoesNotWalkOtherContainers() {
        // Refused where the walk would leave the container, and listing
        // nothing where it would come back to it by a dot segment no key
        // holds.  Delimited, the walk answered with the containers' names.
        for (String prefix : List.of("../" + CONTAINER,
                "../" + CONTAINER + "/", "dir/../../" + CONTAINER)) {
            assertListsNothing(prefix, /*delimited=*/ false);
            assertListsNothing(prefix, /*delimited=*/ true);
        }
    }

    @Test
    public void testAbsolutePrefixDoesNotWalkOtherContainers() {
        assertTraversalRefused(root.resolve(CONTAINER).toString());
    }

    /** The transient store's root is "/", which any client can spell. */
    @Test
    public void testAbsolutePrefixDoesNotWalkOtherContainersTransient()
            throws IOException {
        use(new TransientNio2BlobStore());

        assertTraversalRefused("//" + CONTAINER);
    }

    /** Nor another directory of its own container than the one it names. */
    @Test
    public void testPrefixDoesNotWalkAnotherDirectory() {
        for (String prefix : List.of("dir/../sibling/", "dir/../sib",
                "./", "./dir/", "dir/./")) {
            assertDotSegmentRefused(prefix, /*delimited=*/ false);
        }
    }

    /** A dot is only a segment by itself: these are ordinary names. */
    @Test
    public void testNamesBeginningWithDotsStillList() throws IOException {
        put(CONTAINER, "..hidden");
        put(CONTAINER, "dir/..hidden");
        // Windows trims the dots that end a name, so "..." is no directory
        // name there
        boolean dotsDirectory = !root.getFileSystem().getSeparator()
                .equals("\\");
        if (dotsDirectory) {
            put(CONTAINER, ".../file.txt");
        }

        assertThat(keys("..h")).containsExactly("..hidden");
        assertThat(keys("dir/..h")).containsExactly("dir/..hidden");
        assertThat(keys("dir/")).containsExactly("dir/..hidden",
                "dir/file.txt");
        if (dotsDirectory) {
            assertThat(keys(".../")).containsExactly(".../file.txt");
            assertThat(keys("")).containsExactly(".../file.txt", "..hidden",
                    "dir/..hidden", "dir/file.txt", "sibling/file.txt");
        } else {
            assertThat(keys("")).containsExactly("..hidden",
                    "dir/..hidden", "dir/file.txt", "sibling/file.txt");
        }
    }

    private void use(AbstractNio2BlobStore blobStore) throws IOException {
        store = blobStore;
        store.createContainer(CONTAINER);
        store.createContainer(SIMILAR);
        store.createContainer(OTHER);
        put(CONTAINER, "dir/file.txt");
        put(CONTAINER, "sibling/file.txt");
        put(SIMILAR, "secret.txt");
        put(OTHER, "secret.txt");
    }

    /**
     * No key holds a "." or ".." segment, so no key begins with a prefix
     * that does, and the listing is empty rather than another directory's.
     */
    private void assertDotSegmentRefused(String prefix, boolean delimited) {
        var listing = store.list(request(prefix)
                .delimiter(delimited ? "/" : null).build());
        assertThat(listing.contents()).as("prefix %s", prefix).isEmpty();
        assertThat(listing.commonPrefixes()).as("prefix %s", prefix)
                .isEmpty();
    }

    private void assertListsNothing(String prefix, boolean delimited) {
        try {
            assertDotSegmentRefused(prefix, delimited);
        } catch (S3Exception e) {
            assertThat(S3Exceptions.errorCode(e)).as("prefix %s", prefix)
                    .isEqualTo("InvalidArgument");
        }
    }

    private void assertTraversalRefused(String prefix) {
        for (String delimiter : List.of("", "/")) {
            assertThatThrownBy(() -> store.list(request(prefix)
                    .delimiter(delimiter).build()))
                    .describedAs("prefix %s", prefix)
                    .isInstanceOf(S3Exception.class)
                    .matches(e -> S3Exceptions.errorCode((S3Exception) e)
                            .equals("InvalidArgument"))
                    .hasMessageNotContaining(CONTAINER);
        }
    }

    private void put(String container, String key) throws IOException {
        TestUtils.putBlob(store, container, key,
                ByteSource.wrap(new byte[0]));
    }

    private List<String> keys(String prefix) {
        return store.list(request(prefix).build()).contents().stream()
                .map(o -> o.key()).toList();
    }

    private static ListObjectsV2Request.Builder request(String prefix) {
        return ListObjectsV2Request.builder().bucket(CONTAINER)
                .prefix(prefix);
    }
}
