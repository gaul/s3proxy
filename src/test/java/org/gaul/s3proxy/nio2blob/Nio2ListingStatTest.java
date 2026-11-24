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
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.FileSystem;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileAttributeView;
import java.nio.file.attribute.UserDefinedFileAttributeView;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicInteger;

import com.google.common.jimfs.Configuration;
import com.google.common.jimfs.Jimfs;

import org.apache.sshd.common.file.root.RootedFileSystemProvider;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.CommonPrefix;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.S3Object;

/**
 * A page of a listing reads the attributes of only the entries it can keep.
 * It used to stat every entry of each directory it walked, and read every
 * subdirectory's extended attributes, before asking whether the page wanted
 * it: paging through a directory of N entries cost N stats a page, N^2 /
 * max-keys in all, on a disk, over NFS, and in the transient store alike.
 * Counted by a filesystem that wraps Jimfs, and lists each directory in a
 * shuffled order, as a disk's hashed directories do, where Jimfs's own
 * sorted order would be the best case.
 */
public final class Nio2ListingStatTest {
    private static final String CONTAINER = "container";
    private static final byte[] CONTENT = "content".getBytes(
            StandardCharsets.UTF_8);

    private final AtomicInteger stats = new AtomicInteger();
    private final AtomicInteger xattrViews = new AtomicInteger();
    private FileSystem jimfs;
    private FileSystem counted;
    private AbstractNio2BlobStore store;

    /** A store over whatever filesystem it is handed. */
    private static final class Nio2Store extends AbstractNio2BlobStore {
        Nio2Store(Path root) {
            super(root);
        }
    }

    /** Counts what the store asks; lists a directory in shuffled order. */
    private final class CountingProvider extends RootedFileSystemProvider {
        @Override
        public <A extends BasicFileAttributes> A readAttributes(Path path,
                Class<A> type, LinkOption... options) throws IOException {
            stats.incrementAndGet();
            return super.readAttributes(path, type, options);
        }

        @Override
        public <V extends FileAttributeView> @Nullable V getFileAttributeView(
                Path path, Class<V> type, LinkOption... options) {
            if (type == UserDefinedFileAttributeView.class) {
                xattrViews.incrementAndGet();
            }
            return super.getFileAttributeView(path, type, options);
        }

        @Override
        public DirectoryStream<Path> newDirectoryStream(Path dir,
                DirectoryStream.Filter<? super Path> filter)
                throws IOException {
            var entries = new ArrayList<Path>();
            try (var stream = super.newDirectoryStream(dir, filter)) {
                stream.forEach(entries::add);
            }
            Collections.shuffle(entries, new Random(42));
            return new DirectoryStream<Path>() {
                @Override
                public Iterator<Path> iterator() {
                    return entries.iterator();
                }

                @Override
                public void close() {
                }
            };
        }
    }

    @BeforeEach
    public void setUp() throws IOException {
        jimfs = Jimfs.newFileSystem(Configuration.unix().toBuilder()
                .setAttributeViews("basic", "user")
                .build());
        counted = new CountingProvider().newFileSystem(jimfs.getPath("/"),
                Map.of());
        store = new Nio2Store(counted.getPath("/"));
        store.createContainer(CONTAINER);
    }

    @AfterEach
    public void tearDown() throws IOException {
        counted.close();
        jimfs.close();
    }

    private void write(String key) {
        store.putBlob(PutObjectRequest.builder()
                        .bucket(CONTAINER).key(key)
                        .contentLength((long) CONTENT.length)
                        .build(),
                new ByteArrayInputStream(CONTENT));
    }

    /**
     * Every page of a listing, in order, each page's keys and common
     * prefixes together, counting the stats and extended-attribute reads
     * of the listing alone.
     */
    private List<String> listAll(@Nullable String delimiter, int maxKeys) {
        var names = new ArrayList<String>();
        String token = null;
        stats.set(0);
        xattrViews.set(0);
        do {
            var response = store.list(ListObjectsV2Request.builder()
                    .bucket(CONTAINER).delimiter(delimiter).maxKeys(maxKeys)
                    .continuationToken(token).build());
            var page = new TreeSet<String>();
            response.contents().stream().map(S3Object::key)
                    .forEach(page::add);
            response.commonPrefixes().stream().map(CommonPrefix::prefix)
                    .forEach(page::add);
            assertThat(page).hasSizeLessThanOrEqualTo(maxKeys);
            names.addAll(page);
            token = response.nextContinuationToken();
        } while (token != null);
        return names;
    }

    @Test
    public void testPagingStatsOnlyWhatThePageCanKeep() {
        var keys = new TreeSet<String>();
        for (int i = 0; i < 1000; ++i) {
            keys.add("key%04d".formatted(i));
        }
        // directories, before and among the keys, to page past and into
        for (int i = 0; i < 20; ++i) {
            keys.add("dir%02d/key".formatted(i));
            keys.add("key%04d.d/key".formatted(i * 50));
        }
        keys.forEach(this::write);

        assertThat(listAll(/*delimiter=*/ null, 50))
                .containsExactlyElementsOf(keys);
        // 21 pages of 1040 entries: a stat of every entry of each directory
        // walked was over 22,000, where the entries a page can keep, met in
        // no order, are a few hundred a page
        assertThat(stats.get()).isLessThan(6_000);
    }

    @Test
    public void testDelimitedListingReadsNoExtendedAttributes() {
        var prefixes = new ArrayList<String>();
        for (int i = 0; i < 200; ++i) {
            write("dir%03d/key".formatted(i));
            prefixes.add("dir%03d/".formatted(i));
        }

        assertThat(listAll("/", 20)).containsExactlyElementsOf(prefixes);
        // a common prefix reports nothing of a directory marker there, so
        // no directory's extended attributes are read: it was every one of
        // them on each of the 10 pages
        assertThat(xattrViews.get()).isZero();
        assertThat(stats.get()).isLessThan(10 * 200 / 2);
    }
}
