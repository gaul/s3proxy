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
import java.util.ArrayList;
import java.util.List;
import java.util.TreeSet;

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.BucketVersioningStatus;
import software.amazon.awssdk.services.s3.model.CommonPrefix;
import software.amazon.awssdk.services.s3.model.ListObjectVersionsRequest;
import software.amazon.awssdk.services.s3.model.ListObjectVersionsResponse;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.ObjectVersion;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.S3Object;

/**
 * A listing, of objects or of versions, used to gather an entry for all
 * that lies below the prefix before it cut the page asked for out of them:
 * heap in proportion to the bucket for a request of one key.  Now it keeps
 * one page of them as it reads, and these are the places where that takes
 * care: names met in no order, a page or marker that ends inside a directory
 * or inside a key, a marker whose version is gone, and the common prefixes
 * of a versions listing, which are rows of the page like any other.
 */
public final class Nio2ListingPageTest {
    private static final String CONTAINER = "container";
    private static final byte[] CONTENT = "content".getBytes(
            StandardCharsets.UTF_8);

    private TransientNio2BlobStore store;

    @BeforeEach
    public void setUp() {
        store = new TransientNio2BlobStore();
        store.createContainer(CONTAINER);
    }

    private void write(String key) {
        store.putBlob(PutObjectRequest.builder()
                        .bucket(CONTAINER).key(key)
                        .contentLength((long) CONTENT.length)
                        .build(),
                new ByteArrayInputStream(CONTENT));
    }

    /** The keys and common prefixes of one page of objects, in order. */
    private List<String> objects(@Nullable String prefix,
            @Nullable String delimiter, @Nullable Integer maxKeys,
            @Nullable String startAfter) {
        var response = store.list(ListObjectsV2Request.builder()
                .bucket(CONTAINER).prefix(prefix).delimiter(delimiter)
                .maxKeys(maxKeys).startAfter(startAfter).build());
        var names = new TreeSet<String>();
        response.contents().stream().map(S3Object::key).forEach(names::add);
        response.commonPrefixes().stream().map(CommonPrefix::prefix)
                .forEach(names::add);
        if (maxKeys != null) {
            assertThat(names).hasSizeLessThanOrEqualTo(maxKeys);
        }
        assertThat(response.nextContinuationToken()).isEqualTo(
                response.isTruncated() ? names.last() : null);
        return List.copyOf(names);
    }

    /** Every page of a listing of objects, each no longer than asked for. */
    private List<String> allObjects(@Nullable String prefix,
            @Nullable String delimiter, int maxKeys) {
        var names = new ArrayList<String>();
        while (true) {
            var page = objects(prefix, delimiter, maxKeys,
                    names.isEmpty() ? null : names.get(names.size() - 1));
            names.addAll(page);
            if (page.size() < maxKeys) {
                return names;
            }
        }
    }

    @Test
    public void testObjectPagesAddUpToTheWholeListing() {
        // names that sort around the slash of a directory beside them
        var keys = new TreeSet<String>(List.of("a!", "a.txt", "a/b", "a/c/d",
                "a/c0", "a0", "b/c/d/e", "z"));
        for (int i = 0; i < 30; i++) {
            keys.add("wide/%02d/blob".formatted(i));
            if (i % 10 == 0) {
                keys.add("wide/%02d/deeper/blob".formatted(i));
                keys.add("wide/%02d.txt".formatted(i));
            }
        }
        keys.forEach(this::write);

        assertThat(objects(null, null, null, null))
                .containsExactlyElementsOf(keys);
        for (int maxKeys : new int[] {1, 7, 1000}) {
            for (String prefix : new String[] {null, "a", "wide/", "wide/1"}) {
                assertThat(allObjects(prefix, null, maxKeys))
                        .as("%s by %s", prefix, maxKeys)
                        .containsExactlyElementsOf(keys.stream()
                                .filter(key -> prefix == null ||
                                        key.startsWith(prefix))
                                .toList());
            }
            // common prefixes page as the keys do
            assertThat(allObjects(null, "/", maxKeys))
                    .as("by %s", maxKeys)
                    .containsExactly("a!", "a.txt", "a/", "a0", "b/", "wide/",
                            "z");
            assertThat(allObjects("wide/", "/", maxKeys))
                    .as("by %s", maxKeys)
                    .hasSize(30 + 3)
                    .startsWith("wide/00.txt", "wide/00/", "wide/01/")
                    .endsWith("wide/29/");
        }

        // a marker inside a directory leaves out what is before it there
        // and nothing after
        assertThat(objects("a", null, null, "a/c"))
                .containsExactly("a/c/d", "a/c0", "a0");
        assertThat(objects(null, null, 2, "wide/29/blob"))
                .containsExactly("z");
        // and no key at all has nothing to continue from
        assertThat(objects(null, null, 0, null)).isEmpty();
    }

    /** Versions of every kind: current, archived, null and delete marker. */
    private void populate() {
        write("a");
        write("dir/null");
        store.putBucketVersioning(CONTAINER, BucketVersioningStatus.ENABLED);
        for (String key : List.of("a", "b", "dir/a", "dir/b/c", "dir/null",
                "dir0", "e")) {
            for (int i = 0; i < 3; i++) {
                write(key);
            }
        }
        // keys with nothing current, which only the sidecar names
        for (String key : List.of("b", "dir/b/c", "gone")) {
            write(key);
            store.removeBlob(CONTAINER, key, /*versionId=*/ null);
        }
    }

    private ListObjectVersionsResponse versions(@Nullable String prefix,
            @Nullable String delimiter, @Nullable Integer maxKeys,
            @Nullable String keyMarker, @Nullable String versionIdMarker) {
        return store.listVersions(ListObjectVersionsRequest.builder()
                .bucket(CONTAINER).prefix(prefix).delimiter(delimiter)
                .maxKeys(maxKeys).keyMarker(keyMarker)
                .versionIdMarker(versionIdMarker).build());
    }

    /** The rows of a page, which lists them in three parts, each in order. */
    private static List<String> rows(ListObjectVersionsResponse page) {
        var rows = new ArrayList<String>();
        page.versions().forEach(version -> rows.add(version.key() + " " +
                version.versionId() + " " + version.isLatest() + " " +
                version.size()));
        page.deleteMarkers().forEach(marker -> rows.add(marker.key() + " " +
                marker.versionId() + " " + marker.isLatest() + " marker"));
        page.commonPrefixes().stream().map(CommonPrefix::prefix)
                .forEach(rows::add);
        return rows;
    }

    /** Every page of a listing of versions, each no longer than asked for. */
    private List<String> allVersions(@Nullable String prefix,
            @Nullable String delimiter, int maxKeys) {
        var rows = new ArrayList<String>();
        String keyMarker = null;
        String versionIdMarker = null;
        while (true) {
            var page = versions(prefix, delimiter, maxKeys, keyMarker,
                    versionIdMarker);
            assertThat(rows(page)).hasSizeBetween(1, maxKeys);
            rows.addAll(rows(page));
            if (!page.isTruncated()) {
                return rows;
            }
            keyMarker = page.nextKeyMarker();
            versionIdMarker = page.nextVersionIdMarker();
        }
    }

    @Test
    public void testVersionPagesAddUpToTheWholeListing() {
        populate();

        var whole = versions(null, null, null, null, null);
        assertThat(whole.isTruncated()).isFalse();
        assertThat(whole.versions()).hasSize(2 + 7 * 3 + 3);
        assertThat(whole.deleteMarkers()).hasSize(3);
        // keys ascending, and of one key the newest first
        assertThat(whole.versions()).isSortedAccordingTo((one, other) ->
                one.key().equals(other.key()) ?
                        other.lastModified().compareTo(one.lastModified()) :
                        one.key().compareTo(other.key()));
        assertThat(whole.versions().stream()
                .filter(version -> version.isLatest())
                .map(version -> version.key()))
                .containsExactly("a", "dir/a", "dir/null", "dir0", "e");
        assertThat(whole.deleteMarkers())
                .allMatch(marker -> marker.isLatest())
                .extracting(marker -> marker.key())
                .containsExactly("b", "dir/b/c", "gone");

        for (int maxKeys : new int[] {1, 2, 3, 5, 29}) {
            assertThat(allVersions(null, null, maxKeys))
                    .as("max-keys %s", maxKeys)
                    .containsExactlyInAnyOrderElementsOf(rows(whole));
            assertThat(allVersions("dir", null, maxKeys))
                    .as("max-keys %s", maxKeys)
                    .containsExactlyInAnyOrderElementsOf(
                            rows(versions("dir", null, null, null, null)))
                    .hasSize(4 * 3 + 1 + 2);
        }
    }

    /** A common prefix counts towards max-keys and is listed once. */
    @Test
    public void testCommonPrefixesOfVersionsArePaged() {
        populate();
        for (int i = 0; i < 5; i++) {
            write("wide/%d/blob".formatted(i));
        }

        for (int maxKeys : new int[] {1, 2, 3, 1000}) {
            assertThat(allVersions(null, "/", maxKeys).stream()
                    .filter(row -> row.endsWith("/")))
                    .as("max-keys %s", maxKeys)
                    .containsExactly("dir/", "wide/");
            assertThat(allVersions(null, "/", maxKeys))
                    .as("max-keys %s", maxKeys)
                    .hasSize((1 + 3) + (3 + 2) + 3 + 3 + 2 + 2);
            assertThat(allVersions("wide/", "/", maxKeys))
                    .as("max-keys %s", maxKeys)
                    .containsExactly("wide/0/", "wide/1/", "wide/2/",
                            "wide/3/", "wide/4/");
            // any delimiter, and one the keys of a version only archived
            // roll up by as well
            assertThat(allVersions(null, "n", maxKeys).stream()
                    .filter(row -> row.endsWith("n")))
                    .as("max-keys %s", maxKeys)
                    .containsExactly("dir/n", "gon");
        }
        var first = versions(null, "/", 4 + 5 + 1, null, null);
        assertThat(first.commonPrefixes()).extracting(CommonPrefix::prefix)
                .containsExactly("dir/");
        assertThat(first.nextKeyMarker()).isEqualTo("dir/");
        assertThat(first.nextVersionIdMarker()).isNull();
    }

    /**
     * A bucket is emptied by deleting each page of versions before asking
     * for the next, so the version a marker names is gone by then and the
     * listing goes on from where it was.
     */
    @Test
    public void testVersionsResumeWhereADeletedVersionWas() {
        store.putBucketVersioning(CONTAINER, BucketVersioningStatus.ENABLED);
        for (String key : List.of("a", "b", "dir/a", "e")) {
            for (int i = 0; i < 4; i++) {
                write(key);
            }
        }
        store.removeBlob(CONTAINER, "b", /*versionId=*/ null);

        int listed = 0;
        String keyMarker = null;
        String versionIdMarker = null;
        while (true) {
            var page = versions(null, null, 3, keyMarker, versionIdMarker);
            for (var version : page.versions()) {
                store.removeBlob(CONTAINER, version.key(),
                        version.versionId());
                ++listed;
            }
            for (var marker : page.deleteMarkers()) {
                store.removeBlob(CONTAINER, marker.key(), marker.versionId());
                ++listed;
            }
            if (!page.isTruncated()) {
                break;
            }
            keyMarker = page.nextKeyMarker();
            versionIdMarker = page.nextVersionIdMarker();
        }

        assertThat(listed).isEqualTo(4 * 4 + 1);
        assertThat(rows(versions(null, null, null, null, null))).isEmpty();
    }

    /**
     * The null version has no place before or after a marker by its id, so
     * it follows a marker whose version is gone, also where it is the last
     * row of the listing.
     */
    @Test
    public void testVersionsResumeAtTheNullVersionOfTheLastKey() {
        write("key");
        store.putBucketVersioning(CONTAINER, BucketVersioningStatus.ENABLED);
        write("key");

        var first = versions(null, null, 1, null, null);
        assertThat(first.versions()).hasSize(1);
        assertThat(first.isTruncated()).isTrue();
        store.removeBlob(CONTAINER, "key", first.nextVersionIdMarker());

        var second = versions(null, null, 1, first.nextKeyMarker(),
                first.nextVersionIdMarker());
        assertThat(second.versions()).extracting(ObjectVersion::versionId)
                .containsExactly("null");
        assertThat(second.isTruncated()).isFalse();
    }
}
