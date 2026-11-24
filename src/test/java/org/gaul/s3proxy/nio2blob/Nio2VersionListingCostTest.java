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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.BucketVersioningStatus;
import software.amazon.awssdk.services.s3.model.ListObjectVersionsRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

/**
 * Listing a bucket's versions reads each non-current version once, through
 * the file the enumeration of the sidecar directory found it in.  It used to
 * ask for each by its version id instead, which enumerates that directory
 * again to find the file: a listing cost the square of the number of
 * non-current versions, whatever max-keys asked for, and a few hundred
 * anonymous listings of a public-read bucket holding some thousand versions
 * occupied every server thread for minutes.
 */
public final class Nio2VersionListingCostTest {
    private static final String MANY_KEYS = "many-keys";
    private static final String ONE_KEY = "one-key";
    private static final String WARM_UP = "warm-up";
    private static final String KEY = "myobj";
    private static final byte[] CONTENT =
            "content".getBytes(StandardCharsets.UTF_8);
    private static final int COUNT = 2_000;

    private TransientNio2BlobStore store;

    @BeforeEach
    public void setUp() {
        store = new TransientNio2BlobStore();
        for (var container : new String[] {MANY_KEYS, ONE_KEY, WARM_UP}) {
            store.createContainer(container);
            store.putBucketVersioning(container,
                    BucketVersioningStatus.ENABLED);
        }
    }

    private void write(String container, String key) {
        store.putBlob(PutObjectRequest.builder()
                        .bucket(container).key(key)
                        .contentLength((long) CONTENT.length)
                        .build(),
                new ByteArrayInputStream(CONTENT));
    }

    /**
     * The quickest of up to {@code attempts} one-row listings, in
     * nanoseconds, stopping at the first that takes less than
     * {@code enough}.
     */
    private long listOneRow(String container, int attempts, long enough) {
        long quickest = Long.MAX_VALUE;
        for (int i = 0; i < attempts && quickest >= enough; ++i) {
            long start = System.nanoTime();
            var listing = store.listVersions(ListObjectVersionsRequest
                    .builder().bucket(container).maxKeys(1).build());
            quickest = Math.min(quickest, System.nanoTime() - start);
            assertThat(listing.versions()).hasSize(1);
            assertThat(listing.isTruncated()).isTrue();
        }
        return quickest;
    }

    @Test
    public void testListVersionsCostIsNotQuadratic() {
        // As many rows either way: one version each of many keys, where
        // nothing is non-current, and as many versions of one key, where
        // all but one are.
        for (int i = 0; i < COUNT; ++i) {
            write(MANY_KEYS, KEY + i);
            write(ONE_KEY, KEY);
        }
        for (int i = 0; i < 100; ++i) {
            write(WARM_UP, KEY);
        }
        for (int i = 0; i < 20; ++i) {
            listOneRow(WARM_UP, 1, 0);
            listOneRow(MANY_KEYS, 1, 0);
        }

        // A clock would say how fast the machine is, so the measure is the
        // other bucket: reading a version is about the work reading a key
        // is, and the same number of them costs a small multiple.  Looking
        // each one up again cost several hundred times as much at this
        // size, so the bound is generous both ways.
        long manyKeys = listOneRow(MANY_KEYS, 5, 0);
        long bound = 50 * manyKeys;
        long oneKey = listOneRow(ONE_KEY, 3, bound);
        assertThat(oneKey).as("nanoseconds to list one row of %d versions" +
                " of one key, against %d for one row of %d keys", COUNT,
                manyKeys, COUNT).isLessThan(bound);
    }

    @Test
    public void testListVersionsReportsEachVersion() {
        for (int i = 0; i < 10; ++i) {
            write(ONE_KEY, KEY);
        }

        var versions = store.listVersions(ListObjectVersionsRequest.builder()
                .bucket(ONE_KEY).build()).versions();

        assertThat(versions).hasSize(10);
        assertThat(versions).extracting(version -> version.versionId())
                .doesNotHaveDuplicates();
        assertThat(versions).allSatisfy(version -> {
            assertThat(version.key()).isEqualTo(KEY);
            assertThat(version.size()).isEqualTo(CONTENT.length);
            assertThat(version.eTag()).isEqualTo(versions.get(0).eTag());
        });
        assertThat(versions).filteredOn(version -> version.isLatest())
                .hasSize(1);
    }
}
