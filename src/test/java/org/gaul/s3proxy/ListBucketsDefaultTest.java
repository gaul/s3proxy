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

package org.gaul.s3proxy;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.Bucket;
import software.amazon.awssdk.services.s3.model.ListBucketsRequest;
import software.amazon.awssdk.services.s3.model.ListBucketsResponse;
import software.amazon.awssdk.services.s3.model.Owner;

/**
 * Covers the paging list(ListBucketsRequest) the BlobStore interface
 * supplies over the one-response list(): names sort, the prefix filters,
 * the token names the last bucket of the previous page, and the next
 * token appears only while more buckets remain.
 */
public final class ListBucketsDefaultTest {
    private static final Owner OWNER = Owner.builder()
            .id("id")
            .displayName("name")
            .build();

    /** The stores promise no order, so the page does the sorting. */
    @Test
    public void testSortsAndReturnsEverything() {
        var blobStore = new FakeBlobStore("bb", "aa", "cc");

        var response = blobStore.list(ListBucketsRequest.builder().build());

        assertThat(names(response)).containsExactly("aa", "bb", "cc");
        assertThat(response.continuationToken()).isNull();
        assertThat(response.owner()).isEqualTo(OWNER);
    }

    @Test
    public void testPrefixFilters() {
        var blobStore = new FakeBlobStore("aa", "ab", "ba");

        var response = blobStore.list(ListBucketsRequest.builder()
                .prefix("a")
                .build());

        assertThat(names(response)).containsExactly("aa", "ab");
        assertThat(response.prefix()).isEqualTo("a");
        assertThat(response.continuationToken()).isNull();
    }

    @Test
    public void testPagesWithLastNameTokens() {
        var blobStore = new FakeBlobStore("a", "b", "c", "d", "e");

        var page = blobStore.list(ListBucketsRequest.builder()
                .maxBuckets(2)
                .build());
        assertThat(names(page)).containsExactly("a", "b");
        assertThat(page.continuationToken()).isEqualTo("b");

        page = blobStore.list(ListBucketsRequest.builder()
                .maxBuckets(2)
                .continuationToken(page.continuationToken())
                .build());
        assertThat(names(page)).containsExactly("c", "d");
        assertThat(page.continuationToken()).isEqualTo("d");

        page = blobStore.list(ListBucketsRequest.builder()
                .maxBuckets(2)
                .continuationToken(page.continuationToken())
                .build());
        assertThat(names(page)).containsExactly("e");
        assertThat(page.continuationToken()).isNull();
    }

    /** A page the account exactly fills carries no token to a next one. */
    @Test
    public void testExactFitCarriesNoToken() {
        var blobStore = new FakeBlobStore("a", "b");

        var response = blobStore.list(ListBucketsRequest.builder()
                .maxBuckets(2)
                .build());

        assertThat(names(response)).containsExactly("a", "b");
        assertThat(response.continuationToken()).isNull();
    }

    /** Buckets past a full page that miss the prefix do not truncate it. */
    @Test
    public void testTrailingNonMatchesDoNotTruncate() {
        var blobStore = new FakeBlobStore("aa", "ab", "zz");

        var response = blobStore.list(ListBucketsRequest.builder()
                .prefix("a")
                .maxBuckets(2)
                .build());

        assertThat(names(response)).containsExactly("aa", "ab");
        assertThat(response.continuationToken()).isNull();
    }

    private static List<String> names(ListBucketsResponse response) {
        return response.buckets().stream().map(Bucket::name).toList();
    }

    /**
     * Answers the account's buckets in the order given, the way a store
     * with no order promise of its own would.
     */
    private static final class FakeBlobStore
            extends AbstractUnsupportedBlobStore {
        private final List<String> names;

        FakeBlobStore(String... names) {
            this.names = List.of(names);
        }

        @Override
        public ListBucketsResponse list() {
            return ListBucketsResponse.builder()
                    .buckets(names.stream()
                            .map(name -> Bucket.builder()
                                    .name(name)
                                    .build())
                            .toList())
                    .owner(OWNER)
                    .build();
        }
    }
}
