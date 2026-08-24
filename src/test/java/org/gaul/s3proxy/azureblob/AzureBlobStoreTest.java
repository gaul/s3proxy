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

package org.gaul.s3proxy.azureblob;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.Queue;

import com.azure.core.http.HttpHeaders;
import com.azure.core.http.HttpMethod;
import com.azure.core.http.HttpRequest;
import com.azure.core.http.rest.PagedResponse;
import com.azure.core.http.rest.PagedResponseBase;
import com.azure.storage.blob.models.BlobItem;

import org.junit.jupiter.api.Test;

/**
 * Azure can answer a listing with no blobs and a continuation token onto ones
 * that do exist.  A page like that must not be handed on: an S3 client reading
 * a truncated result with nothing in it has no key to resume from.
 */
public final class AzureBlobStoreTest {
    /** The markers each call asked for, in order. */
    private final List<String> requested = new ArrayList<>();
    private final Queue<PagedResponse<BlobItem>> pages = new ArrayDeque<>();

    @Test
    public void testSkipsEmptyPages() {
        pages.add(page(List.of(), "one"));
        pages.add(page(List.of(), "two"));
        pages.add(page(List.of(blob("foo")), "three"));

        var page = AzureBlobStore.firstPageWithEntries(
                this::next, /*marker=*/ null);

        assertThat(names(page)).containsExactly("foo");
        assertThat(page.continuationToken()).isEqualTo("three");
        // Each page was fetched from the token the one before it named.
        assertThat(requested).containsExactly(null, "one", "two");
    }

    /** A container really is empty when the last page names no successor. */
    @Test
    public void testStopsWhenExhausted() {
        pages.add(page(List.of(), "one"));
        pages.add(page(List.of(), null));

        var page = AzureBlobStore.firstPageWithEntries(
                this::next, /*marker=*/ null);

        assertThat(page.values()).isEmpty();
        assertThat(page.continuationToken()).isNull();
        assertThat(requested).containsExactly(null, "one");
    }

    /** A page with entries is returned as it came, token and all. */
    @Test
    public void testReturnsAPopulatedPageUntouched() {
        pages.add(page(List.of(blob("foo"), blob("bar")), "one"));

        var page = AzureBlobStore.firstPageWithEntries(
                this::next, /*marker=*/ null);

        assertThat(names(page)).containsExactly("foo", "bar");
        assertThat(page.continuationToken()).isEqualTo("one");
        assertThat(requested).containsExactly((String) null);
    }

    /** A caller resuming a listing starts from the marker it was given. */
    @Test
    public void testResumesFromTheGivenMarker() {
        pages.add(page(List.of(), "two"));
        pages.add(page(List.of(blob("foo")), null));

        AzureBlobStore.firstPageWithEntries(this::next, "one");

        assertThat(requested).containsExactly("one", "two");
    }

    /**
     * startFrom includes the name it is given and start-after excludes it, so
     * the entry naming it is dropped and the rest of the page stands.
     */
    @Test
    public void testDropsTheNameStartAfterExcludes() {
        pages.add(page(List.of(blob("foo"), blob("goo")), "one"));

        var page = AzureBlobStore.firstPageWithEntries(this::next,
                /*marker=*/ null, blobs -> AzureBlobStore.afterStartAfter(
                        blobs, "foo"));

        assertThat(names(page)).containsExactly("goo");
        assertThat(page.continuationToken()).isEqualTo("one");
        assertThat(requested).containsExactly((String) null);
    }

    /**
     * A delimiter rolls the blobs start-after names up into the prefix it
     * lives under, so the page comes back naming a prefix S3 has already
     * reported.  Dropping it leaves nothing to report, and the marker is
     * followed as for any other empty page.
     */
    @Test
    public void testFollowsAPageHoldingOnlyExcludedNames() {
        pages.add(page(List.of(blob("boo/")), "one"));
        pages.add(page(List.of(blob("cquux/")), null));

        var page = AzureBlobStore.firstPageWithEntries(this::next,
                /*marker=*/ null, blobs -> AzureBlobStore.afterStartAfter(
                        blobs, "boo/"));

        assertThat(names(page)).containsExactly("cquux/");
        assertThat(page.continuationToken()).isNull();
        assertThat(requested).containsExactly(null, "one");
    }

    private PagedResponse<BlobItem> next(String marker) {
        requested.add(marker);
        return pages.remove();
    }

    private static PagedResponse<BlobItem> page(List<BlobItem> items,
            String continuationToken) {
        return new PagedResponseBase<HttpHeaders, BlobItem>(
                new HttpRequest(HttpMethod.GET, "http://127.0.0.1/container"),
                /*statusCode=*/ 200, new HttpHeaders(), items,
                continuationToken, /*deserializedHeaders=*/ null);
    }

    private static BlobItem blob(String name) {
        return new BlobItem().setName(name);
    }

    private static List<String> names(AzureBlobStore.Page<BlobItem> page) {
        return page.values().stream().map(BlobItem::getName).toList();
    }
}
