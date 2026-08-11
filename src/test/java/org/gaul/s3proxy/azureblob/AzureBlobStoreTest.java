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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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

import org.gaul.s3proxy.blobstore.Credentials;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.BucketVersioningStatus;
import software.amazon.awssdk.services.s3.model.S3Exception;

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

        PagedResponse<BlobItem> page = AzureBlobStore.firstPageWithEntries(
                this::next, /*marker=*/ null);

        assertThat(names(page)).containsExactly("foo");
        assertThat(page.getContinuationToken()).isEqualTo("three");
        // Each page was fetched from the token the one before it named.
        assertThat(requested).containsExactly(null, "one", "two");
    }

    /** A container really is empty when the last page names no successor. */
    @Test
    public void testStopsWhenExhausted() {
        pages.add(page(List.of(), "one"));
        pages.add(page(List.of(), null));

        PagedResponse<BlobItem> page = AzureBlobStore.firstPageWithEntries(
                this::next, /*marker=*/ null);

        assertThat(page.getValue()).isEmpty();
        assertThat(page.getContinuationToken()).isNull();
        assertThat(requested).containsExactly(null, "one");
    }

    /** A page with entries is returned as it came, token and all. */
    @Test
    public void testReturnsAPopulatedPageUntouched() {
        pages.add(page(List.of(blob("foo"), blob("bar")), "one"));

        PagedResponse<BlobItem> page = AzureBlobStore.firstPageWithEntries(
                this::next, /*marker=*/ null);

        assertThat(names(page)).containsExactly("foo", "bar");
        assertThat(page.getContinuationToken()).isEqualTo("one");
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
     * Versioning is off unless the operator opts in, since Azure enables it
     * out of band and the SDK cannot read the setting back.  Opted in, the
     * store reports the account versioned and refuses the per-bucket suspend
     * Azure has no way to honor.
     */
    @Test
    public void testVersioningIsOptIn() {
        assertThat(store(/*versioning=*/ false).supportsVersioning()).isFalse();

        AzureBlobStore on = store(/*versioning=*/ true);
        assertThat(on.supportsVersioning()).isTrue();
        assertThat(on.getContainerVersioning("container"))
                .isEqualTo(BucketVersioningStatus.ENABLED);
        // Enabling is a no-op the account already satisfies.
        on.setContainerVersioning("container", BucketVersioningStatus.ENABLED);
        // Suspending is refused NotImplemented (501).
        assertThatThrownBy(() -> on.setContainerVersioning(
                "container", BucketVersioningStatus.SUSPENDED))
                .isInstanceOfSatisfying(S3Exception.class,
                        e -> assertThat(e.statusCode()).isEqualTo(501));
    }

    private static AzureBlobStore store(boolean versioning) {
        // The endpoint and key are never dialed: the Azure client builds
        // lazily, and these calls read local state only.
        return new AzureBlobStore(
                () -> new Credentials("account", "key"),
                "https://account.blob.core.windows.net",
                /*eTagMode=*/ "opaque", versioning);
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

    private static List<String> names(PagedResponse<BlobItem> page) {
        return page.getValue().stream().map(BlobItem::getName).toList();
    }
}
