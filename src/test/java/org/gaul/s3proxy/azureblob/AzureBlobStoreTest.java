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

import java.time.OffsetDateTime;
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
import com.azure.storage.blob.models.BlobItemProperties;

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

    /**
     * A page of versions maps onto Version entries newest-first, each with its
     * own id, size and reported ETag, exactly one flagged latest; Azure keeps
     * no delete markers, so that list stays empty and the page is not
     * truncated when no token follows.
     */
    @Test
    public void testVersionsPageMapsVersions() {
        var page = page(List.of(
                versionBlob("k", "0xV2", /*current=*/ true, /*size=*/ 5L),
                versionBlob("k", "0xV1", /*current=*/ false, /*size=*/ 3L)),
                /*continuationToken=*/ null);

        var response = store(/*versioning=*/ true).versionsPage(page, "k");

        assertThat(response.isTruncated()).isFalse();
        assertThat(response.deleteMarkers()).isEmpty();
        assertThat(response.versions()).hasSize(2);
        var latest = response.versions().get(0);
        assertThat(latest.key()).isEqualTo("k");
        assertThat(latest.versionId()).isEqualTo("0xV2");
        assertThat(latest.isLatest()).isTrue();
        assertThat(latest.size()).isEqualTo(5L);
        // opaque ETag mode reports Azure's token under the -1 suffix
        assertThat(latest.eTag()).isEqualTo("0xV2-1");
        assertThat(response.versions().get(1).isLatest()).isFalse();
    }

    /** A version Azure stamps with no id stands in as S3's "null" version. */
    @Test
    public void testVersionsPageNamesUnversionedBlobNull() {
        var page = page(List.of(
                versionBlob("k", /*versionId=*/ null, /*current=*/ true, 1L)),
                /*continuationToken=*/ null);

        var response = store(/*versioning=*/ true).versionsPage(page, "k");

        assertThat(response.versions().get(0).versionId()).isEqualTo("null");
    }

    /**
     * A truncated page carries Azure's opaque continuation token as the
     * version-id marker and the last key as the key marker, so a client that
     * echoes both resumes and neither marker comes out null.
     */
    @Test
    public void testVersionsPageTruncationCarriesMarkers() {
        var page = page(List.of(
                versionBlob("k", "0xV1", /*current=*/ true, 3L)),
                /*continuationToken=*/ "TOKEN");

        var response = store(/*versioning=*/ true).versionsPage(page, "k");

        assertThat(response.isTruncated()).isTrue();
        assertThat(response.nextKeyMarker()).isEqualTo("k");
        assertThat(response.nextVersionIdMarker()).isEqualTo("TOKEN");
    }

    /** The SAS token joins with '&' when the URL already carries a query. */
    @Test
    public void testSasSourceUrlJoins() {
        assertThat(AzureBlobStore.sasSourceUrl(
                "https://a.blob.core.windows.net/c/b", "sig=x"))
                .isEqualTo("https://a.blob.core.windows.net/c/b?sig=x");
        assertThat(AzureBlobStore.sasSourceUrl(
                "https://a.blob.core.windows.net/c/b?versionid=V", "sig=x"))
                .isEqualTo(
                        "https://a.blob.core.windows.net/c/b?versionid=V&sig=x");
    }

    private static BlobItem versionBlob(String name, String versionId,
            boolean current, long size) {
        return new BlobItem()
                .setName(name)
                .setVersionId(versionId)
                .setCurrentVersion(current)
                .setProperties(new BlobItemProperties()
                        .setETag(versionId == null ? "0x0" : versionId)
                        .setContentLength(size)
                        .setLastModified(
                                OffsetDateTime.parse("2026-01-01T00:00:00Z")));
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
