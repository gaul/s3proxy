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
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
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

    /**
     * Versioning is off unless the operator opts in, since Azure enables it
     * out of band and the SDK cannot read the setting back.  Opted in, the
     * store reports the account versioned and refuses the per-bucket suspend
     * Azure has no way to honor, before it looks for the container.  Reading
     * or enabling versioning checks the container exists, so needs a backend.
     */
    @Test
    public void testVersioningIsOptIn() {
        assertThat(store(/*versioning=*/ false).supportsVersioning()).isFalse();

        AzureBlobStore on = store(/*versioning=*/ true);
        assertThat(on.supportsVersioning()).isTrue();
        // Suspending is refused NotImplemented (501).
        assertThatThrownBy(() -> on.putBucketVersioning(
                "container", BucketVersioningStatus.SUSPENDED))
                .isInstanceOfSatisfying(S3Exception.class,
                        e -> assertThat(e.statusCode()).isEqualTo(501));
    }

    /**
     * S3 refuses If-Match on a delete naming a version -- 501 NotImplemented,
     * whether or not the ETag matches -- so the store refuses it too, before
     * dialing the service, though Azure itself could judge the condition
     * against the version named.
     */
    @Test
    public void testRefusesConditionalDeleteOfVersion() {
        assertThatThrownBy(() -> store(/*versioning=*/ true).removeBlob(
                DeleteObjectRequest.builder()
                        .bucket("container")
                        .key("key")
                        .versionId("2026-01-01T00:00:00.0000000Z")
                        .ifMatch("\"0x8DE0000000000000-1\"")
                        .build()))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    /**
     * Azure lists a key's versions oldest first and flags only the current one
     * (isCurrentVersion is null, not false, on the rest), as a real account
     * answers.  S3 lists them newest first, so the page maps onto Version
     * entries newest first, each with its own id, size and reported ETag,
     * exactly one flagged latest; Azure keeps no delete markers, so that list
     * stays empty and the page is not truncated when no token follows.
     */
    @Test
    public void testVersionsPageMapsVersions() {
        var rows = List.of(
                versionBlob("k", "0xV1", /*current=*/ false, /*size=*/ 3L),
                versionBlob("k", "0xV2", /*current=*/ true, /*size=*/ 5L));

        var response = store(/*versioning=*/ true).versionsPage(
                rows.iterator(), /*keyMarker=*/ null,
                /*versionIdMarker=*/ null, /*maxKeys=*/ 1000);

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

    /**
     * A blob written while the account's versioning was off has no version
     * id.  Once versioning is back on, a real account lists it after the
     * versions written before it, with no id and with isCurrentVersion unset
     * like every other version, though it is the one a plain read serves.  It
     * stands in as S3's "null" version, and is the latest.
     */
    @Test
    public void testVersionsPageNamesUnversionedBlobNull() {
        var rows = List.of(
                versionBlob("k", "0xV1", /*current=*/ false, 3L),
                versionBlob("k", /*versionId=*/ null, /*current=*/ false, 1L));

        var response = store(/*versioning=*/ true).versionsPage(
                rows.iterator(), /*keyMarker=*/ null,
                /*versionIdMarker=*/ null, /*maxKeys=*/ 1000);

        var unversioned = response.versions().stream()
                .filter(v -> v.versionId().equals("null")).findFirst()
                .orElseThrow();
        assertThat(unversioned.isLatest()).isTrue();
    }

    /**
     * A page that fills inside a key -- one whose versions may straddle
     * Azure's pages -- ends on S3's own (key, version-id) markers, and
     * resuming from them, which startFrom lists from the marker's key again,
     * picks up with that key's next older version.  A key marker naming no
     * version resumes after the key.
     */
    @Test
    public void testVersionsPageResumesInsideAKey() {
        var rows = List.of(
                versionBlob("k", "2026-01-01T00:00:01.0000000Z", false, 1L),
                versionBlob("k", "2026-01-01T00:00:02.0000000Z", false, 2L),
                versionBlob("k", "2026-01-01T00:00:03.0000000Z", true, 3L),
                versionBlob("m", "2026-01-01T00:00:04.0000000Z", true, 4L));
        AzureBlobStore store = store(/*versioning=*/ true);

        var first = store.versionsPage(rows.iterator(), /*keyMarker=*/ null,
                /*versionIdMarker=*/ null, /*maxKeys=*/ 2);
        assertThat(first.isTruncated()).isTrue();
        assertThat(first.versions()).extracting(v -> v.versionId())
                .containsExactly("2026-01-01T00:00:03.0000000Z",
                        "2026-01-01T00:00:02.0000000Z");
        assertThat(first.nextKeyMarker()).isEqualTo("k");
        assertThat(first.nextVersionIdMarker())
                .isEqualTo("2026-01-01T00:00:02.0000000Z");

        var second = store.versionsPage(rows.iterator(),
                first.nextKeyMarker(), first.nextVersionIdMarker(),
                /*maxKeys=*/ 2);
        assertThat(second.isTruncated()).isFalse();
        assertThat(second.versions()).extracting(v -> v.key())
                .containsExactly("k", "m");
        assertThat(second.versions().get(0).versionId())
                .isEqualTo("2026-01-01T00:00:01.0000000Z");

        var afterKey = store.versionsPage(rows.iterator(), "k",
                /*versionIdMarker=*/ null, /*maxKeys=*/ 2);
        assertThat(afterKey.versions()).extracting(v -> v.key())
                .containsExactly("m");
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
                // Azure omits the flag, rather than sending false, on
                // every version but the current one.
                .setCurrentVersion(current ? Boolean.TRUE : null)
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

    private static List<String> names(AzureBlobStore.Page<BlobItem> page) {
        return page.values().stream().map(BlobItem::getName).toList();
    }
}
