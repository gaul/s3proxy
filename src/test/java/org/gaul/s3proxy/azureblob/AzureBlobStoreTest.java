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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Queue;

import com.azure.core.http.HttpHeaderName;
import com.azure.core.http.HttpHeaders;
import com.azure.core.http.HttpMethod;
import com.azure.core.http.HttpRequest;
import com.azure.core.http.rest.PagedResponse;
import com.azure.core.http.rest.PagedResponseBase;
import com.azure.storage.blob.models.BlobItem;
import com.azure.storage.blob.models.BlobItemProperties;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import org.gaul.s3proxy.blobstore.Credentials;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.BucketVersioningStatus;
import software.amazon.awssdk.services.s3.model.CopyObjectRequest;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.HeadObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.S3Exception;

/**
 * Azure can answer a listing with no blobs and a continuation token onto ones
 * that do exist.  A page like that must not be handed on: an S3 client reading
 * a truncated result with nothing in it has no key to resume from.
 */
public final class AzureBlobStoreTest {
    /** The version a key left without a current one falls to. */
    private static final String REMAINING = "2026-01-01T00:00:00.0000000Z";

    /** The markers each call asked for, in order. */
    private final List<String> requested = new ArrayList<>();
    private final Queue<PagedResponse<BlobItem>> pages = new ArrayDeque<>();
    /** What the fake Azure was asked, as "METHOD path?query". */
    private final List<String> azureRequests =
            Collections.synchronizedList(new ArrayList<String>());
    /** How the fake Azure answers a listing of the container's versions. */
    private int listStatus = 200;
    private @Nullable HttpServer server;

    @AfterEach
    public void tearDown() {
        if (server != null) {
            server.stop(0);
        }
    }

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
     * out of band and the SDK cannot read the setting back.  Reading,
     * enabling or suspending it reads the container's metadata, so needs a
     * backend.
     */
    @Test
    public void testVersioningIsOptIn() {
        assertThat(store(/*versioning=*/ false).supportsVersioning()).isFalse();
        assertThat(store(/*versioning=*/ true).supportsVersioning()).isTrue();
    }

    /**
     * A container records Suspended in its metadata, in any spelling Azure
     * hands back, and a container without the entry -- one nobody has
     * suspended -- is Enabled, never unversioned.
     */
    @Test
    public void testVersioningStatusFromContainerMetadata() {
        assertThat(AzureBlobStore.versioningStatus(Map.of()))
                .isEqualTo(BucketVersioningStatus.ENABLED);
        assertThat(AzureBlobStore.versioningStatus(
                Map.of("S3Proxy_Versioning", "suspended")))
                .isEqualTo(BucketVersioningStatus.SUSPENDED);
        assertThat(AzureBlobStore.versioningStatus(
                Map.of("s3proxy_versioning", "Enabled")))
                .isEqualTo(BucketVersioningStatus.ENABLED);
    }

    /**
     * Azure replaces a container's metadata whole, so suspending or enabling
     * keeps every other entry, and a request that changes nothing writes
     * nothing.  Enabled is the entry's absence.
     */
    @Test
    public void testVersioningStatusMergesContainerMetadata() {
        var other = Map.of("owner", "team");

        var suspended = AzureBlobStore.withVersioningStatus(other,
                BucketVersioningStatus.SUSPENDED);
        assertThat(suspended).containsExactlyInAnyOrderEntriesOf(Map.of(
                "owner", "team", "s3proxy_versioning", "Suspended"));
        assertThat(AzureBlobStore.withVersioningStatus(suspended,
                BucketVersioningStatus.SUSPENDED)).isNull();

        assertThat(AzureBlobStore.withVersioningStatus(
                Map.of("owner", "team", "S3PROXY_VERSIONING", "Suspended"),
                BucketVersioningStatus.ENABLED))
                .containsExactlyEntriesOf(other);
        assertThat(AzureBlobStore.withVersioningStatus(other,
                BucketVersioningStatus.ENABLED)).isNull();
    }

    /**
     * A version written while Suspended carries the null-version tag, and
     * one written while Enabled carries nothing of the store's own.
     */
    @Test
    public void testWithNullVersionTag() {
        var metadata = Map.of("color", "blue");

        assertThat(AzureBlobStore.withNullVersionTag(metadata,
                /*suspended=*/ false)).isSameAs(metadata);
        assertThat(AzureBlobStore.withNullVersionTag(metadata,
                /*suspended=*/ true)).containsExactlyInAnyOrderEntriesOf(
                        Map.of("color", "blue",
                                "s3proxy_null_version", "true"));
    }

    /**
     * The null version is reported as "null" whether it is the blob written
     * before the account was versioned, which has no id, or one written
     * while Suspended, whose Azure id is never handed out.
     */
    @Test
    public void testReportedVersionId() {
        assertThat(AzureBlobStore.reportedVersionId(
                "2026-01-01T00:00:01.0000000Z", Map.of()))
                .isEqualTo("2026-01-01T00:00:01.0000000Z");
        assertThat(AzureBlobStore.reportedVersionId(
                "2026-01-01T00:00:01.0000000Z",
                Map.of("s3proxy_null_version", "true")))
                .isEqualTo("null");
        assertThat(AzureBlobStore.reportedVersionId(/*versionId=*/ null,
                /*metadata=*/ null)).isEqualTo("null");
    }

    /**
     * Of a key's versions, the null version is the newest one written while
     * Suspended -- an older one being a null version that a later write
     * replaced but did not get to remove -- or the blob that carries no id,
     * which no versioned write can have come after.  A key written only
     * while Enabled has none.
     */
    @Test
    public void testNullVersionIsTheNewestTagged() {
        var older = nullTagged(versionBlob("k",
                "2026-01-01T00:00:01.0000000Z", false, 1L));
        var newer = nullTagged(versionBlob("k",
                "2026-01-01T00:00:03.0000000Z", false, 3L));
        var enabled = versionBlob("k", "2026-01-01T00:00:04.0000000Z",
                true, 4L);

        assertThat(AzureBlobStore.nullVersion(List.of(older, newer, enabled)))
                .isSameAs(newer);
        assertThat(AzureBlobStore.nullVersion(List.of(enabled))).isNull();
        var unversioned = versionBlob("k", /*versionId=*/ null, false, 1L);
        assertThat(AzureBlobStore.nullVersion(List.of(
                versionBlob("k", "2026-01-01T00:00:01.0000000Z", false, 1L),
                unversioned))).isSameAs(unversioned);
    }

    /**
     * A null version written while Suspended lists as "null", in its place
     * by time: versioning enabled again since, the versions written after it
     * list before it, and the newest of them is the latest.  An older tagged
     * version, one a later suspended write replaced, is no version S3 has
     * and is left out.
     */
    @Test
    public void testVersionsPageNamesTaggedVersionNull() {
        var rows = List.of(
                nullTagged(versionBlob("k", "2026-01-01T00:00:01.0000000Z",
                        false, 1L)),
                versionBlob("k", "2026-01-01T00:00:02.0000000Z", false, 2L),
                nullTagged(versionBlob("k", "2026-01-01T00:00:03.0000000Z",
                        false, 3L)),
                versionBlob("k", "2026-01-01T00:00:04.0000000Z", true, 4L));

        var response = store(/*versioning=*/ true).versionsPage(
                rows.iterator(), /*keyMarker=*/ null,
                /*versionIdMarker=*/ null, /*maxKeys=*/ 1000);

        assertThat(response.versions()).extracting(v -> v.versionId())
                .containsExactly("2026-01-01T00:00:04.0000000Z", "null",
                        "2026-01-01T00:00:02.0000000Z");
        assertThat(response.versions()).extracting(v -> v.isLatest())
                .containsExactly(true, false, false);
        assertThat(response.versions().get(1).size()).isEqualTo(3L);
    }

    /**
     * A page ending on the null version hands out "null" as the version-id
     * marker, which says nothing of where the null version sits once
     * versions newer than it exist; resuming from it picks up with the
     * versions older than the null version, not every version of the key.
     */
    @Test
    public void testVersionsPageResumesAfterTheNullVersion() {
        var rows = List.of(
                versionBlob("k", "2026-01-01T00:00:01.0000000Z", false, 1L),
                nullTagged(versionBlob("k", "2026-01-01T00:00:02.0000000Z",
                        false, 2L)),
                versionBlob("k", "2026-01-01T00:00:03.0000000Z", true, 3L));
        AzureBlobStore store = store(/*versioning=*/ true);

        var first = store.versionsPage(rows.iterator(), /*keyMarker=*/ null,
                /*versionIdMarker=*/ null, /*maxKeys=*/ 2);
        assertThat(first.versions()).extracting(v -> v.versionId())
                .containsExactly("2026-01-01T00:00:03.0000000Z", "null");
        assertThat(first.nextVersionIdMarker()).isEqualTo("null");

        var second = store.versionsPage(rows.iterator(),
                first.nextKeyMarker(), first.nextVersionIdMarker(),
                /*maxKeys=*/ 2);
        assertThat(second.isTruncated()).isFalse();
        assertThat(second.versions()).extracting(v -> v.versionId())
                .containsExactly("2026-01-01T00:00:01.0000000Z");
    }

    /**
     * A delete while Suspended writes a delete marker that is itself the null
     * version, which lists as a DeleteMarker entry named "null".
     */
    @Test
    public void testVersionsPageReportsNullDeleteMarker() {
        var rows = List.of(
                versionBlob("k", "2026-01-01T00:00:01.0000000Z", false, 3L),
                nullTagged(deleteMarker(versionBlob("k",
                        "2026-01-01T00:00:02.0000000Z", true, 0L))));

        var response = store(/*versioning=*/ true).versionsPage(
                rows.iterator(), /*keyMarker=*/ null,
                /*versionIdMarker=*/ null, /*maxKeys=*/ 1000);

        assertThat(response.deleteMarkers()).hasSize(1);
        assertThat(response.deleteMarkers().get(0).versionId())
                .isEqualTo("null");
        assertThat(response.deleteMarkers().get(0).isLatest()).isTrue();
        assertThat(response.versions()).extracting(v -> v.versionId())
                .containsExactly("2026-01-01T00:00:01.0000000Z");
    }

    /**
     * A suspended write that landed removes the null versions it replaced:
     * those written while Suspended before it, and the version Azure minted
     * for the base blob that had no id, found by the ETag it had.  It keeps
     * versions written while Enabled, itself, and a null version written
     * after it by a write it raced, which replaces it in turn.
     */
    @Test
    public void testReplacedNullVersions() {
        String written = "2026-01-01T00:00:05.0000000Z";
        var rows = List.of(
                versionBlob("k", "2026-01-01T00:00:01.0000000Z", false, 1L)
                        .setProperties(new BlobItemProperties()
                                .setETag("0xLEGACY")),
                nullTagged(versionBlob("k", "2026-01-01T00:00:02.0000000Z",
                        false, 2L)),
                versionBlob("k", "2026-01-01T00:00:03.0000000Z", false, 3L),
                nullTagged(versionBlob("k", written, false, 5L)),
                nullTagged(versionBlob("k", "2026-01-01T00:00:06.0000000Z",
                        true, 6L)));

        assertThat(AzureBlobStore.replacedNullVersions(rows, written,
                /*legacyETag=*/ "0xLEGACY")).containsExactly(
                        "2026-01-01T00:00:01.0000000Z",
                        "2026-01-01T00:00:02.0000000Z");
        assertThat(AzureBlobStore.replacedNullVersions(rows, written,
                /*legacyETag=*/ null)).containsExactly(
                        "2026-01-01T00:00:02.0000000Z");
    }

    /**
     * A copy lands with the source's metadata, or the request's under
     * REPLACE, never the store's own entries: a copy of the null version
     * made while Enabled is not the null version.  Made while the
     * destination is Suspended, the copy is.
     */
    @Test
    public void testCopiedMetadata() {
        var source = Map.of("color", "blue", "s3proxy_null_version", "true");
        var requested = Map.of("shape", "round");

        assertThat(AzureBlobStore.copiedMetadata(source, requested,
                /*replace=*/ false, /*suspended=*/ false))
                .containsExactlyEntriesOf(Map.of("color", "blue"));
        assertThat(AzureBlobStore.copiedMetadata(source, requested,
                /*replace=*/ true, /*suspended=*/ false))
                .containsExactlyEntriesOf(requested);
        assertThat(AzureBlobStore.copiedMetadata(Map.of("color", "blue"),
                requested, /*replace=*/ false, /*suspended=*/ true))
                .containsExactlyInAnyOrderEntriesOf(Map.of("color", "blue",
                        "s3proxy_null_version", "true"));
        assertThat(AzureBlobStore.copiedMetadata(/*source=*/ null,
                Map.of(), /*replace=*/ false, /*suspended=*/ false))
                .isEmpty();
    }

    /** Metadata rides on Put Blob From URL as x-ms-meta-* headers. */
    @Test
    public void testMetadataHeaders() {
        var headers = AzureBlobStore.metadataHeaders(
                Map.of("color", "blue", "s3proxy_null_version", "true"));

        assertThat(headers.getValue(
                HttpHeaderName.fromString("x-ms-meta-color")))
                .isEqualTo("blue");
        assertThat(headers.getValue(HttpHeaderName.fromString(
                "x-ms-meta-s3proxy_null_version"))).isEqualTo("true");
        assertThat(headers.getSize()).isEqualTo(2);
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

    /**
     * A versioned delete writes an empty blob tagged as a delete marker,
     * which a real account lists with its metadata like any version.  It is
     * reported as a DeleteMarker entry, not a Version, and as the latest
     * when it is the current blob.
     */
    @Test
    public void testVersionsPageReportsDeleteMarkers() {
        var rows = List.of(
                versionBlob("k", "2026-01-01T00:00:01.0000000Z", false, 3L),
                deleteMarker(versionBlob("k", "2026-01-01T00:00:02.0000000Z",
                        /*current=*/ true, 0L)));

        var response = store(/*versioning=*/ true).versionsPage(
                rows.iterator(), /*keyMarker=*/ null,
                /*versionIdMarker=*/ null, /*maxKeys=*/ 1000);

        assertThat(response.deleteMarkers()).hasSize(1);
        var marker = response.deleteMarkers().get(0);
        assertThat(marker.versionId()).isEqualTo("2026-01-01T00:00:02.0000000Z");
        assertThat(marker.isLatest()).isTrue();
        assertThat(response.versions()).extracting(v -> v.versionId())
                .containsExactly("2026-01-01T00:00:01.0000000Z");
        assertThat(response.versions().get(0).isLatest()).isFalse();
    }

    /**
     * Once the current version is deleted by id a real account flags no
     * version of the key current; S3 promotes the newest remaining one, so
     * that one is the latest.
     */
    @Test
    public void testVersionsPagePromotesNewestWhenNoneCurrent() {
        var rows = List.of(
                versionBlob("k", "2026-01-01T00:00:01.0000000Z", false, 3L),
                versionBlob("k", "2026-01-01T00:00:02.0000000Z", false, 5L));

        var response = store(/*versioning=*/ true).versionsPage(
                rows.iterator(), /*keyMarker=*/ null,
                /*versionIdMarker=*/ null, /*maxKeys=*/ 1000);

        assertThat(response.versions()).extracting(v -> v.isLatest())
                .containsExactly(true, false);
        assertThat(response.versions().get(0).versionId())
                .isEqualTo("2026-01-01T00:00:02.0000000Z");
    }

    /**
     * A versioned listing reports each key once, by its latest version, and
     * leaves out a key whose latest version is a delete marker.
     */
    @Test
    public void testLatestPageHidesDeleteMarkers() {
        var rows = List.of(
                versionBlob("a", "2026-01-01T00:00:01.0000000Z", false, 1L),
                versionBlob("a", "2026-01-01T00:00:02.0000000Z", true, 2L),
                versionBlob("b", "2026-01-01T00:00:01.0000000Z", false, 3L),
                deleteMarker(versionBlob("b",
                        "2026-01-01T00:00:02.0000000Z", true, 0L)));

        var response = store(/*versioning=*/ true).latestPage(
                rows.iterator(), /*after=*/ null, /*maxKeys=*/ 1000);

        assertThat(response.contents()).hasSize(1);
        assertThat(response.contents().get(0).key()).isEqualTo("a");
        assertThat(response.contents().get(0).size()).isEqualTo(2L);
        assertThat(response.isTruncated()).isFalse();
    }

    /**
     * A key whose current version was deleted by id has no current version
     * left, and is listed by its newest remaining one, which reads serve --
     * including a key "undeleted" by deleting its delete marker.
     */
    @Test
    public void testLatestPageListsPromotedVersion() {
        var rows = List.of(
                versionBlob("k", "2026-01-01T00:00:01.0000000Z", false, 1L),
                versionBlob("k", "2026-01-01T00:00:02.0000000Z", false, 2L));

        var response = store(/*versioning=*/ true).latestPage(
                rows.iterator(), /*after=*/ null, /*maxKeys=*/ 1000);

        assertThat(response.contents()).hasSize(1);
        assertThat(response.contents().get(0).key()).isEqualTo("k");
        assertThat(response.contents().get(0).size()).isEqualTo(2L);
    }

    /**
     * A truncated versioned listing resumes after the last key it reported,
     * however that key's versions fell across Azure's pages.
     */
    @Test
    public void testLatestPageResumesAfterLastKey() {
        var rows = List.of(
                versionBlob("a", "2026-01-01T00:00:01.0000000Z", false, 1L),
                versionBlob("a", "2026-01-01T00:00:02.0000000Z", true, 2L),
                versionBlob("b", "2026-01-01T00:00:01.0000000Z", true, 3L),
                versionBlob("c", "2026-01-01T00:00:01.0000000Z", true, 4L));
        var store = store(/*versioning=*/ true);

        var first = store.latestPage(rows.iterator(), /*after=*/ null,
                /*maxKeys=*/ 2);
        assertThat(first.contents()).extracting(o -> o.key())
                .containsExactly("a", "b");
        assertThat(first.isTruncated()).isTrue();

        // startFrom includes the name the page resumes after.
        String after = AzureBlobStore.decodeListToken(
                first.nextContinuationToken());
        assertThat(after).isEqualTo("b");
        var second = store.latestPage(rows.subList(2, 4).iterator(), after,
                /*maxKeys=*/ 2);
        assertThat(second.contents()).extracting(o -> o.key())
                .containsExactly("c");
        assertThat(second.isTruncated()).isFalse();
    }

    /** S3 answers a listing asking for no keys as complete. */
    @Test
    public void testLatestPageMaxKeysZero() {
        var rows = List.of(
                versionBlob("a", "2026-01-01T00:00:01.0000000Z", true, 1L));

        var response = store(/*versioning=*/ true).latestPage(
                rows.iterator(), /*after=*/ null, /*maxKeys=*/ 0);

        assertThat(response.contents()).isEmpty();
        assertThat(response.isTruncated()).isFalse();
    }

    /** A continuation token round-trips any key, '+' and '%' included. */
    @Test
    public void testListTokenRoundTrips() {
        String name = "dir/a+b %2F\u00e9";
        assertThat(AzureBlobStore.decodeListToken(
                AzureBlobStore.encodeListToken(name))).isEqualTo(name);
        assertThatThrownBy(() -> AzureBlobStore.decodeListToken("not*base64"))
                .isInstanceOf(S3Exception.class);
    }

    /**
     * A caller cannot mark an object as a delete marker, or retarget a
     * multipart upload, through user metadata, in any spelling.
     */
    @Test
    public void testReservedMetadataDropped() {
        var metadata = Map.of("S3Proxy_Delete_Marker", "true",
                "S3Proxy_Null_Version", "true",
                "s3proxy_target_blob_name", "other", "color", "blue");

        assertThat(AzureBlobStore.withoutReservedMetadata(metadata))
                .containsExactlyEntriesOf(Map.of("color", "blue"));
        var plain = Map.of("color", "blue");
        assertThat(AzureBlobStore.withoutReservedMetadata(plain))
                .isSameAs(plain);
    }

    /**
     * A version is timed by its id, which Azure stamps to a tenth of a
     * microsecond, not by the whole-second Last-Modified it lists: a PUT and
     * the delete marker after it in the same second still order.  The
     * version written while unversioned has no id and keeps Last-Modified.
     */
    @Test
    public void testVersionTimeFromVersionId() {
        var put = versionBlob("k", "2026-01-01T00:00:00.1000000Z", false, 1L);
        var marker = deleteMarker(versionBlob("k",
                "2026-01-01T00:00:00.2000000Z", true, 0L));

        assertThat(AzureBlobStore.versionTime(marker))
                .isAfter(AzureBlobStore.versionTime(put));
        assertThat(AzureBlobStore.versionTime(versionBlob("k", null, true, 1L)))
                .isEqualTo(OffsetDateTime.parse("2026-01-01T00:00:00Z")
                        .toInstant());
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

    /**
     * A read of a key with no current version lists its versions to find the
     * one to promote.  A credential refused that listing -- an account SAS
     * without resource type c, which Azure answers 403
     * AuthorizationResourceTypeMismatch -- is answered AccessDenied naming
     * the permission, as S3 answers a missing key to a caller that may not
     * list the bucket, rather than 500.  A HEAD, a copy from the key and an
     * If-None-Match: * write of it, which must know whether a version
     * remains, are answered alike.
     */
    @Test
    public void testRefusedVersionListingIsAccessDenied() throws IOException {
        listStatus = 403;
        var store = promotionStore();

        assertThatThrownBy(() -> store.getBlob(GetObjectRequest.builder()
                .bucket("container").key("key").build()))
                .isInstanceOfSatisfying(S3Exception.class, e -> {
                    assertThat(e.statusCode()).isEqualTo(403);
                    assertThat(e.awsErrorDetails().errorCode())
                            .isEqualTo("AccessDenied");
                    assertThat(e.awsErrorDetails().errorMessage())
                            .contains("containers/blobs/read")
                            .contains("permission l")
                            .contains("resource type c")
                            .contains("AuthorizationResourceTypeMismatch");
                });
        assertThatThrownBy(() -> store.blobMetadata(HeadObjectRequest
                .builder().bucket("container").key("key").build()))
                .isInstanceOfSatisfying(S3Exception.class, e -> {
                    assertThat(e.statusCode()).isEqualTo(403);
                    assertThat(e.awsErrorDetails().errorCode())
                            .isEqualTo("AccessDenied");
                });
        assertThatThrownBy(() -> store.copyBlob(CopyObjectRequest.builder()
                .sourceBucket("container").sourceKey("key")
                .destinationBucket("container").destinationKey("copy")
                .build()))
                .isInstanceOfSatisfying(S3Exception.class, e -> {
                    assertThat(e.statusCode()).isEqualTo(403);
                    assertThat(e.awsErrorDetails().errorCode())
                            .isEqualTo("AccessDenied");
                });
        assertThatThrownBy(() -> store.putBlob(PutObjectRequest.builder()
                .bucket("container").key("key").ifNoneMatch("*")
                .contentLength(1L).build(),
                new ByteArrayInputStream(new byte[1])))
                .isInstanceOfSatisfying(S3Exception.class, e ->
                        assertThat(e.awsErrorDetails().errorCode())
                                .isEqualTo("AccessDenied"));
        // Nothing was written.
        assertThat(azureRequests).noneMatch(r -> r.startsWith("PUT "));
    }

    /**
     * With the listing allowed, a key whose current version was deleted by
     * id still serves its newest remaining version, to a GET, a HEAD and a
     * copy alike.
     */
    @Test
    public void testPromotesNewestRemainingVersion() throws IOException {
        var store = promotionStore();

        try (var stream = store.getBlob(GetObjectRequest.builder()
                .bucket("container").key("key").build())) {
            assertThat(stream.response().versionId()).isEqualTo(REMAINING);
            assertThat(stream.readAllBytes()).containsExactly('x');
        }
        assertThat(store.blobMetadata(HeadObjectRequest.builder()
                .bucket("container").key("key").build()).versionId())
                .isEqualTo(REMAINING);
        store.copyBlob(CopyObjectRequest.builder()
                .sourceBucket("container").sourceKey("key")
                .destinationBucket("container").destinationKey("copy")
                .build());

        assertThat(azureRequests).contains(
                "GET /account/container/key?versionid=" + REMAINING,
                "HEAD /account/container/key?versionid=" + REMAINING,
                "PUT /account/container/copy");
    }

    /**
     * A versioned store in front of a fake Azure whose Enabled container
     * holds a key "key" with no current version, only the non-current
     * {@link #REMAINING} that a listing of the container's versions names,
     * answered with {@link #listStatus}.
     */
    private AzureBlobStore promotionStore() throws IOException {
        server = HttpServer.create(new InetSocketAddress(
                InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", this::handlePromotion);
        server.start();
        return new AzureBlobStore(
                () -> new Credentials("", "", "sv=2026-02-06&sig=fake"),
                "http://127.0.0.1:" + server.getAddress().getPort() +
                        "/account",
                /*eTagMode=*/ "opaque", /*auth=*/ null, /*versioning=*/ true);
    }

    private void handlePromotion(HttpExchange exchange) throws IOException {
        try (var in = exchange.getRequestBody()) {
            in.readAllBytes();
        }
        String method = exchange.getRequestMethod();
        String path = exchange.getRequestURI().getPath();
        String query = exchange.getRequestURI().getQuery();
        // The signature rides on every request; leave it out of the record.
        String recorded = query == null ? "" : String.join("&",
                Arrays.stream(query.split("&"))
                        .filter(p -> !p.startsWith("sv=") &&
                                !p.startsWith("sig="))
                        .toList());
        azureRequests.add(method + " " + path +
                (recorded.isEmpty() ? "" : "?" + recorded));
        var headers = exchange.getResponseHeaders();
        headers.set("x-ms-version", "2026-02-06");
        String body = "";
        int status;
        if (path.equals("/account/container") &&
                recorded.contains("comp=list")) {
            status = listStatus;
            headers.set("Content-Type", "application/xml");
            if (status == 200) {
                body = "<?xml version=\"1.0\" encoding=\"utf-8\"?>" +
                        "<EnumerationResults ContainerName=\"container\">" +
                        "<Blobs><Blob><Name>key</Name><VersionId>" +
                        REMAINING + "</VersionId><Properties>" +
                        "<Last-Modified>Thu, 01 Jan 2026 00:00:00 GMT" +
                        "</Last-Modified><Etag>0x1</Etag>" +
                        "<Content-Length>1</Content-Length>" +
                        "<BlobType>BlockBlob</BlobType></Properties>" +
                        "</Blob></Blobs><NextMarker /></EnumerationResults>";
            } else {
                headers.set("x-ms-error-code",
                        "AuthorizationResourceTypeMismatch");
                body = "<?xml version=\"1.0\" encoding=\"utf-8\"?>" +
                        "<Error><Code>AuthorizationResourceTypeMismatch" +
                        "</Code><Message>refused</Message></Error>";
            }
        } else if (path.equals("/account/container")) {
            // Get Container Properties: versioning Enabled.
            status = 200;
            headers.set("ETag", "\"0xC\"");
            headers.set("Last-Modified", "Thu, 01 Jan 2026 00:00:00 GMT");
        } else if (path.equals("/account/container/key") &&
                !recorded.contains("versionid=")) {
            // The key has no current version.
            status = 404;
            headers.set("x-ms-error-code", "BlobNotFound");
            if (method.equals("GET")) {
                headers.set("Content-Type", "application/xml");
                body = "<?xml version=\"1.0\" encoding=\"utf-8\"?>" +
                        "<Error><Code>BlobNotFound</Code>" +
                        "<Message>gone</Message></Error>";
            }
        } else if (path.equals("/account/container/key")) {
            // The remaining version, read by id.
            headers.set("ETag", "\"0x1\"");
            headers.set("Last-Modified", "Thu, 01 Jan 2026 00:00:00 GMT");
            headers.set("x-ms-version-id", REMAINING);
            headers.set("x-ms-blob-type", "BlockBlob");
            headers.set("x-ms-access-tier", "Hot");
            if (method.equals("GET")) {
                status = 206;
                headers.set("Content-Range", "bytes 0-0/1");
                body = "x";
            } else {
                status = 200;
                headers.set("Content-Length", "1");
            }
        } else if (method.equals("PUT")) {
            // Put Blob From URL, the copy.
            status = 201;
            headers.set("ETag", "\"0x2\"");
            headers.set("Last-Modified", "Fri, 02 Jan 2026 00:00:00 GMT");
            headers.set("x-ms-version-id", "2026-01-02T00:00:00.0000000Z");
            headers.set("x-ms-request-server-encrypted", "true");
        } else {
            status = 400;
        }
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        if (bytes.length == 0) {
            exchange.sendResponseHeaders(status, -1);
        } else {
            exchange.sendResponseHeaders(status, bytes.length);
            try (var out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        }
        exchange.close();
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

    private static BlobItem deleteMarker(BlobItem blob) {
        return blob.setMetadata(Map.of("s3proxy_delete_marker", "true"));
    }

    /** A version written while its container was Suspended. */
    private static BlobItem nullTagged(BlobItem blob) {
        var metadata = new java.util.HashMap<String, String>();
        if (blob.getMetadata() != null) {
            metadata.putAll(blob.getMetadata());
        }
        metadata.put("s3proxy_null_version", "true");
        return blob.setMetadata(metadata);
    }

    private static AzureBlobStore store(boolean versioning) {
        // The endpoint and key are never dialed: the Azure client builds
        // lazily, and these calls read local state only.
        return new AzureBlobStore(
                () -> new Credentials("account", "key"),
                "https://account.blob.core.windows.net",
                /*eTagMode=*/ "opaque", /*auth=*/ null, versioning);
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
