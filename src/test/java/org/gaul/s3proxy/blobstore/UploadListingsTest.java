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

package org.gaul.s3proxy.blobstore;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.CommonPrefix;
import software.amazon.awssdk.services.s3.model.ListMultipartUploadsRequest;
import software.amazon.awssdk.services.s3.model.ListMultipartUploadsResponse;
import software.amazon.awssdk.services.s3.model.MultipartUpload;

/** The page a store that can only enumerate its uploads answers with. */
public final class UploadListingsTest {
    /** Given out of order, as a store enumerates them. */
    private static final List<MultipartUpload> UPLOADS = List.of(
            upload("photos/2026/b.jpg", "id1"),
            upload("e", "id2"),
            upload("a", "id1"),
            upload("photos/a.jpg", "id1"),
            upload("e", "id1"),
            upload("photos/2025/a.jpg", "id1"),
            upload("z-y", "id1"));

    @Test
    public void testListsEveryUploadInKeyOrder() {
        var page = page(request().build());

        assertThat(entries(page)).containsExactly("a@id1", "e@id1", "e@id2",
                "photos/2025/a.jpg@id1", "photos/2026/b.jpg@id1",
                "photos/a.jpg@id1", "z-y@id1");
        assertThat(page.isTruncated()).isFalse();
        assertThat(page.nextKeyMarker()).isNull();
    }

    @Test
    public void testDelimiterFoldsKeysIntoCommonPrefixes() {
        var page = page(request().delimiter("/").build());

        assertThat(entries(page)).containsExactly("a@id1", "e@id1", "e@id2",
                "photos/", "z-y@id1");
    }

    @Test
    public void testPrefixAndDelimiterFoldBelowThePrefix() {
        var page = page(request().prefix("photos/").delimiter("/").build());

        assertThat(entries(page)).containsExactly("photos/2025/",
                "photos/2026/", "photos/a.jpg@id1");
    }

    /** S3 takes any string for a delimiter, not only a slash. */
    @Test
    public void testAnyDelimiter() {
        var page = page(request().delimiter("-").build());

        assertThat(entries(page)).containsExactly("a@id1", "e@id1", "e@id2",
                "photos/2025/a.jpg@id1", "photos/2026/b.jpg@id1",
                "photos/a.jpg@id1", "z-");
    }

    @Test
    public void testMarkersResumeAfterTheirUpload() {
        assertThat(entries(page(request().keyMarker("e")
                .uploadIdMarker("id1").build())))
                .startsWith("e@id2", "photos/2025/a.jpg@id1");
        // without an upload ID, after every upload of the key
        assertThat(entries(page(request().keyMarker("e").build())))
                .startsWith("photos/2025/a.jpg@id1");
        // and an upload ID alone is ignored, as S3 ignores it
        assertThat(entries(page(request().uploadIdMarker("id1").build())))
                .startsWith("a@id1");
    }

    /**
     * A page ending in a common prefix names that prefix as its next key
     * marker and no upload ID, and the next page starts after every key
     * folded into it rather than listing them one by one.
     */
    @Test
    public void testCommonPrefixMarkerSkipsItsKeys() {
        var first = page(request().delimiter("/").maxUploads(4).build());
        assertThat(entries(first)).containsExactly("a@id1", "e@id1", "e@id2",
                "photos/");
        assertThat(first.isTruncated()).isTrue();
        assertThat(first.nextKeyMarker()).isEqualTo("photos/");
        assertThat(first.nextUploadIdMarker()).isNull();

        var second = page(request().delimiter("/").maxUploads(4)
                .keyMarker(first.nextKeyMarker()).build());
        assertThat(entries(second)).containsExactly("z-y@id1");
        assertThat(second.isTruncated()).isFalse();
    }

    /** Pages of any size list each entry once, and say when they end. */
    @Test
    public void testPagesListEachEntryOnce() {
        for (String delimiter : new String[] {null, "/"}) {
            var whole = entries(page(request().delimiter(delimiter).build()));
            for (int maxUploads = 1; maxUploads <= whole.size(); ++maxUploads) {
                var listed = new ArrayList<String>();
                String keyMarker = null;
                String uploadIdMarker = null;
                while (true) {
                    var page = page(request().delimiter(delimiter)
                            .maxUploads(maxUploads).keyMarker(keyMarker)
                            .uploadIdMarker(uploadIdMarker).build());
                    assertThat(page.uploads().size() +
                            page.commonPrefixes().size())
                            .isLessThanOrEqualTo(maxUploads);
                    listed.addAll(entries(page));
                    if (!page.isTruncated()) {
                        break;
                    }
                    keyMarker = page.nextKeyMarker();
                    uploadIdMarker = page.nextUploadIdMarker();
                }
                assertThat(listed).as("delimiter %s, max-uploads %d",
                        delimiter, maxUploads)
                        .containsExactlyElementsOf(whole);
            }
        }
    }

    @Test
    public void testNoMoreThanAThousand() {
        var many = new ArrayList<MultipartUpload>();
        for (int i = 0; i < 1500; ++i) {
            many.add(upload("key%04d".formatted(i), "id"));
        }
        var page = UploadListings.page(many, request().maxUploads(5000)
                .build());

        assertThat(page.uploads()).hasSize(1000);
        assertThat(page.isTruncated()).isTrue();
        assertThat(page.nextKeyMarker()).isEqualTo("key0999");
    }

    private static ListMultipartUploadsRequest.Builder request() {
        return ListMultipartUploadsRequest.builder().bucket("bucket");
    }

    private static ListMultipartUploadsResponse page(
            ListMultipartUploadsRequest request) {
        return UploadListings.page(UPLOADS, request);
    }

    /** Uploads and common prefixes in the one order S3 lists them in. */
    private static List<String> entries(ListMultipartUploadsResponse page) {
        var entries = new ArrayList<String>();
        page.uploads().forEach(u -> entries.add(u.key() + "@" + u.uploadId()));
        page.commonPrefixes().stream().map(CommonPrefix::prefix)
                .forEach(entries::add);
        entries.sort(String::compareTo);
        return entries;
    }

    private static MultipartUpload upload(String key, String uploadId) {
        return MultipartUpload.builder().key(key).uploadId(uploadId).build();
    }
}
