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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;

import com.google.common.base.Strings;

import org.jspecify.annotations.Nullable;

import software.amazon.awssdk.services.s3.model.CommonPrefix;
import software.amazon.awssdk.services.s3.model.ListMultipartUploadsRequest;
import software.amazon.awssdk.services.s3.model.ListMultipartUploadsResponse;
import software.amazon.awssdk.services.s3.model.MultipartUpload;

/**
 * One page of ListMultipartUploads cut from every upload a store has, for
 * the stores that can only enumerate them: what the request selects, in
 * S3's order, with the uploads of a key the delimiter folds counted once
 * as a common prefix.
 *
 * <p>A page that ends in a common prefix names that prefix as its next key
 * marker, and the next page resumes after every key folded into it.  S3
 * itself does not: its next key marker is the last upload's key, or empty
 * when a page holds only a prefix, so the prefix comes again on the next
 * page and a client paging one entry at a time never gets past it
 * (measured on S3 and on LocalStack, which copies it, 2026-11-24).  A
 * client that follows the markers it is given finishes here either way.
 */
public final class UploadListings {
    /** S3 answers at most this many entries a page. */
    public static final int MAX_UPLOADS = 1000;

    /**
     * By key, as S3 lists them, and within a key by upload ID, which is
     * the order the upload-id-marker resumes in.  S3 orders a key's
     * uploads by when they were initiated; a store whose IDs do not sort
     * that way differs only there.
     */
    private static final Comparator<MultipartUpload> ORDER =
            Comparator.comparing(MultipartUpload::key)
                    .thenComparing(MultipartUpload::uploadId);

    private UploadListings() {
        throw new AssertionError("intentionally unimplemented");
    }

    public static ListMultipartUploadsResponse page(
            Collection<MultipartUpload> uploads,
            ListMultipartUploadsRequest request) {
        String prefix = Strings.nullToEmpty(request.prefix());
        String delimiter = Strings.emptyToNull(request.delimiter());
        String keyMarker = Strings.emptyToNull(request.keyMarker());
        // S3 ignores the upload-id-marker without a key-marker
        String uploadIdMarker = keyMarker == null ? null :
                Strings.emptyToNull(request.uploadIdMarker());
        int maxUploads = request.maxUploads() == null ? MAX_UPLOADS :
                Math.min(request.maxUploads(), MAX_UPLOADS);

        var selected = uploads.stream()
                .filter(upload -> upload.key().startsWith(prefix))
                .sorted(ORDER)
                .toList();

        var page = new ArrayList<MultipartUpload>();
        var prefixes = new ArrayList<CommonPrefix>();
        String lastPrefix = null;
        String nextKeyMarker = null;
        String nextUploadIdMarker = null;
        boolean truncated = false;
        for (var upload : selected) {
            String key = upload.key();
            String rolled = rollUp(key, prefix, delimiter);
            if (keyMarker != null) {
                int compare = key.compareTo(keyMarker);
                if (compare < 0 || (compare == 0 && (uploadIdMarker == null ||
                        upload.uploadId().compareTo(uploadIdMarker) <= 0))) {
                    continue;
                }
                // A marker that is a common prefix resumes after every key
                // folded into it, which all sort after the prefix itself.
                if (keyMarker.equals(rolled)) {
                    continue;
                }
            }
            if (rolled != null && rolled.equals(lastPrefix)) {
                continue;
            }
            if (page.size() + prefixes.size() == maxUploads) {
                truncated = true;
                break;
            }
            if (rolled != null) {
                prefixes.add(CommonPrefix.builder().prefix(rolled).build());
                lastPrefix = rolled;
                nextKeyMarker = rolled;
                nextUploadIdMarker = null;
            } else {
                page.add(upload);
                nextKeyMarker = key;
                nextUploadIdMarker = upload.uploadId();
            }
        }

        var response = ListMultipartUploadsResponse.builder()
                .uploads(page)
                .commonPrefixes(prefixes)
                .isTruncated(truncated);
        if (truncated) {
            response.nextKeyMarker(nextKeyMarker)
                    .nextUploadIdMarker(nextUploadIdMarker);
        }
        return response.build();
    }

    /**
     * The common prefix a key folds into: the key up to and including the
     * first delimiter after the request's prefix, or null for a key the
     * delimiter leaves alone.
     */
    private static @Nullable String rollUp(String key, String prefix,
            @Nullable String delimiter) {
        if (delimiter == null) {
            return null;
        }
        int at = key.indexOf(delimiter, prefix.length());
        return at < 0 ? null : key.substring(0, at + delimiter.length());
    }
}
