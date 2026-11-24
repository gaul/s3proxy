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

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.HexFormat;
import java.util.regex.Pattern;

import com.google.common.hash.Hashing;

import org.jspecify.annotations.Nullable;

import software.amazon.awssdk.services.s3.model.MultipartUpload;

/**
 * Names for the stores that keep a multipart upload's stub as an object of
 * the bucket, named by the upload's key and ID so that the backend lists
 * the uploads in S3's order: ListMultipartUploads then reads a page of
 * them rather than every one.
 *
 * <p>An upload ID is 36 hex digits: twelve of the time it was issued, so
 * that a key's uploads sort as S3 lists them, sixteen random, and eight of
 * the SHA-256 of its key.  The last tell an ID from another key's at once:
 * a part, listing, completion or abort naming a key the upload was not
 * begun for is NoSuchUpload, as on S3, without a request to the backend --
 * and the store can still tell such a request from one for an upload of
 * the right key that has since completed, whose stub is gone too.  Thirty
 * six is the length of the UUIDs IDs were before, which Azure needs, as it
 * names a part's block by the ID and requires a blob's block IDs to be of
 * one length.
 */
public final class UploadNames {
    /**
     * Ends a stub's escaped key, ahead of its upload ID.  It sorts before
     * anything an escaped key can continue with -- see {@link #escapeKey}
     * -- so a key's uploads sort before those of every longer key.
     */
    public static final String SEPARATOR = "!!";
    /** Sorts after every character an upload ID is spelled with. */
    public static final String AFTER_EVERY_UPLOAD_ID = "~";

    private static final Pattern UPLOAD_ID = Pattern.compile("[0-9a-f]{36}");
    private static final int KEY_DIGEST_LENGTH = 8;
    private static final SecureRandom RANDOM = new SecureRandom();

    private UploadNames() {
        throw new AssertionError("intentionally unimplemented");
    }

    public static String newUploadId(String key) {
        var random = new byte[8];
        RANDOM.nextBytes(random);
        return "%012x".formatted(System.currentTimeMillis()) +
                HexFormat.of().formatHex(random) + keyDigest(key);
    }

    /** Whether the ID is one this class issues, for any key. */
    public static boolean isUploadId(String uploadId) {
        return UPLOAD_ID.matcher(uploadId).matches();
    }

    /** Whether the ID is one issued for an upload of the key. */
    public static boolean namesKey(String uploadId, String key) {
        return isUploadId(uploadId) && uploadId.endsWith(keyDigest(key));
    }

    private static String keyDigest(String key) {
        return Hashing.sha256().hashString(key, StandardCharsets.UTF_8)
                .toString().substring(0, KEY_DIGEST_LENGTH);
    }

    /**
     * The key as it is spelled in a stub's name, sorting as the key does.
     * Every character up to and including '!' is written as '!' and two
     * hex digits, everything else as itself: so the escaped key's order is
     * the key's, a prefix of a key escapes to a prefix of its escaped form,
     * and {@link #SEPARATOR} sorts before whatever an escaped key could
     * continue with.  Spaces and controls, which sort below '!', are the
     * characters this lengthens; '/' is left alone, so a backend's own
     * slash delimiter folds escaped keys as it would the keys.
     */
    public static String escapeKey(String key) {
        var escaped = new StringBuilder(key.length());
        for (int i = 0; i < key.length(); ++i) {
            char c = key.charAt(i);
            if (c <= '!') {
                escaped.append('!').append(Character.forDigit(c >> 4, 16))
                        .append(Character.forDigit(c & 0xf, 16));
            } else {
                escaped.append(c);
            }
        }
        return escaped.toString();
    }

    /**
     * Where a listing of stub names -- each the store's prefix, then the
     * escaped key, {@link #SEPARATOR} and the upload ID -- starts for a
     * page, as the part after the store's prefix: after every upload of
     * the key marker when it names no upload ID, after every key folded
     * into it when it is a common prefix, and at the marked upload
     * otherwise, which the page then passes over.  Null where the listing
     * starts at the beginning.
     */
    public static @Nullable String startName(String prefix,
            @Nullable String delimiter, @Nullable String keyMarker,
            @Nullable String uploadIdMarker) {
        if (keyMarker == null) {
            return null;
        }
        String escaped = escapeKey(keyMarker);
        if (delimiter != null && keyMarker.equals(
                UploadListings.rollUp(keyMarker, prefix, delimiter))) {
            // the first name after all those beginning with the prefix
            char last = escaped.charAt(escaped.length() - 1);
            return escaped.substring(0, escaped.length() - 1) +
                    (char) (last + 1);
        }
        if (uploadIdMarker == null) {
            return escaped + SEPARATOR + AFTER_EVERY_UPLOAD_ID;
        }
        return escaped + SEPARATOR + uploadIdMarker;
    }

    /**
     * The upload a stub records, from the part of its name after the
     * store's prefix, or null for a name that is no stub's.
     */
    public static @Nullable MultipartUpload parseStubName(String name,
            @Nullable Instant initiated) {
        int separator = name.lastIndexOf(SEPARATOR);
        if (separator < 0) {
            return null;
        }
        String uploadId = name.substring(separator + SEPARATOR.length());
        if (!isUploadId(uploadId)) {
            return null;
        }
        return MultipartUpload.builder()
                .key(unescapeKey(name.substring(0, separator)))
                .uploadId(uploadId)
                .initiated(initiated)
                .build();
    }

    public static String unescapeKey(String escaped) {
        var key = new StringBuilder(escaped.length());
        for (int i = 0; i < escaped.length(); ++i) {
            char c = escaped.charAt(i);
            if (c == '!' && i + 2 < escaped.length()) {
                key.append((char) Integer.parseInt(
                        escaped.substring(i + 1, i + 3), 16));
                i += 2;
            } else {
                key.append(c);
            }
        }
        return key.toString();
    }
}
