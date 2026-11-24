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

import java.text.Normalizer;
import java.util.Locale;

/**
 * Recognizes the names S3Proxy keeps for itself among a bucket's keys,
 * however a client spells them.  A key is a byte string to S3 and a file
 * name to the store underneath, and a filesystem may find one file under
 * several spellings: APFS, NTFS and ext4 with casefold ignore case, and
 * some of them also the difference between a character and its
 * decomposition, or characters that print as nothing.  Compared as a
 * string, {@code .S3PROXY-TMP} is not {@code .s3proxy-tmp}; opened as a
 * file it is, and the reservation is of the file.
 */
public final class ReservedNames {
    private ReservedNames() {
    }

    /**
     * Reduce the first path segment of {@code key}, where every reserved
     * name lies, to the lower-case ASCII that the most forgiving filesystem
     * could match it by; the rest of the key is returned as it came.  Every
     * reserved name is lower-case ASCII, so a key that any filesystem would
     * resolve to one folds to exactly that name.
     *
     * <p>This folds more than any one filesystem does, and on every store,
     * so that whether a key is refused does not depend on what the bucket
     * happens to be kept on.  Use the result only to compare with a reserved
     * name, never to name an object.
     */
    public static String fold(String key) {
        int slash = key.indexOf('/');
        String segment = slash == -1 ? key : key.substring(0, slash);
        // There is no case folding in the JDK.  Lower, upper, lower comes
        // to the same for what folds to ASCII, the long s and the sharp s
        // included, and decomposing on either side takes in ligatures and
        // the letters, such as the Kelvin sign, that are another's twin.
        String folded = Normalizer.normalize(segment, Normalizer.Form.NFKD)
                .toLowerCase(Locale.ROOT).toUpperCase(Locale.ROOT)
                .toLowerCase(Locale.ROOT);
        folded = Normalizer.normalize(folded, Normalizer.Form.NFKD);
        var ascii = new StringBuilder(key.length());
        for (int i = 0; i < folded.length(); i++) {
            char c = folded.charAt(i);
            // What is left is either ignored by some filesystem, like the
            // soft hyphen, or makes the name one no reserved name matches.
            // Dropping the second kind refuses a few keys needlessly.
            if (c < 0x80) {
                ascii.append(c);
            }
        }
        if (slash != -1) {
            ascii.append(key, slash, key.length());
        }
        return ascii.toString();
    }
}
