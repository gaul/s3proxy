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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * The MD5 the S3 protocol mandates for ETags, Content-MD5 validation and
 * SSE-C key fingerprints.  Guava deprecated its MD5 support to discourage
 * cryptographic use, which this is not: the protocol fixes the algorithm,
 * so compute it through {@link MessageDigest}, which carries no such
 * judgment.
 */
public final class MD5 {
    /** The length in bytes of an MD5 digest. */
    public static final int LENGTH = 16;

    private MD5() {
    }

    /** A fresh digest for streaming and incremental hashing. */
    public static MessageDigest newDigest() {
        try {
            return MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException nsae) {
            // every conformant JRE ships MD5
            throw new AssertionError(nsae);
        }
    }

    /** The digest of {@code input} as 16 raw bytes. */
    public static byte[] hash(byte[] input) {
        return newDigest().digest(input);
    }
}
