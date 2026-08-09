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

package org.gaul.s3proxy.blobstore.domain;

import org.jspecify.annotations.Nullable;

/**
 * The server-side encryption an object rests under: the algorithm, and the
 * KMS key, context and bucket-key setting when the algorithm names one; or,
 * for an object resting under a customer's own key, the algorithm and the
 * key's MD5 -- the key itself is never kept, only what judges whether a
 * later request presents the same one.  The two modes exclude each other
 * the way S3's headers do: a customer-key object reports no
 * x-amz-server-side-encryption at all, so {@code algorithm} is null exactly
 * when {@code customerKeyMD5} is not.  Only a store that answers
 * {@code supportsServerSideEncryption()} records this, and every response
 * naming such an object reports it.
 */
public record Encryption(
        @Nullable String algorithm,
        @Nullable String kmsKeyId,
        @Nullable String kmsContext,
        @Nullable Boolean bucketKeyEnabled,
        @Nullable String customerAlgorithm,
        @Nullable String customerKeyMD5) {

    /** What S3 applies to an object whose write asked for nothing. */
    public static final String DEFAULT_ALGORITHM = "AES256";

    /** The algorithm value that names a KMS key rather than S3's own. */
    public static final String KMS_ALGORITHM = "aws:kms";

    /**
     * What a write request's encryption fields come to rest as.  A request
     * naming no algorithm rests under the default and carries none of the
     * KMS fields, which describe a key only the caller can have named.
     */
    public static Encryption forRequest(@Nullable String algorithm,
            @Nullable String kmsKeyId, @Nullable String kmsContext,
            @Nullable Boolean bucketKeyEnabled) {
        return algorithm == null ?
                new Encryption(DEFAULT_ALGORITHM, null, null, null, null,
                        null) :
                new Encryption(algorithm, kmsKeyId, kmsContext,
                        bucketKeyEnabled, null, null);
    }

    /**
     * An object resting under a key its caller holds.  The MD5 is all a
     * store may keep of it: enough to recognize the key when a read
     * presents it again, and no more than S3 itself echoes on responses.
     */
    public static Encryption forCustomerKey(String customerAlgorithm,
            String customerKeyMD5) {
        return new Encryption(null, null, null, null, customerAlgorithm,
                customerKeyMD5);
    }

    /** Whether this is the default every unasked-for object rests under. */
    public boolean isDefault() {
        return DEFAULT_ALGORITHM.equals(algorithm) && kmsKeyId == null &&
                kmsContext == null && bucketKeyEnabled == null &&
                customerKeyMD5 == null;
    }
}
