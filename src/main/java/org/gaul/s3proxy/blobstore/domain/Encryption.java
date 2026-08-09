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
 * KMS key, context and bucket-key setting when the algorithm names one.
 * Only a store that answers {@code supportsServerSideEncryption()} records
 * this, and every response naming such an object reports it.
 */
public record Encryption(
        String algorithm,
        @Nullable String kmsKeyId,
        @Nullable String kmsContext,
        @Nullable Boolean bucketKeyEnabled) {

    /** What S3 applies to an object whose write asked for nothing. */
    public static final String DEFAULT_ALGORITHM = "AES256";

    /**
     * What a write request's encryption fields come to rest as.  A request
     * naming no algorithm rests under the default and carries none of the
     * KMS fields, which describe a key only the caller can have named.
     */
    public static Encryption forRequest(@Nullable String algorithm,
            @Nullable String kmsKeyId, @Nullable String kmsContext,
            @Nullable Boolean bucketKeyEnabled) {
        return algorithm == null ?
                new Encryption(DEFAULT_ALGORITHM, null, null, null) :
                new Encryption(algorithm, kmsKeyId, kmsContext,
                        bucketKeyEnabled);
    }

    /** Whether this is the default every unasked-for object rests under. */
    public boolean isDefault() {
        return DEFAULT_ALGORITHM.equals(algorithm) && kmsKeyId == null &&
                kmsContext == null && bucketKeyEnabled == null;
    }
}
