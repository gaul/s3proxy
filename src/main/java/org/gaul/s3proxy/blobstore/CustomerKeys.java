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
import java.security.MessageDigest;
import java.util.Base64;

import org.gaul.s3proxy.blobstore.domain.Encryption;
import org.jspecify.annotations.Nullable;

/**
 * Judges the SSE-C customer-key triple the way S3 does, for a store that
 * answers the header family itself.  The stores vet writes -- a put, a
 * copy's two ends, an upload's create and parts -- and the frontend judges
 * reads, since only it can tell a caller's read from its own bookkeeping:
 * the stub consulted before a completion or the ETag before a conditional
 * write read without a key, the way S3's own internals do.  The aws-s3
 * backend forwards the triple verbatim and its service judges instead.
 */
public final class CustomerKeys {
    private CustomerKeys() {
    }

    /**
     * Vets one request's triple -- all three fields together, AES256, a
     * 256-bit key, an MD5 that matches -- and returns what the object
     * rests under: the algorithm and the key's MD5, never the key.
     */
    public static Encryption vet(@Nullable String customerAlgorithm,
            @Nullable String customerKey, @Nullable String customerKeyMD5) {
        if (customerAlgorithm == null || customerKey == null ||
                customerKeyMD5 == null) {
            throw S3Exceptions.invalidArgument("Requests specifying Server" +
                    " Side Encryption with Customer provided keys must" +
                    " provide the algorithm, the key and the key's MD5.");
        }
        if (!Encryption.DEFAULT_ALGORITHM.equals(customerAlgorithm)) {
            throw S3Exceptions.invalidArgument("The encryption algorithm" +
                    " specified is not valid.  Valid value: AES256.");
        }
        byte[] key;
        try {
            key = Base64.getDecoder().decode(customerKey);
        } catch (IllegalArgumentException iae) {
            throw S3Exceptions.invalidArgument(
                    "The secret key was invalid.");
        }
        if (key.length != 32) {
            throw S3Exceptions.invalidArgument(
                    "The secret key must be 256 bits.");
        }
        byte[] keyMD5;
        try {
            keyMD5 = Base64.getDecoder().decode(customerKeyMD5);
        } catch (IllegalArgumentException iae) {
            throw S3Exceptions.invalidArgument("The calculated MD5 hash of" +
                    " the key did not match the hash that was provided.");
        }
        if (!MessageDigest.isEqual(MD5.hash(key), keyMD5)) {
            throw S3Exceptions.invalidArgument("The calculated MD5 hash of" +
                    " the key did not match the hash that was provided.");
        }
        return Encryption.forCustomerKey(customerAlgorithm, customerKeyMD5);
    }

    /**
     * Judges a read against the key it presents: an object resting under a
     * customer key answers only to that key, 400 whether the read offered
     * none or the wrong one, and an object resting under none refuses any
     * key offered.  {@code storedKeyMD5} is what the object rests under,
     * null for none.
     */
    public static void enforce(@Nullable String storedKeyMD5,
            @Nullable String customerAlgorithm, @Nullable String customerKey,
            @Nullable String customerKeyMD5) {
        if (storedKeyMD5 == null) {
            if (customerAlgorithm != null || customerKey != null ||
                    customerKeyMD5 != null) {
                throw S3Exceptions.invalidRequest("The encryption" +
                        " parameters are not applicable to this object.");
            }
            return;
        }
        if (customerAlgorithm == null && customerKey == null &&
                customerKeyMD5 == null) {
            throw S3Exceptions.invalidRequest("The object was stored using" +
                    " a form of Server Side Encryption.  The correct" +
                    " parameters must be provided to retrieve the object.");
        }
        var presented = vet(customerAlgorithm, customerKey, customerKeyMD5);
        if (!matches(storedKeyMD5, presented.customerKeyMD5())) {
            throw S3Exceptions.invalidArgument("The provided customer key" +
                    " does not match the key the object was stored under.");
        }
    }

    /** Whether two key MD5s name the same key, compared in fixed time. */
    public static boolean matches(String storedKeyMD5,
            @Nullable String presentedKeyMD5) {
        return presentedKeyMD5 != null && MessageDigest.isEqual(
                storedKeyMD5.getBytes(StandardCharsets.US_ASCII),
                presentedKeyMD5.getBytes(StandardCharsets.US_ASCII));
    }
}
