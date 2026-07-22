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

package org.gaul.s3proxy;

import java.util.Objects;
import java.util.Optional;

import org.gaul.s3proxy.blobstore.BlobStore;

/**
 * The blob store which serves a request and the credential which verifies
 * its signature, absent for anonymous access.
 */
public record AccessGrant(Optional<String> credential, BlobStore blobStore) {
    public AccessGrant {
        Objects.requireNonNull(credential);
        Objects.requireNonNull(blobStore);
    }

    public AccessGrant(String credential, BlobStore blobStore) {
        this(Optional.of(credential), blobStore);
    }

    public static AccessGrant anonymous(BlobStore blobStore) {
        return new AccessGrant(Optional.empty(), blobStore);
    }
}
