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

import java.nio.file.FileSystems;
import java.nio.file.PathMatcher;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.jspecify.annotations.Nullable;

public final class GlobBlobStoreLocator implements BlobStoreLocator {
    /**
     * A blob store which serves a bucket glob and the identity which owns
     * it, absent for anonymous access.
     */
    public record GlobTarget(Optional<String> identity, BlobStore blobStore) {
        public GlobTarget {
            Objects.requireNonNull(identity);
            Objects.requireNonNull(blobStore);
        }
    }

    private final Map<String, AccessGrant> locator;
    private final Map<PathMatcher, GlobTarget> globLocator;

    public GlobBlobStoreLocator(Map<String, AccessGrant> locator,
            Map<PathMatcher, GlobTarget> globLocator) {
        this.locator = locator;
        this.globLocator = globLocator;
    }

    @Override
    public @Nullable AccessGrant locateBlobStore(@Nullable String identity,
            @Nullable String container, @Nullable String blob) {
        AccessGrant grant = locator.get(identity);
        GlobTarget globTarget = null;
        if (container != null) {
            for (var entry : globLocator.entrySet()) {
                if (entry.getKey().matches(FileSystems.getDefault()
                        .getPath(container))) {
                    globTarget = entry.getValue();
                }
            }
        }
        if (globTarget == null) {
            if (identity == null) {
                if (!locator.isEmpty()) {
                    return locator.values().iterator().next();
                }
                return AccessGrant.anonymous(
                        globLocator.values().iterator().next().blobStore());
            }
            return grant;
        }
        if (identity == null) {
            return AccessGrant.anonymous(globTarget.blobStore());
        }
        if (!globTarget.identity().equals(Optional.of(identity))) {
            return null;
        }
        if (grant == null) {
            return null;
        }
        return new AccessGrant(grant.credential(), globTarget.blobStore());
    }
}
