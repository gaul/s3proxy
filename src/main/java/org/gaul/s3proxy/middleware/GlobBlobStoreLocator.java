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

package org.gaul.s3proxy.middleware;

import java.nio.file.FileSystems;
import java.nio.file.PathMatcher;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import org.gaul.s3proxy.AccessGrant;
import org.gaul.s3proxy.BlobStoreLocator;
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
    private final @Nullable BlobStore anonymousBlobStore;

    /**
     * Locates by identity, and by bucket where a glob names it.
     *
     * @param locator the grant of each identity
     * @param globLocator matchers of bucket names.  A bucket is matched by
     *     its lower-case spelling first, so patterns should be lower-case;
     *     one which is not matches only the exact spelling and does not
     *     keep other spellings of the bucket from the caller's own store.
     */
    public GlobBlobStoreLocator(Map<String, AccessGrant> locator,
            Map<PathMatcher, GlobTarget> globLocator) {
        this(locator, globLocator, /*anonymousBlobStore=*/ null);
    }

    /**
     * As above, with a blob store for the buckets which no glob matches when
     * a request has no identity: that of a configuration with anonymous
     * access and no bucket locator, which is the one written for them.
     * Without one, such a bucket goes to the first identity's store, or the
     * first glob's where there is no identity either.
     */
    public GlobBlobStoreLocator(Map<String, AccessGrant> locator,
            Map<PathMatcher, GlobTarget> globLocator,
            @Nullable BlobStore anonymousBlobStore) {
        this.locator = locator;
        this.globLocator = globLocator;
        this.anonymousBlobStore = anonymousBlobStore;
    }

    @Override
    public @Nullable AccessGrant locateBlobStore(@Nullable String identity,
            @Nullable String container, @Nullable String blob) {
        // Not every Map answers a null key: Map.of throws.
        AccessGrant grant = identity == null ? null : locator.get(identity);
        GlobTarget globTarget = locateGlob(container, identity);
        if (globTarget == null) {
            if (identity == null) {
                // The store configured for the buckets which no glob names
                // comes before any store which was configured for others.
                if (anonymousBlobStore != null) {
                    return AccessGrant.anonymous(anonymousBlobStore);
                }
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

    /**
     * An unsigned request goes where a glob assigns its bucket, as a signed
     * one does.  A bucket no glob names goes to the store configured for
     * such buckets, or to the identity's where there is but one, since that
     * is where its owner reaches it.  With several identities and no store
     * for unassigned buckets, nothing says whose the bucket is, and the
     * proxy's own store serves it, as before.
     */
    @Override
    public @Nullable AccessGrant locateAnonymousBlobStore(
            @Nullable String container, @Nullable String blob) {
        GlobTarget globTarget = locateGlob(container, /*identity=*/ null);
        if (globTarget != null) {
            return AccessGrant.anonymous(globTarget.blobStore());
        }
        if (anonymousBlobStore != null) {
            return AccessGrant.anonymous(anonymousBlobStore);
        }
        if (locator.size() == 1) {
            return AccessGrant.anonymous(
                    locator.values().iterator().next().blobStore());
        }
        return null;
    }

    private @Nullable GlobTarget locateGlob(@Nullable String container,
            @Nullable String identity) {
        if (container == null) {
            return null;
        }
        // Match the lower-case spelling first.  A glob is case-sensitive but
        // a store need not be: a filesystem store on a case-insensitive
        // volume opens alice-1 for ALICE-1, which would otherwise match no
        // glob and be served from the caller's own store instead of being
        // refused.
        GlobTarget globTarget = matchGlob(container.toLowerCase(Locale.ROOT),
                identity);
        if (globTarget == null) {
            globTarget = matchGlob(container, identity);
        }
        return globTarget;
    }

    /** Without a glob the container is never consulted. */
    @Override
    public boolean scopesBuckets() {
        return !globLocator.isEmpty();
    }

    private @Nullable GlobTarget matchGlob(String container,
            @Nullable String identity) {
        GlobTarget globTarget = null;
        for (var entry : globLocator.entrySet()) {
            if (entry.getKey().matches(FileSystems.getDefault()
                    .getPath(container))) {
                globTarget = entry.getValue();
                // Globs may overlap.  The requester's own match is the
                // one that serves them; taking whichever matched last
                // denied them their bucket whenever another backend's
                // glob also covered its name.
                if (identity != null && globTarget.identity().equals(
                        Optional.of(identity))) {
                    break;
                }
            }
        }
        return globTarget;
    }
}
