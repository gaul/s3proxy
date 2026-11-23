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

import org.jspecify.annotations.Nullable;

public interface BlobStoreLocator {
    @Nullable AccessGrant locateBlobStore(@Nullable String identity,
            @Nullable String container, @Nullable String blob);

    /**
     * Whether the answer depends on the container, so that an identity may
     * be refused one bucket of a blob store and granted another.  ListBuckets
     * names no bucket and so asks about each one the store holds before it
     * pages the listing; a locator which answers for the identity alone
     * spares it that and leaves the paging to the store.  Scoping is the
     * default: presuming it of a locator which does not costs a store its
     * native paging, while presuming otherwise of one which does would show
     * an identity the names of buckets it may not address.
     */
    default boolean scopesBuckets() {
        return true;
    }

    /**
     * The store that serves an unsigned request for the container, when the
     * proxy authenticates the others, or null to leave it to the store the
     * proxy was built with.  A store a container is assigned to has to serve
     * it whoever asks: its middlewares -- a read-only one, say -- and its
     * ACLs are how the operator meant the bucket to be reached.  The default
     * has no opinion, which suits a locator that answers for identities
     * alone.
     */
    default @Nullable AccessGrant locateAnonymousBlobStore(
            @Nullable String container, @Nullable String blob) {
        return null;
    }
}
