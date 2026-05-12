/*
 * Copyright 2009-2025 The Apache Software Foundation
 * Copyright 2026 Andrew Gaul <andrew@gaul.org>
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

package org.gaul.s3proxy.blobstore.options;

import java.util.Objects;

import org.gaul.s3proxy.blobstore.domain.BlobAccess;
import org.jspecify.annotations.Nullable;

/** Options for the put blob operation. */
public record PutOptions(
        BlobAccess blobAccess,
        @Nullable String ifMatch,
        @Nullable String ifNoneMatch) {

    public static final PutOptions NONE = builder().build();

    public PutOptions {
        Objects.requireNonNull(blobAccess, "blobAccess");
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private BlobAccess blobAccess = BlobAccess.PRIVATE;
        private @Nullable String ifMatch;
        private @Nullable String ifNoneMatch;

        public Builder blobAccess(BlobAccess blobAccess) {
            this.blobAccess = Objects.requireNonNull(blobAccess, "blobAccess");
            return this;
        }

        public Builder ifMatch(@Nullable String ifMatch) {
            this.ifMatch = ifMatch;
            return this;
        }

        public Builder ifNoneMatch(@Nullable String ifNoneMatch) {
            this.ifNoneMatch = ifNoneMatch;
            return this;
        }

        public PutOptions build() {
            return new PutOptions(blobAccess, ifMatch, ifNoneMatch);
        }
    }
}
