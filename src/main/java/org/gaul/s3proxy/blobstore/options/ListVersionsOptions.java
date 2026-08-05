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

package org.gaul.s3proxy.blobstore.options;

import org.jspecify.annotations.Nullable;

/** Contains options supported for listing object versions. */
public record ListVersionsOptions(
        @Nullable String prefix,
        @Nullable String delimiter,
        @Nullable String keyMarker,
        @Nullable String versionIdMarker,
        @Nullable Integer maxResults) {

    public static final ListVersionsOptions NONE = builder().build();

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private @Nullable String prefix;
        private @Nullable String delimiter;
        private @Nullable String keyMarker;
        private @Nullable String versionIdMarker;
        private @Nullable Integer maxResults;

        public Builder prefix(@Nullable String prefix) {
            this.prefix = prefix;
            return this;
        }

        public Builder delimiter(@Nullable String delimiter) {
            this.delimiter = delimiter;
            return this;
        }

        public Builder keyMarker(@Nullable String keyMarker) {
            this.keyMarker = keyMarker;
            return this;
        }

        public Builder versionIdMarker(@Nullable String versionIdMarker) {
            this.versionIdMarker = versionIdMarker;
            return this;
        }

        public Builder maxResults(@Nullable Integer maxResults) {
            this.maxResults = maxResults;
            return this;
        }

        public ListVersionsOptions build() {
            return new ListVersionsOptions(prefix, delimiter, keyMarker,
                    versionIdMarker, maxResults);
        }
    }
}
