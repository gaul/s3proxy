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

import static com.google.common.base.Preconditions.checkArgument;

import org.jspecify.annotations.Nullable;

/** Options for listing the contents of a container. */
public record ListContainerOptions(
        @Nullable Integer maxResults,
        @Nullable String marker,
        @Nullable String delimiter,
        @Nullable String prefix,
        boolean recursive) {

    public static final ListContainerOptions NONE = builder().build();

    public static Builder builder() {
        return new Builder();
    }

    public Builder toBuilder() {
        return builder()
                .maxResults(maxResults)
                .afterMarker(marker)
                .delimiter(delimiter)
                .prefix(prefix)
                .recursive(recursive);
    }

    public static final class Builder {
        private @Nullable Integer maxResults;
        private @Nullable String marker;
        private @Nullable String delimiter;
        private @Nullable String prefix;
        private boolean recursive;

        public Builder maxResults(@Nullable Integer maxResults) {
            if (maxResults != null) {
                checkArgument(maxResults >= 0, "maxResults must be >= 0");
            }
            this.maxResults = maxResults;
            return this;
        }

        public Builder afterMarker(@Nullable String marker) {
            this.marker = marker;
            return this;
        }

        public Builder delimiter(@Nullable String delimiter) {
            this.delimiter = delimiter;
            return this;
        }

        public Builder prefix(@Nullable String prefix) {
            this.prefix = prefix;
            return this;
        }

        public Builder recursive() {
            this.recursive = true;
            return this;
        }

        public Builder recursive(boolean recursive) {
            this.recursive = recursive;
            return this;
        }

        public ListContainerOptions build() {
            return new ListContainerOptions(maxResults, marker, delimiter,
                    prefix, recursive);
        }
    }
}
