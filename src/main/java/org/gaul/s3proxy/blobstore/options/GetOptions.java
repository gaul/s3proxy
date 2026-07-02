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

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.jspecify.annotations.Nullable;

/** Contains options supported for HTTP GET operations. */
public record GetOptions(
        List<String> ranges,
        @Nullable Date ifModifiedSince,
        @Nullable Date ifUnmodifiedSince,
        @Nullable String ifMatch,
        @Nullable String ifNoneMatch) {

    public static final GetOptions NONE = builder().build();

    public static Builder builder() {
        return new Builder();
    }

    public Builder toBuilder() {
        var b = builder()
                .ifModifiedSince(ifModifiedSince)
                .ifUnmodifiedSince(ifUnmodifiedSince)
                .ifETagMatches(ifMatch)
                .ifETagDoesntMatch(ifNoneMatch);
        b.ranges.addAll(ranges);
        return b;
    }

    public static final class Builder {
        private final List<String> ranges = new ArrayList<>();
        private @Nullable Date ifModifiedSince;
        private @Nullable Date ifUnmodifiedSince;
        private @Nullable String ifMatch;
        private @Nullable String ifNoneMatch;

        public Builder range(long start, long end) {
            checkArgument(start >= 0, "start must be >= 0");
            checkArgument(end >= 0, "end must be >= 0");
            ranges.add("%d-%d".formatted(start, end));
            return this;
        }

        public Builder startAt(long start) {
            checkArgument(start >= 0, "start must be >= 0");
            ranges.add("%d-".formatted(start));
            return this;
        }

        public Builder tail(long length) {
            checkArgument(length >= 0, "length must be >= 0");
            ranges.add("-%d".formatted(length));
            return this;
        }

        public Builder ifModifiedSince(@Nullable Date ifModifiedSince) {
            this.ifModifiedSince = ifModifiedSince;
            return this;
        }

        public Builder ifUnmodifiedSince(@Nullable Date ifUnmodifiedSince) {
            this.ifUnmodifiedSince = ifUnmodifiedSince;
            return this;
        }

        public Builder ifETagMatches(@Nullable String eTag) {
            this.ifMatch = eTag;
            return this;
        }

        public Builder ifETagDoesntMatch(@Nullable String eTag) {
            this.ifNoneMatch = eTag;
            return this;
        }

        public GetOptions build() {
            return new GetOptions(new ArrayList<>(ranges), ifModifiedSince,
                    ifUnmodifiedSince, ifMatch, ifNoneMatch);
        }
    }
}
