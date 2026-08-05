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

import java.util.List;

import org.jspecify.annotations.Nullable;

/**
 * One page of a version listing.  Versions arrive in S3 order -- keys
 * ascending, and each key's versions newest first -- and pagination resumes
 * from the (nextKeyMarker, nextVersionIdMarker) pair, both null on the last
 * page.
 */
public record VersionPage(
        List<VersionMetadata> versions,
        List<String> commonPrefixes,
        @Nullable String nextKeyMarker,
        @Nullable String nextVersionIdMarker) {

    public VersionPage {
        versions = List.copyOf(versions);
        commonPrefixes = List.copyOf(commonPrefixes);
    }
}
