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

import org.jspecify.annotations.Nullable;

/**
 * What a copy stored: the destination's ETag and, on a versioning-enabled
 * backend, the version the copy minted and the source version it resolved.
 * An unversioned backend reports null version ids.
 */
public record CopyResult(@Nullable String eTag, @Nullable String versionId,
        @Nullable String copySourceVersionId) {

    public CopyResult(@Nullable String eTag) {
        this(eTag, null, null);
    }
}
