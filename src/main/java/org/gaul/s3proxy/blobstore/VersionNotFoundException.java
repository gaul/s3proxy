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

package org.gaul.s3proxy.blobstore;

import org.jspecify.annotations.Nullable;

/**
 * Thrown when a request names a version that does not exist.  Distinct from
 * {@link KeyNotFoundException} because S3 answers NoSuchVersion, not
 * NoSuchKey, when the key exists but the version does not.
 */
public final class VersionNotFoundException extends RuntimeException {

    public VersionNotFoundException(String container, @Nullable String key,
            @Nullable String versionId, @Nullable String message) {
        super("version %s of %s not found in container %s: %s".formatted(
                versionId, key, container, message));
    }
}
