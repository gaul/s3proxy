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

import java.util.Date;

import org.jspecify.annotations.Nullable;

/**
 * One entry of a version listing: an object version or a delete marker.
 * The versionId is the literal "null" for versions written while the bucket
 * was unversioned.  A delete marker carries no ETag or size.
 */
public record VersionMetadata(
        String name,
        String versionId,
        boolean latest,
        boolean deleteMarker,
        @Nullable String eTag,
        @Nullable Date lastModified,
        @Nullable Long size,
        StorageClass storageClass) {
}
