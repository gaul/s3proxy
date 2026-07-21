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

package org.gaul.s3proxy.blobstore.domain;

import java.util.Date;
import java.util.Map;

import org.jspecify.annotations.Nullable;

/** Immutable metadata for a top-level container. */
public record ContainerMetadata(String name, @Nullable Date creationDate)
        implements StorageMetadata {

    @Override
    public StorageType getType() {
        return StorageType.CONTAINER;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public Map<String, String> getUserMetadata() {
        return Map.of();
    }

    @Override
    public @Nullable String getETag() {
        return null;
    }

    @Override
    public @Nullable Date getCreationDate() {
        return creationDate;
    }

    @Override
    public @Nullable Date getLastModified() {
        return null;
    }

    @Override
    public @Nullable Long getSize() {
        return null;
    }

    @Override
    public StorageClass getStorageClass() {
        return StorageClass.STANDARD;
    }
}
