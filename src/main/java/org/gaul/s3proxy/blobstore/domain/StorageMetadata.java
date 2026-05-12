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

/**
 * Identifies containers, files, etc. Permits exactly
 * {@link ContainerMetadata} and {@link BlobMetadata}.
 *
 * TODO: drop the {@code get} prefix on these accessors so the record
 * components in {@link BlobMetadata} and {@link ContainerMetadata} satisfy
 * the interface directly, eliminating the manual {@code @Override}
 * getters in each.
 */
public sealed interface StorageMetadata extends Comparable<StorageMetadata>
        permits ContainerMetadata, BlobMetadata {

    StorageType getType();

    String getName();

    Map<String, String> getUserMetadata();

    @Nullable
    String getETag();

    @Nullable
    Date getCreationDate();

    @Nullable
    Date getLastModified();

    @Nullable
    Long getSize();

    StorageClass getStorageClass();

    @Override
    default int compareTo(StorageMetadata o) {
        if (getName() == null) {
            return -1;
        }
        return (this == o) ? 0 : getName().compareTo(o.getName());
    }
}
