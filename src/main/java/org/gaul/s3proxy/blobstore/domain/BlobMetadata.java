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

import static java.util.Objects.requireNonNull;

import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

import com.google.common.collect.ImmutableMap;

import org.gaul.s3proxy.blobstore.ContentMetadata;
import org.jspecify.annotations.Nullable;

/**
 * Immutable metadata for a {@link Blob} or for non-container list entries
 * ({@link StorageType#FOLDER} / {@link StorageType#RELATIVE_PATH}). Use
 * {@link #builder} or {@link #toBuilder} to construct or modify.
 */
public record BlobMetadata(
        StorageType type,
        String name,
        Map<String, String> userMetadata,
        @Nullable String eTag,
        @Nullable Date lastModified,
        StorageClass storageClass,
        @Nullable String container,
        ContentMetadata contentMetadata) implements StorageMetadata {

    public BlobMetadata {
        userMetadata = ImmutableMap.copyOf(userMetadata);
    }

    @Override
    public @Nullable Long size() {
        return contentMetadata.contentLength();
    }

    @Override
    public @Nullable Date creationDate() {
        return null;
    }

    public static Builder builder() {
        return new Builder();
    }

    public Builder toBuilder() {
        return builder()
                .type(type)
                .name(name)
                .userMetadata(userMetadata)
                .eTag(eTag)
                .lastModified(lastModified)
                .storageClass(storageClass)
                .container(container)
                .contentMetadata(contentMetadata);
    }

    public static final class Builder {
        private StorageType type = StorageType.BLOB;
        private @Nullable String name;
        private Map<String, String> userMetadata = new LinkedHashMap<>();
        private @Nullable String eTag;
        private @Nullable Date lastModified;
        private StorageClass storageClass = StorageClass.STANDARD;
        private @Nullable String container;
        private ContentMetadata contentMetadata =
                ContentMetadata.builder().build();

        private Builder() {
        }

        public Builder type(StorageType type) {
            this.type = type;
            return this;
        }

        public Builder name(String name) {
            this.name = name;
            return this;
        }

        public Builder userMetadata(Map<String, String> userMetadata) {
            this.userMetadata = userMetadata != null ?
                    new LinkedHashMap<>(userMetadata) :
                    new LinkedHashMap<>();
            return this;
        }

        public Builder eTag(@Nullable String eTag) {
            this.eTag = eTag;
            return this;
        }

        public Builder lastModified(@Nullable Date lastModified) {
            this.lastModified = lastModified;
            return this;
        }

        public Builder storageClass(StorageClass storageClass) {
            this.storageClass = storageClass;
            return this;
        }

        public Builder container(@Nullable String container) {
            this.container = container;
            return this;
        }

        public Builder contentMetadata(ContentMetadata contentMetadata) {
            this.contentMetadata = contentMetadata;
            return this;
        }

        public Builder contentLength(@Nullable Long contentLength) {
            this.contentMetadata = contentMetadata.toBuilder()
                    .contentLength(contentLength)
                    .build();
            return this;
        }

        public BlobMetadata build() {
            return new BlobMetadata(type, requireNonNull(name, "name"),
                    userMetadata, eTag,
                    lastModified, storageClass, container, contentMetadata);
        }
    }
}
