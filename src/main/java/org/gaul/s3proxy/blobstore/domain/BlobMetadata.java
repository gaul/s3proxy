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

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

import com.google.common.collect.ImmutableMap;

import org.gaul.s3proxy.blobstore.ContentMetadata;
import org.jspecify.annotations.Nullable;

import software.amazon.awssdk.services.s3.model.StorageClass;

/**
 * Immutable metadata for a {@link Blob} or for non-container list entries
 * ({@link StorageType#FOLDER} / {@link StorageType#RELATIVE_PATH}). Use
 * {@link #builder} or {@link #toBuilder} to construct or modify.
 */
public record BlobMetadata(
        String name,
        Map<String, String> userMetadata,
        @Nullable String eTag,
        @Nullable Instant lastModified,
        StorageClass storageClass,
        @Nullable String container,
        ContentMetadata contentMetadata,
        @Nullable String versionId,
        @Nullable Encryption encryption) {

    public BlobMetadata {
        userMetadata = ImmutableMap.copyOf(userMetadata);
    }

    /** Metadata without a version, as every unversioned store reports it. */
    public BlobMetadata(String name,
            Map<String, String> userMetadata, @Nullable String eTag,
            @Nullable Instant lastModified, StorageClass storageClass,
            @Nullable String container, ContentMetadata contentMetadata) {
        this(name, userMetadata, eTag, lastModified, storageClass,
                container, contentMetadata, /*versionId=*/ null,
                /*encryption=*/ null);
    }

    public @Nullable Long size() {
        return contentMetadata.contentLength();
    }

    public static Builder builder() {
        return new Builder();
    }

    public Builder toBuilder() {
        return builder()
                .name(name)
                .userMetadata(userMetadata)
                .eTag(eTag)
                .lastModified(lastModified)
                .storageClass(storageClass)
                .container(container)
                .contentMetadata(contentMetadata)
                .versionId(versionId)
                .encryption(encryption);
    }

    public static final class Builder {
        private @Nullable String name;
        private Map<String, String> userMetadata = new LinkedHashMap<>();
        private @Nullable String eTag;
        private @Nullable Instant lastModified;
        private StorageClass storageClass = StorageClass.STANDARD;
        private @Nullable String container;
        private ContentMetadata contentMetadata =
                ContentMetadata.builder().build();
        private @Nullable String versionId;
        private @Nullable Encryption encryption;

        private Builder() {
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

        public Builder lastModified(@Nullable Instant lastModified) {
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

        public Builder versionId(@Nullable String versionId) {
            this.versionId = versionId;
            return this;
        }

        public Builder encryption(@Nullable Encryption encryption) {
            this.encryption = encryption;
            return this;
        }

        public BlobMetadata build() {
            return new BlobMetadata(requireNonNull(name, "name"),
                    userMetadata, eTag,
                    lastModified, storageClass, container, contentMetadata,
                    versionId, encryption);
        }
    }
}
