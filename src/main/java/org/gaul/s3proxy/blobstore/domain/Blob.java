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

import static com.google.common.base.Preconditions.checkArgument;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.Date;
import java.util.Map;
import java.util.Objects;

import com.google.common.hash.HashCode;
import com.google.common.io.ByteSource;

import org.gaul.s3proxy.blobstore.ContentMetadata;
import org.jspecify.annotations.Nullable;

/**
 * Immutable value type for an HTTP Blob service. Use {@link #builder} to
 * construct a fresh {@link Blob} or {@link #toBuilder} to derive a new one
 * from this instance.
 */
public final class Blob {

    private final BlobMetadata metadata;
    private final @Nullable InputStream payload;
    private final @Nullable String contentRange;

    private Blob(BlobMetadata metadata, @Nullable InputStream payload,
            @Nullable String contentRange) {
        this.metadata = Objects.requireNonNull(metadata, "metadata");
        this.payload = payload;
        this.contentRange = contentRange;
    }

    /** Returns the system and user metadata relevant to this object. */
    public BlobMetadata getMetadata() {
        return metadata;
    }

    /** Returns the single-use content stream, if any. */
    public @Nullable InputStream getPayload() {
        return payload;
    }

    /** Returns the {@code Content-Range} response header, if any. */
    public @Nullable String getContentRange() {
        return contentRange;
    }

    public static Builder builder(String name) {
        return new Builder(name);
    }

    public Builder toBuilder() {
        return new Builder(this);
    }

    @Override
    public String toString() {
        return "[metadata=" + metadata + "]";
    }

    /**
     * Builds an immutable {@link Blob}. Obtain an instance via {@link
     * Blob#builder(String)} or {@link Blob#toBuilder()}.
     */
    public static final class Builder {

        private final BlobMetadata.Builder metadataBuilder;
        private final ContentMetadata.Builder contentMetadataBuilder;
        private @Nullable InputStream payload;
        private @Nullable String contentRange;

        private Builder(String name) {
            this.metadataBuilder = BlobMetadata.builder();
            this.contentMetadataBuilder = ContentMetadata.builder();
            name(name);
        }

        private Builder(Blob blob) {
            this.metadataBuilder = blob.getMetadata().toBuilder();
            this.contentMetadataBuilder = blob.getMetadata()
                    .contentMetadata().toBuilder();
            this.payload = blob.getPayload();
            this.contentRange = blob.getContentRange();
        }

        public Builder name(String name) {
            Objects.requireNonNull(name, "name");
            checkArgument(!name.isEmpty(), "name");
            metadataBuilder.name(name);
            return this;
        }

        public Builder storageClass(StorageClass storageClass) {
            metadataBuilder.storageClass(Objects.requireNonNull(storageClass,
                    "storageClass"));
            return this;
        }

        public Builder type(StorageType type) {
            metadataBuilder.type(type);
            return this;
        }

        public Builder eTag(@Nullable String eTag) {
            metadataBuilder.eTag(eTag);
            return this;
        }

        public Builder userMetadata(Map<String, String> userMetadata) {
            metadataBuilder.userMetadata(userMetadata);
            return this;
        }

        public Builder lastModified(@Nullable Date lastModified) {
            metadataBuilder.lastModified(lastModified);
            return this;
        }

        public Builder container(@Nullable String container) {
            metadataBuilder.container(container);
            return this;
        }

        public Builder payload(InputStream data) {
            this.payload = Objects.requireNonNull(data, "data");
            return this;
        }

        /**
         * Opens {@code data} eagerly and seeds the content length when
         * known.
         */
        public Builder payload(ByteSource data) {
            Objects.requireNonNull(data, "data");
            try {
                this.payload = data.openStream();
            } catch (IOException ioe) {
                throw new UncheckedIOException(ioe);
            }
            Long size = data.sizeIfKnown().orNull();
            if (size != null) {
                contentMetadataBuilder.contentLength(size);
            }
            return this;
        }

        public Builder cacheControl(@Nullable String cacheControl) {
            contentMetadataBuilder.cacheControl(cacheControl);
            return this;
        }

        public Builder contentLength(long contentLength) {
            checkArgument(contentLength >= 0,
                    "content length must be non-negative, was: %s",
                    contentLength);
            contentMetadataBuilder.contentLength(contentLength);
            return this;
        }

        public Builder contentMD5(@Nullable HashCode md5) {
            contentMetadataBuilder.contentMD5(md5);
            return this;
        }

        public Builder contentType(@Nullable String contentType) {
            contentMetadataBuilder.contentType(contentType);
            return this;
        }

        public Builder contentDisposition(
                @Nullable String contentDisposition) {
            contentMetadataBuilder.contentDisposition(contentDisposition);
            return this;
        }

        public Builder contentLanguage(@Nullable String contentLanguage) {
            contentMetadataBuilder.contentLanguage(contentLanguage);
            return this;
        }

        public Builder contentEncoding(@Nullable String contentEncoding) {
            contentMetadataBuilder.contentEncoding(contentEncoding);
            return this;
        }

        public Builder expires(@Nullable Date expires) {
            contentMetadataBuilder.expires(expires);
            return this;
        }

        public Builder contentRange(@Nullable String contentRange) {
            this.contentRange = contentRange;
            return this;
        }

        public Blob build() {
            metadataBuilder.contentMetadata(contentMetadataBuilder.build());
            return new Blob(metadataBuilder.build(), payload, contentRange);
        }
    }
}
