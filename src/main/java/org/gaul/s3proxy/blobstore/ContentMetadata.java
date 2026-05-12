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

package org.gaul.s3proxy.blobstore;

import static com.google.common.base.Preconditions.checkArgument;

import java.util.Date;

import com.google.common.hash.HashCode;

import org.jspecify.annotations.Nullable;

/**
 * Immutable HTTP content-* metadata. Use {@link Builder} or {@link #toBuilder}
 * to construct or modify instances.
 */
public record ContentMetadata(
        @Nullable String cacheControl,
        @Nullable String contentType,
        @Nullable Long contentLength,
        @Nullable HashCode contentMD5,
        @Nullable String contentDisposition,
        @Nullable String contentLanguage,
        @Nullable String contentEncoding,
        @Nullable Date expires) {

    public ContentMetadata {
        if (contentMD5 != null) {
            checkArgument(contentMD5.bits() == 128,
                    "MD5 hash must have 128 bits, was: %s",
                    contentMD5.bits());
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    public Builder toBuilder() {
        return new Builder()
                .cacheControl(cacheControl)
                .contentType(contentType)
                .contentLength(contentLength)
                .contentMD5(contentMD5)
                .contentDisposition(contentDisposition)
                .contentLanguage(contentLanguage)
                .contentEncoding(contentEncoding)
                .expires(expires);
    }

    public static final class Builder {
        private @Nullable String cacheControl;
        private @Nullable String contentType = "application/unknown";
        private @Nullable Long contentLength;
        private @Nullable HashCode contentMD5;
        private @Nullable String contentDisposition;
        private @Nullable String contentLanguage;
        private @Nullable String contentEncoding;
        private @Nullable Date expires;

        private Builder() {
        }

        public Builder cacheControl(@Nullable String cacheControl) {
            this.cacheControl = cacheControl;
            return this;
        }

        public Builder contentType(@Nullable String contentType) {
            this.contentType = contentType;
            return this;
        }

        public Builder contentLength(@Nullable Long contentLength) {
            this.contentLength = contentLength;
            return this;
        }

        public Builder contentMD5(@Nullable HashCode contentMD5) {
            this.contentMD5 = contentMD5;
            return this;
        }

        public Builder contentDisposition(@Nullable String contentDisposition) {
            this.contentDisposition = contentDisposition;
            return this;
        }

        public Builder contentLanguage(@Nullable String contentLanguage) {
            this.contentLanguage = contentLanguage;
            return this;
        }

        public Builder contentEncoding(@Nullable String contentEncoding) {
            this.contentEncoding = contentEncoding;
            return this;
        }

        public Builder expires(@Nullable Date expires) {
            this.expires = expires;
            return this;
        }

        public ContentMetadata build() {
            return new ContentMetadata(cacheControl, contentType, contentLength,
                    contentMD5, contentDisposition, contentLanguage,
                    contentEncoding, expires);
        }
    }
}
