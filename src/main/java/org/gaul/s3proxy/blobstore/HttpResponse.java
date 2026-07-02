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

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.google.common.collect.ImmutableMultimap;
import com.google.common.collect.Multimap;

import org.jspecify.annotations.Nullable;

public record HttpResponse(int statusCode, Multimap<String, String> headers) {

    public @Nullable String firstHeaderOrNull(String name) {
        for (Map.Entry<String, String> entry : headers.entries()) {
            if (entry.getKey().equalsIgnoreCase(name)) {
                return entry.getValue();
            }
        }
        return null;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private int statusCode;
        private final Map<String, List<String>> headers = new LinkedHashMap<>();

        public Builder statusCode(int statusCode) {
            this.statusCode = statusCode;
            return this;
        }

        public Builder addHeader(String name, String value) {
            headers.computeIfAbsent(name, k -> new ArrayList<>()).add(value);
            return this;
        }

        public HttpResponse build() {
            ImmutableMultimap.Builder<String, String> b =
                    ImmutableMultimap.builder();
            for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
                b.putAll(entry.getKey(), entry.getValue());
            }
            return new HttpResponse(statusCode, b.build());
        }
    }
}
