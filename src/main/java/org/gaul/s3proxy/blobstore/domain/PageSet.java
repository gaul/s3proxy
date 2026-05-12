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

import java.util.LinkedHashSet;
import java.util.Objects;

import com.google.common.collect.Iterables;

import org.jspecify.annotations.Nullable;

public final class PageSet<T> extends LinkedHashSet<T> {

    private final String marker;

    public PageSet(Iterable<? extends T> contents,
            @Nullable String nextMarker) {
        Iterables.addAll(this, contents);
        this.marker = nextMarker;
    }

    /**
     * If non-null, the listing is incomplete and the marker should be passed
     * to a subsequent list call to retrieve the next page.
     */
    public String getNextMarker() {
        return marker;
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), marker);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof PageSet<?> other) || !super.equals(obj)) {
            return false;
        }
        return Objects.equals(marker, other.marker);
    }

    @Override
    public String toString() {
        return "marker: " + marker + " elements: " + super.toString();
    }
}
