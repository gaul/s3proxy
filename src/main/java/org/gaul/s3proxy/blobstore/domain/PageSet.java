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

import java.util.Iterator;
import java.util.List;

import com.google.common.collect.ImmutableList;

import org.jspecify.annotations.Nullable;

/**
 * One page of a listing.  If {@code nextMarker} is non-null, the listing is
 * incomplete and the marker should be passed to a subsequent list call to
 * retrieve the next page.
 */
public record PageSet<T>(List<T> entries, @Nullable String nextMarker)
        implements Iterable<T> {

    public PageSet {
        entries = List.copyOf(entries);
    }

    public PageSet(Iterable<? extends T> entries,
            @Nullable String nextMarker) {
        this(ImmutableList.copyOf(entries), nextMarker);
    }

    @Override
    public Iterator<T> iterator() {
        return entries.iterator();
    }
}
