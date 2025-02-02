/*
 * Copyright 2014-2025 Andrew Gaul <andrew@gaul.org>
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

package org.gaul.s3proxy;

import java.util.Collection;

import com.google.common.collect.ForwardingMultimap;
import com.google.common.collect.ImmutableMultimap;
import com.google.common.collect.Multimap;

final class CaseInsensitiveImmutableMultimap
        extends ForwardingMultimap<String, String> {
    private final Multimap<String, String> inner;

    CaseInsensitiveImmutableMultimap(Multimap<String, String> map) {
        var builder = ImmutableMultimap.<String, String>builder();
        for (var entry : map.entries()) {
            builder.put(lower(entry.getKey()), entry.getValue());
        }
        this.inner = builder.build();
    }

    @Override
    protected Multimap<String, String> delegate() {
        return inner;
    }

    @Override
    public Collection<String> get(String key) {
        return inner.get(lower(key));
    }

    private static String lower(String key) {
        return key == null ? null : key.toLowerCase();
    }
}
