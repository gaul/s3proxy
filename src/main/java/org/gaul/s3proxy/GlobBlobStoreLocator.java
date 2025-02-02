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

import java.nio.file.FileSystems;
import java.nio.file.PathMatcher;
import java.util.Map;

import javax.annotation.Nullable;

import com.google.common.collect.Maps;

import org.jclouds.blobstore.BlobStore;

public final class GlobBlobStoreLocator implements BlobStoreLocator {
    private final Map<String, Map.Entry<String, BlobStore>> locator;
    private final Map<PathMatcher, Map.Entry<String, BlobStore>> globLocator;

    public GlobBlobStoreLocator(
            Map<String, Map.Entry<String, BlobStore>> locator,
            Map<PathMatcher, Map.Entry<String, BlobStore>> globLocator) {
        this.locator = locator;
        this.globLocator = globLocator;
    }

    @Override
    public Map.Entry<String, BlobStore> locateBlobStore(
            @Nullable String identity, String container, String blob) {
        Map.Entry<String, BlobStore> locatorEntry =
                locator.get(identity);
        Map.Entry<String, BlobStore> globEntry = null;
        if (container != null) {
            for (var entry : globLocator.entrySet()) {
                if (entry.getKey().matches(FileSystems.getDefault()
                        .getPath(container))) {
                    globEntry = entry.getValue();
                }
            }
        }
        if (globEntry == null) {
            if (identity == null) {
                if (!locator.isEmpty()) {
                    return locator.entrySet().iterator().next()
                            .getValue();
                }
                return Maps.immutableEntry(null,
                        globLocator.entrySet().iterator().next().getValue()
                                .getValue());
            }
            return locatorEntry;
        }
        if (identity == null) {
            return Maps.immutableEntry(null, globEntry.getValue());
        }
        if (!globEntry.getKey().equals(identity)) {
            return null;
        }
        if (locatorEntry == null) {
            return null;
        }
        return Map.entry(locatorEntry.getKey(), globEntry.getValue());
    }
}
