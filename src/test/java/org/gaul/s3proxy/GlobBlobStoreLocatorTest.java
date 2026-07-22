/*
 * Copyright 2014-2026 Andrew Gaul <andrew@gaul.org>
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

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.FileSystems;
import java.util.Map;
import java.util.Optional;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSortedMap;

import org.gaul.s3proxy.GlobBlobStoreLocator.GlobTarget;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public final class GlobBlobStoreLocatorTest {
    private BlobStore blobStoreOne;
    private BlobStore blobStoreTwo;

    @BeforeEach
    public void setUp() {
        blobStoreOne = TestUtils.createTransientBlobStore();
        blobStoreTwo = TestUtils.createTransientBlobStore();
    }

    @Test
    public void testLocateIdentity() {
        var credsMap = ImmutableSortedMap.of(
                "id1", new AccessGrant("one", blobStoreOne),
                "id2", new AccessGrant("two", blobStoreTwo));
        var locator = new GlobBlobStoreLocator(
                credsMap, Map.of());
        assertThat(locator.locateBlobStore("id2", null, null).credential())
                .contains("two");
        assertThat(locator.locateBlobStore(null, null, null).credential())
                .contains("one");
        assertThat(locator.locateBlobStore("foo", null, null)).isNull();
    }

    @Test
    public void testLocateContainer() {
        var credsMap = ImmutableMap.of(
                "id1", new AccessGrant("one", blobStoreOne),
                "id2", new AccessGrant("two", blobStoreTwo));
        var globMap = Map.of(
                FileSystems.getDefault().getPathMatcher("glob:container1"),
                new GlobTarget(Optional.of("id1"), blobStoreOne),
                FileSystems.getDefault().getPathMatcher("glob:container2"),
                new GlobTarget(Optional.of("id2"), blobStoreTwo));
        var locator = new GlobBlobStoreLocator(credsMap,
                globMap);

        assertThat(locator.locateBlobStore(null, "container1", null)
                .blobStore()).isSameAs(blobStoreOne);
        assertThat(locator.locateBlobStore(null, "container2", null)
                .blobStore()).isSameAs(blobStoreTwo);
        assertThat(locator.locateBlobStore("id1", "foo", null)
                .blobStore()).isSameAs(blobStoreOne);
        assertThat(locator.locateBlobStore("id2", "foo", null)
                .blobStore()).isSameAs(blobStoreTwo);
        assertThat(locator.locateBlobStore("foo", "container1", null))
                .isNull();
        assertThat(locator.locateBlobStore("foo", "container2", null))
                .isNull();
    }

    @Test
    public void testLocateGlob() {
        var credsMap = ImmutableSortedMap.of(
                "id0", new AccessGrant("zero", blobStoreOne),
                "id1", new AccessGrant("one", blobStoreOne),
                "id2", new AccessGrant("two", blobStoreTwo));
        var globMap = Map.of(
                FileSystems.getDefault().getPathMatcher("glob:{one,two}"),
                new GlobTarget(Optional.of("id1"), blobStoreOne),
                FileSystems.getDefault().getPathMatcher("glob:cont?X*"),
                new GlobTarget(Optional.of("id2"), blobStoreTwo));
        var locator = new GlobBlobStoreLocator(credsMap,
                globMap);

        assertThat(locator.locateBlobStore(null, "one", null)
                .blobStore()).isSameAs(blobStoreOne);
        assertThat(locator.locateBlobStore("id1", "two", null)
                .blobStore()).isSameAs(blobStoreOne);
        assertThat(locator.locateBlobStore("id2", "cont5X.extra", null)
                .blobStore()).isSameAs(blobStoreTwo);
    }

    @Test
    public void testGlobLocatorAnonymous() {
        // Anonymous access stores an absent identity in the glob map
        var globMap = ImmutableMap.of(
                FileSystems.getDefault().getPathMatcher("glob:one"),
                new GlobTarget(Optional.empty(), blobStoreOne),
                FileSystems.getDefault().getPathMatcher("glob:two"),
                new GlobTarget(Optional.empty(), blobStoreTwo));
        var locator = new GlobBlobStoreLocator(
                ImmutableMap.of(), globMap);

        assertThat(locator.locateBlobStore(null, null, null)
                .blobStore()).isSameAs(blobStoreOne);
        assertThat(locator.locateBlobStore(null, "one", null)
                .blobStore()).isSameAs(blobStoreOne);
        assertThat(locator.locateBlobStore(null, "two", null)
                .blobStore()).isSameAs(blobStoreTwo);
        // A presented identity must not match an anonymous glob entry
        assertThat(locator.locateBlobStore("foo", "one", null)).isNull();
    }
}
