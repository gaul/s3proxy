/*
 * Copyright 2014-2021 Andrew Gaul <andrew@gaul.org>
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
import java.nio.file.PathMatcher;
import java.util.Map;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSortedMap;
import com.google.common.collect.Maps;
import com.google.inject.Module;

import org.jclouds.ContextBuilder;
import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.BlobStoreContext;
import org.jclouds.logging.slf4j.config.SLF4JLoggingModule;
import org.junit.Before;
import org.junit.Test;

public final class GlobBlobStoreLocatorTest {
    private BlobStore blobStoreOne;
    private BlobStore blobStoreTwo;

    @Before
    public void setUp() {
        blobStoreOne = ContextBuilder
                .newBuilder("transient")
                .credentials("identity", "credential")
                .modules(ImmutableList.<Module>of(new SLF4JLoggingModule()))
                .build(BlobStoreContext.class).getBlobStore();
        blobStoreTwo = ContextBuilder
                .newBuilder("transient")
                .credentials("identity", "credential")
                .modules(ImmutableList.<Module>of(new SLF4JLoggingModule()))
                .build(BlobStoreContext.class).getBlobStore();

    }

    @Test
    public void testLocateIdentity() {
        ImmutableMap<String, Map.Entry<String, BlobStore>> credsMap =
                ImmutableSortedMap.of(
                        "id1", Maps.immutableEntry("one", blobStoreOne),
                        "id2", Maps.immutableEntry("two", blobStoreTwo));
        GlobBlobStoreLocator locator = new GlobBlobStoreLocator(
                credsMap, ImmutableMap.of());
        assertThat(locator.locateBlobStore("id2", null, null).getKey())
                .isEqualTo("two");
        assertThat(locator.locateBlobStore(null, null, null).getKey())
                .isEqualTo("one");
        assertThat(locator.locateBlobStore("foo", null, null)).isNull();
    }

    @Test
    public void testLocateContainer() {
        ImmutableMap<String, Map.Entry<String, BlobStore>> credsMap =
                ImmutableMap.of(
                        "id1", Maps.immutableEntry("one", blobStoreOne),
                        "id2", Maps.immutableEntry("two", blobStoreTwo));
        ImmutableMap<PathMatcher, Map.Entry<String, BlobStore>> globMap =
                ImmutableMap.of(
                        FileSystems.getDefault().getPathMatcher(
                                "glob:container1"),
                        Maps.immutableEntry("id1", blobStoreOne),
                        FileSystems.getDefault().getPathMatcher(
                                "glob:container2"),
                        Maps.immutableEntry("id2", blobStoreTwo)
                );
        GlobBlobStoreLocator locator = new GlobBlobStoreLocator(credsMap,
                globMap);

        assertThat(locator.locateBlobStore(null, "container1", null)
                .getValue()).isSameAs(blobStoreOne);
        assertThat(locator.locateBlobStore(null, "container2", null)
                .getValue()).isSameAs(blobStoreTwo);
        assertThat(locator.locateBlobStore("id1", "foo", null)
                .getValue()).isSameAs(blobStoreOne);
        assertThat(locator.locateBlobStore("id2", "foo", null)
                .getValue()).isSameAs(blobStoreTwo);
        assertThat(locator.locateBlobStore("foo", "container1", null))
                .isNull();
        assertThat(locator.locateBlobStore("foo", "container2", null))
                .isNull();
    }

    @Test
    public void testLocateGlob() {
        ImmutableMap<String, Map.Entry<String, BlobStore>> credsMap =
                ImmutableSortedMap.of(
                        "id0", Maps.immutableEntry("zero", null),
                        "id1", Maps.immutableEntry("one", blobStoreOne),
                        "id2", Maps.immutableEntry("two", blobStoreTwo));
        ImmutableMap<PathMatcher, Map.Entry<String, BlobStore>> globMap =
                ImmutableMap.of(
                        FileSystems.getDefault().getPathMatcher(
                                "glob:{one,two}"),
                        Maps.immutableEntry("id1", blobStoreOne),
                        FileSystems.getDefault().getPathMatcher(
                                "glob:cont?X*"),
                        Maps.immutableEntry("id2", blobStoreTwo)
                );
        GlobBlobStoreLocator locator = new GlobBlobStoreLocator(credsMap,
                globMap);

        assertThat(locator.locateBlobStore(null, "one", null)
                .getValue()).isSameAs(blobStoreOne);
        assertThat(locator.locateBlobStore("id1", "two", null)
                .getValue()).isSameAs(blobStoreOne);
        assertThat(locator.locateBlobStore("id2", "cont5X.extra", null)
                .getValue()).isSameAs(blobStoreTwo);
    }

    @Test
    public void testGlobLocatorAnonymous() {
        ImmutableMap<PathMatcher, Map.Entry<String, BlobStore>> globMap =
                ImmutableMap.of(
                        FileSystems.getDefault().getPathMatcher(
                                "glob:one"),
                        Maps.immutableEntry(null, blobStoreOne),
                        FileSystems.getDefault().getPathMatcher(
                                "glob:two"),
                        Maps.immutableEntry(null, blobStoreTwo)
                );
        GlobBlobStoreLocator locator = new GlobBlobStoreLocator(
                ImmutableMap.of(), globMap);

        assertThat(locator.locateBlobStore(null, null, null)
                .getValue()).isSameAs(blobStoreOne);
        assertThat(locator.locateBlobStore(null, "one", null)
                .getValue()).isSameAs(blobStoreOne);
        assertThat(locator.locateBlobStore(null, "two", null)
                .getValue()).isSameAs(blobStoreTwo);
    }
}
