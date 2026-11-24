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

package org.gaul.s3proxy.openstackswift;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import org.junit.jupiter.api.Test;

/**
 * Swift lists a container a page at a time, and the listings the store
 * depends on -- an upload's parts, the uploads of a bucket -- have to read
 * every page.  Ten thousand objects is too many to make for a test, so the
 * paging is tested apart from the service.
 */
public final class ListAllPagesTest {
    private static final List<String> NAMES =
            List.of("a", "b", "c", "d", "e", "f", "g");

    /** A listing of NAMES served {@code pageSize} at a time. */
    private static Function<String, List<? extends String>> paged(
            int pageSize, List<String> markersAsked) {
        return marker -> {
            markersAsked.add(marker);
            return NAMES.stream()
                    .filter(name -> marker == null ||
                            name.compareTo(marker) > 0)
                    .limit(pageSize)
                    .toList();
        };
    }

    @Test
    public void testFollowsEveryPage() {
        var asked = new ArrayList<String>();
        assertThat(OpenStackSwiftBlobStore.<String>allPages(
                paged(3, asked), name -> name)).isEqualTo(NAMES);
        // three pages of names and the empty one that ends the listing
        assertThat(asked).containsExactly(null, "c", "f", "g");
    }

    @Test
    public void testSinglePage() {
        var asked = new ArrayList<String>();
        assertThat(OpenStackSwiftBlobStore.<String>allPages(
                paged(100, asked), name -> name)).isEqualTo(NAMES);
        assertThat(asked).containsExactly(null, "g");
    }

    @Test
    public void testEmpty() {
        assertThat(OpenStackSwiftBlobStore.<String>allPages(
                marker -> List.of(), name -> name)).isEmpty();
    }

    /** Names not kept still move the marker, or the listing would end. */
    @Test
    public void testKeepsOnlyAcceptedNames() {
        var asked = new ArrayList<String>();
        assertThat(OpenStackSwiftBlobStore.<String>allPages(
                paged(3, asked), name -> name, name -> name.equals("g")))
                .containsExactly("g");
        assertThat(asked).containsExactly(null, "c", "f", "g");
    }

    /** A backend that ignores the marker must not loop or repeat names. */
    @Test
    public void testBackendIgnoringMarkers() {
        var calls = new ArrayList<String>();
        Function<String, List<? extends String>> ignoring = marker -> {
            calls.add(marker);
            return NAMES;
        };
        assertThat(OpenStackSwiftBlobStore.<String>allPages(
                ignoring, name -> name)).isEqualTo(NAMES);
        assertThat(calls).hasSize(2);
    }
}
