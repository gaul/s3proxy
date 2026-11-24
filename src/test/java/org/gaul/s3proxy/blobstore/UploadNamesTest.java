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

package org.gaul.s3proxy.blobstore;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import org.junit.jupiter.api.Test;

public final class UploadNamesTest {
    private static final List<String> KEYS = List.of("", "a", "a\u0000",
            "a\t", "a b", "a!", "a!b", "a\"", "a/b", "a~", "ab", "b",
            "été", "dir/sub dir/x!y");

    @Test
    public void testEscapingRoundTrips() {
        for (String key : KEYS) {
            assertThat(UploadNames.unescapeKey(UploadNames.escapeKey(key)))
                    .isEqualTo(key);
        }
    }

    /**
     * A stub's name sorts as its key, then its upload ID: a key before the
     * keys it begins, whatever character continues them.
     */
    @Test
    public void testStubNamesSortAsTheirKeys() {
        var keys = new ArrayList<>(KEYS);
        keys.sort(Comparator.naturalOrder());
        var names = new ArrayList<String>();
        for (String key : keys) {
            names.add(UploadNames.escapeKey(key) + UploadNames.SEPARATOR +
                    UploadNames.newUploadId(key));
        }
        assertThat(names).isSorted();
    }

    @Test
    public void testSlashIsLeftForADelimiter() {
        assertThat(UploadNames.escapeKey("dir/sub dir/x"))
                .isEqualTo("dir/sub!20dir/x");
    }

    @Test
    public void testUploadIdNamesItsKey() throws Exception {
        String id = UploadNames.newUploadId("a");
        assertThat(id).hasSize(36);
        assertThat(UploadNames.isUploadId(id)).isTrue();
        assertThat(UploadNames.namesKey(id, "a")).isTrue();
        assertThat(UploadNames.namesKey(id, "b")).isFalse();
        assertThat(UploadNames.isUploadId(id + "0")).isFalse();

        // issued later, it sorts later
        Thread.sleep(2);
        assertThat(UploadNames.newUploadId("a")).isGreaterThan(id);
    }
}
