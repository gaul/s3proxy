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

import java.time.Instant;
import java.util.Date;

import org.gaul.s3proxy.blobstore.options.GetOptions;
import org.junit.jupiter.api.Test;

public final class NoCacheBlobStoreTest {
    @Test
    public void testResetCacheHeadersKeepRange() {
        var options = GetOptions.builder().range(1, 5).build();
        var optionsResult = NoCacheBlobStore.resetCacheHeaders(options);
        assertThat(optionsResult.ranges()).isEqualTo(options.ranges());
    }

    @Test
    public void testResetCacheHeadersKeepTail() {
        var options = GetOptions.builder()
                .range(1, 5).tail(3).startAt(10).build();
        var optionsResult = NoCacheBlobStore.resetCacheHeaders(options);
        assertThat(optionsResult.ranges()).isEqualTo(options.ranges());
    }

    @Test
    public void testResetCacheHeadersRangeDropCache() {
        var options = GetOptions.builder()
                .range(1, 5)
                .tail(3)
                .startAt(10)
                .ifETagDoesntMatch("abc")
                .ifModifiedSince(Date.from(Instant.EPOCH))
                .build();
        var optionsResult = NoCacheBlobStore.resetCacheHeaders(options);
        assertThat(optionsResult.ranges()).isEqualTo(options.ranges());
        assertThat(optionsResult.ifNoneMatch()).isEqualTo(null);
        assertThat(optionsResult.ifModifiedSince()).isEqualTo((Date) null);
    }

    @Test
    public void testResetCacheHeadersNoRange() {
        var options = GetOptions.builder()
                .ifETagMatches("abc")
                .ifUnmodifiedSince(Date.from(Instant.EPOCH))
                .build();
        var optionsResult = NoCacheBlobStore.resetCacheHeaders(options);
        assertThat(optionsResult.ranges()).isEqualTo(options.ranges());
        assertThat(optionsResult.ifMatch()).isEqualTo(null);
        assertThat(optionsResult.ifUnmodifiedSince()).isEqualTo((Date) null);
    }
}
