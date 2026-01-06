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

import org.jclouds.blobstore.options.GetOptions;
import org.junit.jupiter.api.Test;

public final class NoCacheBlobStoreTest {
    @Test
    public void testResetCacheHeadersKeepRange() {
        var options = GetOptions.Builder.range(1, 5);
        var optionsResult = NoCacheBlobStore.resetCacheHeaders(options);
        assertThat(optionsResult.getRanges()).isEqualTo(options.getRanges());
    }

    @Test
    public void testResetCacheHeadersKeepTail() {
        var options = GetOptions.Builder.range(1, 5).tail(3).startAt(10);
        var optionsResult = NoCacheBlobStore.resetCacheHeaders(options);
        assertThat(optionsResult.getRanges()).isEqualTo(options.getRanges());
    }

    @Test
    public void testResetCacheHeadersRangeDropCache() {
        var options = GetOptions.Builder
                .range(1, 5)
                .tail(3)
                .startAt(10)
                .ifETagDoesntMatch("abc")
                .ifModifiedSince(Date.from(Instant.EPOCH));
        var optionsResult = NoCacheBlobStore.resetCacheHeaders(options);
        assertThat(optionsResult.getRanges()).isEqualTo(options.getRanges());
        assertThat(optionsResult.getIfNoneMatch()).isEqualTo(null);
        assertThat(optionsResult.getIfModifiedSince()).isEqualTo((Date) null);
    }

    @Test
    public void testResetCacheHeadersNoRange() {
        var options = GetOptions.Builder
                .ifETagMatches("abc")
                .ifUnmodifiedSince(Date.from(Instant.EPOCH));
        var optionsResult = NoCacheBlobStore.resetCacheHeaders(options);
        assertThat(optionsResult.getRanges()).isEqualTo(options.getRanges());
        assertThat(optionsResult.getIfMatch()).isEqualTo(null);
        assertThat(optionsResult.getIfUnmodifiedSince()).isEqualTo((Date) null);
    }
}
