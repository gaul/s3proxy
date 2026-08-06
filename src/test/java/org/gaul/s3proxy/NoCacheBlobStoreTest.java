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

import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.GetObjectRequest;

public final class NoCacheBlobStoreTest {
    private static GetObjectRequest.Builder request() {
        return GetObjectRequest.builder().bucket("container").key("blob");
    }

    @Test
    public void testResetCacheHeadersKeepRange() {
        var request = request().range("bytes=1-5").build();
        var result = NoCacheBlobStore.resetCacheHeaders(request);
        assertThat(result.range()).isEqualTo(request.range());
    }

    @Test
    public void testResetCacheHeadersRangeDropCache() {
        var request = request()
                .range("bytes=1-5")
                .ifNoneMatch("abc")
                .ifModifiedSince(Instant.EPOCH)
                .build();
        var result = NoCacheBlobStore.resetCacheHeaders(request);
        assertThat(result.range()).isEqualTo(request.range());
        assertThat(result.ifNoneMatch()).isNull();
        assertThat(result.ifModifiedSince()).isNull();
    }

    @Test
    public void testResetCacheHeadersNoRange() {
        var request = request()
                .ifMatch("abc")
                .ifUnmodifiedSince(Instant.EPOCH)
                .build();
        var result = NoCacheBlobStore.resetCacheHeaders(request);
        assertThat(result.range()).isNull();
        assertThat(result.ifMatch()).isNull();
        assertThat(result.ifUnmodifiedSince()).isNull();
    }
}
