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

import java.io.InputStream;

import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.GetObjectResponse;

public final class SdkResponsesTest {
    /**
     * The SDK's timeout keeps a stream reachable from its scheduler until it
     * runs out, even one that was closed, unless the stream was read first.
     */
    @Test
    public void testGetResponseIsNotHeldByATimeout() throws Exception {
        try (var blob = SdkResponses.getResponse(
                GetObjectResponse.builder().build(),
                InputStream.nullInputStream())) {
            assertThat(blob.hasTimeoutTask()).isFalse();
        }
    }
}
