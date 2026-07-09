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

package org.gaul.s3proxy.azureblob;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.junit.Test;

public final class AzureBlobStoreTest {
    @Test
    public void testTargetBlobNameTagEncodingIsBackwardCompatible() {
        String blobName = "folder/with spaces/+-_=.txt";
        String encoded = AzureBlobStore.encodeTargetBlobNameTagValue(blobName);

        assertThat(encoded).isNotEqualTo(blobName);
        assertThat(AzureBlobStore.decodeTargetBlobNameTagValue(encoded))
                .isEqualTo(blobName);

        String legacyPlain = "legacy/blob/name";
        assertThat(AzureBlobStore.decodeTargetBlobNameTagValue(legacyPlain))
                .isEqualTo(legacyPlain);

        String legacyPrefix = "base64url:legacy-not-base64-*";
        assertThat(AzureBlobStore.decodeTargetBlobNameTagValue(legacyPrefix))
                .isEqualTo(legacyPrefix);

        String legacyBase64 = "base64url:" + Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString("legacy-markerless".getBytes(StandardCharsets.UTF_8));
        assertThat(AzureBlobStore.decodeTargetBlobNameTagValue(legacyBase64))
                .isEqualTo(legacyBase64);
    }
}
