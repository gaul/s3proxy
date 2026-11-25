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

import com.code_intelligence.jazzer.junit.FuzzTest;
import com.code_intelligence.jazzer.mutation.annotation.NotNull;

import org.gaul.s3proxy.blobstore.UploadNames;
import org.junit.jupiter.api.Tag;

/**
 * The escaping of a key into the name of the stub that records a
 * multipart upload: any key survives the round trip.  Without JAZZER_FUZZ
 * this runs the saved inputs only.
 */
@Tag("fuzz")
public final class UploadKeyEscapingFuzzTest {
    @FuzzTest
    void uploadKeyEscaping(@NotNull String key) {
        assertThat(UploadNames.unescapeKey(UploadNames.escapeKey(key)))
                .isEqualTo(key);
    }
}
