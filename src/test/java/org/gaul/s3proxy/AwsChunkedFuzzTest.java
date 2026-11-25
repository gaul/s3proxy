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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;

import org.gaul.s3proxy.checksum.ChunkedInputStream;
import org.junit.jupiter.api.Tag;

/**
 * An aws-chunked body: it may be refused with an IOException, which the
 * handler reports as a truncated or malformed body, and never otherwise.
 * Without JAZZER_FUZZ this runs the saved inputs only.
 */
@Tag("fuzz")
public final class AwsChunkedFuzzTest {
    @FuzzTest
    void awsChunked(FuzzedDataProvider data) throws IOException {
        String trailer = data.pickValue(List.of(
                "", "x-amz-checksum-crc32", "x-amz-checksum-crc64nvme",
                "x-amz-checksum-sha256"));
        byte[] body = data.consumeRemainingAsBytes();
        try (InputStream is = new ChunkedInputStream(
                new ByteArrayInputStream(body), 64 * 1024,
                trailer.isEmpty() ? null : trailer)) {
            is.transferTo(OutputStream.nullOutputStream());
        } catch (IOException ioe) {
            // a malformed body
        } catch (RuntimeException re) {
            if (!FuzzOracles.isClientError(re)) {
                throw new AssertionError(new String(body,
                        StandardCharsets.ISO_8859_1), re);
            }
        }
    }
}
