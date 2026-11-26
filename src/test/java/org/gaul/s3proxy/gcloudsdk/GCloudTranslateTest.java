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

package org.gaul.s3proxy.gcloudsdk;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;

import com.google.cloud.storage.StorageException;

import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.S3Exception;

/**
 * A GCS refusal no case names is judged by its status.  It was passed on
 * raw, which the frontend answers 500 InternalError whatever GCS said, and
 * which every SDK retries.  A status with no S3 counterpart still is.
 */
public final class GCloudTranslateTest {
    @Test
    public void testUnnamedStatusIsTranslated() {
        for (var entry : List.of(
                Map.entry(409, "OperationAborted"),
                Map.entry(411, "MissingContentLength"),
                Map.entry(413, "EntityTooLarge"),
                Map.entry(416, "InvalidRange"),
                Map.entry(429, "SlowDown"),
                Map.entry(503, "ServiceUnavailable"))) {
            assertThat(GCloudBlobStore.translate(
                    new StorageException(entry.getKey(), "refused"),
                    "bucket", "key"))
                    .as("%d", entry.getKey())
                    .isInstanceOfSatisfying(S3Exception.class,
                            e -> assertThat(e.awsErrorDetails().errorCode())
                                    .isEqualTo(entry.getValue()));
        }
        assertThat(GCloudBlobStore.translate(
                new StorageException(418, "refused"), "bucket", "key"))
                .isInstanceOf(StorageException.class);
    }
}
