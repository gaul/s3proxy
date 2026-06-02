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

import org.junit.jupiter.api.Test;

public final class S3ProxyMetricsTest {
    @Test
    public void testScrapeReturnsPrometheusExposition() throws Exception {
        var metrics = new S3ProxyMetrics();
        try {
            metrics.recordRequest("GET", "http", 200, S3Operation.GET_OBJECT,
                    "bucket", 1_500_000L);
            String body = metrics.scrape();
            assertThat(body).contains("http_server_request_duration");
            assertThat(body).contains("s3_operation=\"GetObject\"");
        } finally {
            metrics.close();
        }
    }
}
