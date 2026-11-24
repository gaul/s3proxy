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
                    "bucket", 1_500_000L, /*requestBytes=*/ 0,
                    /*responseBytes=*/ 4096);
            String body = metrics.scrape();
            assertThat(body).contains("http_server_request_duration");
            assertThat(body).contains("s3_operation=\"GetObject\"");
            assertThat(body).contains("http_server_request_body_size_bytes");
            assertThat(body).contains("http_server_response_body_size_bytes");
        } finally {
            metrics.close();
        }
    }

    /**
     * Unauthenticated requests are recorded too and every distinct label set
     * is kept, so the method and the scheme may not be whatever the client
     * wrote.
     */
    @Test
    public void testMethodAndSchemeAreNotTheClientsWords() throws Exception {
        var metrics = new S3ProxyMetrics();
        try {
            metrics.recordRequest("CHOSEN-METHOD", "chosen-scheme", 501,
                    S3Operation.UNKNOWN, "bucket", 1_500_000L,
                    /*requestBytes=*/ 0, /*responseBytes=*/ 0);
            metrics.recordRequest("PUT", "https", 200, S3Operation.PUT_OBJECT,
                    "bucket", 1_500_000L,
                    /*requestBytes=*/ 0, /*responseBytes=*/ 0);
            String body = metrics.scrape();
            assertThat(body).contains("http_request_method=\"_OTHER\"");
            assertThat(body).contains("url_scheme=\"http\"");
            assertThat(body).doesNotContain("CHOSEN-METHOD");
            assertThat(body).doesNotContain("chosen-scheme");
            assertThat(body).contains("http_request_method=\"PUT\"");
            assertThat(body).contains("url_scheme=\"https\"");
        } finally {
            metrics.close();
        }
    }
}
