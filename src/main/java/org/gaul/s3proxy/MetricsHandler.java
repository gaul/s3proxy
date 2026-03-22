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

import java.io.IOException;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/** Servlet that serves Prometheus metrics at /metrics endpoint. */
public final class MetricsHandler extends HttpServlet {
    private final S3ProxyMetrics metrics;

    public MetricsHandler(S3ProxyMetrics metrics) {
        this.metrics = metrics;
    }

    @Override
    protected void service(HttpServletRequest request,
            HttpServletResponse response) throws IOException {
        response.setContentType("text/plain; version=0.0.4; charset=utf-8");
        response.setStatus(HttpServletResponse.SC_OK);
        response.getWriter().write(metrics.scrape());
    }
}
