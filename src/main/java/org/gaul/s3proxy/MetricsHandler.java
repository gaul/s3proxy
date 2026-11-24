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
import java.util.concurrent.Semaphore;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/** Servlet that serves Prometheus metrics at /metrics endpoint. */
public final class MetricsHandler extends HttpServlet {
    /**
     * How many scrapes may be in progress at once.  Each holds its own
     * snapshot of every series until its client has read all of it, and
     * /metrics asks for no credentials, so without a bound clients that stop
     * reading could fill the heap with as many snapshots as there are request
     * threads.
     */
    static final int MAX_CONCURRENT_SCRAPES = 8;

    private final S3ProxyMetrics metrics;
    private final Semaphore scrapes = new Semaphore(MAX_CONCURRENT_SCRAPES);

    public MetricsHandler(S3ProxyMetrics metrics) {
        this.metrics = metrics;
    }

    @Override
    protected void service(HttpServletRequest request,
            HttpServletResponse response) throws IOException {
        if (!scrapes.tryAcquire()) {
            response.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE,
                    "Too many concurrent scrapes");
            return;
        }
        try {
            response.setContentType(
                    "text/plain; version=0.0.4; charset=utf-8");
            response.setStatus(HttpServletResponse.SC_OK);
            // Rendered into the response rather than into a string, which
            // would be held whole, beside the snapshot, until it is read.
            metrics.scrape(response.getOutputStream());
        } finally {
            scrapes.release();
        }
    }
}
