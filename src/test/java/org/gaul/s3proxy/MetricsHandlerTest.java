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

import java.io.IOException;
import java.io.InterruptedIOException;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.Test;

public final class MetricsHandlerTest {
    // Clients that stop reading their scrapes until resume is counted down.
    private final CountDownLatch reading = new CountDownLatch(
            MetricsHandler.MAX_CONCURRENT_SCRAPES);
    private final CountDownLatch resume = new CountDownLatch(1);

    /**
     * A scrape holds a snapshot of every series for as long as its client
     * takes to read it, and /metrics asks for no credentials, so clients
     * that stop reading must not be able to hold more than a few.
     */
    @Test
    public void testScrapesBeyondTheBoundAreRefused() throws Exception {
        var metrics = new S3ProxyMetrics();
        var executor = Executors.newFixedThreadPool(
                MetricsHandler.MAX_CONCURRENT_SCRAPES + 1);
        try {
            metrics.recordRequest("GET", "http", 200, S3Operation.GET_OBJECT,
                    "bucket", 1_500_000L,
                    /*requestBytes=*/ 0, /*responseBytes=*/ 0);
            var handler = new MetricsHandler(metrics);

            var stalled = new ArrayList<Future<Integer>>();
            for (int i = 0; i < MetricsHandler.MAX_CONCURRENT_SCRAPES; ++i) {
                stalled.add(executor.submit(() -> scrape(handler)));
            }
            assertThat(reading.await(30, TimeUnit.SECONDS)).isTrue();

            // On another thread so that a scrape that is let in, and then
            // waits for its client like the others, fails the test.
            assertThat(executor.submit(() -> scrape(handler))
                    .get(30, TimeUnit.SECONDS)).isEqualTo(
                    HttpServletResponse.SC_SERVICE_UNAVAILABLE);

            resume.countDown();
            for (var scrape : stalled) {
                assertThat(scrape.get(30, TimeUnit.SECONDS)).isEqualTo(
                        HttpServletResponse.SC_OK);
            }
            assertThat(scrape(handler)).isEqualTo(HttpServletResponse.SC_OK);
        } finally {
            executor.shutdownNow();
            metrics.close();
        }
    }

    /** Returns the status the handler answers a scrape with. */
    private int scrape(MetricsHandler handler) throws IOException {
        var status = new AtomicInteger();
        var body = new ServletOutputStream() {
            @Override
            public void write(int b) throws IOException {
                reading.countDown();
                try {
                    resume.await();
                } catch (InterruptedException ie) {
                    throw new InterruptedIOException();
                }
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setWriteListener(WriteListener listener) {
                throw new UnsupportedOperationException();
            }
        };
        var request = (HttpServletRequest) Proxy.newProxyInstance(
                HttpServletRequest.class.getClassLoader(),
                new Class<?>[] {HttpServletRequest.class},
                (proxy, method, args) -> null);
        var response = (HttpServletResponse) Proxy.newProxyInstance(
                HttpServletResponse.class.getClassLoader(),
                new Class<?>[] {HttpServletResponse.class},
                (proxy, method, args) -> {
                    switch (method.getName()) {
                    case "setStatus", "sendError" ->
                        status.set((Integer) args[0]);
                    case "getOutputStream" -> {
                        return body;
                    }
                    default -> { }
                    }
                    return null;
                });
        handler.service(request, response);
        return status.get();
    }
}
