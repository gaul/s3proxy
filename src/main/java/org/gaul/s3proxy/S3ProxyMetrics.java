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

import java.util.List;

import javax.annotation.Nullable;

import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.common.AttributesBuilder;
import io.opentelemetry.api.metrics.DoubleHistogram;
import io.opentelemetry.api.metrics.Meter;
import io.opentelemetry.exporter.prometheus.PrometheusHttpServer;
import io.opentelemetry.sdk.metrics.SdkMeterProvider;
import io.opentelemetry.semconv.HttpAttributes;
import io.opentelemetry.semconv.UrlAttributes;

public final class S3ProxyMetrics {
    /** Default metrics port (0 = ephemeral). */
    public static final int DEFAULT_METRICS_PORT = 0;
    public static final String DEFAULT_METRICS_HOST = "0.0.0.0";

    private static final AttributeKey<String> S3_OPERATION =
            AttributeKey.stringKey("s3.operation");
    private static final AttributeKey<String> S3_BUCKET =
            AttributeKey.stringKey("s3.bucket");
    // OTel semantic conventions specify these bucket boundaries for
    // http.server.request.duration histogram.
    // See: https://opentelemetry.io/docs/specs/semconv/http/http-metrics/
    private static final List<Double> DURATION_BUCKETS = List.of(
            0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5,
            0.75, 1.0, 2.5, 5.0, 7.5, 10.0);

    private final SdkMeterProvider meterProvider;
    private final DoubleHistogram requestDuration;
    private final PrometheusHttpServer prometheusServer;

    public S3ProxyMetrics() {
        this(DEFAULT_METRICS_HOST, DEFAULT_METRICS_PORT);
    }

    public S3ProxyMetrics(String host, int port) {
        prometheusServer = PrometheusHttpServer.builder()
                .setHost(host)
                .setPort(port)
                .build();

        meterProvider = SdkMeterProvider.builder()
                .registerMetricReader(prometheusServer)
                .build();

        Meter meter = meterProvider.get("org.gaul.s3proxy");

        requestDuration = meter.histogramBuilder("http.server.request.duration")
                .setDescription("Duration of HTTP server requests")
                .setUnit("s")
                .setExplicitBucketBoundariesAdvice(DURATION_BUCKETS)
                .build();
    }

    public void recordRequest(
            String method,
            String scheme,
            int statusCode,
            @Nullable S3Operation operation,
            @Nullable String bucket,
            long durationNanos) {
        if (operation == null) {
            return;
        }

        double durationSeconds = durationNanos / 1_000_000_000.0;

        AttributesBuilder builder = Attributes.builder()
                .put(HttpAttributes.HTTP_REQUEST_METHOD, method)
                .put(UrlAttributes.URL_SCHEME, scheme)
                .put(HttpAttributes.HTTP_RESPONSE_STATUS_CODE, statusCode)
                .put(S3_OPERATION, operation.getValue());

        if (bucket != null && !bucket.isEmpty()) {
            builder.put(S3_BUCKET, bucket);
        }

        requestDuration.record(durationSeconds, builder.build());
    }

    public String scrape() {
        return prometheusServer.toString();
    }

    public void close() {
        if (prometheusServer != null) {
            prometheusServer.close();
        }
        if (meterProvider != null) {
            meterProvider.close();
        }
    }
}
