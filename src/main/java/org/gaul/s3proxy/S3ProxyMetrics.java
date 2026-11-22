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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.common.AttributesBuilder;
import io.opentelemetry.api.metrics.DoubleHistogram;
import io.opentelemetry.api.metrics.LongHistogram;
import io.opentelemetry.api.metrics.Meter;
import io.opentelemetry.exporter.prometheus.PrometheusMetricReader;
import io.opentelemetry.sdk.metrics.SdkMeterProvider;
import io.opentelemetry.semconv.HttpAttributes;
import io.opentelemetry.semconv.UrlAttributes;
import io.prometheus.metrics.expositionformats.PrometheusTextFormatWriter;

import org.jspecify.annotations.Nullable;

public final class S3ProxyMetrics {
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

    /**
     * Body sizes run from a few bytes of XML to objects of gigabytes, which
     * the default boundaries, made for durations in milliseconds, would put
     * in one bucket.
     */
    private static final List<Long> BODY_SIZE_BUCKETS = List.of(
            1024L, 16L * 1024, 256L * 1024, 1024L * 1024,
            16L * 1024 * 1024, 64L * 1024 * 1024, 256L * 1024 * 1024,
            1024L * 1024 * 1024, 5L * 1024 * 1024 * 1024);

    private final SdkMeterProvider meterProvider;
    private final DoubleHistogram requestDuration;
    private final LongHistogram requestBodySize;
    private final LongHistogram responseBodySize;
    private final PrometheusMetricReader metricReader;
    private final PrometheusTextFormatWriter textFormatWriter;

    public S3ProxyMetrics() {
        metricReader = PrometheusMetricReader.create();
        textFormatWriter = PrometheusTextFormatWriter.create();

        meterProvider = SdkMeterProvider.builder()
                .registerMetricReader(metricReader)
                .build();

        Meter meter = meterProvider.get("org.gaul.s3proxy");

        requestDuration = meter.histogramBuilder("http.server.request.duration")
                .setDescription("Duration of HTTP server requests")
                .setUnit("s")
                .setExplicitBucketBoundariesAdvice(DURATION_BUCKETS)
                .build();

        // Named by the OpenTelemetry HTTP conventions.  Each sum is the
        // bytes received or sent, by the same attributes as the duration.
        requestBodySize = meter.histogramBuilder(
                "http.server.request.body.size")
                .ofLongs()
                .setDescription("Size of HTTP server request bodies")
                .setUnit("By")
                .setExplicitBucketBoundariesAdvice(BODY_SIZE_BUCKETS)
                .build();
        responseBodySize = meter.histogramBuilder(
                "http.server.response.body.size")
                .ofLongs()
                .setDescription("Size of HTTP server response bodies")
                .setUnit("By")
                .setExplicitBucketBoundariesAdvice(BODY_SIZE_BUCKETS)
                .build();
    }

    public void recordRequest(
            String method,
            String scheme,
            int statusCode,
            @Nullable S3Operation operation,
            @Nullable String bucket,
            long durationNanos,
            long requestBytes,
            long responseBytes) {
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

        Attributes attributes = builder.build();
        requestDuration.record(durationSeconds, attributes);
        requestBodySize.record(requestBytes, attributes);
        responseBodySize.record(responseBytes, attributes);
    }

    public String scrape() throws IOException {
        var out = new ByteArrayOutputStream();
        textFormatWriter.write(out, metricReader.collect());
        return out.toString(StandardCharsets.UTF_8);
    }

    public void close() {
        meterProvider.close();
    }
}
