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

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;

import org.jclouds.ContextBuilder;
import org.jclouds.blobstore.BlobStoreContext;
import org.jclouds.logging.slf4j.config.SLF4JLoggingModule;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

public final class S3ProxyMetricsEndpointTest {
    // Prometheus text exposition marker in the metrics Content-Type; absent
    // from ordinary S3 (XML) responses.
    private static final String PROMETHEUS_CONTENT_TYPE = "version=0.0.4";

    private BlobStoreContext context;
    private S3Proxy s3Proxy;

    @AfterEach
    public void tearDown() throws Exception {
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
        if (context != null) {
            context.close();
        }
    }

    private S3Proxy.Builder baseBuilder() {
        context = ContextBuilder.newBuilder("transient")
                .credentials("identity", "credential")
                .modules(List.of(new SLF4JLoggingModule()))
                .build(BlobStoreContext.class);
        return S3Proxy.builder()
                .endpoint(URI.create("http://127.0.0.1:0"))
                .blobStore(context.getBlobStore());
    }

    private static HttpResponse<String> get(String url) throws Exception {
        return HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(URI.create(url)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }

    @Test
    public void testMetricsPortServesMetricsAndS3PortDoesNot()
            throws Exception {
        s3Proxy = baseBuilder()
                .metricsEnabled(true)
                .metricsPort(0)
                .metricsHost("127.0.0.1")
                .build();
        s3Proxy.start();

        int metricsPort = s3Proxy.getMetricsPort();
        assertThat(metricsPort).isGreaterThan(0);
        assertThat(metricsPort).isNotEqualTo(s3Proxy.getPort());

        // /metrics is served on the dedicated port.
        HttpResponse<String> onMetricsPort = get(
                "http://127.0.0.1:" + metricsPort + "/metrics");
        assertThat(onMetricsPort.statusCode()).isEqualTo(200);
        assertThat(onMetricsPort.headers().firstValue("Content-Type")
                .orElse("")).contains(PROMETHEUS_CONTENT_TYPE);

        // /metrics is not exposed on the S3 endpoint.
        HttpResponse<String> onS3Port = get(
                "http://127.0.0.1:" + s3Proxy.getPort() + "/metrics");
        assertThat(onS3Port.headers().firstValue("Content-Type")
                .orElse("")).doesNotContain(PROMETHEUS_CONTENT_TYPE);
    }

    @Test
    public void testMetricsWithoutPortServedOnS3Endpoint() throws Exception {
        s3Proxy = baseBuilder()
                .metricsEnabled(true)
                .build();
        s3Proxy.start();

        assertThat(s3Proxy.getMetricsPort()).isEqualTo(-1);

        HttpResponse<String> response = get(
                "http://127.0.0.1:" + s3Proxy.getPort() + "/metrics");
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.headers().firstValue("Content-Type")
                .orElse("")).contains(PROMETHEUS_CONTENT_TYPE);
    }
}
