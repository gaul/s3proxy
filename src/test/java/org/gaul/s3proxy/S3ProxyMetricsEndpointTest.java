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

import java.net.InetAddress;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;

import org.gaul.s3proxy.auth.AuthenticationType;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.BucketCannedACL;

public final class S3ProxyMetricsEndpointTest {
    // Prometheus text exposition marker in the metrics Content-Type; absent
    // from ordinary S3 (XML) responses.
    private static final String PROMETHEUS_CONTENT_TYPE = "version=0.0.4";

    private BlobStore blobStore;
    private S3Proxy s3Proxy;

    @AfterEach
    public void tearDown() throws Exception {
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
        if (blobStore != null) {
            blobStore.close();
        }
    }

    private S3Proxy.Builder baseBuilder() {
        blobStore = TestUtils.createTransientBlobStore();
        return S3Proxy.builder()
                .stopTimeout(0)
                .endpoint(URI.create("http://127.0.0.1:0"))
                .blobStore(blobStore);
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

    /**
     * The body size histograms sum to the bytes each operation received and
     * sent: an upload counts toward the request sizes and a download toward
     * the response sizes.
     */
    @Test
    public void testBodySizesAreRecorded() throws Exception {
        s3Proxy = baseBuilder()
                .metricsEnabled(true)
                .build();
        s3Proxy.start();
        String base = "http://127.0.0.1:" + s3Proxy.getPort();
        var client = HttpClient.newHttpClient();
        var content = new byte[1000];

        assertThat(client.send(HttpRequest.newBuilder(
                URI.create(base + "/bucket"))
                .PUT(HttpRequest.BodyPublishers.noBody()).build(),
                HttpResponse.BodyHandlers.discarding()).statusCode())
                .isEqualTo(200);
        assertThat(client.send(HttpRequest.newBuilder(
                URI.create(base + "/bucket/key"))
                .PUT(HttpRequest.BodyPublishers.ofByteArray(content)).build(),
                HttpResponse.BodyHandlers.discarding()).statusCode())
                .isEqualTo(200);
        for (int i = 0; i < 2; ++i) {
            assertThat(client.send(HttpRequest.newBuilder(
                    URI.create(base + "/bucket/key")).build(),
                    HttpResponse.BodyHandlers.ofByteArray()).body())
                    .hasSize(content.length);
        }

        String metrics = get(base + "/metrics").body();
        assertThat(sum(metrics, "http_server_request_body_size_bytes",
                "PutObject")).isEqualTo(1000);
        assertThat(sum(metrics, "http_server_response_body_size_bytes",
                "PutObject")).isZero();
        assertThat(sum(metrics, "http_server_request_body_size_bytes",
                "GetObject")).isZero();
        assertThat(sum(metrics, "http_server_response_body_size_bytes",
                "GetObject")).isEqualTo(2000);
    }

    /** The _sum sample of one histogram for one S3 operation. */
    private static double sum(String metrics, String name, String operation) {
        return metrics.lines()
                .filter(line -> line.startsWith(name + "_sum{"))
                .filter(line -> line.contains(
                        "s3_operation=\"" + operation + "\""))
                .mapToDouble(line -> Double.parseDouble(
                        line.substring(line.lastIndexOf(' ') + 1)))
                .findFirst()
                .orElseThrow(() -> new AssertionError(
                        "no " + name + " for " + operation + " in:\n" +
                        metrics));
    }

    /**
     * A raw socket, since HttpClient will not send a request line in
     * absolute form, whose scheme Jetty reports as the request's.
     */
    @Test
    public void testUnauthenticatedRequestDoesNotChooseLabels()
            throws Exception {
        s3Proxy = baseBuilder()
                .awsAuthentication(AuthenticationType.AWS_V2_OR_V4,
                        "local-identity", "local-credential")
                .metricsEnabled(true)
                .build();
        s3Proxy.start();
        blobStore.createContainer("public-bucket");
        blobStore.setContainerAccess("public-bucket",
                BucketCannedACL.PUBLIC_READ);

        String response;
        try (var socket = new Socket(InetAddress.getLoopbackAddress(),
                s3Proxy.getPort())) {
            socket.getOutputStream().write(("DELETE chosen-scheme:" +
                    "//127.0.0.1/chosen-bucket/key HTTP/1.1\r\n" +
                    "Host: 127.0.0.1\r\n" +
                    "Connection: close\r\n\r\n").getBytes(
                            StandardCharsets.US_ASCII));
            response = new String(socket.getInputStream().readAllBytes(),
                    StandardCharsets.UTF_8);
        }
        assertThat(response).startsWith("HTTP/1.1 404 ");
        // An anonymous request that is let through does name its bucket.
        assertThat(get("http://127.0.0.1:" + s3Proxy.getPort() +
                "/public-bucket").statusCode()).isEqualTo(200);

        String metrics = get("http://127.0.0.1:" + s3Proxy.getPort() +
                "/metrics").body();
        assertThat(metrics).contains("s3_operation=\"DeleteObject\"");
        assertThat(metrics).contains("url_scheme=\"http\"");
        assertThat(metrics).doesNotContain("chosen-scheme");
        assertThat(metrics).doesNotContain("chosen-bucket");
        assertThat(metrics).contains("s3_bucket=\"public-bucket\"");
    }
}
