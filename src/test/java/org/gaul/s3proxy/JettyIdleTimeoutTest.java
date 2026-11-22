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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

import javax.net.ssl.SSLContext;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/** Configured idle timeouts apply to the S3 listeners, not backend reads. */
public final class JettyIdleTimeoutTest {
    private S3Proxy s3Proxy;
    private BlobStore blobStore;

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

    private static Properties properties(String timeout) {
        var properties = new Properties();
        properties.setProperty(S3ProxyConstants.PROPERTY_ENDPOINT,
                "http://127.0.0.1:0");
        properties.setProperty(S3ProxyConstants.PROPERTY_AUTHORIZATION, "none");
        if (timeout != null) {
            properties.setProperty(
                    S3ProxyConstants.PROPERTY_JETTY_IDLE_TIMEOUT, timeout);
        }
        return properties;
    }

    private static Server server(S3Proxy proxy) throws Exception {
        // Inspect both listeners without exposing Jetty in the public API
        // or needing a certificate just to inspect the HTTPS configuration.
        var field = S3Proxy.class.getDeclaredField("server");
        field.setAccessible(true);
        return (Server) field.get(proxy);
    }

    @Test
    public void testDefaultUnchangedOnHttpAndHttps() throws Exception {
        s3Proxy = baseBuilder()
                .secureEndpoint(URI.create("https://127.0.0.1:0"))
                .sslContext(SSLContext.getDefault())
                .build();
        assertThat(server(s3Proxy).getConnectors()).hasSize(2);
        for (var connector : server(s3Proxy).getConnectors()) {
            assertThat(((ServerConnector) connector).getIdleTimeout())
                    .isEqualTo(30_000);
        }
    }

    @Test
    public void testBuilderSetsBothListeners() throws Exception {
        s3Proxy = baseBuilder()
                .secureEndpoint(URI.create("https://127.0.0.1:0"))
                .sslContext(SSLContext.getDefault())
                .jettyIdleTimeout(120_000)
                .build();
        assertThat(server(s3Proxy).getConnectors()).hasSize(2);
        for (var connector : server(s3Proxy).getConnectors()) {
            assertThat(((ServerConnector) connector).getIdleTimeout())
                    .isEqualTo(120_000);
        }
    }

    @Test
    public void testPropertiesSetTimeout() throws Exception {
        blobStore = TestUtils.createTransientBlobStore();
        s3Proxy = S3Proxy.Builder.fromProperties(properties("120000"))
                .blobStore(blobStore)
                .stopTimeout(0)
                .build();
        assertThat(((ServerConnector) server(s3Proxy).getConnectors()[0])
                .getIdleTimeout()).isEqualTo(120_000);
    }

    @Test
    public void testOmittedPropertyKeepsDefault() throws Exception {
        blobStore = TestUtils.createTransientBlobStore();
        s3Proxy = S3Proxy.Builder.fromProperties(properties(null))
                .blobStore(blobStore)
                .stopTimeout(0)
                .build();
        assertThat(((ServerConnector) server(s3Proxy).getConnectors()[0])
                .getIdleTimeout()).isEqualTo(30_000);
    }

    @Test
    public void testZeroDisablesTimeout() throws Exception {
        blobStore = TestUtils.createTransientBlobStore();
        s3Proxy = S3Proxy.Builder.fromProperties(properties("0"))
                .blobStore(blobStore)
                .stopTimeout(0)
                .build();
        assertThat(((ServerConnector) server(s3Proxy).getConnectors()[0])
                .getIdleTimeout()).isZero();
    }

    @Test
    public void testNegativeTimeoutRejected() {
        assertThatThrownBy(() -> S3Proxy.builder().jettyIdleTimeout(-1))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() ->
                S3Proxy.Builder.fromProperties(properties("-1")))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    public void testInvalidTimeoutRejected() {
        assertThatThrownBy(() ->
                S3Proxy.Builder.fromProperties(properties("not-a-number")))
                .isInstanceOf(NumberFormatException.class);
        assertThatThrownBy(() -> S3Proxy.Builder.fromProperties(
                properties("9223372036854775808")))
                .isInstanceOf(NumberFormatException.class);
    }

    @Test
    public void testShortTimeoutClosesStalledRequest() throws Exception {
        s3Proxy = baseBuilder().jettyIdleTimeout(100).build();
        s3Proxy.start();
        try (var socket = new Socket(
                InetAddress.getByAddress(new byte[] {127, 0, 0, 1}),
                s3Proxy.getPort())) {
            socket.setSoTimeout(5000);
            socket.getOutputStream().write(
                    "GET /healthz HTTP/1.1\r\nHost: localhost\r\n"
                            .getBytes(StandardCharsets.US_ASCII));
            var reader = new BufferedReader(new InputStreamReader(
                    socket.getInputStream(), StandardCharsets.US_ASCII));
            String status = reader.readLine();
            assertThat(status == null || status.contains("408")).isTrue();
        }
    }

    @Test
    public void testLongerTimeoutAllowsRequestToResume() throws Exception {
        s3Proxy = baseBuilder().jettyIdleTimeout(5000).build();
        s3Proxy.start();
        try (var socket = new Socket(
                InetAddress.getByAddress(new byte[] {127, 0, 0, 1}),
                s3Proxy.getPort())) {
            socket.setSoTimeout(10_000);
            socket.getOutputStream().write(
                    "GET /healthz HTTP/1.1\r\nHost: localhost\r\n"
                            .getBytes(StandardCharsets.US_ASCII));
            Thread.sleep(350);
            socket.getOutputStream().write(
                    "Connection: close\r\n\r\n"
                            .getBytes(StandardCharsets.US_ASCII));
            var reader = new BufferedReader(new InputStreamReader(
                    socket.getInputStream(), StandardCharsets.US_ASCII));
            assertThat(reader.readLine()).contains("200");
        }
    }
}
