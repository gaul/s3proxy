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
import java.util.List;
import java.util.Properties;

import org.apache.http.HttpHost;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.gaul.s3proxy.auth.AuthenticationType;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * A request whose Host names neither the proxy nor an allowed host is
 * refused, as is the request of a web page which pointed its own DNS name at
 * the proxy to become same-origin with it.
 */
public final class AllowedHostsTest {
    private S3Proxy s3Proxy;

    @AfterEach
    public void tearDown() throws Exception {
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
    }

    @Test
    public void testAnonymousLoopbackChecksHost() throws Exception {
        start(builder());

        assertThat(listBuckets("attacker.example:" + s3Proxy.getPort()))
                .isEqualTo(HttpStatus.SC_FORBIDDEN);
        assertThat(listBuckets("attacker.example"))
                .isEqualTo(HttpStatus.SC_FORBIDDEN);
        assertThat(listBuckets("localhost.attacker.example"))
                .isEqualTo(HttpStatus.SC_FORBIDDEN);
        assertThat(listBuckets("127.0.0.1.attacker.example"))
                .isEqualTo(HttpStatus.SC_FORBIDDEN);

        assertThat(listBuckets("127.0.0.1:" + s3Proxy.getPort()))
                .isEqualTo(HttpStatus.SC_OK);
        assertThat(listBuckets("[::1]:" + s3Proxy.getPort()))
                .isEqualTo(HttpStatus.SC_OK);
        assertThat(listBuckets("localhost:" + s3Proxy.getPort()))
                .isEqualTo(HttpStatus.SC_OK);
        assertThat(listBuckets("LOCALHOST")).isEqualTo(HttpStatus.SC_OK);
    }

    @Test
    public void testRefusalIsAccessDenied() throws Exception {
        start(builder());

        try (CloseableHttpClient client = HttpClients.createDefault();
                CloseableHttpResponse response = client.execute(
                        new HttpHost("127.0.0.1", s3Proxy.getPort()),
                        request("attacker.example"))) {
            assertThat(response.getStatusLine().getStatusCode())
                    .isEqualTo(HttpStatus.SC_FORBIDDEN);
            assertThat(EntityUtils.toString(response.getEntity()))
                    .contains("<Code>AccessDenied</Code>");
        }
    }

    @Test
    public void testAllowedHosts() throws Exception {
        start(builder().allowedHosts(List.of("s3.example.com")));

        assertThat(listBuckets("s3.example.com"))
                .isEqualTo(HttpStatus.SC_OK);
        assertThat(listBuckets("S3.Example.Com:8080"))
                .isEqualTo(HttpStatus.SC_OK);
        assertThat(listBuckets("bucket.s3.example.com"))
                .isEqualTo(HttpStatus.SC_FORBIDDEN);
        assertThat(listBuckets("attacker.example"))
                .isEqualTo(HttpStatus.SC_FORBIDDEN);
    }

    @Test
    public void testAllowedHostsProperty() throws Exception {
        var properties = new Properties();
        properties.setProperty(S3ProxyConstants.PROPERTY_ENDPOINT,
                "http://127.0.0.1:0");
        properties.setProperty(S3ProxyConstants.PROPERTY_AUTHORIZATION,
                "none");
        properties.setProperty(S3ProxyConstants.PROPERTY_ALLOWED_HOSTS,
                "s3.example.com storage.internal");
        start(S3Proxy.Builder.fromProperties(properties)
                .stopTimeout(0)
                .blobStore(TestUtils.createTransientBlobStore()));

        assertThat(listBuckets("s3.example.com"))
                .isEqualTo(HttpStatus.SC_OK);
        assertThat(listBuckets("storage.internal"))
                .isEqualTo(HttpStatus.SC_OK);
        assertThat(listBuckets("attacker.example"))
                .isEqualTo(HttpStatus.SC_FORBIDDEN);
    }

    @Test
    public void testAllowAnyHost() throws Exception {
        start(builder().allowedHosts(List.of("*")));

        assertThat(listBuckets("attacker.example"))
                .isEqualTo(HttpStatus.SC_OK);
    }

    @Test
    public void testVirtualHost() throws Exception {
        start(builder().virtualHost("s3.test"));

        assertThat(listBuckets("s3.test")).isEqualTo(HttpStatus.SC_OK);
        // a bucket that does not exist, addressed by a name that is allowed
        assertThat(listBuckets("bucket.s3.test"))
                .isEqualTo(HttpStatus.SC_NOT_FOUND);
        assertThat(listBuckets("attacker.example"))
                .isEqualTo(HttpStatus.SC_FORBIDDEN);
    }

    @Test
    public void testAuthenticatedProxyChecksHostWhenConfigured()
            throws Exception {
        // /healthz answers without credentials
        start(builder().awsAuthentication(AuthenticationType.AWS_V2_OR_V4,
                "identity", "credential"));
        assertThat(get("/healthz", "s3.example.com"))
                .isEqualTo(HttpStatus.SC_OK);
        s3Proxy.stop();

        start(builder().awsAuthentication(AuthenticationType.AWS_V2_OR_V4,
                "identity", "credential")
                .allowedHosts(List.of("s3.example.com")));
        assertThat(get("/healthz", "s3.example.com"))
                .isEqualTo(HttpStatus.SC_OK);
        assertThat(get("/healthz", "attacker.example"))
                .isEqualTo(HttpStatus.SC_FORBIDDEN);
    }

    private static S3Proxy.Builder builder() {
        return S3Proxy.builder()
                .stopTimeout(0)
                .blobStore(TestUtils.createTransientBlobStore())
                .endpoint(URI.create("http://127.0.0.1:0"));
    }

    private void start(S3Proxy.Builder builder) throws Exception {
        s3Proxy = builder.build();
        s3Proxy.start();
        while (!s3Proxy.getState().equals("STARTED")) {
            Thread.sleep(10);
        }
    }

    private static HttpGet request(String host) {
        return request("/", host);
    }

    private static HttpGet request(String path, String host) {
        var request = new HttpGet(path);
        request.setHeader("Host", host);
        return request;
    }

    private int listBuckets(String host) throws Exception {
        return get("/", host);
    }

    /** Sends to the proxy's address whatever name the request is for. */
    private int get(String path, String host) throws Exception {
        try (CloseableHttpClient client = HttpClients.createDefault();
                CloseableHttpResponse response = client.execute(
                        new HttpHost("127.0.0.1", s3Proxy.getPort()),
                        request(path, host))) {
            EntityUtils.consume(response.getEntity());
            return response.getStatusLine().getStatusCode();
        }
    }
}
