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
import java.util.Properties;
import java.util.concurrent.CopyOnWriteArrayList;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * The access log is one line per completed request, written only when asked
 * for, and names the path without the query string that a presigned URL
 * keeps its access key and signature in.  Issues #368 and #767.
 */
public final class AccessLogTest {
    private final List<String> lines = new CopyOnWriteArrayList<>();
    private final HttpClient client = HttpClient.newHttpClient();
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

    private String start(boolean accessLog) throws Exception {
        blobStore = TestUtils.createTransientBlobStore();
        s3Proxy = S3Proxy.builder()
                .stopTimeout(0)
                .endpoint(URI.create("http://127.0.0.1:0"))
                .blobStore(blobStore)
                .accessLog(accessLog)
                .accessLogWriter(lines::add)
                .build();
        s3Proxy.start();
        return "http://127.0.0.1:" + s3Proxy.getPort();
    }

    private int send(HttpRequest.Builder request) throws Exception {
        return client.send(request.header("User-Agent", "access-log-test")
                .build(), HttpResponse.BodyHandlers.discarding())
                .statusCode();
    }

    /** The line is written as the response completes, after the client. */
    private void awaitLines(int count) throws Exception {
        for (int i = 0; i < 500 && lines.size() < count; ++i) {
            Thread.sleep(10);
        }
        assertThat(lines).hasSize(count);
    }

    @Test
    public void testRequestsAreLogged() throws Exception {
        String base = start(/*accessLog=*/ true);

        assertThat(send(HttpRequest.newBuilder(URI.create(base + "/bucket"))
                .PUT(HttpRequest.BodyPublishers.noBody()))).isEqualTo(200);
        assertThat(send(HttpRequest.newBuilder(
                URI.create(base + "/bucket/key"))
                .PUT(HttpRequest.BodyPublishers.ofByteArray(new byte[1000]))))
                .isEqualTo(200);
        assertThat(send(HttpRequest.newBuilder(
                URI.create(base + "/bucket/missing")))).isEqualTo(404);

        awaitLines(3);
        assertThat(lines.get(0)).contains("\"PUT /bucket HTTP/1.1\" 200 ");
        // 1000 bytes received, none sent
        assertThat(lines.get(1)).contains(
                "\"PUT /bucket/key HTTP/1.1\" 200 1000 0 ");
        assertThat(lines.get(2)).contains(
                "\"GET /bucket/missing HTTP/1.1\" 404 ");
        assertThat(lines).allSatisfy(line -> assertThat(line)
                .startsWith("127.0.0.1 ")
                .endsWith(" \"access-log-test\""));
    }

    @Test
    public void testQueryStringIsNotLogged() throws Exception {
        String base = start(/*accessLog=*/ true);
        assertThat(send(HttpRequest.newBuilder(URI.create(base + "/bucket"))
                .PUT(HttpRequest.BodyPublishers.noBody()))).isEqualTo(200);

        assertThat(send(HttpRequest.newBuilder(URI.create(base +
                "/bucket?list-type=2&prefix=not-for-the-log"))))
                .isEqualTo(200);

        awaitLines(2);
        assertThat(lines.get(1)).contains("\"GET /bucket HTTP/1.1\" 200 ")
                .doesNotContain("not-for-the-log")
                .doesNotContain("list-type");
    }

    /** A request Jetty refuses before S3ProxyHandler is logged all the same. */
    @Test
    public void testRequestRejectedByJettyIsLogged() throws Exception {
        String base = start(/*accessLog=*/ true);

        assertThat(send(HttpRequest.newBuilder(
                URI.create(base + "/bucket/%AE")))).isEqualTo(400);

        awaitLines(1);
        assertThat(lines.get(0)).contains(" 400 ");
    }

    @Test
    public void testNothingIsLoggedByDefault() throws Exception {
        String base = start(/*accessLog=*/ false);

        assertThat(send(HttpRequest.newBuilder(URI.create(base + "/bucket"))
                .PUT(HttpRequest.BodyPublishers.noBody()))).isEqualTo(200);

        Thread.sleep(200);
        assertThat(lines).isEmpty();
    }

    @Test
    public void testPropertyEnablesTheLog() throws Exception {
        var properties = new Properties();
        properties.setProperty(S3ProxyConstants.PROPERTY_ENDPOINT,
                "http://127.0.0.1:0");
        properties.setProperty(S3ProxyConstants.PROPERTY_AUTHORIZATION,
                "none");
        var without = S3Proxy.Builder.fromProperties(properties);
        properties.setProperty(S3ProxyConstants.PROPERTY_ACCESS_LOG, "true");
        var with = S3Proxy.Builder.fromProperties(properties);

        // every properties file must agree on it, as on any listener setting
        assertThat(without.differingProperties(with))
                .containsExactly(S3ProxyConstants.PROPERTY_ACCESS_LOG);

        blobStore = TestUtils.createTransientBlobStore();
        s3Proxy = with.stopTimeout(0).blobStore(blobStore)
                .accessLogWriter(lines::add).build();
        s3Proxy.start();
        assertThat(send(HttpRequest.newBuilder(URI.create(
                "http://127.0.0.1:" + s3Proxy.getPort() + "/"))))
                .isEqualTo(200);
        awaitLines(1);
    }
}
