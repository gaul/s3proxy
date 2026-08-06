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

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Responses do not advertise the embedded server or its version. */
public final class ServerBannerTest {
    private S3Proxy s3Proxy;
    private String baseUri;

    @BeforeEach
    public void setUp() throws Exception {
        s3Proxy = S3Proxy.builder()
                .stopTimeout(0)
                .blobStore(TestUtils.createTransientBlobStore())
                .awsAuthentication(AuthenticationType.AWS_V2_OR_V4, "identity",
                        "credential")
                .endpoint(URI.create("http://127.0.0.1:0"))
                .build();
        s3Proxy.start();
        while (!s3Proxy.getState().equals("STARTED")) {
            Thread.sleep(10);
        }
        baseUri = "http://127.0.0.1:" + s3Proxy.getPort();
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
    }

    @Test
    public void testNoServerHeader() throws Exception {
        HttpResponse<String> response = get("/");
        assertThat(response.headers().firstValue("Server")).isEmpty();
    }

    @Test
    public void testErrorPageOmitsServerVersion() throws Exception {
        // A request Jetty rejects before S3ProxyHandler renders its own page
        HttpResponse<String> response = get("/container/blob?AWSAccessKeyId=" +
                "identity&Signature=abc&Expires=not-a-number");
        assertThat(response.body()).doesNotContain("Jetty");
        assertThat(response.headers().firstValue("Server")).isEmpty();
    }

    private HttpResponse<String> get(String pathAndQuery) throws Exception {
        return HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(URI.create(baseUri + pathAndQuery))
                        .GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }
}
