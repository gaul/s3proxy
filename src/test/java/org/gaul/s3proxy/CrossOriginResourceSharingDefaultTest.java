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

import com.google.common.net.HttpHeaders;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * A proxy built through the API without a CORS policy -- what
 * {@link org.gaul.s3proxy.junit.S3ProxyJunitCore} and other embedders do --
 * shares nothing cross-origin.  Sharing is opt-in, as it is for the
 * s3proxy.cors-* properties.
 */
public final class CrossOriginResourceSharingDefaultTest {
    private S3Proxy s3Proxy;

    @BeforeEach
    public void setUp() throws Exception {
        s3Proxy = S3Proxy.builder()
                .blobStore(TestUtils.createTransientBlobStore())
                .awsAuthentication(AuthenticationType.NONE, "", "")
                .endpoint(URI.create("http://127.0.0.1:0"))
                .build();
        s3Proxy.start();
        while (!s3Proxy.getState().equals("STARTED")) {
            Thread.sleep(10);
        }
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
    }

    @Test
    public void testUnconfiguredCorsSharesNothing() throws Exception {
        var uri = URI.create("http://127.0.0.1:" + s3Proxy.getPort() + "/");
        HttpResponse<String> response = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(uri)
                        .header(HttpHeaders.ORIGIN, "https://evil.example")
                        .GET().build(),
                HttpResponse.BodyHandlers.ofString());

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.headers().firstValue(
                HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN)).isEmpty();
        assertThat(response.headers().firstValue(
                HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS)).isEmpty();
        // Nothing depends on Origin, so nothing needs to vary on it
        assertThat(response.headers().firstValue(HttpHeaders.VARY)).isEmpty();
    }
}
