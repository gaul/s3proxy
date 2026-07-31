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

/**
 * The lifetime of a presigned URL rides in the query string and is parsed
 * before any signature is checked, so a caller who knows only an access key
 * id -- not a secret -- reaches it.  Malformed values must be denied, not
 * escape as a 500.
 */
public final class PresignedExpiryTest {
    private static final String IDENTITY = "identity";

    private S3Proxy s3Proxy;
    private String baseUri;

    @BeforeEach
    public void setUp() throws Exception {
        s3Proxy = S3Proxy.builder()
                .blobStore(TestUtils.createTransientBlobStore())
                .awsAuthentication(AuthenticationType.AWS_V2_OR_V4, IDENTITY,
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
    public void testUnparseableV2Expires() throws Exception {
        assertThat(statusOf("/container/blob?AWSAccessKeyId=" + IDENTITY +
                "&Signature=abc&Expires=not-a-number")).isEqualTo(403);
    }

    @Test
    public void testUnparseableV4Expires() throws Exception {
        assertThat(statusOf("/container/blob?X-Amz-Algorithm=AWS4-HMAC-SHA256" +
                "&X-Amz-Credential=" + IDENTITY +
                "%2F20260101%2Fus-east-1%2Fs3%2Faws4_request" +
                "&X-Amz-SignedHeaders=host&X-Amz-Signature=abc" +
                "&X-Amz-Date=20260101T000000Z&X-Amz-Expires=not-a-number"))
                .isEqualTo(403);
    }

    @Test
    public void testUnparseableV4Date() throws Exception {
        assertThat(statusOf("/container/blob?X-Amz-Algorithm=AWS4-HMAC-SHA256" +
                "&X-Amz-Credential=" + IDENTITY +
                "%2F20260101%2Fus-east-1%2Fs3%2Faws4_request" +
                "&X-Amz-SignedHeaders=host&X-Amz-Signature=abc" +
                "&X-Amz-Date=not-a-date&X-Amz-Expires=900")).isEqualTo(403);
    }

    private int statusOf(String pathAndQuery) throws Exception {
        HttpResponse<String> response = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(URI.create(baseUri + pathAndQuery))
                        .GET().build(),
                HttpResponse.BodyHandlers.ofString());
        return response.statusCode();
    }
}
