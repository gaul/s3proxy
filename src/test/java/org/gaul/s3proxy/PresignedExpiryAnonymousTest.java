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
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import com.google.common.io.ByteSource;

import org.gaul.s3proxy.auth.AuthenticationType;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * A presigned URL states when it stops working, and it stops working even
 * where the proxy runs without authorization and cannot check the signature
 * over that statement.  Serving an object an hour after a caller asked for
 * fifteen seconds tells them something untrue, which is issue #688.
 *
 * <p>This bounds a URL's life rather than guarding the object: anyone who can
 * reach a proxy running without authorization can read from it whether a URL
 * has expired or not.
 */
public final class PresignedExpiryAnonymousTest {
    private static final String CONTENT = "blob-content";
    private static final String BLOB_NAME = "blob";
    private static final DateTimeFormatter ISO8601 =
            DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'")
                    .withZone(ZoneOffset.UTC);

    private S3Proxy s3Proxy;
    private BlobStore blobStore;
    private String containerName;
    private String baseUri;
    private final HttpClient httpClient = HttpClient.newHttpClient();

    @BeforeEach
    public void setUp() throws Exception {
        blobStore = TestUtils.createTransientBlobStore();
        containerName = "container-" + new Random().nextInt(Integer.MAX_VALUE);
        blobStore.createContainer(containerName);
        ByteSource payload = ByteSource.wrap(
                CONTENT.getBytes(StandardCharsets.UTF_8));
        TestUtils.putBlob(blobStore, containerName, BLOB_NAME,
                payload);

        s3Proxy = S3Proxy.builder()
                .stopTimeout(0)
                .blobStore(blobStore)
                .awsAuthentication(AuthenticationType.NONE, null, null)
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

    /** Without any signing parameters the proxy serves as it always has. */
    @Test
    public void testPlainRequest() throws Exception {
        HttpResponse<String> response = get("");
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).isEqualTo(CONTENT);
    }

    /** A v4 URL still inside its window is served. */
    @Test
    public void testUnexpiredV4() throws Exception {
        HttpResponse<String> response = get(v4Query(Instant.now(), 900));
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).isEqualTo(CONTENT);
    }

    /** Issue #688: past its window, it is not. */
    @Test
    public void testExpiredV4() throws Exception {
        HttpResponse<String> response = get(v4Query(
                Instant.now().minusSeconds(60), 15));
        assertThat(response.statusCode()).isEqualTo(403);
        assertThat(response.body()).contains("Request has expired");
    }

    /** The same for the v2 spelling, whose Expires is an absolute time. */
    @Test
    public void testExpiredV2() throws Exception {
        long expires = System.currentTimeMillis() / 1000 - 60;
        HttpResponse<String> response = get(
                "?AWSAccessKeyId=identity&Signature=abc&Expires=" + expires);
        assertThat(response.statusCode()).isEqualTo(403);
        assertThat(response.body()).contains("Request has expired");
    }

    @Test
    public void testUnexpiredV2() throws Exception {
        long expires = System.currentTimeMillis() / 1000 + 900;
        HttpResponse<String> response = get(
                "?AWSAccessKeyId=identity&Signature=abc&Expires=" + expires);
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).isEqualTo(CONTENT);
    }

    /** A window longer than S3 will sign is refused, as when authorized. */
    @Test
    public void testWindowTooLong() throws Exception {
        HttpResponse<String> response = get(v4Query(Instant.now(),
                TimeUnit.DAYS.toSeconds(8)));
        assertThat(response.statusCode()).isEqualTo(403);
    }

    /** An unparseable lifetime is denied rather than escaping as a 500. */
    @Test
    public void testUnparseableExpires() throws Exception {
        HttpResponse<String> response = get(v4Query(Instant.now(), 900)
                .replaceFirst("X-Amz-Expires=\\d+", "X-Amz-Expires=nope"));
        assertThat(response.statusCode()).isEqualTo(403);
    }

    private static String v4Query(Instant date, long expiresSeconds) {
        return "?X-Amz-Algorithm=AWS4-HMAC-SHA256" +
                "&X-Amz-Credential=identity%2F20260101%2Fus-east-1%2Fs3" +
                "%2Faws4_request" +
                "&X-Amz-Date=" + ISO8601.format(date) +
                "&X-Amz-Expires=" + expiresSeconds +
                "&X-Amz-SignedHeaders=host" +
                "&X-Amz-Signature=" + "0".repeat(64);
    }

    private HttpResponse<String> get(String query) throws Exception {
        return httpClient.send(
                HttpRequest.newBuilder(URI.create(baseUri + "/" +
                        containerName + "/" + BLOB_NAME + query)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }
}
