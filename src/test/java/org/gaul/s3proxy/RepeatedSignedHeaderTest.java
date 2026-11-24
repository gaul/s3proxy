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
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Collections;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The canonical request repeats a header's value for every mention of its
 * name among the signed headers, and a failed signature echoes the canonical
 * request.  A list naming one header many times must therefore be refused,
 * or a small request with any signature at all buys a very large answer.
 */
public final class RepeatedSignedHeaderTest {
    private static final DateTimeFormatter ISO8601 =
            DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'")
                    .withZone(ZoneOffset.UTC);
    private static final String VALUE = "x".repeat(1000);

    private S3Proxy s3Proxy;
    private String identity;
    private String baseUri;
    private final HttpClient httpClient = HttpClient.newHttpClient();

    @BeforeEach
    public void setUp() throws Exception {
        TestUtils.S3ProxyLaunchInfo info = TestUtils.startS3Proxy(
                "s3proxy.conf");
        s3Proxy = info.getS3Proxy();
        identity = info.getS3Identity();
        baseUri = "http://" + info.getEndpoint().getHost() + ":" +
                s3Proxy.getPort();
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
    }

    @Test
    public void testAuthorizationHeaderRepeatedName() throws Exception {
        assertRefused(withAuthorizationHeader("a",
                String.join(";", Collections.nCopies(1000, "a"))));
    }

    /** Header names are not case sensitive, so neither is the comparison. */
    @Test
    public void testAuthorizationHeaderRepeatedNameDifferentCase()
            throws Exception {
        assertRefused(withAuthorizationHeader("a", "a;A"));
    }

    @Test
    public void testQueryStringRepeatedName() throws Exception {
        assertRefused(withQueryString("a",
                String.join(";", Collections.nCopies(1000, "a"))));
    }

    /**
     * The container ignores case the way String.equalsIgnoreCase does, to
     * which U+017F LATIN SMALL LETTER LONG S is another "s".
     */
    @Test
    public void testQueryStringRepeatedNameCaseFolded() throws Exception {
        assertRefused(withQueryString("ss", "ss;s\u017f;\u017fs;\u017f\u017f"));
    }

    /** A name mentioned once is still canonicalized and reported. */
    @Test
    public void testDistinctNames() throws Exception {
        HttpResponse<String> response = withAuthorizationHeader("a",
                "a;host;x-amz-content-sha256;x-amz-date");
        assertThat(response.statusCode()).isEqualTo(403);
        assertThat(response.body()).contains("SignatureDoesNotMatch");
        assertThat(response.body()).containsOnlyOnce(VALUE);
    }

    private static void assertRefused(HttpResponse<String> response) {
        assertThat(response.statusCode()).isEqualTo(403);
        assertThat(response.body()).contains("AccessDenied");
        assertThat(response.body()).contains(
                "SignedHeaders names a header more than once");
        assertThat(response.body()).doesNotContain(VALUE);
    }

    private HttpResponse<String> withAuthorizationHeader(String headerName,
            String signedHeaders) throws Exception {
        String timestamp = ISO8601.format(Instant.now());
        return httpClient.send(
                HttpRequest.newBuilder(URI.create(baseUri + "/container/key"))
                        .header(headerName, VALUE)
                        .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
                        .header("x-amz-date", timestamp)
                        .header("Authorization", "AWS4-HMAC-SHA256" +
                                " Credential=" + identity + "/" +
                                timestamp.substring(0, 8) +
                                "/us-east-1/s3/aws4_request," +
                                " SignedHeaders=" + signedHeaders + "," +
                                " Signature=" + "0".repeat(64))
                        .GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> withQueryString(String headerName,
            String signedHeaders) throws Exception {
        String timestamp = ISO8601.format(Instant.now());
        return httpClient.send(
                HttpRequest.newBuilder(URI.create(baseUri + "/container/key" +
                                "?X-Amz-Algorithm=AWS4-HMAC-SHA256" +
                                "&X-Amz-Credential=" + urlEncode(identity +
                                "/" + timestamp.substring(0, 8) +
                                "/us-east-1/s3/aws4_request") +
                                "&X-Amz-Date=" + timestamp +
                                "&X-Amz-Expires=60" +
                                "&X-Amz-SignedHeaders=" +
                                urlEncode(signedHeaders) +
                                "&X-Amz-Signature=" + "0".repeat(64)))
                        .header(headerName, VALUE)
                        .GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private static String urlEncode(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }
}
