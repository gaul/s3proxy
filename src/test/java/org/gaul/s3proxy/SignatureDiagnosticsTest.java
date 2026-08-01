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
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Random;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.options.CreateContainerOptions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * A signature that does not match says so and nothing else, yet the causes --
 * a wrong secret, a rewritten Host, a clock, a signed header the client never
 * repeated -- are indistinguishable from outside.  S3 answers with the strings
 * it signed so the client can diff them against its own; so does the proxy.
 */
public final class SignatureDiagnosticsTest {
    private static final String BLOB_NAME = "test";
    private static final DateTimeFormatter ISO8601 =
            DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'")
                    .withZone(ZoneOffset.UTC);

    private S3Proxy s3Proxy;
    private BlobStore blobStore;
    private String containerName;
    private String identity;
    private String baseUri;
    private final HttpClient httpClient = HttpClient.newHttpClient();

    @BeforeEach
    public void setUp() throws Exception {
        TestUtils.S3ProxyLaunchInfo info = TestUtils.startS3Proxy(
                "s3proxy.conf");
        s3Proxy = info.getS3Proxy();
        blobStore = info.getBlobStore();
        identity = info.getS3Identity();
        baseUri = "http://" + info.getEndpoint().getHost() + ":" +
                s3Proxy.getPort();

        containerName = "container-" + new Random().nextInt(Integer.MAX_VALUE);
        blobStore.createContainer(containerName, CreateContainerOptions.NONE);
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
        if (blobStore != null && containerName != null) {
            blobStore.deleteContainer(containerName);
        }
    }

    /** A v4 header naming a signature that cannot be right. */
    private String authorization(String timestamp) {
        return "AWS4-HMAC-SHA256" +
                " Credential=" + identity + "/" + timestamp.substring(0, 8) +
                "/us-east-1/s3/aws4_request," +
                " SignedHeaders=host;x-amz-content-sha256;x-amz-date," +
                " Signature=" + "0".repeat(64);
    }

    /** A v4 Authorization header carries a canonical request to report. */
    @Test
    public void testV4HeaderMismatch() throws Exception {
        String timestamp = ISO8601.format(Instant.now());
        HttpResponse<String> response = httpClient.send(
                HttpRequest.newBuilder(URI.create(
                                baseUri + "/" + containerName + "/" +
                                BLOB_NAME))
                        .header("Authorization", authorization(timestamp))
                        .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
                        .header("x-amz-date", timestamp)
                        .GET().build(),
                HttpResponse.BodyHandlers.ofString());
        String body = response.body();
        System.err.println("v4 header: " + response.statusCode() + " " + body);

        assertThat(response.statusCode()).isEqualTo(403);
        assertThat(body).contains("SignatureDoesNotMatch");
        assertThat(body).contains("<AWSAccessKeyId>" + identity);
        assertThat(body).contains("<SignatureProvided>" + "0".repeat(64));
        assertThat(body).contains("<StringToSign>AWS4-HMAC-SHA256");
        assertThat(body).contains("<CanonicalRequest>GET");
        assertThat(body).contains("x-amz-content-sha256:UNSIGNED-PAYLOAD");
    }

    /** A signed header the caller never sent is named outright. */
    @Test
    public void testV4HeaderMissingSignedHeader() throws Exception {
        String timestamp = ISO8601.format(Instant.now());
        String authorization = "AWS4-HMAC-SHA256" +
                " Credential=" + identity + "/" + timestamp.substring(0, 8) +
                "/us-east-1/s3/aws4_request," +
                " SignedHeaders=host;range;x-amz-content-sha256;x-amz-date," +
                " Signature=" + "0".repeat(64);
        HttpResponse<String> response = httpClient.send(
                HttpRequest.newBuilder(URI.create(
                                baseUri + "/" + containerName + "/" +
                                BLOB_NAME))
                        .header("Authorization", authorization)
                        .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
                        .header("x-amz-date", timestamp)
                        .GET().build(),
                HttpResponse.BodyHandlers.ofString());
        String body = response.body();
        System.err.println("v4 missing: " + response.statusCode() + " " + body);

        assertThat(response.statusCode()).isEqualTo(403);
        assertThat(body).contains("omits headers it declares as signed: range");
        // The canonical request states the same thing, but only by the
        // absence of anything after the colon.
        assertThat(body).contains("range:\n");
    }

    /**
     * A v2 signature has no canonical request, only a string to sign, so the
     * report carries what exists and omits what does not.
     */
    @Test
    public void testV2QueryMismatch() throws Exception {
        long expires = System.currentTimeMillis() / 1000 + 3600;
        URI uri = URI.create(baseUri + "/" + containerName + "/" + BLOB_NAME +
                "?AWSAccessKeyId=" + identity +
                "&Signature=YmFkLXNpZ25hdHVyZQ%3D%3D" +
                "&Expires=" + expires);
        HttpResponse<String> response = httpClient.send(
                HttpRequest.newBuilder(uri).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        String body = response.body();
        System.err.println("v2 query: " + response.statusCode() + " " + body);

        assertThat(response.statusCode()).isEqualTo(403);
        assertThat(body).contains("SignatureDoesNotMatch");
        assertThat(body).contains("<AWSAccessKeyId>" + identity);
        assertThat(body).contains("<StringToSign>GET");
        assertThat(body).doesNotContain("<CanonicalRequest>");
    }

    /** The expected signature stays in, as it does at S3. */
    @Test
    public void testExpectedSignatureWithheld() throws Exception {
        long expires = System.currentTimeMillis() / 1000 + 3600;
        URI uri = URI.create(baseUri + "/" + containerName + "/" + BLOB_NAME +
                "?AWSAccessKeyId=" + identity +
                "&Signature=YmFkLXNpZ25hdHVyZQ%3D%3D" +
                "&Expires=" + expires);
        HttpResponse<String> response = httpClient.send(
                HttpRequest.newBuilder(uri).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(response.body()).doesNotContain("SignatureExpected");
        assertThat(response.body()).doesNotContain("local-credential");
    }
}
