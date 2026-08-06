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
import java.util.HexFormat;
import java.util.Random;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.google.common.hash.Hashing;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * A presigned URL may name x-amz-content-sha256 among its signed headers to
 * pin the payload hash, as in issue #652.  S3 then uses that value as the
 * payload line of the canonical request rather than UNSIGNED-PAYLOAD.
 */
public final class PresignedContentSha256Test {
    private static final String CONTENT = "blob-content";
    private static final String BLOB_NAME = "test";
    private static final String UNSIGNED = "UNSIGNED-PAYLOAD";
    private static final DateTimeFormatter ISO8601 =
            DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'")
                    .withZone(ZoneOffset.UTC);

    private S3Proxy s3Proxy;
    private BlobStore blobStore;
    private String containerName;
    private String identity;
    private String credential;
    private String host;
    private final HttpClient httpClient = HttpClient.newHttpClient();

    @BeforeEach
    public void setUp() throws Exception {
        TestUtils.S3ProxyLaunchInfo info = TestUtils.startS3Proxy(
                "s3proxy.conf");
        s3Proxy = info.getS3Proxy();
        blobStore = info.getBlobStore();
        identity = info.getS3Identity();
        credential = info.getS3Credential();
        host = info.getEndpoint().getHost() + ":" + s3Proxy.getPort();

        containerName = "container-" + new Random().nextInt(Integer.MAX_VALUE);
        blobStore.createContainer(containerName);
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
        if (blobStore != null && containerName != null) {
            blobStore.removeBlob(containerName, BLOB_NAME);
            blobStore.deleteContainer(containerName);
        }
    }

    /** Baseline: host alone signed, UNSIGNED-PAYLOAD, no header sent. */
    @Test
    public void testPlainPresignedPut() throws Exception {
        HttpResponse<String> response = put(
                presign(/*headerValue=*/ null, UNSIGNED), null);
        assertThat(response.statusCode()).isEqualTo(200);
    }

    /** Issue #652: the header is signed and pins the payload hash. */
    @Test
    public void testPinnedContentSha256() throws Exception {
        String hash = sha256(CONTENT);
        HttpResponse<String> response = put(presign(hash, hash), hash);
        System.err.println("pinned: " + response.statusCode() + " " +
                response.body());
        assertThat(response.statusCode()).isEqualTo(200);
    }

    /** The header is signed but the payload line is UNSIGNED-PAYLOAD. */
    @Test
    public void testSignedHeaderUnsignedPayload() throws Exception {
        String hash = sha256(CONTENT);
        HttpResponse<String> response = put(presign(hash, UNSIGNED), hash);
        System.err.println("signed header, unsigned payload: " +
                response.statusCode() + " " + response.body());
        assertThat(response.statusCode()).isEqualTo(200);
    }

    /** A signed header whose value is literally UNSIGNED-PAYLOAD. */
    @Test
    public void testSignedUnsignedPayloadHeader() throws Exception {
        HttpResponse<String> response = put(presign(UNSIGNED, UNSIGNED),
                UNSIGNED);
        System.err.println("signed UNSIGNED-PAYLOAD header: " +
                response.statusCode() + " " + response.body());
        assertThat(response.statusCode()).isEqualTo(200);
    }

    /** The header rides along unsigned; the URL pins nothing. */
    @Test
    public void testUnsignedHeaderPresent() throws Exception {
        HttpResponse<String> response = put(presign(null, UNSIGNED),
                sha256(CONTENT));
        System.err.println("unsigned header: " + response.statusCode() + " " +
                response.body());
        assertThat(response.statusCode()).isEqualTo(200);
    }

    /**
     * A URL that signs the header commits the caller to sending it; omitting
     * it at upload time leaves the canonical headers a value short, which is
     * the shape a client hits when it presigns with the header but uploads
     * through a plain HTTP client that does not know to repeat it.
     */
    @Test
    public void testSignedHeaderNotSent() throws Exception {
        String hash = sha256(CONTENT);
        HttpResponse<String> response = put(presign(hash, hash), null);
        System.err.println("signed header not sent: " + response.statusCode() +
                " " + response.body());
        assertThat(response.statusCode()).isEqualTo(403);
        assertThat(response.body()).contains("SignatureDoesNotMatch");
        // The whole point of the diagnostics: say which header is absent
        // rather than leaving the caller to bisect its own signer.
        assertThat(response.body()).contains(
                "omits headers it declares as signed: x-amz-content-sha256");
    }

    /** A mismatch quotes what the proxy signed, as S3 does. */
    @Test
    public void testMismatchReportsCanonicalRequest() throws Exception {
        URI uri = presign(null, UNSIGNED);
        URI tampered = URI.create(uri.toString().replaceFirst(
                "X-Amz-Signature=.*", "X-Amz-Signature=" + "0".repeat(64)));
        HttpResponse<String> response = put(tampered, null);
        System.err.println("tampered: " + response.statusCode() + " " +
                response.body());
        assertThat(response.statusCode()).isEqualTo(403);
        assertThat(response.body()).contains("SignatureDoesNotMatch");
        assertThat(response.body()).contains("<CanonicalRequest>");
        assertThat(response.body()).contains("<StringToSign>");
        assertThat(response.body()).contains(
                "<SignatureProvided>" + "0".repeat(64));
        assertThat(response.body()).contains("<AWSAccessKeyId>" + identity);
        // The canonical request must show the proxy's own view of the
        // request, which is what makes it worth returning.
        assertThat(response.body()).contains("PUT");
        assertThat(response.body()).contains("host:" + host);
        assertThat(response.body()).contains(UNSIGNED);
        // Never the expected signature, which S3 also withholds.
        assertThat(response.body()).doesNotContain("<SignatureExpected>");
    }

    /** A pinned hash the body does not match must be refused. */
    @Test
    public void testPinnedContentSha256Mismatch() throws Exception {
        String hash = sha256("some other content");
        HttpResponse<String> response = put(presign(hash, hash), hash);
        System.err.println("mismatch: " + response.statusCode() + " " +
                response.body());
        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.body()).contains("XAmzContentSHA256Mismatch");
    }

    private static String sha256(String s) {
        return Hashing.sha256().hashString(s, StandardCharsets.UTF_8)
                .toString();
    }

    private static String hex(byte[] bytes) {
        return HexFormat.of().formatHex(bytes);
    }

    private static byte[] hmac(byte[] key, String data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Build a presigned PUT by hand so the test controls both the signed
     * header list and the payload line of the canonical request.
     */
    private URI presign(String headerValue, String payloadLine)
            throws Exception {
        String timestamp = ISO8601.format(Instant.now());
        String date = timestamp.substring(0, 8);
        String scope = date + "/us-east-1/s3/aws4_request";
        String signedHeaders = headerValue != null ?
                "host;x-amz-content-sha256" : "host";
        String query = "X-Amz-Algorithm=AWS4-HMAC-SHA256" +
                "&X-Amz-Credential=" +
                urlEncode(identity + "/" + scope) +
                "&X-Amz-Date=" + timestamp +
                "&X-Amz-Expires=3600" +
                "&X-Amz-SignedHeaders=" + urlEncode(signedHeaders);
        String canonicalHeaders = "host:" + host + "\n";
        if (headerValue != null) {
            canonicalHeaders += "x-amz-content-sha256:" + headerValue + "\n";
        }
        String path = "/" + containerName + "/" + BLOB_NAME;
        String canonicalRequest = String.join("\n",
                "PUT", path, query, canonicalHeaders, signedHeaders,
                payloadLine);
        String stringToSign = String.join("\n",
                "AWS4-HMAC-SHA256", timestamp, scope,
                sha256(canonicalRequest));
        byte[] key = hmac(("AWS4" + credential).getBytes(
                StandardCharsets.UTF_8), date);
        key = hmac(key, "us-east-1");
        key = hmac(key, "s3");
        key = hmac(key, "aws4_request");
        String signature = hex(hmac(key, stringToSign));
        return URI.create("http://" + host + path + "?" + query +
                "&X-Amz-Signature=" + signature);
    }

    private static String urlEncode(String s) {
        var builder = new StringBuilder();
        for (byte b : s.getBytes(StandardCharsets.UTF_8)) {
            char c = (char) (b & 0xff);
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                    (c >= '0' && c <= '9') || c == '-' || c == '_' ||
                    c == '.' || c == '~') {
                builder.append(c);
            } else {
                builder.append("%%%02X".formatted(b & 0xff));
            }
        }
        return builder.toString();
    }

    private HttpResponse<String> put(URI uri, String contentSha256)
            throws Exception {
        var builder = HttpRequest.newBuilder(uri)
                .PUT(HttpRequest.BodyPublishers.ofString(CONTENT));
        if (contentSha256 != null) {
            builder.header("x-amz-content-sha256", contentSha256);
        }
        return httpClient.send(builder.build(),
                HttpResponse.BodyHandlers.ofString());
    }
}
