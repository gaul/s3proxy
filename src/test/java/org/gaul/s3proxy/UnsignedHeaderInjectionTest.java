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
import com.google.common.io.ByteSource;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * A SigV4 signature covers only the headers the request names as signed, so
 * an x-amz-* header outside that list rides along uncovered and the signature
 * verifies without it.  A presigned PUT signed for one object -- host alone
 * signed -- would then gain x-amz-copy-source to read another object the URL
 * never named and x-amz-acl to publish it, all as the signer.  S3 refuses any
 * request carrying an unsigned x-amz-* header, naming it in HeadersNotSigned;
 * so must the proxy, on the presigned and the Authorization-header paths
 * alike.  Measured against live S3 by the reporter of this issue on
 * 2026-09-01 and corroborated by the identical Ceph RGW flaw CVE-2026-54330.
 */
public final class UnsignedHeaderInjectionTest {
    private static final String SECRET = "THIS-IS-THE-VICTIM-FILE-12345";
    private static final String PLACEHOLDER = "PLACEHOLDER-ORIGINAL-CONTENT";
    private static final String UPLOAD = "the-signed-upload-body";
    private static final String SRC_KEY = "secret";
    private static final String DST_KEY = "target";
    private static final DateTimeFormatter ISO8601 =
            DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'")
                    .withZone(ZoneOffset.UTC);

    private S3Proxy s3Proxy;
    private BlobStore blobStore;
    private String srcContainer;
    private String dstContainer;
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

        srcContainer = "src-" + new Random().nextInt(Integer.MAX_VALUE);
        dstContainer = "dst-" + new Random().nextInt(Integer.MAX_VALUE);
        blobStore.createContainer(srcContainer);
        blobStore.createContainer(dstContainer);
        TestUtils.putBlob(blobStore, srcContainer, SRC_KEY,
                ByteSource.wrap(SECRET.getBytes(StandardCharsets.UTF_8)));
        TestUtils.putBlob(blobStore, dstContainer, DST_KEY,
                ByteSource.wrap(PLACEHOLDER.getBytes(StandardCharsets.UTF_8)));
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
        if (blobStore != null) {
            if (srcContainer != null) {
                blobStore.removeBlob(srcContainer, SRC_KEY);
                blobStore.deleteContainer(srcContainer);
            }
            if (dstContainer != null) {
                blobStore.removeBlob(dstContainer, DST_KEY);
                blobStore.deleteContainer(dstContainer);
            }
        }
    }

    /** The exact replay from the report: copy the victim object and publish. */
    @Test
    public void testPresignedCopySourceAndAclRejected() throws Exception {
        HttpResponse<String> response = put(presign(),
                "x-amz-copy-source", "/" + srcContainer + "/" + SRC_KEY,
                "x-amz-acl", "public-read");
        System.err.println("copy+acl: " + response.statusCode() + " " +
                response.body());
        assertThat(response.statusCode()).isEqualTo(403);
        assertThat(response.body()).contains("AccessDenied");
        assertThat(response.body()).contains("HeadersNotSigned");
        assertThat(response.body()).contains("x-amz-copy-source");
        assertThat(response.body()).contains("x-amz-acl");
        // The copy never ran: the destination still holds its own content,
        // not the secret, and the secret was never republished.
        assertThat(read(dstContainer, DST_KEY)).isEqualTo(PLACEHOLDER);
    }

    /** x-amz-copy-source alone is enough to trip the check. */
    @Test
    public void testPresignedCopySourceAloneRejected() throws Exception {
        HttpResponse<String> response = put(presign(),
                "x-amz-copy-source", "/" + srcContainer + "/" + SRC_KEY);
        assertThat(response.statusCode()).isEqualTo(403);
        assertThat(response.body()).contains("HeadersNotSigned");
        assertThat(response.body()).contains("x-amz-copy-source");
        assertThat(read(dstContainer, DST_KEY)).isEqualTo(PLACEHOLDER);
    }

    /** So is x-amz-acl alone, which would publish whatever the PUT wrote. */
    @Test
    public void testPresignedAclAloneRejected() throws Exception {
        HttpResponse<String> response = put(presign(),
                "x-amz-acl", "public-read");
        assertThat(response.statusCode()).isEqualTo(403);
        assertThat(response.body()).contains("HeadersNotSigned");
        assertThat(response.body()).contains("x-amz-acl");
    }

    /** Used as signed, the very same URL still performs its one PUT. */
    @Test
    public void testPresignedUrlUsedAsSignedSucceeds() throws Exception {
        HttpResponse<String> response = put(presign());
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(read(dstContainer, DST_KEY)).isEqualTo(UPLOAD);
    }

    /** The same injection through an Authorization-header PUT, also refused. */
    @Test
    public void testAuthorizationHeaderCopySourceRejected() throws Exception {
        String timestamp = ISO8601.format(Instant.now());
        var request = HttpRequest.newBuilder(URI.create(
                        "http://" + host + "/" + dstContainer + "/" + DST_KEY))
                .header("Authorization", authorization(timestamp))
                .header("x-amz-date", timestamp)
                .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
                .header("x-amz-copy-source", "/" + srcContainer + "/" + SRC_KEY)
                .PUT(HttpRequest.BodyPublishers.ofString(UPLOAD))
                .build();
        HttpResponse<String> response = httpClient.send(request,
                HttpResponse.BodyHandlers.ofString());
        System.err.println("header copy: " + response.statusCode() + " " +
                response.body());
        assertThat(response.statusCode()).isEqualTo(403);
        assertThat(response.body()).contains("AccessDenied");
        assertThat(response.body()).contains(
                "<HeadersNotSigned>x-amz-copy-source</HeadersNotSigned>");
        assertThat(read(dstContainer, DST_KEY)).isEqualTo(PLACEHOLDER);
    }

    /**
     * The Authorization-header control: host, x-amz-content-sha256 and
     * x-amz-date signed, no unsigned header added, so the PUT proceeds.
     */
    @Test
    public void testAuthorizationHeaderWithoutInjectionSucceeds()
            throws Exception {
        String timestamp = ISO8601.format(Instant.now());
        var request = HttpRequest.newBuilder(URI.create(
                        "http://" + host + "/" + dstContainer + "/" + DST_KEY))
                .header("Authorization", authorization(timestamp))
                .header("x-amz-date", timestamp)
                .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
                .PUT(HttpRequest.BodyPublishers.ofString(UPLOAD))
                .build();
        HttpResponse<String> response = httpClient.send(request,
                HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(read(dstContainer, DST_KEY)).isEqualTo(UPLOAD);
    }

    /**
     * A presigned PUT to dst/target signing host alone, as the AWS SDK
     * presigner emits and the report exercised.
     */
    private URI presign() throws Exception {
        String timestamp = ISO8601.format(Instant.now());
        String date = timestamp.substring(0, 8);
        String scope = date + "/us-east-1/s3/aws4_request";
        String signedHeaders = "host";
        String query = "X-Amz-Algorithm=AWS4-HMAC-SHA256" +
                "&X-Amz-Credential=" + urlEncode(identity + "/" + scope) +
                "&X-Amz-Date=" + timestamp +
                "&X-Amz-Expires=3600" +
                "&X-Amz-SignedHeaders=" + urlEncode(signedHeaders);
        String path = "/" + dstContainer + "/" + DST_KEY;
        String canonicalRequest = String.join("\n",
                "PUT", path, query, "host:" + host + "\n", signedHeaders,
                "UNSIGNED-PAYLOAD");
        String stringToSign = String.join("\n",
                "AWS4-HMAC-SHA256", timestamp, scope,
                sha256(canonicalRequest));
        String signature = hex(hmac(signingKey(date), stringToSign));
        return URI.create("http://" + host + path + "?" + query +
                "&X-Amz-Signature=" + signature);
    }

    /**
     * An Authorization header signing host, x-amz-content-sha256 and
     * x-amz-date -- the minimum a header-authorized PUT signs -- so that an
     * x-amz-copy-source added afterward is the one unsigned header.
     */
    private String authorization(String timestamp) throws Exception {
        String date = timestamp.substring(0, 8);
        String scope = date + "/us-east-1/s3/aws4_request";
        String signedHeaders =
                "host;x-amz-content-sha256;x-amz-date";
        String path = "/" + dstContainer + "/" + DST_KEY;
        String canonicalHeaders = "host:" + host + "\n" +
                "x-amz-content-sha256:UNSIGNED-PAYLOAD\n" +
                "x-amz-date:" + timestamp + "\n";
        String canonicalRequest = String.join("\n",
                "PUT", path, "", canonicalHeaders, signedHeaders,
                "UNSIGNED-PAYLOAD");
        String stringToSign = String.join("\n",
                "AWS4-HMAC-SHA256", timestamp, scope,
                sha256(canonicalRequest));
        String signature = hex(hmac(signingKey(date), stringToSign));
        return "AWS4-HMAC-SHA256 Credential=" + identity + "/" + scope +
                ", SignedHeaders=" + signedHeaders +
                ", Signature=" + signature;
    }

    private byte[] signingKey(String date) throws Exception {
        byte[] key = hmac(("AWS4" + credential).getBytes(
                StandardCharsets.UTF_8), date);
        key = hmac(key, "us-east-1");
        key = hmac(key, "s3");
        return hmac(key, "aws4_request");
    }

    private HttpResponse<String> put(URI uri, String... headers)
            throws Exception {
        var builder = HttpRequest.newBuilder(uri)
                .PUT(HttpRequest.BodyPublishers.ofString(UPLOAD));
        for (int i = 0; i < headers.length; i += 2) {
            builder.header(headers[i], headers[i + 1]);
        }
        return httpClient.send(builder.build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private String read(String container, String key) throws Exception {
        try (var stream = blobStore.getBlob(container, key)) {
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        }
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
}
