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

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.HexFormat;
import java.util.Map;
import java.util.TreeMap;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.google.common.hash.Hashing;
import com.google.common.io.ByteSource;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * A SigV4 signature covers the URI as the client sent it and the headers the
 * request names as signed.  Under s3proxy.virtual-host the bucket is in
 * neither unless host is one of those headers: the URI holds only the key,
 * and Host, which names the bucket, rides along uncovered.  The bearer of an
 * upload URL signed that way for one bucket could then send it with the Host
 * of another and overwrite an object there as the signer.  SigV4 requires
 * host to be signed, and the proxy refuses a request that did not sign it,
 * on the presigned and the Authorization-header paths alike.  These go
 * through a raw socket, since an HTTP client would not send a Host other
 * than the one it connects to, nor leave it out.
 */
public final class UnsignedHostTest {
    private static final String OWNER_CONTENT = "alice,5000";
    private static final String UPLOAD = "mallory,9000";
    private static final String KEY = "october.csv";
    private static final DateTimeFormatter ISO8601 =
            DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'")
                    .withZone(ZoneOffset.UTC);

    private S3Proxy s3Proxy;
    private BlobStore blobStore;
    private String inbox;
    private String payroll;
    private String identity;
    private String credential;
    private String virtualHost;

    @BeforeEach
    public void setUp() throws Exception {
        TestUtils.S3ProxyLaunchInfo info = TestUtils.startS3Proxy(
                "s3proxy-virtual-host.conf");
        s3Proxy = info.getS3Proxy();
        blobStore = info.getBlobStore();
        identity = info.getS3Identity();
        credential = info.getS3Credential();
        virtualHost = info.getProperties().getProperty(
                S3ProxyConstants.PROPERTY_VIRTUAL_HOST);
        assertThat(virtualHost).isNotEmpty();

        inbox = TestUtils.createRandomContainerName();
        payroll = TestUtils.createRandomContainerName();
        blobStore.createContainer(inbox);
        blobStore.createContainer(payroll);
        TestUtils.putBlob(blobStore, payroll, KEY, ByteSource.wrap(
                OWNER_CONTENT.getBytes(StandardCharsets.UTF_8)));
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
        if (blobStore != null) {
            if (inbox != null) {
                blobStore.removeBlob(inbox, KEY);
                blobStore.deleteContainer(inbox);
            }
            if (payroll != null) {
                blobStore.removeBlob(payroll, KEY);
                blobStore.deleteContainer(payroll);
            }
        }
    }

    /**
     * The report: an upload into inbox, presigned over content-type alone,
     * sent with the Host of payroll.
     */
    @Test
    public void testPresignedWithoutHostRejectedOnAnotherBucket()
            throws Exception {
        String response = put("HTTP/1.1",
                presign("/" + KEY, Map.of("content-type", "text/csv")),
                "Host: " + payroll + "." + virtualHost,
                "Content-Type: text/csv");
        assertThat(response).startsWith("HTTP/1.1 403 ");
        assertThat(response).contains("<Code>AccessDenied</Code>");
        assertThat(response).contains(
                "<HeadersNotSigned>host</HeadersNotSigned>");
        assertThat(read(payroll, KEY)).isEqualTo(OWNER_CONTENT);
    }

    /**
     * Leaving Host out moves the bucket as well: the proxy then reads the
     * first segment of the key the URL was signed for as the bucket.  So the
     * refusal must not wait for a Host header to find unsigned.
     */
    @Test
    public void testPresignedWithoutHostRejectedWhenHostIsAbsent()
            throws Exception {
        String response = put("HTTP/1.0",
                presign("/" + payroll + "/" + KEY,
                        Map.of("content-type", "text/csv")),
                "Content-Type: text/csv");
        assertThat(response).startsWith("HTTP/1.1 403 ");
        assertThat(response).contains(
                "<HeadersNotSigned>host</HeadersNotSigned>");
        assertThat(read(payroll, KEY)).isEqualTo(OWNER_CONTENT);
    }

    /** The same through an Authorization header that does not sign host. */
    @Test
    public void testAuthorizationHeaderWithoutHostRejected() throws Exception {
        String timestamp = ISO8601.format(Instant.now());
        String response = put("HTTP/1.1", "/" + KEY,
                "Host: " + payroll + "." + virtualHost,
                "Authorization: " + authorization("/" + KEY, timestamp),
                "x-amz-content-sha256: UNSIGNED-PAYLOAD",
                "x-amz-date: " + timestamp);
        assertThat(response).startsWith("HTTP/1.1 403 ");
        assertThat(response).contains(
                "<HeadersNotSigned>host</HeadersNotSigned>");
        assertThat(read(payroll, KEY)).isEqualTo(OWNER_CONTENT);
    }

    /**
     * The control: signed over host as the AWS SDKs sign it, the URL uploads
     * into the bucket it was signed for and into no other.
     */
    @Test
    public void testPresignedWithHostIsHeldToItsBucket() throws Exception {
        String url = presign("/" + KEY, Map.of(
                "content-type", "text/csv",
                "host", inbox + "." + virtualHost));

        String response = put("HTTP/1.1", url,
                "Host: " + payroll + "." + virtualHost,
                "Content-Type: text/csv");
        assertThat(response).startsWith("HTTP/1.1 403 ");
        assertThat(response).contains("<Code>SignatureDoesNotMatch</Code>");
        assertThat(read(payroll, KEY)).isEqualTo(OWNER_CONTENT);

        response = put("HTTP/1.1", url,
                "Host: " + inbox + "." + virtualHost,
                "Content-Type: text/csv");
        assertThat(response).startsWith("HTTP/1.1 200 ");
        assertThat(read(inbox, KEY)).isEqualTo(UPLOAD);
    }

    /**
     * A presigned PUT of the path, valid for an hour, whose signature covers
     * exactly the headers given, lower-cased names to values.
     */
    private String presign(String path, Map<String, String> headers)
            throws Exception {
        var signed = new TreeMap<String, String>(headers);
        String timestamp = ISO8601.format(Instant.now());
        String date = timestamp.substring(0, 8);
        String scope = date + "/us-east-1/s3/aws4_request";
        String signedHeaders = String.join(";", signed.keySet());
        String query = "X-Amz-Algorithm=AWS4-HMAC-SHA256" +
                "&X-Amz-Credential=" + urlEncode(identity + "/" + scope) +
                "&X-Amz-Date=" + timestamp +
                "&X-Amz-Expires=3600" +
                "&X-Amz-SignedHeaders=" + urlEncode(signedHeaders);
        String canonicalRequest = String.join("\n",
                "PUT", path, query, canonicalHeaders(signed), signedHeaders,
                "UNSIGNED-PAYLOAD");
        String stringToSign = String.join("\n",
                "AWS4-HMAC-SHA256", timestamp, scope,
                sha256(canonicalRequest));
        return path + "?" + query + "&X-Amz-Signature=" +
                hex(hmac(signingKey(date), stringToSign));
    }

    /**
     * An Authorization header for a PUT of the path signing
     * x-amz-content-sha256 and x-amz-date, and not host.
     */
    private String authorization(String path, String timestamp)
            throws Exception {
        var signed = new TreeMap<String, String>();
        signed.put("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        signed.put("x-amz-date", timestamp);
        String date = timestamp.substring(0, 8);
        String scope = date + "/us-east-1/s3/aws4_request";
        String signedHeaders = String.join(";", signed.keySet());
        String canonicalRequest = String.join("\n",
                "PUT", path, "", canonicalHeaders(signed), signedHeaders,
                "UNSIGNED-PAYLOAD");
        String stringToSign = String.join("\n",
                "AWS4-HMAC-SHA256", timestamp, scope,
                sha256(canonicalRequest));
        return "AWS4-HMAC-SHA256 Credential=" + identity + "/" + scope +
                ", SignedHeaders=" + signedHeaders +
                ", Signature=" + hex(hmac(signingKey(date), stringToSign));
    }

    private static String canonicalHeaders(Map<String, String> signed) {
        var builder = new StringBuilder();
        for (Map.Entry<String, String> entry :
                new TreeMap<>(signed).entrySet()) {
            builder.append(entry.getKey()).append(':')
                    .append(entry.getValue()).append('\n');
        }
        return builder.toString();
    }

    private byte[] signingKey(String date) throws Exception {
        byte[] key = hmac(("AWS4" + credential).getBytes(
                StandardCharsets.UTF_8), date);
        key = hmac(key, "us-east-1");
        key = hmac(key, "s3");
        return hmac(key, "aws4_request");
    }

    /** PUT the upload to the target with exactly the header lines given. */
    private String put(String version, String target, String... headers)
            throws Exception {
        var request = new StringBuilder("PUT " + target + " " + version +
                "\r\n");
        for (String header : headers) {
            request.append(header).append("\r\n");
        }
        request.append("Content-Length: " + UPLOAD.length() + "\r\n" +
                "Connection: close\r\n\r\n" + UPLOAD);

        try (var socket = new Socket()) {
            socket.connect(new InetSocketAddress(
                    InetAddress.getLoopbackAddress(), s3Proxy.getPort()));
            socket.setSoTimeout(10_000);
            socket.getOutputStream().write(
                    request.toString().getBytes(StandardCharsets.UTF_8));
            socket.getOutputStream().flush();

            var out = new ByteArrayOutputStream();
            try (InputStream is = socket.getInputStream()) {
                is.transferTo(out);
            } catch (SocketTimeoutException ste) {
                // Answer with what arrived; the assertions say what is
                // missing better than a timeout does.
            }
            return out.toString(StandardCharsets.UTF_8);
        }
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
