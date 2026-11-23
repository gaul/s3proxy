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
import java.util.Base64;
import java.util.HexFormat;
import java.util.Map;
import java.util.Random;
import java.util.TreeMap;
import java.util.zip.CRC32;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.google.common.hash.Hashing;
import com.google.common.io.ByteSource;
import com.google.common.primitives.Ints;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * A presigner may move x-amz-* headers into the query string, as the AWS SDK
 * for JavaScript does, and the V4 signature covers them there.  A URL signed
 * to copy one object then carries x-amz-copy-source as a parameter and signs
 * no such header.  It must do what it was signed to do, not store whatever
 * body its bearer sends.
 */
public final class PresignedQueryHeaderTest {
    private static final String SOURCE = "the-approved-source";
    private static final String PLACEHOLDER = "PLACEHOLDER-ORIGINAL-CONTENT";
    private static final String UPLOAD = "chosen-by-the-url-bearer";
    private static final String SRC_KEY = "source";
    private static final String DST_KEY = "target";
    private static final String HEADER = "x-amz-copy-source";
    private static final DateTimeFormatter ISO8601 =
            DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'")
                    .withZone(ZoneOffset.UTC);

    private S3Proxy s3Proxy;
    private BlobStore blobStore;
    private String containerName;
    private String copySource;
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
        copySource = "/" + containerName + "/" + SRC_KEY;
        blobStore.createContainer(containerName);
        TestUtils.putBlob(blobStore, containerName, SRC_KEY,
                ByteSource.wrap(SOURCE.getBytes(StandardCharsets.UTF_8)));
        TestUtils.putBlob(blobStore, containerName, DST_KEY,
                ByteSource.wrap(PLACEHOLDER.getBytes(StandardCharsets.UTF_8)));
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
        if (blobStore != null && containerName != null) {
            blobStore.removeBlob(containerName, SRC_KEY);
            blobStore.removeBlob(containerName, DST_KEY);
            blobStore.deleteContainer(containerName);
        }
    }

    /** The URL copies the object it names, whatever body comes with it. */
    @Test
    public void testQueryCopySource() throws Exception {
        HttpResponse<String> response = send("PUT",
                presign("PUT", Map.of(HEADER, copySource)));
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).contains("CopyObjectResult");
        assertThat(read(DST_KEY)).isEqualTo(SOURCE);
    }

    /** The name is a header's, so its case is the signer's choice. */
    @Test
    public void testQueryCopySourceCanonicalCase() throws Exception {
        HttpResponse<String> response = send("PUT",
                presign("PUT", Map.of("X-Amz-Copy-Source", copySource)));
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(read(DST_KEY)).isEqualTo(SOURCE);
    }

    /** The headers that go with it are read from there too. */
    @Test
    public void testQueryCopySourceCondition() throws Exception {
        HttpResponse<String> response = send("PUT",
                presign("PUT", Map.of(HEADER, copySource,
                        "x-amz-copy-source-if-match", "\"no-such-etag\"")));
        assertThat(response.statusCode()).isEqualTo(412);
        assertThat(read(DST_KEY)).isEqualTo(PLACEHOLDER);
    }

    /** A URL signed for UploadPartCopy copies its part the same way. */
    @Test
    public void testQueryCopySourceOfPart() throws Exception {
        HttpResponse<String> response = send("POST",
                presign("POST", Map.of("uploads", "")));
        assertThat(response.statusCode()).isEqualTo(200);
        String uploadId = element(response.body(), "UploadId");

        response = send("PUT",
                presign("PUT", Map.of("uploadId", uploadId,
                        "partNumber", "1", HEADER, copySource)));
        assertThat(response.statusCode()).isEqualTo(200);
        String eTag = element(response.body(), "ETag");

        response = send("POST",
                presign("POST", Map.of("uploadId", uploadId)),
                "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber>" +
                "<ETag>" + eTag + "</ETag></Part>" +
                "</CompleteMultipartUpload>");
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(read(DST_KEY)).isEqualTo(SOURCE);
    }

    /** A checksum signed in the query string pins the body. */
    @Test
    public void testQueryChecksum() throws Exception {
        HttpResponse<String> response = send("PUT", presign("PUT", Map.of(
                "x-amz-checksum-crc32", crc32("approved body"))));
        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.body()).contains("BadDigest");
        assertThat(read(DST_KEY)).isEqualTo(PLACEHOLDER);

        response = send("PUT", presign("PUT", Map.of(
                "x-amz-checksum-crc32", crc32(UPLOAD))));
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(read(DST_KEY)).isEqualTo(UPLOAD);
    }

    /**
     * A condition on a DELETE holds from the query string as well.  The
     * nio2 stores judge it; elsewhere the store may not take the size form
     * and the delete is refused NotImplemented, which as much as 412 shows
     * the parameter was read rather than ignored.
     */
    @Test
    public void testQueryIfMatchSize() throws Exception {
        HttpResponse<String> response = send("DELETE",
                presign("DELETE", Map.of("x-amz-if-match-size", "99999")));
        if (Quirks.NIO2_BACKENDS.contains(TestUtils.testBlobStoreProvider())) {
            assertThat(response.statusCode()).isEqualTo(412);
        } else {
            assertThat(response.statusCode()).isIn(412, 501);
        }
        assertThat(read(DST_KEY)).isEqualTo(PLACEHOLDER);
    }

    /** A parameter S3Proxy does not implement as a header is refused. */
    @Test
    public void testQueryUnknownHeader() throws Exception {
        HttpResponse<String> response = send("PUT",
                presign("PUT", Map.of("x-amz-unknown", "value")));
        assertThat(response.statusCode()).isEqualTo(501);
        assertThat(read(DST_KEY)).isEqualTo(PLACEHOLDER);
    }

    /** A URL with no such parameter still uploads what its bearer sends. */
    @Test
    public void testNoQueryHeader() throws Exception {
        HttpResponse<String> response = send("PUT",
                presign("PUT", Map.of()));
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(read(DST_KEY)).isEqualTo(UPLOAD);
    }

    /**
     * A header given twice, here in two cases, leaves it open which one the
     * signer meant, so the request is refused rather than read either way.
     */
    @Test
    public void testQueryCopySourceRepeated() throws Exception {
        HttpResponse<String> response = send("PUT", presign("PUT", Map.of(
                HEADER, copySource,
                "X-Amz-Copy-Source", "/" + containerName + "/" + DST_KEY)));
        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.body()).contains("InvalidRequest");
        assertThat(read(DST_KEY)).isEqualTo(PLACEHOLDER);
    }

    /**
     * A V2 signature covers none of these parameters, so one added to a
     * request it authenticates is not a header anybody signed.
     */
    @Test
    public void testV2QueryCopySourceIgnored() throws Exception {
        String date = DateTimeFormatter.RFC_1123_DATE_TIME.format(
                Instant.now().atZone(ZoneOffset.UTC));
        String path = "/" + containerName + "/" + DST_KEY;
        String stringToSign = "PUT\n\n\n\nx-amz-date:" + date + "\n" + path;
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(new SecretKeySpec(credential.getBytes(
                StandardCharsets.UTF_8), "HmacSHA1"));
        String signature = Base64.getEncoder().encodeToString(mac.doFinal(
                stringToSign.getBytes(StandardCharsets.UTF_8)));
        HttpResponse<String> response = send("PUT", URI.create(
                "http://" + host + path + "?X-Amz-Algorithm=AWS4-HMAC-SHA256" +
                "&" + HEADER + "=" + urlEncode("/no-such-bucket/" + SRC_KEY)),
                UPLOAD, "Authorization", "AWS " + identity + ":" + signature,
                "x-amz-date", date);
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(read(DST_KEY)).isEqualTo(UPLOAD);
    }

    private static String crc32(String content) {
        var crc = new CRC32();
        crc.update(content.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(
                Ints.toByteArray((int) crc.getValue()));
    }

    private static byte[] hmac(byte[] key, String data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Presign a request for the target by hand, signing host alone and
     * carrying the given query parameters.
     */
    private URI presign(String method, Map<String, String> extraParameters)
            throws Exception {
        String timestamp = ISO8601.format(Instant.now());
        String date = timestamp.substring(0, 8);
        String scope = date + "/us-east-1/s3/aws4_request";
        // The canonical query string is sorted by parameter name.
        var parameters = new TreeMap<String, String>(extraParameters);
        parameters.put("X-Amz-Algorithm", "AWS4-HMAC-SHA256");
        parameters.put("X-Amz-Credential", identity + "/" + scope);
        parameters.put("X-Amz-Date", timestamp);
        parameters.put("X-Amz-Expires", "3600");
        parameters.put("X-Amz-SignedHeaders", "host");
        var query = new StringBuilder();
        for (var entry : parameters.entrySet()) {
            if (!query.isEmpty()) {
                query.append('&');
            }
            query.append(urlEncode(entry.getKey())).append('=')
                    .append(urlEncode(entry.getValue()));
        }
        String path = "/" + containerName + "/" + DST_KEY;
        String canonicalRequest = String.join("\n",
                method, path, query, "host:" + host + "\n", "host",
                "UNSIGNED-PAYLOAD");
        String stringToSign = String.join("\n",
                "AWS4-HMAC-SHA256", timestamp, scope,
                Hashing.sha256().hashString(canonicalRequest,
                        StandardCharsets.UTF_8).toString());
        byte[] key = hmac(("AWS4" + credential).getBytes(
                StandardCharsets.UTF_8), date);
        key = hmac(key, "us-east-1");
        key = hmac(key, "s3");
        key = hmac(key, "aws4_request");
        String signature = HexFormat.of().formatHex(
                hmac(key, stringToSign));
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

    /** Send the URL with a body of the bearer's choosing. */
    private HttpResponse<String> send(String method, URI uri)
            throws Exception {
        return send(method, uri, method.equals("PUT") ? UPLOAD : "");
    }

    private HttpResponse<String> send(String method, URI uri, String body,
            String... headers) throws Exception {
        var builder = HttpRequest.newBuilder(uri).method(method,
                HttpRequest.BodyPublishers.ofString(body));
        for (int i = 0; i < headers.length; i += 2) {
            builder.header(headers[i], headers[i + 1]);
        }
        return httpClient.send(builder.build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private static String element(String xml, String name) {
        String open = "<" + name + ">";
        return xml.substring(xml.indexOf(open) + open.length(),
                xml.indexOf("</" + name + ">"));
    }

    private String read(String key) throws Exception {
        try (var stream = blobStore.getBlob(containerName, key)) {
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
