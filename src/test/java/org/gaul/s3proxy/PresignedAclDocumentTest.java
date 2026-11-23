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

import software.amazon.awssdk.services.s3.model.BucketCannedACL;
import software.amazon.awssdk.services.s3.model.ObjectCannedACL;

/**
 * A presigned PUT ?acl signs the canned ACL it states, as the x-amz-acl
 * header or as that parameter of the URL, but not its body.  An ACL document
 * sent along used to replace the canned ACL, so the bearer of a URL signed to
 * make an object private could publish it instead, and the bearer of the
 * bucket's could open the bucket to writes.  S3 takes the access from the
 * headers or from the body, never both, and answers UnexpectedContent; so
 * must the proxy.
 */
public final class PresignedAclDocumentTest {
    /** Where a presigned URL states x-amz-acl: private, if anywhere. */
    private enum CannedAcl { HEADER, PARAMETER, ABSENT }

    private static final String KEY = "object";
    private static final String PUBLIC_READ = policy("READ");
    private static final String PUBLIC_READ_WRITE = policy("READ", "WRITE");
    private static final DateTimeFormatter ISO8601 =
            DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'")
                    .withZone(ZoneOffset.UTC);

    private S3Proxy s3Proxy;
    private BlobStore blobStore;
    private String container;
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

        container = "container-" + new Random().nextInt(Integer.MAX_VALUE);
        blobStore.createContainer(container);
        TestUtils.putBlob(blobStore, container, KEY,
                ByteSource.wrap("content".getBytes(StandardCharsets.UTF_8)));
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
        if (blobStore != null && container != null) {
            blobStore.removeBlob(container, KEY);
            blobStore.deleteContainer(container);
        }
    }

    /** The report's replay: a URL signed for private, sent with a document. */
    @Test
    public void testObjectAclDocumentNextToSignedHeader() throws Exception {
        HttpResponse<String> response = put(
                presign("/" + container + "/" + KEY, CannedAcl.HEADER),
                PUBLIC_READ, "x-amz-acl", "private");
        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.body()).contains("UnexpectedContent");
        assertThat(blobStore.getBlobAccess(container, KEY))
                .isEqualTo(ObjectCannedACL.PRIVATE);
    }

    /** The bucket's form, which let anyone write to the bucket. */
    @Test
    public void testBucketAclDocumentNextToSignedHeader() throws Exception {
        HttpResponse<String> response = put(
                presign("/" + container, CannedAcl.HEADER),
                PUBLIC_READ_WRITE, "x-amz-acl", "private");
        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.body()).contains("UnexpectedContent");
        assertThat(blobStore.getContainerAccess(container))
                .isEqualTo(BucketCannedACL.PRIVATE);
    }

    /** A URL may state the canned ACL as a parameter, signed like the rest. */
    @Test
    public void testAclDocumentNextToSignedParameter() throws Exception {
        HttpResponse<String> response = put(
                presign("/" + container + "/" + KEY, CannedAcl.PARAMETER),
                PUBLIC_READ);
        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.body()).contains("UnexpectedContent");
        assertThat(blobStore.getBlobAccess(container, KEY))
                .isEqualTo(ObjectCannedACL.PRIVATE);

        response = put(presign("/" + container, CannedAcl.PARAMETER),
                PUBLIC_READ_WRITE);
        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.body()).contains("UnexpectedContent");
        assertThat(blobStore.getContainerAccess(container))
                .isEqualTo(BucketCannedACL.PRIVATE);
    }

    /** Used as signed, with no body, the same URLs set their canned ACL. */
    @Test
    public void testCannedAclAlone() throws Exception {
        blobStore.setBlobAccess(container, KEY, ObjectCannedACL.PUBLIC_READ);
        HttpResponse<String> response = put(
                presign("/" + container + "/" + KEY, CannedAcl.HEADER),
                "", "x-amz-acl", "private");
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(blobStore.getBlobAccess(container, KEY))
                .isEqualTo(ObjectCannedACL.PRIVATE);

        blobStore.setContainerAccess(container, BucketCannedACL.PUBLIC_READ);
        response = put(presign("/" + container, CannedAcl.HEADER),
                "", "x-amz-acl", "private");
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(blobStore.getContainerAccess(container))
                .isEqualTo(BucketCannedACL.PRIVATE);
    }

    /** A URL that states no canned ACL still leaves the ACL to its body. */
    @Test
    public void testAclDocumentAlone() throws Exception {
        HttpResponse<String> response = put(
                presign("/" + container + "/" + KEY, CannedAcl.ABSENT),
                PUBLIC_READ);
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(blobStore.getBlobAccess(container, KEY))
                .isEqualTo(ObjectCannedACL.PUBLIC_READ);

        response = put(presign("/" + container, CannedAcl.ABSENT),
                PUBLIC_READ_WRITE);
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(blobStore.getContainerAccess(container))
                .isEqualTo(BucketCannedACL.PUBLIC_READ_WRITE);
    }

    /** The owner's full control, and the permissions given to AllUsers. */
    private static String policy(String... permissions) {
        String xsi = " xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"";
        var builder = new StringBuilder("<AccessControlPolicy>" +
                "<Owner><ID>owner</ID></Owner><AccessControlList>" +
                "<Grant><Grantee" + xsi + " xsi:type=\"CanonicalUser\">" +
                "<ID>owner</ID></Grantee>" +
                "<Permission>FULL_CONTROL</Permission></Grant>");
        for (String permission : permissions) {
            builder.append("<Grant><Grantee" + xsi + " xsi:type=\"Group\">" +
                    "<URI>http://acs.amazonaws.com/groups/global/AllUsers" +
                    "</URI></Grantee><Permission>" + permission +
                    "</Permission></Grant>");
        }
        return builder.append("</AccessControlList></AccessControlPolicy>")
                .toString();
    }

    /**
     * A presigned PUT ?acl of the path, its payload unsigned as the AWS SDKs
     * presign it.  x-amz-acl: private is a signed header that the bearer has
     * to send, a parameter of the URL, or absent.
     */
    private URI presign(String path, CannedAcl cannedAcl) throws Exception {
        String timestamp = ISO8601.format(Instant.now());
        String date = timestamp.substring(0, 8);
        String scope = date + "/us-east-1/s3/aws4_request";
        String signedHeaders = "host";
        String canonicalHeaders = "host:" + host + "\n";
        if (cannedAcl == CannedAcl.HEADER) {
            signedHeaders += ";x-amz-acl";
            canonicalHeaders += "x-amz-acl:private\n";
        }
        // in the order the canonical request sorts them
        String query = "X-Amz-Algorithm=AWS4-HMAC-SHA256" +
                "&X-Amz-Credential=" + urlEncode(identity + "/" + scope) +
                "&X-Amz-Date=" + timestamp +
                "&X-Amz-Expires=3600" +
                "&X-Amz-SignedHeaders=" + urlEncode(signedHeaders) +
                "&acl=";
        if (cannedAcl == CannedAcl.PARAMETER) {
            query += "&x-amz-acl=private";
        }
        String canonicalRequest = String.join("\n",
                "PUT", path, query, canonicalHeaders, signedHeaders,
                "UNSIGNED-PAYLOAD");
        String stringToSign = String.join("\n",
                "AWS4-HMAC-SHA256", timestamp, scope,
                sha256(canonicalRequest));
        String signature = hex(hmac(signingKey(date), stringToSign));
        return URI.create("http://" + host + path + "?" + query +
                "&X-Amz-Signature=" + signature);
    }

    private byte[] signingKey(String date) throws Exception {
        byte[] key = hmac(("AWS4" + credential).getBytes(
                StandardCharsets.UTF_8), date);
        key = hmac(key, "us-east-1");
        key = hmac(key, "s3");
        return hmac(key, "aws4_request");
    }

    private HttpResponse<String> put(URI uri, String body, String... headers)
            throws Exception {
        var builder = HttpRequest.newBuilder(uri)
                .PUT(HttpRequest.BodyPublishers.ofString(body));
        for (int i = 0; i < headers.length; i += 2) {
            builder.header(headers[i], headers[i + 1]);
        }
        return httpClient.send(builder.build(),
                HttpResponse.BodyHandlers.ofString());
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
