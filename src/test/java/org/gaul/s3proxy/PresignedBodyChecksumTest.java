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
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.google.common.hash.Hashing;
import com.google.common.io.ByteSource;

import org.gaul.s3proxy.auth.AuthenticationType;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.MD5;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.BucketCannedACL;
import software.amazon.awssdk.services.s3.model.BucketVersioningStatus;
import software.amazon.awssdk.services.s3.model.ObjectCannedACL;
import software.amazon.awssdk.services.s3.model.ServerSideEncryption;

/**
 * A presigned URL that signs Content-MD5 or an x-amz-checksum-* header is
 * good for the one body that digest describes: the AWS SDK presigners leave
 * UNSIGNED-PAYLOAD on the payload line, so a signed digest header is all
 * that ties the URL to what its signer approved.  The operations that parse
 * their body instead of storing it must hold the body to that header as the
 * uploads do, or the bearer of a URL signed for a private policy can send a
 * public one.
 */
public final class PresignedBodyChecksumTest {
    private static final String IDENTITY = "identity";
    private static final String CREDENTIAL = "credential";
    private static final String BLOB_NAME = "test";
    private static final String CONTENT_MD5 = "content-md5";
    private static final String CHECKSUM_SHA256 = "x-amz-checksum-sha256";
    private static final String XMLNS =
            "xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"";
    private static final String OWNER_ID =
            "75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a";
    private static final String OWNER_GRANT =
            "<Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/" +
            "XMLSchema-instance\" xsi:type=\"CanonicalUser\"><ID>" + OWNER_ID +
            "</ID></Grantee><Permission>FULL_CONTROL</Permission></Grant>";
    private static final String PRIVATE_ACL = acl(OWNER_GRANT);
    private static final String PUBLIC_READ_ACL = acl(OWNER_GRANT +
            allUsersGrant("READ"));
    private static final String PUBLIC_READ_WRITE_ACL = acl(OWNER_GRANT +
            allUsersGrant("READ") + allUsersGrant("WRITE"));
    private static final DateTimeFormatter ISO8601 =
            DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'")
                    .withZone(ZoneOffset.UTC);

    private S3Proxy s3Proxy;
    private BlobStore blobStore;
    private String containerName;
    private String host;
    private final HttpClient httpClient = HttpClient.newHttpClient();

    @BeforeEach
    public void setUp() throws Exception {
        blobStore = TestUtils.createTransientBlobStore();
        containerName = TestUtils.createRandomContainerName();
        blobStore.createContainer(containerName);
        TestUtils.putBlob(blobStore, containerName, BLOB_NAME,
                ByteSource.wrap("private data".getBytes(
                        StandardCharsets.UTF_8)));
        s3Proxy = S3Proxy.builder()
                .stopTimeout(0)
                .blobStore(blobStore)
                .awsAuthentication(AuthenticationType.AWS_V2_OR_V4,
                        IDENTITY, CREDENTIAL)
                .endpoint(URI.create("http://127.0.0.1:0"))
                .build();
        s3Proxy.start();
        while (!s3Proxy.getState().equals("STARTED")) {
            Thread.sleep(10);
        }
        host = "127.0.0.1:" + s3Proxy.getPort();
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
        if (blobStore != null) {
            blobStore.close();
        }
    }

    @Test
    public void testObjectAclPinnedByChecksum() throws Exception {
        String path = "/" + containerName + "/" + BLOB_NAME;
        var pin = Map.of(CHECKSUM_SHA256, sha256(PRIVATE_ACL));
        URI uri = presign("PUT", path, Map.of("acl", ""), pin);

        assertBadDigest(send("PUT", uri, pin, PUBLIC_READ_ACL));
        assertThat(blobStore.getBlobAccess(containerName, BLOB_NAME))
                .isEqualTo(ObjectCannedACL.PRIVATE);
        assertThat(send("GET", URI.create("http://" + host + path), Map.of(),
                null).statusCode()).isEqualTo(403);

        assertThat(send("PUT", uri, pin, PRIVATE_ACL).statusCode())
                .isEqualTo(200);
    }

    @Test
    public void testObjectAclPinnedByContentMD5() throws Exception {
        String path = "/" + containerName + "/" + BLOB_NAME;
        var pin = Map.of(CONTENT_MD5, md5(PRIVATE_ACL));
        URI uri = presign("PUT", path, Map.of("acl", ""), pin);

        assertBadDigest(send("PUT", uri, pin, PUBLIC_READ_ACL));
        assertThat(blobStore.getBlobAccess(containerName, BLOB_NAME))
                .isEqualTo(ObjectCannedACL.PRIVATE);

        assertThat(send("PUT", uri, pin, PRIVATE_ACL).statusCode())
                .isEqualTo(200);
    }

    @Test
    public void testBucketAclPinnedByChecksum() throws Exception {
        String path = "/" + containerName;
        var pin = Map.of(CHECKSUM_SHA256, sha256(PRIVATE_ACL));
        URI uri = presign("PUT", path, Map.of("acl", ""), pin);

        assertBadDigest(send("PUT", uri, pin, PUBLIC_READ_WRITE_ACL));
        assertThat(blobStore.getContainerAccess(containerName))
                .isEqualTo(BucketCannedACL.PRIVATE);

        assertThat(send("PUT", uri, pin, PRIVATE_ACL).statusCode())
                .isEqualTo(200);
    }

    @Test
    public void testBucketAclPinnedByContentMD5() throws Exception {
        String path = "/" + containerName;
        var pin = Map.of(CONTENT_MD5, md5(PRIVATE_ACL));
        URI uri = presign("PUT", path, Map.of("acl", ""), pin);

        assertBadDigest(send("PUT", uri, pin, PUBLIC_READ_WRITE_ACL));
        assertThat(blobStore.getContainerAccess(containerName))
                .isEqualTo(BucketCannedACL.PRIVATE);
        assertThat(send("PUT", URI.create("http://" + host + path +
                "/planted"), Map.of(), "planted").statusCode())
                .isEqualTo(403);

        assertThat(send("PUT", uri, pin, PRIVATE_ACL).statusCode())
                .isEqualTo(200);
    }

    /** A pin on no body at all is still a pin. */
    @Test
    public void testAclPinnedToEmptyBody() throws Exception {
        String path = "/" + containerName + "/" + BLOB_NAME;
        var pin = Map.of(CONTENT_MD5, md5(""));
        URI uri = presign("PUT", path, Map.of("acl", ""), pin);

        assertBadDigest(send("PUT", uri, pin, PUBLIC_READ_ACL));
        assertThat(blobStore.getBlobAccess(containerName, BLOB_NAME))
                .isEqualTo(ObjectCannedACL.PRIVATE);

        assertThat(send("PUT", uri, pin, "").statusCode()).isEqualTo(200);
    }

    @Test
    public void testBucketVersioning() throws Exception {
        String suspended = versioning("Suspended");
        String enabled = versioning("Enabled");
        for (var pin : pins(suspended)) {
            URI uri = presign("PUT", "/" + containerName,
                    Map.of("versioning", ""), pin);

            assertBadDigest(send("PUT", uri, pin, enabled));
            assertThat(blobStore.getBucketVersioning(containerName))
                    .isNotEqualTo(BucketVersioningStatus.ENABLED);

            assertThat(send("PUT", uri, pin, suspended).statusCode())
                    .isEqualTo(200);
        }
    }

    @Test
    public void testBucketEncryption() throws Exception {
        String aes256 = encryption("AES256");
        String kms = encryption("aws:kms");
        for (var pin : pins(aes256)) {
            URI uri = presign("PUT", "/" + containerName,
                    Map.of("encryption", ""), pin);

            assertBadDigest(send("PUT", uri, pin, kms));

            assertThat(send("PUT", uri, pin, aes256).statusCode())
                    .isEqualTo(200);
            assertThat(blobStore.getBucketEncryption(containerName).rules()
                    .get(0).applyServerSideEncryptionByDefault()
                    .sseAlgorithm()).isEqualTo(ServerSideEncryption.AES256);
        }
    }

    @Test
    public void testCreateBucket() throws Exception {
        String created = TestUtils.createRandomContainerName();
        String constraint = "<CreateBucketConfiguration " + XMLNS + ">" +
                "<LocationConstraint>us-east-1</LocationConstraint>" +
                "</CreateBucketConfiguration>";
        for (var pin : pins(constraint)) {
            URI uri = presign("PUT", "/" + created, Map.of(), pin);

            assertBadDigest(send("PUT", uri, pin, constraint.replace(
                    "us-east-1", "eu-west-1")));
            assertThat(blobStore.containerExists(created)).isFalse();
        }
    }

    /**
     * Every digest the request carries has to hold.  Content-MD5 need not
     * be among a V4 signature's headers, so the bearer can add one that
     * matches a body of its own, and it must not stand in for the checksum
     * the URL signed.
     */
    @Test
    public void testDeleteObjectsUnsignedContentMD5() throws Exception {
        String approved = delete("some-other-key");
        String forged = delete(BLOB_NAME);
        var pin = Map.of(CHECKSUM_SHA256, sha256(approved));
        URI uri = presign("POST", "/" + containerName, Map.of("delete", ""),
                pin);

        assertBadDigest(send("POST", uri, pin, forged));
        assertBadDigest(send("POST", uri, Map.of(
                CHECKSUM_SHA256, sha256(approved),
                CONTENT_MD5, md5(forged)), forged));
        assertThat(blobStore.blobExists(containerName, BLOB_NAME)).isTrue();

        assertThat(send("POST", uri, pin, approved).statusCode())
                .isEqualTo(200);
        assertThat(blobStore.blobExists(containerName, BLOB_NAME)).isTrue();
    }

    /**
     * On a completion x-amz-checksum-* describes the object, which leaves
     * Content-MD5 as what pins the list of parts.
     */
    @Test
    public void testCompleteMultipartUploadContentMD5() throws Exception {
        String path = "/" + containerName + "/multipart";
        HttpResponse<String> response = send("POST", presign("POST", path,
                Map.of("uploads", ""), Map.of()), Map.of(), "");
        assertThat(response.statusCode()).isEqualTo(200);
        Matcher matcher = Pattern.compile("<UploadId>(.*)</UploadId>")
                .matcher(response.body());
        assertThat(matcher.find()).isTrue();
        String uploadId = matcher.group(1);

        response = send("PUT", presign("PUT", path, Map.of(
                "partNumber", "1", "uploadId", uploadId), Map.of()),
                Map.of(), "part");
        assertThat(response.statusCode()).isEqualTo(200);
        String eTag = response.headers().firstValue("ETag").orElseThrow();

        String approved = "<CompleteMultipartUpload " + XMLNS + "><Part>" +
                "<PartNumber>1</PartNumber><ETag>" + eTag + "</ETag></Part>" +
                "</CompleteMultipartUpload>";
        var pin = Map.of(CONTENT_MD5, md5(approved));
        URI uri = presign("POST", path, Map.of("uploadId", uploadId), pin);

        assertBadDigest(send("POST", uri, pin, approved + "\n"));
        assertThat(blobStore.blobExists(containerName, "multipart"))
                .isFalse();

        assertThat(send("POST", uri, pin, approved).statusCode())
                .isEqualTo(200);
        assertThat(blobStore.blobExists(containerName, "multipart")).isTrue();
    }

    private void assertBadDigest(HttpResponse<String> response) {
        assertThat(response.body()).contains("<Code>BadDigest</Code>");
        assertThat(response.statusCode()).isEqualTo(400);
    }

    /** Each header that can pin {@code body}, alone. */
    private static Iterable<Map<String, String>> pins(String body) {
        return List.of(Map.of(CONTENT_MD5, md5(body)),
                Map.of(CHECKSUM_SHA256, sha256(body)));
    }

    private static String acl(String grants) {
        return "<AccessControlPolicy " + XMLNS + "><Owner><ID>" + OWNER_ID +
                "</ID></Owner><AccessControlList>" + grants +
                "</AccessControlList></AccessControlPolicy>";
    }

    private static String allUsersGrant(String permission) {
        return "<Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/" +
                "XMLSchema-instance\" xsi:type=\"Group\"><URI>" +
                "http://acs.amazonaws.com/groups/global/AllUsers</URI>" +
                "</Grantee><Permission>" + permission + "</Permission>" +
                "</Grant>";
    }

    private static String versioning(String status) {
        return "<VersioningConfiguration " + XMLNS + "><Status>" + status +
                "</Status></VersioningConfiguration>";
    }

    private static String encryption(String algorithm) {
        return "<ServerSideEncryptionConfiguration " + XMLNS + "><Rule>" +
                "<ApplyServerSideEncryptionByDefault><SSEAlgorithm>" +
                algorithm + "</SSEAlgorithm>" +
                "</ApplyServerSideEncryptionByDefault></Rule>" +
                "</ServerSideEncryptionConfiguration>";
    }

    private static String delete(String key) {
        return "<Delete " + XMLNS + "><Object><Key>" + key +
                "</Key></Object></Delete>";
    }

    private static String md5(String body) {
        return Base64.getEncoder().encodeToString(MD5.hash(body.getBytes(
                StandardCharsets.UTF_8)));
    }

    private static String sha256(String body) {
        return Base64.getEncoder().encodeToString(Hashing.sha256().hashString(
                body, StandardCharsets.UTF_8).asBytes());
    }

    private static byte[] hmac(byte[] key, String data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Presign by hand the way the AWS SDK presigners do: UNSIGNED-PAYLOAD
     * on the payload line, and {@code signedHeaders} beside host among the
     * headers the bearer has to send unchanged.
     */
    private URI presign(String method, String path, Map<String, String> query,
            Map<String, String> signedHeaders) throws Exception {
        String timestamp = ISO8601.format(Instant.now());
        String date = timestamp.substring(0, 8);
        String scope = date + "/us-east-1/s3/aws4_request";
        var headers = new TreeMap<String, String>(signedHeaders);
        headers.put("host", host);
        var parameters = new TreeMap<String, String>(query);
        parameters.put("X-Amz-Algorithm", "AWS4-HMAC-SHA256");
        parameters.put("X-Amz-Credential", IDENTITY + "/" + scope);
        parameters.put("X-Amz-Date", timestamp);
        parameters.put("X-Amz-Expires", "3600");
        parameters.put("X-Amz-SignedHeaders", String.join(";",
                headers.keySet()));

        var canonicalQuery = new StringBuilder();
        for (var parameter : parameters.entrySet()) {
            if (!canonicalQuery.isEmpty()) {
                canonicalQuery.append('&');
            }
            canonicalQuery.append(urlEncode(parameter.getKey())).append('=')
                    .append(urlEncode(parameter.getValue()));
        }
        var canonicalHeaders = new StringBuilder();
        for (var header : headers.entrySet()) {
            canonicalHeaders.append(header.getKey()).append(':')
                    .append(header.getValue()).append('\n');
        }
        String canonicalRequest = String.join("\n",
                method, path, canonicalQuery, canonicalHeaders,
                String.join(";", headers.keySet()), "UNSIGNED-PAYLOAD");
        String stringToSign = String.join("\n",
                "AWS4-HMAC-SHA256", timestamp, scope,
                Hashing.sha256().hashString(canonicalRequest,
                        StandardCharsets.UTF_8).toString());
        byte[] key = hmac(("AWS4" + CREDENTIAL).getBytes(
                StandardCharsets.UTF_8), date);
        key = hmac(key, "us-east-1");
        key = hmac(key, "s3");
        key = hmac(key, "aws4_request");
        String signature = HexFormat.of().formatHex(hmac(key, stringToSign));
        return URI.create("http://" + host + path + "?" + canonicalQuery +
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

    private HttpResponse<String> send(String method, URI uri,
            Map<String, String> headers, String body) throws Exception {
        var builder = HttpRequest.newBuilder(uri).method(method,
                body == null ? HttpRequest.BodyPublishers.noBody() :
                        HttpRequest.BodyPublishers.ofString(body));
        for (var header : headers.entrySet()) {
            builder.header(header.getKey(), header.getValue());
        }
        return httpClient.send(builder.build(),
                HttpResponse.BodyHandlers.ofString());
    }
}
