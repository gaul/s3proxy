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
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Random;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.google.common.collect.ImmutableMap;
import com.google.common.io.ByteSource;

import org.gaul.s3proxy.auth.AuthenticationType;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.middleware.GlobBlobStoreLocator;
import org.gaul.s3proxy.middleware.GlobBlobStoreLocator.GlobTarget;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;

/**
 * The service root names no bucket, and ListBuckets is all there is to ask
 * of it.  Every other request sent there used to run against the empty
 * bucket name "/" splits into, which a {@link BlobStoreLocator} scopes to
 * nobody and which the nio2 stores took for the directory holding every
 * bucket -- so that an identity confined to its own buckets reached
 * another's objects by moving the bucket's name into the key.  The same
 * name arrives through x-amz-copy-source, which carries its bucket past the
 * check the request URI goes through.
 */
public final class ServiceRootTest {
    private static final String VICTIM_IDENTITY = "victim-identity";
    private static final String VICTIM_CREDENTIAL = "victim-credential";
    private static final String ATTACKER_IDENTITY = "attacker-identity";
    private static final String ATTACKER_CREDENTIAL = "attacker-credential";
    private static final String KEY = "object";
    private static final String CONTENT = "written by the victim";
    private static final String BOUNDARY = "----------s3proxytest";

    private S3Proxy s3Proxy;
    private BlobStore blobStore;
    private String victimContainer;
    private String attackerContainer;
    private String baseUri;
    private final HttpClient httpClient = HttpClient.newHttpClient();

    @BeforeEach
    public void setUp() throws Exception {
        blobStore = TestUtils.createTransientBlobStore();
        victimContainer = "victim-" + new Random().nextInt(Integer.MAX_VALUE);
        attackerContainer = "attacker-" +
                new Random().nextInt(Integer.MAX_VALUE);
        blobStore.createContainer(victimContainer);
        blobStore.createContainer(attackerContainer);
        TestUtils.putBlob(blobStore, victimContainer, KEY,
                ByteSource.wrap(CONTENT.getBytes(StandardCharsets.UTF_8)));

        s3Proxy = S3Proxy.builder()
                .stopTimeout(0)
                .blobStore(blobStore)
                .awsAuthentication(AuthenticationType.AWS_V2_OR_V4,
                        ATTACKER_IDENTITY, ATTACKER_CREDENTIAL)
                .endpoint(URI.create("http://127.0.0.1:0"))
                .build();
        // Both identities are served by the same backing store but each owns
        // a disjoint set of buckets, so neither may touch the other's.
        var credsMap = ImmutableMap.of(
                VICTIM_IDENTITY,
                new AccessGrant(VICTIM_CREDENTIAL, blobStore),
                ATTACKER_IDENTITY,
                new AccessGrant(ATTACKER_CREDENTIAL, blobStore));
        var globMap = Map.of(
                FileSystems.getDefault().getPathMatcher("glob:victim-*"),
                new GlobTarget(Optional.of(VICTIM_IDENTITY), blobStore),
                FileSystems.getDefault().getPathMatcher("glob:attacker-*"),
                new GlobTarget(Optional.of(ATTACKER_IDENTITY), blobStore));
        s3Proxy.setBlobStoreLocator(
                new GlobBlobStoreLocator(credsMap, globMap));
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

    /** What the root is for still works, and shows an identity its own. */
    @Test
    public void testListBuckets() throws Exception {
        HttpResponse<String> response = send("GET", "/", "", "");
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).contains(attackerContainer)
                .doesNotContain(victimContainer);
    }

    /**
     * DeleteObjects takes its bucket from the path and its keys from the
     * body.  Sent to the victim's bucket it is refused; sent to the root,
     * with the bucket's name moved into the key, it must not be carried out
     * instead.
     */
    @Test
    public void testDeleteObjectsAtServiceRootIsRefused() throws Exception {
        assertThat(send("POST", "/" + victimContainer, "delete",
                deleteBody(KEY)).statusCode()).isEqualTo(403);

        HttpResponse<String> response = send("POST", "/", "delete",
                deleteBody(victimContainer + "/" + KEY));
        assertThat(response.statusCode()).isEqualTo(405);
        assertThat(response.body()).contains("<Code>MethodNotAllowed</Code>");
        assertThat(victimContent()).isEqualTo(CONTENT);
    }

    /**
     * A form POST is signed inside the form, so it arrives on the path that
     * serves requests carrying no Authorization, and names its key in a
     * field.
     */
    @Test
    public void testFormPostAtServiceRootIsRefused() throws Exception {
        assertThat(postForm("/" + victimContainer, KEY).statusCode())
                .isEqualTo(403);

        HttpResponse<String> response = postForm("/",
                victimContainer + "/" + KEY);
        assertThat(response.statusCode()).isEqualTo(405);
        assertThat(response.body()).contains("<Code>MethodNotAllowed</Code>");
        assertThat(victimContent()).isEqualTo(CONTENT);
    }

    /** Nor is the root a bucket to probe, configure, create or delete. */
    @Test
    public void testBucketOperationsAtServiceRootAreRefused()
            throws Exception {
        for (String method : List.of("HEAD", "PUT", "DELETE", "POST")) {
            assertThat(send(method, "/", "", "").statusCode())
                    .as("signed " + method).isEqualTo(405);
            assertThat(httpClient.send(
                    HttpRequest.newBuilder(URI.create(baseUri + "/"))
                            .method(method,
                                    HttpRequest.BodyPublishers.noBody())
                            .build(),
                    HttpResponse.BodyHandlers.ofString()).statusCode())
                    .as("unsigned " + method).isEqualTo(405);
        }
        assertThat(send("PUT", "/", "acl", "",
                "x-amz-acl", "public-read-write").statusCode())
                .isEqualTo(405);
        assertThat(blobStore.containerExists(victimContainer)).isTrue();
        assertThat(victimContent()).isEqualTo(CONTENT);
    }

    /**
     * A copy source of "//bucket/key" names the bucket "", and one of
     * "/./bucket/key" the bucket ".": neither is a name a bucket can have,
     * and both used to read the victim's object out of the store's root.
     */
    @Test
    public void testCopySourceNamingNoBucketIsRefused() throws Exception {
        String target = "/" + attackerContainer + "/copy";
        assertThat(send("PUT", target, "", "", "x-amz-copy-source",
                "/" + victimContainer + "/" + KEY).body())
                .contains("<Code>AccessDenied</Code>");

        for (String prefix : List.of("//", "/./")) {
            HttpResponse<String> response = send("PUT", target, "", "",
                    "x-amz-copy-source", prefix + victimContainer + "/" + KEY);
            assertThat(response.statusCode()).as(prefix).isEqualTo(404);
            assertThat(response.body()).contains("<Code>NoSuchBucket</Code>");
            assertThat(blobStore.blobExists(attackerContainer, "copy"))
                    .isFalse();
        }
    }

    /** UploadPartCopy reads the header the same way. */
    @Test
    public void testPartCopySourceNamingNoBucketIsRefused() throws Exception {
        String uploadId = blobStore.initiateMultipartUpload(
                CreateMultipartUploadRequest.builder()
                        .bucket(attackerContainer).key("copy").build()).id();

        for (String prefix : List.of("//", "/./")) {
            HttpResponse<String> response = send("PUT",
                    "/" + attackerContainer + "/copy",
                    "partNumber=1&uploadId=" + uploadId, "",
                    "x-amz-copy-source", prefix + victimContainer + "/" + KEY);
            assertThat(response.statusCode()).as(prefix).isEqualTo(404);
            assertThat(response.body()).contains("<Code>NoSuchBucket</Code>");
        }
    }

    private String victimContent() throws Exception {
        try (var stream = blobStore.getBlob(victimContainer, KEY)) {
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static String deleteBody(String key) {
        return "<Delete><Object><Key>" + key + "</Key></Object></Delete>";
    }

    /**
     * Send a request the attacker signed with its own credential, by V2
     * query authentication: one HMAC over the method, the Content-MD5, the
     * expiry, the x-amz- headers -- here at most one -- and the resource
     * with the subresources that select an operation.
     */
    private HttpResponse<String> send(String method, String path,
            String subresources, String body, String... amzHeader)
            throws Exception {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        String contentMd5 = bytes.length == 0 ? "" :
                Base64.getEncoder().encodeToString(
                        MessageDigest.getInstance("MD5").digest(bytes));
        long expires = System.currentTimeMillis() / 1000 + 3600;
        String stringToSign = method + "\n" + contentMd5 + "\n\n" + expires +
                "\n" +
                (amzHeader.length == 0 ? "" :
                        amzHeader[0] + ":" + amzHeader[1] + "\n") +
                path + (subresources.isEmpty() ? "" : "?" + subresources);
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(new SecretKeySpec(ATTACKER_CREDENTIAL.getBytes(
                StandardCharsets.UTF_8), "HmacSHA1"));
        String signature = URLEncoder.encode(
                Base64.getEncoder().encodeToString(mac.doFinal(
                        stringToSign.getBytes(StandardCharsets.UTF_8))),
                StandardCharsets.UTF_8);

        var request = HttpRequest.newBuilder(URI.create(baseUri + path + "?" +
                (subresources.isEmpty() ? "" : subresources + "&") +
                "AWSAccessKeyId=" + ATTACKER_IDENTITY + "&Expires=" + expires +
                "&Signature=" + signature))
                .method(method, bytes.length == 0 ?
                        HttpRequest.BodyPublishers.noBody() :
                        HttpRequest.BodyPublishers.ofByteArray(bytes));
        if (bytes.length != 0) {
            request.header("Content-MD5", contentMd5);
        }
        if (amzHeader.length != 0) {
            request.header(amzHeader[0], amzHeader[1]);
        }
        return httpClient.send(request.build(),
                HttpResponse.BodyHandlers.ofString());
    }

    /**
     * Post a form that would store "written by the attacker" under the key,
     * with a policy admitting any bucket and key that the attacker signed
     * with its own credential.
     */
    private HttpResponse<String> postForm(String path, String key)
            throws Exception {
        String policy = Base64.getEncoder().encodeToString(
                ("{\"expiration\": \"" +
                Instant.now().plus(1, ChronoUnit.HOURS) +
                "\", \"conditions\": [[\"starts-with\", \"$bucket\", \"\"]," +
                " [\"starts-with\", \"$key\", \"\"]]}")
                .getBytes(StandardCharsets.UTF_8));
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(new SecretKeySpec(ATTACKER_CREDENTIAL.getBytes(
                StandardCharsets.UTF_8), "HmacSHA1"));
        String signature = Base64.getEncoder().encodeToString(
                mac.doFinal(policy.getBytes(StandardCharsets.UTF_8)));

        var out = new ByteArrayOutputStream();
        for (var field : List.of(
                Map.entry("key", key),
                Map.entry("AWSAccessKeyId", ATTACKER_IDENTITY),
                Map.entry("policy", policy),
                Map.entry("signature", signature))) {
            out.write(("--" + BOUNDARY + "\r\nContent-Disposition: form-data;" +
                    " name=\"" + field.getKey() + "\"\r\n\r\n" +
                    field.getValue() + "\r\n")
                    .getBytes(StandardCharsets.UTF_8));
        }
        out.write(("--" + BOUNDARY + "\r\nContent-Disposition: form-data;" +
                " name=\"file\"; filename=\"payload.txt\"\r\n\r\n" +
                "written by the attacker\r\n")
                .getBytes(StandardCharsets.UTF_8));
        out.write(("--" + BOUNDARY + "--\r\n")
                .getBytes(StandardCharsets.UTF_8));

        return httpClient.send(
                HttpRequest.newBuilder(URI.create(baseUri + path))
                        .header("Content-Type",
                                "multipart/form-data; boundary=" + BOUNDARY)
                        .POST(HttpRequest.BodyPublishers.ofByteArray(
                                out.toByteArray()))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
    }
}
