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
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Random;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.BucketCannedACL;

/**
 * A browser cannot set headers on a form submission, so everything a PUT says
 * in headers a POST says in form fields instead -- where the object goes, what
 * metadata it carries, and what the browser should be shown afterwards.  These
 * cover the fields the handler acts on; {@link PostPolicyTest} covers the
 * document that says which of them are allowed.
 */
public final class PostObjectTest {
    private static final String IDENTITY = "identity";
    private static final String CREDENTIAL = "credential";
    private static final String BOUNDARY = "----------s3proxytest";
    private static final int MAX_REQUEST_SIZE = 16 * 1024;

    private S3Proxy s3Proxy;
    private BlobStore blobStore;
    private String containerName;
    private String bucketUri;
    private final HttpClient httpClient = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER).build();

    @BeforeEach
    public void setUp() throws Exception {
        blobStore = TestUtils.createTransientBlobStore();
        containerName = "container-" + new Random().nextInt(Integer.MAX_VALUE);
        blobStore.createContainer(containerName);

        s3Proxy = S3Proxy.builder()
                .blobStore(blobStore)
                .awsAuthentication(AuthenticationType.AWS_V2_OR_V4, IDENTITY,
                        CREDENTIAL)
                // Small enough that a test can send more than the proxy will
                // hold without sending the default 128 MB; every form here
                // but that one is a few hundred bytes.
                .v4MaxNonChunkedRequestSize(MAX_REQUEST_SIZE)
                .endpoint(URI.create("http://127.0.0.1:0"))
                .build();
        s3Proxy.start();
        while (!s3Proxy.getState().equals("STARTED")) {
            Thread.sleep(10);
        }
        bucketUri = "http://127.0.0.1:" + s3Proxy.getPort() + "/" +
                containerName;
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
    }

    /**
     * A form carrying no credential at all is answered from the bucket's
     * own permissions, as S3 answers it: a private bucket refuses.
     */
    @Test
    public void testUnsignedPostIsDenied() throws Exception {
        HttpResponse<String> response = postUnsigned(
                "key", "foo.txt", "Content-Type", "text/plain");
        assertThat(response.statusCode()).isEqualTo(403);
        assertThat(blobStore.blobExists(containerName, "foo.txt")).isFalse();
    }

    /** ... and a bucket granting AllUsers WRITE uploads it. */
    @Test
    public void testUnsignedPostToPublicReadWriteBucket() throws Exception {
        blobStore.setContainerAccess(containerName,
                BucketCannedACL.PUBLIC_READ_WRITE);
        HttpResponse<String> response = postUnsigned(
                "key", "foo.txt", "Content-Type", "text/plain");
        assertThat(response.statusCode()).isEqualTo(204);
        assertThat(blobStore.blobExists(containerName, "foo.txt")).isTrue();
    }

    /** The browser has nowhere to show a body, so the form picks a status. */
    @Test
    public void testSuccessActionStatus201() throws Exception {
        HttpResponse<String> response = post(
                "key", "foo.txt", "success_action_status", "201");
        assertThat(response.statusCode()).isEqualTo(201);
        assertThat(response.body())
                .contains("<Key>foo.txt</Key>")
                .contains("<Bucket>" + containerName + "</Bucket>")
                .contains("<ETag>");
        assertThat(body("foo.txt")).isEqualTo("bar");
    }

    @Test
    public void testSuccessActionStatus200() throws Exception {
        HttpResponse<String> response = post(
                "key", "foo.txt", "success_action_status", "200");
        assertThat(response.statusCode()).isEqualTo(200);
    }

    /**
     * A status S3 will not send is treated as unsaid rather than refused,
     * which is what lets a form name one a later version might add.
     */
    @Test
    public void testUnknownSuccessActionStatusFallsBackTo204()
            throws Exception {
        HttpResponse<String> response = post(
                "key", "foo.txt", "success_action_status", "404");
        assertThat(response.statusCode()).isEqualTo(204);
        assertThat(response.body()).isEmpty();
        assertThat(body("foo.txt")).isEqualTo("bar");
    }

    /** The upload's result is handed back in the query of a redirect. */
    @Test
    public void testSuccessActionRedirect() throws Exception {
        HttpResponse<String> response = post(
                "key", "foo.txt",
                "success_action_redirect", "http://example.com/done");
        assertThat(response.statusCode()).isEqualTo(303);
        String location = response.headers().firstValue("Location")
                .orElseThrow();
        assertThat(location)
                .startsWith("http://example.com/done?")
                .contains("bucket=" + containerName)
                .contains("key=foo.txt")
                // The quotes an ETag carries are not legal in a URI.
                .contains("etag=%22");
    }

    /** The legacy spelling, which older form builders still emit. */
    @Test
    public void testRedirectFieldIsHonoured() throws Exception {
        HttpResponse<String> response = post(
                "key", "foo.txt", "redirect", "http://example.com/done");
        assertThat(response.statusCode()).isEqualTo(303);
        assertThat(response.headers().firstValue("Location").orElseThrow())
                .startsWith("http://example.com/done?");
    }

    /** A form that does not know the name until the user picks the file. */
    @Test
    public void testFilenameSubstitution() throws Exception {
        HttpResponse<String> response = post(
                "key", "uploads/${filename}");
        assertThat(response.statusCode()).isEqualTo(204);
        assertThat(body("uploads/payload.txt")).isEqualTo("bar");
    }

    @Test
    public void testUserMetadata() throws Exception {
        HttpResponse<String> response = post(
                "key", "foo.txt", "x-amz-meta-foo", "barclamp");
        assertThat(response.statusCode()).isEqualTo(204);
        assertThat(blobStore.blobMetadata(containerName, "foo.txt")
                .metadata()).containsEntry("foo", "barclamp");
    }

    /** A signed policy the form satisfies. */
    @Test
    public void testAuthenticatedPost() throws Exception {
        String policy = policy(
                "{\"bucket\": \"" + containerName + "\"}," +
                "[\"starts-with\", \"$key\", \"foo\"]," +
                "[\"content-length-range\", 0, 1024]");
        HttpResponse<String> response = post(
                "key", "foo.txt",
                "AWSAccessKeyId", IDENTITY,
                "policy", policy,
                "signature", sign(policy));
        assertThat(response.statusCode()).isEqualTo(204);
        assertThat(body("foo.txt")).isEqualTo("bar");
    }

    /** The same policy, and a key it does not admit. */
    @Test
    public void testAuthenticatedPostViolatingItsPolicy() throws Exception {
        String policy = policy(
                "{\"bucket\": \"" + containerName + "\"}," +
                "[\"starts-with\", \"$key\", \"foo\"]," +
                "[\"content-length-range\", 0, 1024]");
        HttpResponse<String> response = post(
                "key", "elsewhere.txt",
                "AWSAccessKeyId", IDENTITY,
                "policy", policy,
                "signature", sign(policy));
        assertThat(response.statusCode()).isEqualTo(403);
        assertThat(response.body()).contains("Policy Condition failed");
    }

    /**
     * A form arrives before the policy inside it can say who authorized the
     * upload, so how much of it the proxy will read is bounded rather than
     * trusted.  Jetty bounds the number of parts and nothing else, which left
     * an unauthenticated request able to spill as much as it liked through
     * the temporary directory and into memory.
     */
    @Test
    public void testOversizedPostIsRefused() throws Exception {
        var out = new ByteArrayOutputStream();
        out.write(("--" + BOUNDARY + "\r\nContent-Disposition: form-data;" +
                " name=\"file\"; filename=\"big.txt\"\r\n\r\n")
                .getBytes(StandardCharsets.UTF_8));
        out.write("x".repeat(2 * MAX_REQUEST_SIZE)
                .getBytes(StandardCharsets.UTF_8));
        out.write(("\r\n--" + BOUNDARY + "--\r\n")
                .getBytes(StandardCharsets.UTF_8));

        HttpResponse<String> response = httpClient.send(
                HttpRequest.newBuilder(URI.create(bucketUri))
                        .header("Content-Type",
                                "multipart/form-data; boundary=" + BOUNDARY)
                        .POST(HttpRequest.BodyPublishers.ofByteArray(
                                out.toByteArray()))
                        .build(), HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.body())
                .contains("<Code>MaxMessageLengthExceeded</Code>");
    }

    /** A body the parser cannot finish is a bad request, not a 500. */
    @Test
    public void testMalformedPostIsRefused() throws Exception {
        HttpResponse<String> response = httpClient.send(
                HttpRequest.newBuilder(URI.create(bucketUri))
                        .header("Content-Type",
                                "multipart/form-data; boundary=" + BOUNDARY)
                        .POST(HttpRequest.BodyPublishers.ofString(
                                "--" + BOUNDARY + "\r\nContent-Disposition:" +
                                " form-data; name=\"file\";" +
                                " filename=\"x\"\r\n\r\ntruncated"))
                        .build(), HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.body()).contains("<Code>InvalidRequest</Code>");
    }

    /** A policy with no signature is a form built wrong, not a refusal. */
    @Test
    public void testPolicyWithoutSignature() throws Exception {
        HttpResponse<String> response = post(
                "key", "foo.txt",
                "AWSAccessKeyId", IDENTITY,
                "policy", policy("{\"bucket\": \"" + containerName + "\"}"));
        assertThat(response.statusCode()).isEqualTo(400);
    }

    private String policy(String conditions) {
        return Base64.getEncoder().encodeToString(
                ("{\"expiration\": \"" +
                Instant.now().plus(1, ChronoUnit.HOURS) +
                "\", \"conditions\": [" + conditions + "]}")
                .getBytes(StandardCharsets.UTF_8));
    }

    private static String sign(String policy) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(new SecretKeySpec(
                CREDENTIAL.getBytes(StandardCharsets.UTF_8), "HmacSHA1"));
        return Base64.getEncoder().encodeToString(
                mac.doFinal(policy.getBytes(StandardCharsets.UTF_8)));
    }

    private String body(String blobName) throws Exception {
        try (var stream = blobStore.getBlob(containerName, blobName)) {
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    /**
     * Build and send a multipart form whose file part is always "bar",
     * authorized by a policy admitting whatever fields the caller sent.  A
     * form that carries a policy of its own is left as it is.
     */
    private HttpResponse<String> post(String... fields) throws Exception {
        for (int i = 0; i < fields.length; i += 2) {
            if (fields[i].equalsIgnoreCase("policy")) {
                return postUnsigned(fields);
            }
        }
        // A policy must name every field the form sends, so mirror them.
        var conditions = new StringBuilder(
                "{\"bucket\": \"" + containerName + "\"}");
        for (int i = 0; i < fields.length; i += 2) {
            conditions.append(", [\"starts-with\", \"$")
                    .append(fields[i]).append("\", \"\"]");
        }
        String policy = policy(conditions.toString());
        List<String> signed = new ArrayList<>(List.of(fields));
        signed.addAll(List.of(
                "AWSAccessKeyId", IDENTITY,
                "policy", policy,
                "signature", sign(policy)));
        return postUnsigned(signed.toArray(new String[0]));
    }

    /** The same, sending exactly the fields given and nothing else. */
    private HttpResponse<String> postUnsigned(String... fields)
            throws Exception {
        var out = new ByteArrayOutputStream();
        List<String> pairs = new ArrayList<>(List.of(fields));
        for (int i = 0; i < pairs.size(); i += 2) {
            out.write(("--" + BOUNDARY + "\r\nContent-Disposition: form-data;" +
                    " name=\"" + pairs.get(i) + "\"\r\n\r\n" +
                    pairs.get(i + 1) + "\r\n")
                    .getBytes(StandardCharsets.UTF_8));
        }
        out.write(("--" + BOUNDARY + "\r\nContent-Disposition: form-data;" +
                " name=\"file\"; filename=\"payload.txt\"\r\n\r\nbar\r\n")
                .getBytes(StandardCharsets.UTF_8));
        out.write(("--" + BOUNDARY + "--\r\n")
                .getBytes(StandardCharsets.UTF_8));

        return httpClient.send(HttpRequest.newBuilder(URI.create(bucketUri))
                .header("Content-Type",
                        "multipart/form-data; boundary=" + BOUNDARY)
                .POST(HttpRequest.BodyPublishers.ofByteArray(
                        out.toByteArray()))
                .build(), HttpResponse.BodyHandlers.ofString());
    }
}
