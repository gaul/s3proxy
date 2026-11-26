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
import java.security.MessageDigest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Random;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.gaul.s3proxy.auth.AuthenticationType;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.BucketCannedACL;
import software.amazon.awssdk.services.s3.model.ObjectCannedACL;

/**
 * A browser cannot set headers on a form submission, so everything a PUT says
 * in headers a POST says in form fields instead -- where the object goes, what
 * metadata it carries, and what the browser should be shown afterwards.  These
 * cover the fields the handler acts on;
 * {@link org.gaul.s3proxy.auth.PostPolicyTest} covers the
 * document that says which of them are allowed.
 */
public final class PostObjectTest {
    private static final String IDENTITY = "identity";
    private static final String CREDENTIAL = "credential";
    private static final String BOUNDARY = "----------s3proxytest";
    private static final int MAX_REQUEST_SIZE = 32 * 1024;

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
                .stopTimeout(0)
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

    /**
     * A form that asks for an object lock is refused rather than uploaded
     * without one: the upload would succeed and leave unprotected what the
     * form asked to have retained.
     */
    @Test
    public void testObjectLockFieldIsRefused() throws Exception {
        HttpResponse<String> response = post(
                "key", "foo.txt",
                "x-amz-object-lock-mode", "COMPLIANCE",
                "x-amz-object-lock-retain-until-date",
                "2038-01-01T00:00:00Z");
        assertThat(response.statusCode()).isEqualTo(501);
        assertThat(blobStore.blobExists(containerName, "foo.txt")).isFalse();
    }

    /**
     * A key is no longer than S3 allows, 1024 bytes of UTF-8.  The key of a
     * form is a field of its body, so that nothing short of the body's own
     * limit bounded it, and the store makes a directory for every slash.
     */
    @Test
    public void testOverlongKeyIsRefused() throws Exception {
        blobStore.setContainerAccess(containerName,
                BucketCannedACL.PUBLIC_READ_WRITE);
        String longest = "d/".repeat(511) + "ab";
        assertThat(postUnsigned("key", longest).statusCode()).isEqualTo(204);
        assertThat(blobStore.blobExists(containerName, longest)).isTrue();

        HttpResponse<String> response = postUnsigned("key", longest + "c");
        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.body()).contains("KeyTooLongError");
        assertThat(blobStore.blobExists(containerName, longest + "c"))
                .isFalse();

        // counted in bytes, not characters
        assertThat(postUnsigned("key", "\u00e9".repeat(512)).statusCode())
                .isEqualTo(204);
        response = postUnsigned("key", "\u00e9".repeat(513));
        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.body()).contains("KeyTooLongError");

        // and the same limit holds for a key named by the URI
        response = httpClient.send(HttpRequest.newBuilder(
                URI.create(bucketUri + "/" + "a".repeat(1025)))
                .PUT(HttpRequest.BodyPublishers.ofString("bar")).build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.body()).contains("KeyTooLongError");
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

    /**
     * An empty key is refused for what it is rather than left to the store:
     * a middleware that adds to the key would have the store accept it.
     */
    @Test
    public void testEmptyKeyIsRefused() throws Exception {
        HttpResponse<String> response = post("key", "");
        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.body())
                .contains("<Code>InvalidArgument</Code>")
                .contains("User key must have a length greater than 0.");
    }

    /**
     * The key is measured before the file name is substituted into it, not
     * after: the result is as long as the two multiplied, and a form no one
     * has authorized would otherwise have megabytes built from kilobytes.
     */
    @Test
    public void testFilenameSubstitutionIsBoundedByKeyLength()
            throws Exception {
        blobStore.setContainerAccess(containerName,
                BucketCannedACL.PUBLIC_READ_WRITE);
        String name = "a".repeat(510);
        String longest = name + "/" + name + "/ab";
        assertThat(postFileNamed(name, "${filename}/${filename}/ab")
                .statusCode()).isEqualTo(204);
        assertThat(blobStore.blobExists(containerName, longest)).isTrue();

        HttpResponse<String> response = postFileNamed(name,
                "${filename}/${filename}/abc");
        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.body()).contains("<Code>KeyTooLongError</Code>");
        assertThat(blobStore.blobExists(containerName, longest + "c"))
                .isFalse();

        // 13 KB of form asking for a key of 4 MB
        response = postFileNamed("a".repeat(7000), "${filename}".repeat(600));
        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.body()).contains("<Code>KeyTooLongError</Code>");

        // what is bounded is the key, and a short name makes a shorter one
        assertThat(postFileNamed("abc", "${filename}".repeat(100))
                .statusCode()).isEqualTo(204);
        assertThat(blobStore.blobExists(containerName, "abc".repeat(100)))
                .isTrue();
    }

    @Test
    public void testUserMetadata() throws Exception {
        HttpResponse<String> response = post(
                "key", "foo.txt", "x-amz-meta-foo", "barclamp");
        assertThat(response.statusCode()).isEqualTo(204);
        assertThat(blobStore.blobMetadata(containerName, "foo.txt")
                .metadata()).containsEntry("foo", "barclamp");
    }

    /** An empty Content-Type field names no type, as an empty header does. */
    @Test
    public void testEmptyContentTypeField() throws Exception {
        HttpResponse<String> response = post(
                "key", "foo", "Content-Type", "");
        assertThat(response.statusCode()).isEqualTo(204);
        assertThat(blobStore.blobMetadata(containerName, "foo")
                .contentType()).isEqualTo("binary/octet-stream");
    }

    /**
     * S3 takes 20 KB of fields beside the file.  Without that bound the
     * metadata of a form is as large as the form may be, where the metadata
     * of a PUT has to fit its headers, and everything that reads or lists the
     * object afterwards holds all of it.
     */
    @Test
    public void testOversizedFieldsAreRefused() throws Exception {
        blobStore.setContainerAccess(containerName,
                BucketCannedACL.PUBLIC_READ_WRITE);
        HttpResponse<String> response = postUnsigned(
                "key", "foo.txt", "x-amz-meta-foo", "x".repeat(19 * 1024));
        assertThat(response.statusCode()).isEqualTo(204);

        for (String field : List.of(
                "x-amz-meta-foo", "Content-Type", "key")) {
            response = postUnsigned(
                    "key", "bar.txt", field, "x".repeat(20 * 1024));
            assertThat(response.statusCode()).isEqualTo(400);
            assertThat(response.body()).contains(
                    "<Code>MaxPostPreDataLengthExceededError</Code>");
        }

        // counted together, and by name as well as by value
        response = postUnsigned(
                "key", "bar.txt", "x-amz-meta-foo", "x".repeat(10 * 1024),
                "x-amz-meta-" + "y".repeat(1024), "",
                "Content-Type", "x".repeat(9 * 1024));
        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.body()).contains(
                "<Code>MaxPostPreDataLengthExceededError</Code>");
        assertThat(blobStore.blobExists(containerName, "bar.txt")).isFalse();
        assertThat(blobStore.list(containerName).contents()).hasSize(1);
    }

    /**
     * The file's name is a field in all but form, since the key may ask for
     * it, and ask more than once.
     */
    @Test
    public void testOversizedFileNameIsRefused() throws Exception {
        blobStore.setContainerAccess(containerName,
                BucketCannedACL.PUBLIC_READ_WRITE);
        HttpResponse<String> response = postFile("payload.txt",
                "key", "${filename}/${filename}");
        assertThat(response.statusCode()).isEqualTo(204);
        assertThat(body("payload.txt/payload.txt")).isEqualTo("bar");

        // under the bound on a part's headers, which carry the name, but
        // over the bound on the fields once counted with them
        response = postFile("x".repeat(7 * 1024), "key", "${filename}",
                "x-amz-meta-foo", "x".repeat(14 * 1024));
        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.body()).contains(
                "<Code>MaxPostPreDataLengthExceededError</Code>");

        // a key the substitution would make too long is refused before
        // it is built
        response = postFile("x".repeat(1024),
                "key", "${filename}".repeat(32));
        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.body()).contains("<Code>KeyTooLongError</Code>");
        assertThat(blobStore.list(containerName).contents()).hasSize(1);
    }

    /** The form names the type in a field, as a PUT does in a header. */
    @Test
    public void testContentType() throws Exception {
        HttpResponse<String> response = post(
                "key", "foo.txt", "Content-Type", "text/plain");
        assertThat(response.statusCode()).isEqualTo(204);
        assertThat(blobStore.blobMetadata(containerName, "foo.txt")
                .contentType()).isEqualTo("text/plain");
    }

    /**
     * A form without that field names no type, and its key does not name
     * one in its place: a policy that admits no Content-Type field would
     * otherwise leave the type to whoever picks the key.
     */
    @Test
    public void testKeyExtensionIsNotTheContentType() throws Exception {
        HttpResponse<String> response = post("key", "foo.html");
        assertThat(response.statusCode()).isEqualTo(204);
        assertThat(blobStore.blobMetadata(containerName, "foo.html")
                .contentType()).isEqualTo("binary/octet-stream");
    }

    /**
     * Metadata under the name this proxy keeps a validated checksum by is
     * not the form's to set: it would be reported back as the checksum.
     */
    @Test
    public void testReservedChecksumMetadataIsDropped() throws Exception {
        HttpResponse<String> response = post(
                "key", "foo.txt", "x-amz-meta-foo", "barclamp",
                "x-amz-meta-s3proxy_checksum_crc32", "AAAAAA==");
        assertThat(response.statusCode()).isEqualTo(204);
        assertThat(blobStore.blobMetadata(containerName, "foo.txt")
                .metadata()).containsOnlyKeys("foo");
    }

    /** Content-MD5 is a header on a PUT and a field here, and binds alike. */
    @Test
    public void testContentMD5() throws Exception {
        HttpResponse<String> response = post(
                "key", "foo.txt", "Content-MD5", md5("bar"));
        assertThat(response.statusCode()).isEqualTo(204);
        assertThat(body("foo.txt")).isEqualTo("bar");
    }

    /**
     * A policy can pin the field but cannot see the payload, so a form that
     * sends the digest the policy admits beside some other payload has to be
     * refused by the handler.
     */
    @Test
    public void testContentMD5Mismatch() throws Exception {
        String policy = policy(
                "{\"bucket\": \"" + containerName + "\"}," +
                "{\"key\": \"foo.txt\"}," +
                "{\"Content-MD5\": \"" + md5("approved") + "\"}");
        HttpResponse<String> response = post(
                "key", "foo.txt",
                "Content-MD5", md5("approved"),
                "AWSAccessKeyId", IDENTITY,
                "policy", policy,
                "signature", sign(policy));
        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.body()).contains("<Code>BadDigest</Code>");
        assertThat(blobStore.blobExists(containerName, "foo.txt")).isFalse();
    }

    @Test
    public void testContentMD5Malformed() throws Exception {
        HttpResponse<String> response = post(
                "key", "foo.txt", "Content-MD5", "not-a-digest");
        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.body()).contains("<Code>InvalidDigest</Code>");
        assertThat(blobStore.blobExists(containerName, "foo.txt")).isFalse();
    }

    /**
     * The headers a PUT describes its object with are fields here, and are
     * stored like them.  A policy pinning Content-Disposition to attachment
     * is otherwise satisfied by a value nothing kept, and what it meant to
     * be downloaded is served as a page.
     */
    @Test
    public void testContentHeaderFields() throws Exception {
        String policy = policy(
                "{\"bucket\": \"" + containerName + "\"}," +
                "{\"key\": \"foo.html\"}," +
                "[\"starts-with\", \"$Content-Type\", \"\"]," +
                "{\"Content-Disposition\": \"attachment\"}," +
                "[\"starts-with\", \"$Content-Encoding\", \"\"]," +
                "[\"starts-with\", \"$Content-Language\", \"\"]," +
                "[\"starts-with\", \"$Cache-Control\", \"\"]," +
                "[\"starts-with\", \"$Expires\", \"\"]");
        HttpResponse<String> response = post(
                "key", "foo.html",
                "Content-Type", "text/html",
                "Content-Disposition", "attachment",
                "Content-Encoding", "identity",
                "Content-Language", "en",
                "Cache-Control", "no-store",
                "Expires", "Thu, 01 Dec 1994 16:00:00 GMT",
                "AWSAccessKeyId", IDENTITY,
                "policy", policy,
                "signature", sign(policy));
        assertThat(response.statusCode()).isEqualTo(204);

        // what a reader's browser is then told about the object
        blobStore.setBlobAccess(containerName, "foo.html",
                ObjectCannedACL.PUBLIC_READ);
        var headers = httpClient.send(
                HttpRequest.newBuilder(URI.create(bucketUri + "/foo.html"))
                        .build(), HttpResponse.BodyHandlers.ofString())
                .headers();
        assertThat(headers.firstValue("Content-Type")).hasValue("text/html");
        assertThat(headers.firstValue("Content-Disposition"))
                .hasValue("attachment");
        assertThat(headers.firstValue("Content-Encoding"))
                .hasValue("identity");
        assertThat(headers.firstValue("Content-Language")).hasValue("en");
        assertThat(headers.firstValue("Cache-Control")).hasValue("no-store");
        assertThat(headers.firstValue("Expires"))
                .hasValue("Thu, 01 Dec 1994 16:00:00 GMT");
    }

    /**
     * An Expires that is no date is accepted, as S3 accepts any text and a
     * PUT does, and the object stored with none.
     */
    @Test
    // the stores keep Expires as the instant the SDK has deprecated
    @SuppressWarnings("deprecation")
    public void testMalformedExpiresFieldIsIgnored() throws Exception {
        HttpResponse<String> response = post(
                "key", "foo.txt", "Expires", "tomorrow");
        assertThat(response.statusCode()).isEqualTo(204);
        assertThat(blobStore.blobMetadata(containerName, "foo.txt")
                .expires()).isNull();
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
     * A policy naming a checksum pins the payload, so the value the payload
     * is verified against has to be the one the policy was shown.  A field
     * whose name only Unicode case folding equates with the checksum's --
     * U+017F LATIN SMALL LETTER LONG S for the s of sha256 -- is another
     * field to the policy and must be another field to the digest check.
     */
    @Test
    public void testChecksumFieldLookalikeDoesNotReplacePinnedChecksum()
            throws Exception {
        String pinned = sha256("reviewed");
        String policy = checksumPolicy(pinned);
        HttpResponse<String> response = post(
                "key", "foo.txt",
                "AWSAccessKeyId", IDENTITY,
                "policy", policy,
                "signature", sign(policy),
                "x-amz-checksum-sha256", pinned,
                "x-amz-checksum-\u017fha256", sha256("bar"));
        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.body()).contains("<Code>BadDigest</Code>");
        assertThat(blobStore.blobExists(containerName, "foo.txt")).isFalse();
    }

    /**
     * The other direction: U+212A KELVIN SIGN lowercases to the k of
     * checksum, so this spelling is the pinned field to the policy and must
     * be the checksum to the digest check as well.
     */
    @Test
    public void testChecksumFieldFoldedToPinnedNameIsTheChecksum()
            throws Exception {
        String pinned = sha256("reviewed");
        String policy = checksumPolicy(pinned);
        HttpResponse<String> response = post(
                "key", "foo.txt",
                "AWSAccessKeyId", IDENTITY,
                "policy", policy,
                "signature", sign(policy),
                "x-amz-checksum-sha256", sha256("bar"),
                "x-amz-chec\u212asum-sha256", pinned);
        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.body()).contains("<Code>BadDigest</Code>");
        assertThat(blobStore.blobExists(containerName, "foo.txt")).isFalse();
    }

    /** The pinned payload itself is still admitted. */
    @Test
    public void testChecksumPinnedByPolicy() throws Exception {
        String pinned = sha256("bar");
        String policy = checksumPolicy(pinned);
        HttpResponse<String> response = post(
                "key", "foo.txt",
                "AWSAccessKeyId", IDENTITY,
                "policy", policy,
                "signature", sign(policy),
                "X-Amz-Checksum-SHA256", pinned);
        assertThat(response.statusCode()).isEqualTo(204);
        assertThat(body("foo.txt")).isEqualTo("bar");
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

    /**
     * A part's headers are bounded apart from the body they arrive in.  The
     * parser holds each one as objects many times its size, so a form well
     * inside the body bound could otherwise hold many times that bound.
     */
    @Test
    public void testOversizedPartHeadersAreRefused() throws Exception {
        String body = "--" + BOUNDARY + "\r\nContent-Disposition: form-data;" +
                " name=\"key\"\r\n" + "aa:bb\r\n".repeat(2000) +
                "\r\nfoo.txt\r\n--" + BOUNDARY + "--\r\n";
        // The headers are what is refused, not the form they arrive in.
        assertThat(body.length()).isLessThan(MAX_REQUEST_SIZE);

        HttpResponse<String> response = httpClient.send(
                HttpRequest.newBuilder(URI.create(bucketUri))
                        .header("Content-Type",
                                "multipart/form-data; boundary=" + BOUNDARY)
                        .POST(HttpRequest.BodyPublishers.ofString(body))
                        .build(), HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.body())
                .contains("<Code>MaxMessageLengthExceeded</Code>");
    }

    /**
     * ... and so is the number of parts, since a bound on the headers of each
     * bounds the form only as tightly as the number of them.
     */
    @Test
    public void testTooManyPartsAreRefused() throws Exception {
        var fields = new ArrayList<String>(List.of("key", "foo.txt"));
        for (int i = 0; i < 98; i++) {
            fields.add("x-amz-meta-" + i);
            fields.add("");
        }
        // With the file part this is as many as a form may have, and it gets
        // as far as being refused for carrying no credential.
        HttpResponse<String> response = postUnsigned(
                fields.toArray(new String[0]));
        assertThat(response.statusCode()).isEqualTo(403);

        fields.add("x-amz-meta-98");
        fields.add("");
        response = postUnsigned(fields.toArray(new String[0]));
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
        assertThat(response.body())
                .contains("<Code>MalformedPOSTRequest</Code>");
    }

    /**
     * The refusals of a form built wrong say what is wrong with it, as S3's
     * do.  Each was a 400 with no body, which a client reports as an
     * unknown error.
     */
    @Test
    public void testWrongEnclosureIsPreconditionFailed() throws Exception {
        for (String contentType : List.of("text/plain",
                "application/octet-stream; boundary=" + BOUNDARY)) {
            HttpResponse<String> response = httpClient.send(
                    HttpRequest.newBuilder(URI.create(bucketUri))
                            .header("Content-Type", contentType)
                            .POST(HttpRequest.BodyPublishers.ofString("x"))
                            .build(), HttpResponse.BodyHandlers.ofString());
            assertThat(response.statusCode()).as(contentType).isEqualTo(412);
            assertThat(response.body()).as(contentType)
                    .contains("<Code>PreconditionFailed</Code>")
                    .contains("<Condition>Bucket POST must be of the" +
                            " enclosure-type multipart/form-data</Condition>");
        }
    }

    @Test
    public void testMissingBoundaryIsMalformed() throws Exception {
        HttpResponse<String> response = httpClient.send(
                HttpRequest.newBuilder(URI.create(bucketUri))
                        .header("Content-Type", "multipart/form-data")
                        .POST(HttpRequest.BodyPublishers.ofString("x"))
                        .build(), HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.body())
                .contains("<Code>MalformedPOSTRequest</Code>");
    }

    @Test
    public void testMissingKeyFieldIsNamed() throws Exception {
        HttpResponse<String> response = postUnsigned(
                "Content-Type", "text/plain");
        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.body())
                .contains("<Code>InvalidArgument</Code>")
                .contains("<ArgumentName>key</ArgumentName>");
    }

    @Test
    public void testMissingFileIsNamed() throws Exception {
        String form = "--" + BOUNDARY + "\r\nContent-Disposition: form-data;" +
                " name=\"key\"\r\n\r\nfoo.txt\r\n" +
                "--" + BOUNDARY + "--\r\n";
        HttpResponse<String> response = httpClient.send(
                HttpRequest.newBuilder(URI.create(bucketUri))
                        .header("Content-Type",
                                "multipart/form-data; boundary=" + BOUNDARY)
                        .POST(HttpRequest.BodyPublishers.ofString(form))
                        .build(), HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.body())
                .contains("<Code>InvalidArgument</Code>")
                .contains("<ArgumentName>file</ArgumentName>");
        assertThat(blobStore.blobExists(containerName, "foo.txt")).isFalse();
    }

    @Test
    public void testUnknownAlgorithmIsNamed() throws Exception {
        String policy = policy("{\"bucket\": \"" + containerName + "\"}");
        HttpResponse<String> response = postUnsigned(
                "key", "foo.txt",
                "x-amz-algorithm", "AWS4-HMAC-SHA512",
                "x-amz-credential", IDENTITY,
                "policy", policy,
                "x-amz-signature", sign(policy));
        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.body())
                .contains("<Code>InvalidArgument</Code>")
                .contains("<ArgumentName>X-Amz-Algorithm</ArgumentName>")
                .contains("<ArgumentValue>AWS4-HMAC-SHA512</ArgumentValue>");
        assertThat(blobStore.blobExists(containerName, "foo.txt")).isFalse();
    }

    /**
     * RFC 2046 allows a boundary 70 characters, quotes aside.  Jetty searches
     * the body for whatever boundary the header names, at a cost that grows
     * with its length, and does so before the form has been authorized -- so
     * a longer one is refused before the body is read.
     */
    @Test
    public void testOverlongBoundaryIsRefused() throws Exception {
        blobStore.setContainerAccess(containerName,
                BucketCannedACL.PUBLIC_READ_WRITE);
        assertThat(postWithBoundary("a".repeat(70)).statusCode())
                .isEqualTo(204);
        assertThat(postWithBoundary("\"" + "a".repeat(70) + "\"")
                .statusCode()).isEqualTo(204);
        assertThat(blobStore.blobExists(containerName, "foo.txt")).isTrue();
        blobStore.removeBlob(containerName, "foo.txt");

        HttpResponse<String> overlong = postWithBoundary("a".repeat(71));
        assertThat(overlong.statusCode()).isEqualTo(400);
        assertThat(overlong.body())
                .contains("<Code>MalformedPOSTRequest</Code>");
        assertThat(postWithBoundary("\"" + "a".repeat(71) + "\"")
                .statusCode()).isEqualTo(400);
        assertThat(blobStore.blobExists(containerName, "foo.txt")).isFalse();
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

    /** A policy admitting one key and one payload, named by its SHA-256. */
    private String checksumPolicy(String checksum) {
        return policy(
                "{\"bucket\": \"" + containerName + "\"}," +
                "{\"key\": \"foo.txt\"}," +
                "{\"x-amz-checksum-sha256\": \"" + checksum + "\"}");
    }

    private static String sha256(String payload) throws Exception {
        return Base64.getEncoder().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(
                        payload.getBytes(StandardCharsets.UTF_8)));
    }

    private static String sign(String policy) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(new SecretKeySpec(
                CREDENTIAL.getBytes(StandardCharsets.UTF_8), "HmacSHA1"));
        return Base64.getEncoder().encodeToString(
                mac.doFinal(policy.getBytes(StandardCharsets.UTF_8)));
    }

    private static String md5(String payload) throws Exception {
        return Base64.getEncoder().encodeToString(
                MessageDigest.getInstance("MD5").digest(
                        payload.getBytes(StandardCharsets.UTF_8)));
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
        return postFile("payload.txt", fields);
    }

    /** ... with the file part carrying the given name. */
    private HttpResponse<String> postFile(String fileName, String... fields)
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
                " name=\"file\"; filename=\"" + fileName +
                "\"\r\n\r\nbar\r\n")
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

    /** A form of a key and a file part of the given name, and no more. */
    private HttpResponse<String> postFileNamed(String fileName, String key)
            throws Exception {
        String form = "--" + BOUNDARY + "\r\nContent-Disposition: form-data;" +
                " name=\"key\"\r\n\r\n" + key + "\r\n" +
                "--" + BOUNDARY + "\r\nContent-Disposition: form-data;" +
                " name=\"file\"; filename=\"" + fileName + "\"\r\n\r\nbar\r\n" +
                "--" + BOUNDARY + "--\r\n";
        return httpClient.send(HttpRequest.newBuilder(URI.create(bucketUri))
                .header("Content-Type",
                        "multipart/form-data; boundary=" + BOUNDARY)
                .POST(HttpRequest.BodyPublishers.ofString(form))
                .build(), HttpResponse.BodyHandlers.ofString());
    }

    /**
     * An unsigned form whose Content-Type names the boundary exactly as
     * given, quotes and all, and whose body is delimited by it unquoted.
     */
    private HttpResponse<String> postWithBoundary(String boundary)
            throws Exception {
        String delimiter = boundary.replace("\"", "");
        return httpClient.send(HttpRequest.newBuilder(URI.create(bucketUri))
                .header("Content-Type",
                        "multipart/form-data; boundary=" + boundary)
                .POST(HttpRequest.BodyPublishers.ofString(
                        "--" + delimiter + "\r\nContent-Disposition:" +
                        " form-data; name=\"key\"\r\n\r\nfoo.txt\r\n" +
                        "--" + delimiter + "\r\nContent-Disposition:" +
                        " form-data; name=\"file\"; filename=\"x\"" +
                        "\r\n\r\nbar\r\n--" + delimiter + "--\r\n"))
                .build(), HttpResponse.BodyHandlers.ofString());
    }
}
