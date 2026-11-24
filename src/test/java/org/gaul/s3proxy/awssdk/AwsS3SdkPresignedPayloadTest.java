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

package org.gaul.s3proxy.awssdk;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.HexFormat;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.google.common.hash.Hashing;

import org.gaul.s3proxy.S3Proxy;
import org.gaul.s3proxy.TestUtils;
import org.gaul.s3proxy.auth.AuthenticationType;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.Credentials;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * A presigned URL that signs x-amz-content-sha256 is good for one payload.
 * The hash is compared where the body ends, and this store is handed the
 * body with the length x-amz-decoded-content-length declares: the SDK reads
 * that many bytes and never asks for the end of stream, so a body that ends
 * anywhere else must be judged before the last declared byte is handed
 * over.  The backend here is another S3Proxy, as in
 * {@link AwsS3SdkEmulatedConditionalWritesTest}.
 */
public final class AwsS3SdkPresignedPayloadTest {
    private static final String CONTAINER = "container";
    private static final String KEY = "key";
    private static final String IDENTITY = "identity";
    private static final String CREDENTIAL = "credential";
    private static final byte[] APPROVED =
            "approved payload".getBytes(StandardCharsets.UTF_8);
    private static final byte[] FORGED =
            "EVIL EVIL EVIL!!".getBytes(StandardCharsets.UTF_8);
    private static final byte[] FORGED_AND_A_BYTE =
            "EVIL EVIL EVIL!!x".getBytes(StandardCharsets.UTF_8);
    private static final DateTimeFormatter ISO8601 =
            DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'")
                    .withZone(ZoneOffset.UTC);

    private S3Proxy backend;
    private S3Proxy s3Proxy;
    private BlobStore transientStore;
    private String host;
    private final HttpClient httpClient = HttpClient.newHttpClient();

    @BeforeEach
    public void setUp() throws Exception {
        transientStore = TestUtils.createTransientBlobStore();
        transientStore.createContainer(CONTAINER);
        backend = start(transientStore);
        s3Proxy = start(new AwsS3SdkBlobStore(
                () -> new Credentials(IDENTITY, CREDENTIAL),
                "http://127.0.0.1:" + backend.getPort(), "us-east-1",
                /*conditionalWrites=*/ "native",
                /*chunkedEncodingEnabled=*/ "true",
                /*stripETagQuotes=*/ "false"));
        host = "127.0.0.1:" + s3Proxy.getPort();
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
        if (backend != null) {
            backend.stop();
        }
    }

    /** The upload the URL is for. */
    @Test
    public void testPinnedBodyIsStored() throws Exception {
        var response = put(HttpRequest.BodyPublishers.ofByteArray(APPROVED));
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(stored()).isEqualTo(APPROVED);
    }

    @Test
    public void testOtherBodyOfTheDeclaredLengthRejected() throws Exception {
        var response = put(HttpRequest.BodyPublishers.ofByteArray(FORGED));
        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.body()).contains("XAmzContentSHA256Mismatch");
        assertThat(transientStore.blobExists(CONTAINER, KEY)).isFalse();
    }

    /**
     * Content-Length is not signed, so the bearer may send a byte more than
     * was declared.  The hash is then due one byte past the last the store
     * reads, and the store had every byte it wanted before anything looked.
     */
    @Test
    public void testOtherBodyLongerThanDeclaredRejected() throws Exception {
        var response = put(HttpRequest.BodyPublishers.ofByteArray(
                FORGED_AND_A_BYTE));
        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(transientStore.blobExists(CONTAINER, KEY)).isFalse();
    }

    /** Nor does a chunked transfer say where the body ends. */
    @Test
    public void testOtherBodyWithoutContentLengthRejected() throws Exception {
        var response = put(HttpRequest.BodyPublishers.ofInputStream(
                () -> new ByteArrayInputStream(FORGED)));
        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.body()).contains("XAmzContentSHA256Mismatch");
        assertThat(transientStore.blobExists(CONTAINER, KEY)).isFalse();
    }

    /** An object the URL's owner put there is not replaced either. */
    @Test
    public void testStoredObjectIsNotReplaced() throws Exception {
        assertThat(put(HttpRequest.BodyPublishers.ofByteArray(APPROVED))
                .statusCode()).isEqualTo(200);
        assertThat(put(HttpRequest.BodyPublishers.ofByteArray(
                FORGED_AND_A_BYTE)).statusCode()).isEqualTo(400);
        assertThat(stored()).isEqualTo(APPROVED);
    }

    private static S3Proxy start(BlobStore blobStore) throws Exception {
        S3Proxy proxy = S3Proxy.builder()
                .stopTimeout(0)
                .blobStore(blobStore)
                .awsAuthentication(AuthenticationType.AWS_V2_OR_V4,
                        IDENTITY, CREDENTIAL)
                .endpoint(URI.create("http://127.0.0.1:0"))
                .build();
        proxy.start();
        while (!proxy.getState().equals("STARTED")) {
            Thread.sleep(10);
        }
        return proxy;
    }

    private byte[] stored() throws Exception {
        try (var stream = transientStore.getBlob(CONTAINER, KEY)) {
            return stream.readAllBytes();
        }
    }

    /**
     * Send a body to a URL presigned for APPROVED alone: it signs the hash
     * and the decoded length of that payload, and leaves Content-Length to
     * whoever holds it.
     */
    private HttpResponse<String> put(HttpRequest.BodyPublisher body)
            throws Exception {
        String hash = Hashing.sha256().hashBytes(APPROVED).toString();
        String length = String.valueOf(APPROVED.length);
        String timestamp = ISO8601.format(Instant.now());
        String date = timestamp.substring(0, 8);
        String scope = date + "/us-east-1/s3/aws4_request";
        String signedHeaders =
                "host;x-amz-content-sha256;x-amz-decoded-content-length";
        String query = "X-Amz-Algorithm=AWS4-HMAC-SHA256" +
                "&X-Amz-Credential=" + URLEncoder.encode(
                        IDENTITY + "/" + scope, StandardCharsets.UTF_8) +
                "&X-Amz-Date=" + timestamp +
                "&X-Amz-Expires=3600" +
                "&X-Amz-SignedHeaders=" + URLEncoder.encode(
                        signedHeaders, StandardCharsets.UTF_8);
        String path = "/" + CONTAINER + "/" + KEY;
        String canonicalRequest = String.join("\n",
                "PUT", path, query,
                "host:" + host,
                "x-amz-content-sha256:" + hash,
                "x-amz-decoded-content-length:" + length,
                "", signedHeaders, hash);
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
        return httpClient.send(HttpRequest.newBuilder(URI.create(
                "http://" + host + path + "?" + query +
                "&X-Amz-Signature=" + signature))
                .header("x-amz-content-sha256", hash)
                .header("x-amz-decoded-content-length", length)
                .PUT(body)
                .build(), HttpResponse.BodyHandlers.ofString());
    }

    private static byte[] hmac(byte[] key, String data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }
}
