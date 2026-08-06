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
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * A v4 signature covers a digest of the body, so the body is read before the
 * signature over it can be checked: what it costs to read is spent on behalf
 * of a caller who has offered only an access key id, which is not a secret.
 * A request that announces more than the proxy will hold is refused on that
 * announcement, before any of it arrives.
 */
public final class SignedPayloadLimitTest {
    private static final String IDENTITY = "identity";
    private static final long MAX_REQUEST_SIZE = 1024;
    /**
     * The digest of the empty body both requests send.  It has to be the
     * right one for the small request: a body that does not match what
     * x-amz-content-sha256 claims is refused before the signature is, and
     * this is about which check the length reaches.
     */
    private static final String EMPTY_SHA256 =
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    private static final DateTimeFormatter TIMESTAMP =
            DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'")
                    .withZone(ZoneOffset.UTC);

    private S3Proxy s3Proxy;
    private BlobStore blobStore;
    private String containerName;

    @BeforeEach
    public void setUp() throws Exception {
        blobStore = TestUtils.createTransientBlobStore();
        containerName = TestUtils.createRandomContainerName();
        blobStore.createContainer(containerName);

        s3Proxy = S3Proxy.builder()
                .stopTimeout(0)
                .blobStore(blobStore)
                .awsAuthentication(AuthenticationType.AWS_V2_OR_V4, IDENTITY,
                        "credential")
                .v4MaxNonChunkedRequestSize(MAX_REQUEST_SIZE)
                .endpoint(URI.create("http://127.0.0.1:0"))
                .build();
        s3Proxy.start();
        while (!s3Proxy.getState().equals("STARTED")) {
            Thread.sleep(10);
        }
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

    /**
     * The declared length alone refuses the request: the body is never sent,
     * so a proxy that waited for it before checking would answer nothing.
     */
    @Test
    public void testOversizedPayloadRefusedBeforeItArrives() throws Exception {
        String response = sendHeaders(Long.MAX_VALUE / 2);
        assertThat(response).startsWith("HTTP/1.1 400 ");
        assertThat(response).contains("<Code>MaxMessageLengthExceeded</Code>");
    }

    /**
     * Refusing on the length must not shadow the signature check for a body
     * the proxy would hold: this one is small, so the bad signature is what
     * the caller hears about.
     */
    @Test
    public void testPayloadWithinTheLimitStillChecksTheSignature()
            throws Exception {
        String response = sendHeaders(/*contentLength=*/ 0);
        assertThat(response).startsWith("HTTP/1.1 403 ");
        assertThat(response).contains("<Code>SignatureDoesNotMatch</Code>");
    }

    /**
     * Send a PUT naming a length and stopping there, with a signature that
     * cannot verify: an access key id is all the caller offers, which is all
     * it takes to reach the read this bounds.
     */
    private String sendHeaders(long contentLength) throws Exception {
        // Now, since a stale date is refused before the length is looked at.
        Instant now = Instant.now();
        String timestamp = TIMESTAMP.format(now);
        return send("PUT /" + containerName + "/blob HTTP/1.1\r\n" +
                "Host: 127.0.0.1\r\n" +
                "Authorization: AWS4-HMAC-SHA256 Credential=" + IDENTITY +
                "/" + timestamp.substring(0, 8) +
                "/us-east-1/s3/aws4_request," +
                " SignedHeaders=host;x-amz-content-sha256;x-amz-date," +
                " Signature=" + "0".repeat(64) + "\r\n" +
                "x-amz-content-sha256: " + EMPTY_SHA256 + "\r\n" +
                "x-amz-date: " + timestamp + "\r\n" +
                "Content-Length: " + contentLength + "\r\n" +
                "Connection: close\r\n\r\n");
    }

    private String send(String request) throws Exception {
        try (var socket = new Socket()) {
            socket.connect(new InetSocketAddress(
                    InetAddress.getLoopbackAddress(), s3Proxy.getPort()));
            socket.setSoTimeout(10_000);
            socket.getOutputStream().write(
                    request.getBytes(StandardCharsets.UTF_8));
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
}
