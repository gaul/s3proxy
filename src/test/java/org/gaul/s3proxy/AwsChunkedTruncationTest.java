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

import org.gaul.s3proxy.blobstore.BlobStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * An aws-chunked body says it is over with a zero-length chunk, and nothing
 * else does: the HTTP framing around it is satisfied by whatever
 * Content-Length announced, so a body cut short arrives as a well-formed
 * request carrying an unfinished object.  Storing what turned up would tell
 * the caller its whole object is safe when part of it never arrived.  These
 * speak HTTP directly because an SDK always finishes the framing.
 */
public final class AwsChunkedTruncationTest {
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

    /** The whole framing, which stores the whole object. */
    @Test
    public void testCompleteBodyIsStored() throws Exception {
        String response = putChunked(
                "5;chunk-signature=" + "0".repeat(64) + "\r\nhello\r\n" +
                "0;chunk-signature=" + "0".repeat(64) + "\r\n\r\n",
                /*decodedContentLength=*/ 5);

        assertThat(response).startsWith("HTTP/1.1 200 ");
        assertThat(blobStore.blobExists(containerName, "blob")).isTrue();
    }

    /** The chunks stop before the one that says the body is over. */
    @Test
    public void testBodyWithoutItsFinalChunkIsRefused() throws Exception {
        String response = putChunked(
                "5;chunk-signature=" + "0".repeat(64) + "\r\nhello\r\n",
                /*decodedContentLength=*/ 20);

        assertThat(response).startsWith("HTTP/1.1 400 ");
        assertThat(response).contains("<Code>IncompleteBody</Code>");
        assertThat(blobStore.blobExists(containerName, "blob")).isFalse();
    }

    /** A chunk header promising bytes the body does not carry. */
    @Test
    public void testChunkShorterThanItsHeaderIsRefused() throws Exception {
        String response = putChunked(
                "14;chunk-signature=" + "0".repeat(64) + "\r\nhello",
                /*decodedContentLength=*/ 20);

        assertThat(response).startsWith("HTTP/1.1 400 ");
        assertThat(response).contains("<Code>IncompleteBody</Code>");
        assertThat(blobStore.blobExists(containerName, "blob")).isFalse();
    }

    /**
     * Send a PUT whose Content-Length covers exactly the aws-chunked bytes
     * given, so that the HTTP message is complete however unfinished the
     * framing inside it is.
     */
    private String putChunked(String chunkedBody, long decodedContentLength)
            throws Exception {
        return send("PUT /" + containerName + "/blob HTTP/1.1\r\n" +
                "Host: 127.0.0.1\r\n" +
                "x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD\r\n" +
                "x-amz-decoded-content-length: " + decodedContentLength +
                "\r\n" +
                "Content-Length: " + chunkedBody.length() + "\r\n" +
                "Connection: close\r\n\r\n" +
                chunkedBody);
    }

    private String send(String request) throws Exception {
        try (var socket = new Socket()) {
            socket.connect(new InetSocketAddress(
                    InetAddress.getLoopbackAddress(), s3Proxy.getPort()));
            socket.setSoTimeout(10_000);
            socket.getOutputStream().write(
                    request.getBytes(StandardCharsets.ISO_8859_1));
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
