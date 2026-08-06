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
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * An upload framed with Transfer-Encoding: chunked, which S3 accepts and
 * which declares no length.  S3Proxy reads such a body to learn its length
 * before storing it, bounded by the same limit a SigV4 payload it must digest
 * carries.  These speak HTTP directly because an SDK frames the body itself.
 */
public final class TransferEncodingChunkedTest {
    private S3Proxy s3Proxy;
    private int port;

    private void startProxy(long maxRequestSize) throws Exception {
        s3Proxy = S3Proxy.builder()
                .stopTimeout(0)
                .blobStore(TestUtils.createTransientBlobStore())
                .v4MaxNonChunkedRequestSize(maxRequestSize)
                .endpoint(URI.create("http://127.0.0.1:0"))
                .build();
        s3Proxy.start();
        while (!s3Proxy.getState().equals("STARTED")) {
            Thread.sleep(10);
        }
        port = s3Proxy.getPort();
        send("""
                PUT /container HTTP/1.1\r
                Host: 127.0.0.1\r
                Content-Length: 0\r
                \r
                """);
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
    }

    @Test
    public void testChunkedUpload() throws Exception {
        startProxy(128 * 1024);
        assertThat(putChunked("/container/blob", "3\r\nbar\r\n0\r\n\r\n"))
                .startsWith("HTTP/1.1 200 ");
        assertThat(get("/container/blob")).endsWith("bar");
    }

    /** The chunks are a framing, not a boundary the object keeps. */
    @Test
    public void testChunkedUploadOfSeveralChunks() throws Exception {
        startProxy(128 * 1024);
        assertThat(putChunked("/container/blob",
                "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"))
                .startsWith("HTTP/1.1 200 ");
        assertThat(get("/container/blob")).endsWith("hello world");
    }

    /** A part of a multipart upload is framed the same way. */
    @Test
    public void testChunkedUploadPart() throws Exception {
        startProxy(128 * 1024);
        String initiate = send("""
                POST /container/blob?uploads HTTP/1.1\r
                Host: 127.0.0.1\r
                Content-Length: 0\r
                \r
                """);
        assertThat(initiate).startsWith("HTTP/1.1 200 ");
        String uploadId = initiate.replaceAll(
                "(?s).*<UploadId>(.*?)</UploadId>.*", "$1");
        assertThat(putChunked("/container/blob?partNumber=1&uploadId=" +
                uploadId, "3\r\nbar\r\n0\r\n\r\n"))
                .startsWith("HTTP/1.1 200 ");
    }

    /** A body framed neither way is the one S3 answers 411 to. */
    @Test
    public void testMissingContentLength() throws Exception {
        startProxy(128 * 1024);
        String response = send("""
                PUT /container/blob HTTP/1.1\r
                Host: 127.0.0.1\r
                \r
                """);
        assertThat(response).startsWith("HTTP/1.1 411 ");
        assertThat(response).contains("<Code>MissingContentLength</Code>");
    }

    /** A chunked body says nothing about its size, so the read is bounded. */
    @Test
    public void testChunkedUploadAboveTheLimit() throws Exception {
        startProxy(1024);
        String chunk = "x".repeat(2048);
        String response = putChunked("/container/blob",
                Integer.toHexString(chunk.length()) + "\r\n" + chunk +
                "\r\n0\r\n\r\n");
        assertThat(response).startsWith("HTTP/1.1 400 ");
        assertThat(response).contains(
                "<Code>MaxMessageLengthExceeded</Code>");
    }

    private String putChunked(String pathAndQuery, String chunkedBody)
            throws Exception {
        return send("PUT " + pathAndQuery + " HTTP/1.1\r\n" +
                "Host: 127.0.0.1\r\n" +
                "Transfer-Encoding: chunked\r\n" +
                "\r\n" +
                chunkedBody);
    }

    private String get(String pathAndQuery) throws Exception {
        return send("GET " + pathAndQuery + " HTTP/1.1\r\n" +
                "Host: 127.0.0.1\r\n" +
                "Connection: close\r\n\r\n");
    }

    private String send(String request) throws Exception {
        try (var socket = new Socket()) {
            socket.connect(new InetSocketAddress(
                    InetAddress.getLoopbackAddress(), port));
            socket.setSoTimeout(10_000);
            OutputStream out = socket.getOutputStream();
            out.write(request.getBytes(StandardCharsets.ISO_8859_1));
            out.flush();

            InputStream in = socket.getInputStream();
            var response = new ByteArrayOutputStream();
            var buffer = new byte[8192];
            try {
                while (true) {
                    int count = in.read(buffer);
                    if (count == -1) {
                        break;
                    }
                    response.write(buffer, 0, count);
                    // Only the Connection: close requests reach EOF; the rest
                    // end at their body on a connection the server keeps.
                    if (request.indexOf("Connection: close") == -1 &&
                            response.toString(StandardCharsets.ISO_8859_1)
                                    .contains("\r\n\r\n")) {
                        break;
                    }
                }
            } catch (SocketTimeoutException ste) {
                // fall through with whatever arrived
            }
            return response.toString(StandardCharsets.UTF_8);
        }
    }
}
