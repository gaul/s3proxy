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
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Requests Jetty rejects before S3ProxyHandler sees them still answer the XML
 * an S3 client parses.  These send raw bytes because a client library refuses
 * to put them on the wire.
 */
public final class S3ErrorHandlerTest {
    /** A character RFC 9110 forbids in a header value. */
    private static final char CONTROL_CHARACTER = 0x04;

    private S3Proxy s3Proxy;
    private int port;

    @BeforeEach
    public void setUp() throws Exception {
        s3Proxy = S3Proxy.builder()
                .blobStore(TestUtils.createTransientBlobStore())
                .awsAuthentication(AuthenticationType.AWS_V2_OR_V4, "identity",
                        "credential")
                .endpoint(URI.create("http://127.0.0.1:0"))
                .build();
        s3Proxy.start();
        while (!s3Proxy.getState().equals("STARTED")) {
            Thread.sleep(10);
        }
        port = s3Proxy.getPort();
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
    }

    /** A percent-encoding which does not decode to UTF-8. */
    @Test
    public void testUnparseableUri() throws Exception {
        String response = send("GET /container/%AE%8A- HTTP/1.1\r\n" +
                "Host: 127.0.0.1\r\n\r\n");
        assertThat(response).startsWith("HTTP/1.1 400 ");
        assertThat(response).contains("<Code>InvalidURI</Code>");
        assertThat(response).contains(
                "<Message>Couldn't parse the specified URI.</Message>");
    }

    /**
     * A header value the parser rejects.  The method matters: Jetty writes an
     * error page only for the methods a browser follows one with, so a PUT
     * once answered a status and nothing else.
     */
    @Test
    public void testIllegalHeaderCharacter() throws Exception {
        String response = send("PUT /container/blob HTTP/1.1\r\n" +
                "Host: 127.0.0.1\r\n" +
                "x-amz-meta-key: bad" + CONTROL_CHARACTER + "value\r\n" +
                "Content-Length: 3\r\n" +
                "\r\n" +
                "foo");
        assertThat(response).startsWith("HTTP/1.1 400 ");
        assertThat(response).contains("<Code>InvalidRequest</Code>");
        assertThat(response).contains("application/xml");
    }

    /** The error names the request, as every S3 error does. */
    @Test
    public void testRequestId() throws Exception {
        String response = send("GET /container/%AE%8A- HTTP/1.1\r\n" +
                "Host: 127.0.0.1\r\n\r\n");
        assertThat(response).contains("x-amz-request-id");
        assertThat(response).containsPattern(
                "<RequestId>[0-9A-F]{16}</RequestId>");
    }

    private String send(String request) throws Exception {
        try (var socket = new Socket()) {
            socket.connect(new InetSocketAddress("127.0.0.1", port));
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
                }
            } catch (SocketTimeoutException ste) {
                // Jetty closes the connection after rejecting a request, but
                // do not hang the suite on one it keeps open.
            }
            return response.toString(StandardCharsets.UTF_8);
        }
    }
}
