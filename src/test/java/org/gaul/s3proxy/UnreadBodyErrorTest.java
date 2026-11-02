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

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Random;

import org.gaul.s3proxy.auth.AuthenticationType;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * An error sent before the request body was read says Connection: close.
 * Jetty closes such a connection anyway once the body has not all arrived,
 * but only after the response committed, so a client that pooled it sent its
 * next request into a closing socket.  These send raw bytes to hold the body
 * back, which a client library will not do on request.
 */
public final class UnreadBodyErrorTest {
    private S3Proxy s3Proxy;
    private String containerName;
    private int port;

    @BeforeEach
    public void setUp() throws Exception {
        BlobStore blobStore = TestUtils.createTransientBlobStore();
        containerName =
                "container-" + new Random().nextInt(Integer.MAX_VALUE);
        blobStore.createContainer(containerName);

        s3Proxy = S3Proxy.builder()
                .stopTimeout(0)
                .blobStore(blobStore)
                .awsAuthentication(AuthenticationType.AWS_V2_OR_V4,
                        "identity", "credential")
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

    /** An anonymous PUT to a private bucket, refused before its body. */
    @Test
    public void testRefusedBeforeBodyClosesConnection() throws Exception {
        try (var socket = connect()) {
            OutputStream out = socket.getOutputStream();
            // The headers promise a body that is never sent.
            out.write(("PUT /" + containerName + "/key HTTP/1.1\r\n" +
                    "Host: 127.0.0.1\r\n" +
                    "Content-Length: 16\r\n" +
                    "\r\n").getBytes(StandardCharsets.ISO_8859_1));
            out.flush();

            String head = readHead(
                    new BufferedInputStream(socket.getInputStream()));
            assertThat(head).startsWith("HTTP/1.1 403 ");
            assertThat(head).containsIgnoringCase("Connection: close");
        }
    }

    /** An error with no request body left unread keeps the connection. */
    @Test
    public void testRefusedWithoutBodyKeepsConnection() throws Exception {
        try (var socket = connect()) {
            OutputStream out = socket.getOutputStream();
            InputStream in = new BufferedInputStream(socket.getInputStream());
            // HEAD so that the response has no body to skip before the next.
            byte[] request = ("HEAD /" + containerName + "/key HTTP/1.1\r\n" +
                    "Host: 127.0.0.1\r\n" +
                    "\r\n").getBytes(StandardCharsets.ISO_8859_1);
            for (int i = 0; i < 2; i++) {
                out.write(request);
                out.flush();
                String head = readHead(in);
                assertThat(head).startsWith("HTTP/1.1 4");
                assertThat(head).doesNotContainIgnoringCase(
                        "Connection: close");
            }
        }
    }

    private Socket connect() throws Exception {
        var socket = new Socket();
        socket.connect(new InetSocketAddress(
                InetAddress.getLoopbackAddress(), port));
        socket.setSoTimeout(10_000);
        return socket;
    }

    /** Reads a response's status line and headers, through the blank line. */
    private static String readHead(InputStream in) throws Exception {
        var head = new ByteArrayOutputStream();
        int matched = 0;
        byte[] terminator = "\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1);
        while (matched < terminator.length) {
            int b = in.read();
            if (b == -1) {
                throw new EOFException("EOF in response head: " +
                        head.toString(StandardCharsets.ISO_8859_1));
            }
            head.write(b);
            matched = b == terminator[matched] ? matched + 1 :
                    b == terminator[0] ? 1 : 0;
        }
        return head.toString(StandardCharsets.ISO_8859_1);
    }
}
