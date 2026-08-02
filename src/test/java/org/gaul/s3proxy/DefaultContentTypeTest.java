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
 * An object uploaded without a Content-Type reads back as S3 answers for one,
 * binary/octet-stream.  These speak HTTP directly because an SDK sets a
 * Content-Type of its own, which is the whole condition under test.
 */
public final class DefaultContentTypeTest {
    private S3Proxy s3Proxy;
    private int port;

    @BeforeEach
    public void setUp() throws Exception {
        s3Proxy = S3Proxy.builder()
                .blobStore(TestUtils.createTransientBlobStore())
                .ignoreUnknownHeaders(true)
                .endpoint(URI.create("http://127.0.0.1:0"))
                .build();
        s3Proxy.start();
        while (!s3Proxy.getState().equals("STARTED")) {
            Thread.sleep(10);
        }
        port = s3Proxy.getPort();
        send("PUT /container HTTP/1.1\r\n" +
                "Host: 127.0.0.1\r\n" +
                "Content-Length: 0\r\n\r\n");
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
    }

    @Test
    public void testPutWithoutContentType() throws Exception {
        put("blob", /*contentType=*/ null);
        assertThat(contentTypeOf(head("blob"))).isEqualTo(
                "binary/octet-stream");
        assertThat(contentTypeOf(get("blob"))).isEqualTo(
                "binary/octet-stream");
    }

    @Test
    public void testPutWithContentType() throws Exception {
        put("blob", "text/plain");
        assertThat(contentTypeOf(head("blob"))).isEqualTo("text/plain");
    }

    /** The override wins over the default, as it does over a stored type. */
    @Test
    public void testResponseContentTypeOverride() throws Exception {
        put("blob", /*contentType=*/ null);
        String response = send("GET /container/blob" +
                "?response-content-type=text/html HTTP/1.1\r\n" +
                "Host: 127.0.0.1\r\n" +
                "Connection: close\r\n\r\n");
        assertThat(contentTypeOf(response)).isEqualTo("text/html");
    }

    private void put(String key, String contentType) throws Exception {
        String response = send("PUT /container/" + key + " HTTP/1.1\r\n" +
                "Host: 127.0.0.1\r\n" +
                (contentType == null ? "" :
                        "Content-Type: " + contentType + "\r\n") +
                "Content-Length: 3\r\n" +
                "\r\n" +
                "foo");
        assertThat(response).startsWith("HTTP/1.1 200 ");
    }

    private String head(String key) throws Exception {
        return send("HEAD /container/" + key + " HTTP/1.1\r\n" +
                "Host: 127.0.0.1\r\n" +
                "Connection: close\r\n\r\n");
    }

    private String get(String key) throws Exception {
        return send("GET /container/" + key + " HTTP/1.1\r\n" +
                "Host: 127.0.0.1\r\n" +
                "Connection: close\r\n\r\n");
    }

    private static String contentTypeOf(String response) {
        for (String line : response.split("\r\n")) {
            if (line.toLowerCase().startsWith("content-type:")) {
                return line.substring(line.indexOf(':') + 1).trim();
            }
        }
        return "";
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
                    // A keep-alive response ends at its body; only the
                    // Connection: close requests above reach EOF.
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
