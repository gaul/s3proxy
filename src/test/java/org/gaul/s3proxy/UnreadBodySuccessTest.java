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
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import com.google.common.io.ByteSource;

import org.gaul.s3proxy.auth.AuthenticationType;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * A request answered without its body being read -- a copy, which names its
 * source in a header -- keeps its connection usable.  When the body was
 * still on its way as the response completed, Jetty closed the connection
 * after a 200 that did not say so, and a client that pooled it read EOF
 * for its next request.  These send raw bytes to hold the body back.
 */
public final class UnreadBodySuccessTest {
    private static final String CONTAINER = "container";

    private S3Proxy s3Proxy;
    private int port;

    @BeforeEach
    public void setUp() throws Exception {
        BlobStore blobStore = TestUtils.createTransientBlobStore();
        blobStore.createContainer(CONTAINER);
        TestUtils.putBlob(blobStore, CONTAINER, "source",
                ByteSource.wrap("content".getBytes(StandardCharsets.UTF_8)));

        s3Proxy = S3Proxy.builder()
                .stopTimeout(0)
                .blobStore(blobStore)
                .awsAuthentication(AuthenticationType.NONE, null, null)
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

    @Test
    public void testCopyWithLateBodyKeepsConnection() throws Exception {
        try (var socket = new Socket()) {
            socket.connect(new InetSocketAddress(
                    InetAddress.getLoopbackAddress(), port));
            socket.setSoTimeout(10_000);
            OutputStream out = socket.getOutputStream();
            InputStream in = new BufferedInputStream(socket.getInputStream());

            out.write(("PUT /" + CONTAINER + "/target HTTP/1.1\r\n" +
                    "Host: 127.0.0.1\r\n" +
                    "x-amz-copy-source: /" + CONTAINER + "/source\r\n" +
                    "Content-Length: 16\r\n" +
                    "\r\n").getBytes(StandardCharsets.ISO_8859_1));
            out.flush();
            String head = readHead(in);
            assertThat(head).startsWith("HTTP/1.1 200 ");
            assertThat(head).doesNotContainIgnoringCase("Connection: close");
            skipBody(in, head);

            // the body the copy never asked for, once its answer is here
            Thread.sleep(200);
            out.write(new byte[16]);
            out.flush();

            // the connection the 200 said was open answers the next request
            out.write(("HEAD /" + CONTAINER + "/target HTTP/1.1\r\n" +
                    "Host: 127.0.0.1\r\n" +
                    "\r\n").getBytes(StandardCharsets.ISO_8859_1));
            out.flush();
            assertThat(readHead(in)).startsWith("HTTP/1.1 200 ");
        }
    }

    /**
     * A body sent whole with a request whose answer has none of its own.
     * The answer is not held back while the body is thrown away, and the
     * connection takes its next request at once.  The answer waited out the
     * drain's idle second, since it was unsent until the handler returned;
     * and the drain itself waited that second out on a body it had already
     * read, refused requests' included, since Jetty calls a body finished
     * only once a read has met its end.
     */
    @Test
    public void testWholeBodyAnsweredPromptly() throws Exception {
        // the last is refused: its body is no CreateBucketConfiguration
        for (String request : List.of(
                "HEAD /" + CONTAINER,
                "HEAD /" + CONTAINER + "/source",
                "DELETE /" + CONTAINER + "/absent",
                "PUT /other")) {
            try (var socket = new Socket()) {
                socket.connect(new InetSocketAddress(
                        InetAddress.getLoopbackAddress(), port));
                socket.setSoTimeout(10_000);
                OutputStream out = socket.getOutputStream();
                InputStream in = new BufferedInputStream(
                        socket.getInputStream());

                long start = System.nanoTime();
                out.write((request + " HTTP/1.1\r\n" +
                        "Host: 127.0.0.1\r\n" +
                        "Content-Length: 2\r\n" +
                        "\r\n" +
                        "ab").getBytes(StandardCharsets.ISO_8859_1));
                out.flush();
                String head = readHead(in);
                assertThat(millisSince(start)).as(request).isLessThan(500);
                // a HEAD's answer and a 204 have no body to skip
                if (!request.startsWith("HEAD ") &&
                        !head.startsWith("HTTP/1.1 204 ")) {
                    skipBody(in, head);
                }

                start = System.nanoTime();
                out.write(("HEAD /" + CONTAINER + " HTTP/1.1\r\n" +
                        "Host: 127.0.0.1\r\n" +
                        "\r\n").getBytes(StandardCharsets.ISO_8859_1));
                out.flush();
                assertThat(readHead(in)).as(request)
                        .startsWith("HTTP/1.1 200 ");
                assertThat(millisSince(start)).as(request).isLessThan(500);
            }
        }
    }

    /**
     * An aws-chunked body, stored and refused, does not hold up its
     * connection.  The decoder stops after the last chunk, short of the
     * CRLF that ends the body, and the drain counted only what it read
     * itself against the whole length: it waited a second for the rest of a
     * body that had all arrived, holding up the next request on the
     * connection, and the answer itself when the request was refused before
     * its response completed.
     */
    @Test
    public void testAwsChunkedBodyAnsweredPromptly() throws Exception {
        String stored = "7\r\ncontent\r\n0\r\n\r\n";
        String empty = "0\r\n\r\n";
        // the second is refused for its canned ACL, before its body is read
        for (var request : List.of(
                List.of("PUT /" + CONTAINER + "/chunked", "7", stored, ""),
                List.of("PUT /" + CONTAINER + "/refused", "0", empty,
                        "x-amz-acl: bogus\r\n"))) {
            try (var socket = new Socket()) {
                socket.connect(new InetSocketAddress(
                        InetAddress.getLoopbackAddress(), port));
                socket.setSoTimeout(10_000);
                OutputStream out = socket.getOutputStream();
                InputStream in = new BufferedInputStream(
                        socket.getInputStream());

                long start = System.nanoTime();
                out.write((request.get(0) + " HTTP/1.1\r\n" +
                        "Host: 127.0.0.1\r\n" +
                        "Content-Encoding: aws-chunked\r\n" +
                        "x-amz-content-sha256: " +
                        "STREAMING-UNSIGNED-PAYLOAD-TRAILER\r\n" +
                        "x-amz-decoded-content-length: " + request.get(1) +
                        "\r\n" +
                        request.get(3) +
                        "Content-Length: " + request.get(2).length() +
                        "\r\n" +
                        "\r\n" +
                        request.get(2)).getBytes(StandardCharsets.ISO_8859_1));
                out.flush();
                String head = readHead(in);
                assertThat(millisSince(start)).as(request.get(0))
                        .isLessThan(500);
                assertThat(head).as(request.get(0)).startsWith(
                        request.get(3).isEmpty() ? "HTTP/1.1 200 " :
                        "HTTP/1.1 400 ");
                skipBody(in, head);
                if (head.contains("Connection: close")) {
                    continue;
                }

                start = System.nanoTime();
                out.write(("HEAD /" + CONTAINER + " HTTP/1.1\r\n" +
                        "Host: 127.0.0.1\r\n" +
                        "\r\n").getBytes(StandardCharsets.ISO_8859_1));
                out.flush();
                assertThat(readHead(in)).as(request.get(0))
                        .startsWith("HTTP/1.1 200 ");
                assertThat(millisSince(start)).as(request.get(0))
                        .isLessThan(500);
            }
        }
    }

    private static long millisSince(long start) {
        return TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
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

    /** Skips a response body framed by Content-Length or by chunks. */
    private static void skipBody(InputStream in, String head)
            throws Exception {
        var length = Pattern.compile("(?im)^Content-Length: (\\d+)$")
                .matcher(head.replace("\r", ""));
        if (length.find()) {
            in.readNBytes(Integer.parseInt(length.group(1)));
            return;
        }
        while (true) {
            var size = new ByteArrayOutputStream();
            int b;
            while ((b = in.read()) != '\n') {
                if (b == -1) {
                    throw new EOFException("EOF in chunk size");
                }
                if (b != '\r') {
                    size.write(b);
                }
            }
            int chunk = Integer.parseInt(
                    size.toString(StandardCharsets.ISO_8859_1).trim(), 16);
            in.readNBytes(chunk + 2);
            if (chunk == 0) {
                return;
            }
        }
    }
}
