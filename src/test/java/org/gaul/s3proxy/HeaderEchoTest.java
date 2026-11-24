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

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import com.google.common.base.Splitter;

import org.gaul.s3proxy.auth.AuthenticationType;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.PutObjectRequest;

/**
 * Values S3Proxy echoes into response headers go out as S3 sends them,
 * with no control character a strict client would refuse to parse: a
 * response-* override from the URL, and the system headers and user
 * metadata an object was stored with, which POST Object takes from form
 * fields that may hold anything.  Raw sockets, so the bytes are the ones
 * Jetty wrote.  HeaderValuesTest holds the values AWS answered.
 */
public final class HeaderEchoTest {
    private static final String BUCKET = "bucket";

    private S3Proxy s3Proxy;

    @BeforeEach
    public void setUp() throws Exception {
        BlobStore blobStore = TestUtils.createTransientBlobStore();
        blobStore.createContainer(BUCKET);
        blobStore.putBlob(PutObjectRequest.builder()
                .bucket(BUCKET).key("key")
                .cacheControl("a\u007fb")
                .contentDisposition("aǇb")
                .metadata(Map.of("x", "a b\u007f"))
                .build(),
                new ByteArrayInputStream(
                        "content".getBytes(StandardCharsets.UTF_8)));
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
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
    }

    @Test
    public void testStoredValues() throws Exception {
        for (String method : new String[] {"GET", "HEAD"}) {
            String head = send(method, "/" + BUCKET + "/key");
            assertThat(head).as(method).startsWith("HTTP/1.1 200 ")
                    .contains("\r\nCache-Control: a b\r\n")
                    .contains("\r\nContent-Disposition: a?b\r\n")
                    .contains("\r\nx-amz-meta-x: =?UTF-8?Q?a_b=7F?=\r\n");
            assertNoControlCharacters(head);
        }
    }

    @Test
    public void testOverrideControlBecomesSpace() throws Exception {
        String head = send("GET", "/" + BUCKET +
                "/key?response-cache-control=a%7Fb" +
                "&response-content-type=text%2Fa%01b" +
                "&response-expires=soon%0A");
        assertThat(head).startsWith("HTTP/1.1 200 ")
                .contains("\r\nCache-Control: a b\r\n")
                .contains("\r\nContent-Type: text/a b\r\n");
        assertNoControlCharacters(head);
    }

    /**
     * Refused before the object's own headers are written, which would
     * otherwise go out on the error.
     */
    @Test
    public void testOverrideBeyondLatin1IsRefused() throws Exception {
        for (String method : new String[] {"GET", "HEAD"}) {
            String response = send(method, "/" + BUCKET +
                    "/key?response-content-disposition=a%C7%87b");
            assertThat(response).as(method).startsWith("HTTP/1.1 400 ")
                    .doesNotContain("x-amz-meta-x")
                    .doesNotContain("Cache-Control");
            if (method.equals("GET")) {
                assertThat(response).contains(
                        "<Code>InvalidArgument</Code>",
                        "Header value cannot be represented using" +
                                " ISO-8859-1.");
            }
        }
    }

    /** Whatever arrives before the connection closes, read as ISO-8859-1. */
    private String send(String method, String target) throws Exception {
        try (var socket = new Socket(InetAddress.getLoopbackAddress(),
                s3Proxy.getPort())) {
            socket.setSoTimeout(10_000);
            OutputStream out = socket.getOutputStream();
            out.write((method + " " + target + " HTTP/1.1\r\n" +
                    "Host: 127.0.0.1\r\n" +
                    "Connection: close\r\n" +
                    "\r\n").getBytes(StandardCharsets.ISO_8859_1));
            out.flush();
            InputStream in = socket.getInputStream();
            return new String(in.readAllBytes(), StandardCharsets.ISO_8859_1);
        }
    }

    /** No byte of the head that RFC 9110 keeps out of a field value. */
    private static void assertNoControlCharacters(String response) {
        String head = response.substring(0, response.indexOf("\r\n\r\n"));
        for (String line : Splitter.on("\r\n").split(head)) {
            for (int i = 0; i < line.length(); ++i) {
                char c = line.charAt(i);
                assertThat(c == '\t' || (c >= 0x20 && c != 0x7f))
                        .as("%s: character %d", line, (int) c).isTrue();
            }
        }
    }
}
