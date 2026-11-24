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
import java.net.URI;
import java.nio.charset.StandardCharsets;

import org.gaul.s3proxy.auth.AuthenticationType;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;

import software.amazon.awssdk.services.s3.model.BucketCannedACL;

/**
 * What a form POST holds in memory follows the length of its body, not the
 * number of pieces the body arrives in.  Jetty's multipart parser keeps, for
 * every read of the request, the whole buffer the read went into, and a read
 * returns no more than one HTTP chunk holds; a form sent a byte to a chunk
 * held a buffer of 8 KiB for each byte, which the bound on the body's length
 * never saw.  A buffer for each byte of this form is more than the 512 MB the
 * tests run in, so it is stored only if that is no longer what is held.
 * Isolated because the heap is what tells the two apart, and a form that
 * takes all of it takes the tests running beside it down too.  This speaks
 * HTTP directly because a client chooses its own chunks.
 */
@Isolated
public final class PostObjectTinyChunksTest {
    private static final String BOUNDARY = "----------s3proxytest";
    private static final int LENGTH = 100_000;

    private S3Proxy s3Proxy;
    private BlobStore blobStore;
    private String containerName;

    @BeforeEach
    public void setUp() throws Exception {
        blobStore = TestUtils.createTransientBlobStore();
        containerName = TestUtils.createRandomContainerName();
        blobStore.createContainer(containerName);
        blobStore.setContainerAccess(containerName,
                BucketCannedACL.PUBLIC_READ_WRITE);

        s3Proxy = S3Proxy.builder()
                .stopTimeout(0)
                .blobStore(blobStore)
                .awsAuthentication(AuthenticationType.AWS_V2_OR_V4, "identity",
                        "credential")
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

    @Test
    public void testPostOneByteToAChunk() throws Exception {
        String request = "POST /" + containerName + " HTTP/1.1\r\n" +
                "Host: 127.0.0.1\r\n" +
                "Content-Type: multipart/form-data; boundary=" + BOUNDARY +
                "\r\n" +
                "Transfer-Encoding: chunked\r\n" +
                "Connection: close\r\n\r\n" +
                chunk("--" + BOUNDARY + "\r\nContent-Disposition: form-data;" +
                        " name=\"key\"\r\n\r\nfoo.txt\r\n" +
                        "--" + BOUNDARY + "\r\nContent-Disposition:" +
                        " form-data; name=\"file\";" +
                        " filename=\"payload.txt\"\r\n\r\n") +
                chunk("x").repeat(LENGTH) +
                chunk("\r\n--" + BOUNDARY + "--\r\n") +
                "0\r\n\r\n";

        String response;
        try (var socket = new Socket()) {
            socket.connect(new InetSocketAddress(
                    InetAddress.getLoopbackAddress(), s3Proxy.getPort()));
            socket.setSoTimeout(60_000);
            socket.getOutputStream().write(
                    request.getBytes(StandardCharsets.ISO_8859_1));
            socket.getOutputStream().flush();

            var out = new ByteArrayOutputStream();
            try (InputStream is = socket.getInputStream()) {
                is.transferTo(out);
            }
            response = out.toString(StandardCharsets.UTF_8);
        }

        assertThat(response).startsWith("HTTP/1.1 204 ");
        assertThat(blobStore.blobMetadata(containerName, "foo.txt")
                .contentLength()).isEqualTo(LENGTH);
    }

    /** One chunk of Transfer-Encoding: chunked. */
    private static String chunk(String data) {
        return Integer.toHexString(data.length()) + "\r\n" + data + "\r\n";
    }
}
