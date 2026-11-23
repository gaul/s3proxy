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
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.gaul.s3proxy.auth.AuthenticationType;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.PutObjectRequest;

/**
 * A V2 signature covers the request's Content-Type, and signs a header that
 * is present but empty exactly as it signs an absent one.  A URL presigned
 * for no Content-Type therefore admits the empty header, and the object must
 * come out of that as it comes out of the request the signer had in mind:
 * with the default type, not with an empty one that leaves a browser to pick
 * a type from bytes the uploader chose.  These speak HTTP directly because a
 * client library does not send a header without a value.
 */
public final class EmptyContentTypeTest {
    private static final String IDENTITY = "identity";
    private static final String CREDENTIAL = "credential";
    private static final String BODY = "<script>alert(1)</script>";
    private static final String EMPTY_CONTENT_TYPE = "Content-Type:\r\n";

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
                        CREDENTIAL)
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

    /** The control: the URL as it was signed stores the default type. */
    @Test
    public void testAbsentContentType() throws Exception {
        assertThat(send("PUT", "object", "", "", "", BODY))
                .startsWith("HTTP/1.1 200 ");
        assertDefaultType("object");
    }

    /** The control: the holder of that URL may not name a type. */
    @Test
    public void testNamedContentTypeIsRefused() throws Exception {
        String response = send("PUT", "object", "", "",
                "Content-Type: text/html\r\n", BODY);
        assertThat(response).startsWith("HTTP/1.1 403 ");
        assertThat(response).contains("<Code>SignatureDoesNotMatch</Code>");
    }

    @Test
    public void testPutObject() throws Exception {
        assertThat(send("PUT", "object", "", "", EMPTY_CONTENT_TYPE, BODY))
                .startsWith("HTTP/1.1 200 ");
        assertDefaultType("object");
    }

    @Test
    public void testCopyObjectReplace() throws Exception {
        assertThat(send("PUT", "object", "", "", "", BODY))
                .startsWith("HTTP/1.1 200 ");
        String copySource = "/" + containerName + "/object";
        assertThat(send("PUT", "copy", "",
                "x-amz-copy-source:" + copySource + "\n" +
                "x-amz-metadata-directive:REPLACE\n",
                "x-amz-copy-source: " + copySource + "\r\n" +
                "x-amz-metadata-directive: REPLACE\r\n" +
                EMPTY_CONTENT_TYPE, ""))
                .startsWith("HTTP/1.1 200 ");
        assertDefaultType("copy");
    }

    @Test
    public void testMultipartUpload() throws Exception {
        String response = send("POST", "object", "?uploads", "",
                EMPTY_CONTENT_TYPE, "");
        assertThat(response).startsWith("HTTP/1.1 200 ");
        String uploadId = between(response, "<UploadId>", "</UploadId>");

        response = send("PUT", "object",
                "?partNumber=1&uploadId=" + uploadId, "", "", BODY);
        assertThat(response).startsWith("HTTP/1.1 200 ");
        String eTag = between(response, "ETag: ", "\r\n");

        assertThat(send("POST", "object", "?uploadId=" + uploadId, "", "",
                "<CompleteMultipartUpload><Part>" +
                "<PartNumber>1</PartNumber><ETag>" + eTag + "</ETag>" +
                "</Part></CompleteMultipartUpload>"))
                .startsWith("HTTP/1.1 200 ");
        assertDefaultType("object");
    }

    /**
     * An object that already rests under an empty type, or that a backend
     * reports one for, names no type either.
     */
    @Test
    public void testStoredEmptyContentType() throws Exception {
        byte[] content = BODY.getBytes(StandardCharsets.UTF_8);
        blobStore.putBlob(PutObjectRequest.builder()
                .bucket(containerName)
                .key("object")
                .contentLength((long) content.length)
                .contentType("")
                .build(), new ByteArrayInputStream(content));
        assertThat(blobStore.blobMetadata(containerName, "object")
                .contentType()).isEmpty();

        assertThat(send("HEAD", "object", "", "", "", "")).contains(
                "\r\nContent-Type: binary/octet-stream\r\n");
        assertThat(send("GET", "object", "", "", "", "")).contains(
                "\r\nContent-Type: binary/octet-stream\r\n");
    }

    /** What the proxy answers for the key, and what the store holds. */
    private void assertDefaultType(String key) throws Exception {
        String response = send("GET", key, "", "", "", "");
        assertThat(response).startsWith("HTTP/1.1 200 ");
        assertThat(response).contains(
                "\r\nContent-Type: binary/octet-stream\r\n");
        assertThat(response).endsWith("\r\n\r\n" + BODY);
        assertThat(blobStore.blobMetadata(containerName, key).contentType())
                .isEqualTo("binary/octet-stream");
    }

    private static String between(String response, String start, String end) {
        int from = response.indexOf(start) + start.length();
        return response.substring(from, response.indexOf(end, from));
    }

    /**
     * Send a V2 presigned request signed for no Content-Type, and return the
     * whole response.
     *
     * @param subresource the signed query string, from its "?" on, or empty
     * @param signedHeaders the canonicalized x-amz-* headers, each ending in
     *     a newline
     * @param headers the header lines to send, each ending in CRLF
     */
    private String send(String method, String key, String subresource,
            String signedHeaders, String headers, String body)
            throws Exception {
        String resource = "/" + containerName + "/" + key + subresource;
        long expires = System.currentTimeMillis() / 1000 + 3600;
        String stringToSign = method + "\n" +
                /*contentMD5=*/ "\n" +
                /*contentType=*/ "\n" +
                expires + "\n" +
                signedHeaders + resource;
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(new SecretKeySpec(CREDENTIAL.getBytes(
                StandardCharsets.UTF_8), "HmacSHA1"));
        String signature = Base64.getEncoder().encodeToString(mac.doFinal(
                stringToSign.getBytes(StandardCharsets.UTF_8)));
        byte[] payload = body.getBytes(StandardCharsets.UTF_8);
        String request = method + " " + resource +
                (subresource.isEmpty() ? "?" : "&") +
                "AWSAccessKeyId=" + IDENTITY +
                "&Expires=" + expires +
                "&Signature=" + URLEncoder.encode(signature,
                        StandardCharsets.UTF_8) + " HTTP/1.1\r\n" +
                "Host: 127.0.0.1\r\n" +
                headers +
                "Content-Length: " + payload.length + "\r\n" +
                "Connection: close\r\n" +
                "\r\n";

        try (var socket = new Socket()) {
            socket.connect(new InetSocketAddress(
                    InetAddress.getLoopbackAddress(), s3Proxy.getPort()));
            socket.setSoTimeout(10_000);
            OutputStream out = socket.getOutputStream();
            out.write(request.getBytes(StandardCharsets.ISO_8859_1));
            out.write(payload);
            out.flush();
            return new String(socket.getInputStream().readAllBytes(),
                    StandardCharsets.UTF_8);
        }
    }
}
