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

import java.net.InetAddress;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.List;

import org.gaul.s3proxy.auth.AuthenticationType;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.ForwardingBlobStore;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.ListBucketsResponse;

/**
 * Requests refused for what they asked are answered with the code S3 gives
 * them.  Each was refused by an IllegalArgumentException, which the Jetty
 * handler answered as a bare 400 InvalidRequest: no code a client can act
 * on, and for a limit of S3Proxy's own, a status that blamed the client.
 * The handler now answers one 500.
 */
public final class RequestInputErrorTest {
    private final HttpClient httpClient = HttpClient.newHttpClient();

    /** A presigned URL signed with an algorithm S3Proxy does not verify. */
    @Test
    public void testUnknownAlgorithm() throws Exception {
        S3Proxy proxy = start(AuthenticationType.AWS_V2_OR_V4);
        try {
            HttpResponse<String> response = get(proxy, "/bucket" +
                    "?X-Amz-Algorithm=AWS4-ECDSA-P256-SHA256" +
                    "&X-Amz-Credential=identity%2F20261125%2Fus-east-1" +
                    "%2Fs3%2Faws4_request" +
                    "&X-Amz-Date=20261125T000000Z&X-Amz-Expires=60" +
                    "&X-Amz-SignedHeaders=host&X-Amz-Signature=00");
            assertThat(response.statusCode()).isEqualTo(400);
            assertThat(response.body()).contains(
                    "<Code>AuthorizationQueryParametersError</Code>");
        } finally {
            proxy.stop();
        }
    }

    /**
     * S3 takes any delimiter; the nio2 stores group only on "/", which is
     * their limit and not the request's fault.
     */
    @Test
    public void testDelimiterTheStoreCannotGroupOn() throws Exception {
        S3Proxy proxy = start(AuthenticationType.NONE);
        try {
            for (String query : List.of("?delimiter=x",
                    "?list-type=2&delimiter=x")) {
                HttpResponse<String> response = get(proxy, "/bucket" + query);
                assertThat(response.statusCode()).as(query).isEqualTo(501);
                assertThat(response.body()).as(query)
                        .contains("<Code>NotImplemented</Code>");
            }
        } finally {
            proxy.stop();
        }
    }

    /**
     * S3 takes a part of at most 5 GiB and refuses a larger one before
     * reading it.  Nothing limited a part: a store took what it could, and
     * Azure, whose blocks stop at 4000 MiB, answered a 500.  The body is
     * declared and never sent, since the refusal must not wait for it.
     */
    @Test
    public void testPartLargerThanS3TakesIsEntityTooLarge() throws Exception {
        S3Proxy proxy = start(AuthenticationType.NONE);
        try {
            String created = httpClient.send(HttpRequest.newBuilder(
                    URI.create("http://127.0.0.1:" + proxy.getPort() +
                            "/bucket/key?uploads"))
                    .POST(HttpRequest.BodyPublishers.noBody()).build(),
                    HttpResponse.BodyHandlers.ofString()).body();
            String uploadId = created.substring(
                    created.indexOf("<UploadId>") + "<UploadId>".length(),
                    created.indexOf("</UploadId>"));
            String answer;
            try (var socket = new Socket(InetAddress.getLoopbackAddress(),
                    proxy.getPort())) {
                socket.setSoTimeout(10_000);
                socket.getOutputStream().write((
                        "PUT /bucket/key?partNumber=1&uploadId=" + uploadId +
                        " HTTP/1.1\r\nHost: 127.0.0.1\r\n" +
                        "Content-Length: " + (5L * 1024 * 1024 * 1024 + 1) +
                        "\r\nConnection: close\r\n\r\n")
                        .getBytes(StandardCharsets.US_ASCII));
                socket.getOutputStream().flush();
                answer = new String(socket.getInputStream().readAllBytes(),
                        StandardCharsets.UTF_8);
            }
            assertThat(answer).startsWith("HTTP/1.1 400 ")
                    .contains("<Code>EntityTooLarge</Code>");
        } finally {
            proxy.stop();
        }
    }

    /**
     * Refusals of a request's input are S3 errors of their own, so an
     * IllegalArgumentException or IllegalStateException that reaches the
     * handler is a fault on this side: a 500, not the client's 400.
     */
    @Test
    public void testStrayIllegalExceptionIsServerError() throws Exception {
        for (RuntimeException e : List.of(
                new IllegalArgumentException("stray"),
                new IllegalStateException("stray"))) {
            BlobStore blobStore = new ForwardingBlobStore(
                    TestUtils.createTransientBlobStore()) {
                @Override
                public ListBucketsResponse list() {
                    throw e;
                }
            };
            S3Proxy proxy = start(blobStore, AuthenticationType.NONE);
            try {
                HttpResponse<String> response = get(proxy, "/");
                assertThat(response.statusCode()).as(e.toString())
                        .isEqualTo(500);
                assertThat(response.body()).as(e.toString())
                        .contains("<Code>InternalError</Code>");
            } finally {
                proxy.stop();
            }
        }
    }

    private static S3Proxy start(AuthenticationType type) throws Exception {
        BlobStore blobStore = TestUtils.createTransientBlobStore();
        blobStore.createContainer("bucket");
        return start(blobStore, type);
    }

    private static S3Proxy start(BlobStore blobStore, AuthenticationType type)
            throws Exception {
        S3Proxy proxy = S3Proxy.builder()
                .stopTimeout(0)
                .blobStore(blobStore)
                .awsAuthentication(type, "identity", "credential")
                .endpoint(URI.create("http://127.0.0.1:0"))
                .build();
        proxy.start();
        while (!proxy.getState().equals("STARTED")) {
            Thread.sleep(10);
        }
        return proxy;
    }

    private HttpResponse<String> get(S3Proxy proxy, String pathAndQuery)
            throws Exception {
        return httpClient.send(HttpRequest.newBuilder(URI.create(
                "http://127.0.0.1:" + proxy.getPort() + pathAndQuery))
                .GET().build(), HttpResponse.BodyHandlers.ofString());
    }
}
