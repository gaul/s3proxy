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
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import org.eclipse.jetty.util.VirtualThreads;
import org.gaul.s3proxy.auth.AuthenticationType;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.awscore.retry.AwsRetryStrategy;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.model.BucketCannedACL;
import software.amazon.awssdk.services.s3.model.ObjectIdentifier;
import software.amazon.awssdk.services.s3.model.S3Exception;

/**
 * Bodies read before their requests are authenticated -- a form POST, whose
 * policy rides inside it, and a V4 request signing a digest of its body.
 * Sent slowly, each held a pooled thread for as long as its sender liked,
 * and a few hundred stopped the proxy answering anything; on virtual threads
 * they hold none, and what their bodies hold is bounded by one budget.
 */
public final class PreAuthBodyTest {
    private static final String CONTAINER = "container";
    private static final String BOUNDARY = "boundary";

    private S3Proxy s3Proxy;
    private final List<Socket> sockets = new ArrayList<>();
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    @AfterEach
    public void tearDown() throws Exception {
        for (Socket socket : sockets) {
            socket.close();
        }
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
    }

    private void start(S3Proxy.Builder builder) throws Exception {
        BlobStore blobStore = TestUtils.createTransientBlobStore();
        blobStore.createContainer(CONTAINER);
        blobStore.setContainerAccess(CONTAINER,
                BucketCannedACL.PUBLIC_READ_WRITE);
        s3Proxy = builder
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
    }

    private String base() {
        return "http://127.0.0.1:" + s3Proxy.getPort();
    }

    @Test
    public void testStalledFormPostsDoNotStopTheProxy() throws Exception {
        assumeTrue(VirtualThreads.areSupported());
        int threads = 2 * Runtime.getRuntime().availableProcessors() + 16;
        start(S3Proxy.builder().jettyMaxThreads(threads));

        // each sends the start of a form and then nothing more
        for (int i = 0; i < 2 * threads; ++i) {
            var socket = new Socket();
            sockets.add(socket);
            socket.connect(new InetSocketAddress(
                    InetAddress.getLoopbackAddress(), s3Proxy.getPort()));
            OutputStream out = socket.getOutputStream();
            out.write(("POST /" + CONTAINER + " HTTP/1.1\r\n" +
                    "Host: 127.0.0.1\r\n" +
                    "Content-Type: multipart/form-data; boundary=" +
                    BOUNDARY + "\r\n" +
                    "Content-Length: 1000000\r\n" +
                    "\r\n" +
                    "--" + BOUNDARY + "\r\n")
                    .getBytes(StandardCharsets.ISO_8859_1));
            out.flush();
        }
        // give them time to be dispatched and to block
        Thread.sleep(500);

        HttpResponse<String> health = httpClient.send(HttpRequest.newBuilder(
                URI.create(base() + "/healthz"))
                .timeout(Duration.ofSeconds(5)).build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(health.statusCode()).isEqualTo(200);
    }

    @Test
    public void testFormPostBeyondBudgetIsSlowDown() throws Exception {
        start(S3Proxy.builder().preAuthBodyBudget(64 * 1024));

        HttpResponse<String> response = postForm("big", 100 * 1024);
        assertThat(response.statusCode()).isEqualTo(503);
        assertThat(response.body()).contains("<Code>SlowDown</Code>");

        // each gives back what it took, so these fit one after another
        for (int i = 0; i < 10; ++i) {
            assertThat(postForm("small" + i, 10 * 1024).statusCode())
                    .isEqualTo(204);
        }
        assertBudgetWhole();
    }

    @Test
    public void testSignedBodyBeyondBudgetIsSlowDown() throws Exception {
        start(S3Proxy.builder().preAuthBodyBudget(64 * 1024));
        try (S3Client client = S3Client.builder()
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create("identity", "credential")))
                .region(Region.US_EAST_1)
                .endpointOverride(URI.create(base()))
                .serviceConfiguration(S3Configuration.builder()
                        .pathStyleAccessEnabled(true)
                        .build())
                .overrideConfiguration(c -> c.retryStrategy(
                        AwsRetryStrategy.doNotRetry()))
                .build()) {
            // a key list of about 130 KB, whose digest the signature covers
            var keys = new ArrayList<ObjectIdentifier>();
            for (int i = 0; i < 1000; ++i) {
                keys.add(ObjectIdentifier.builder()
                        .key("k".repeat(100) + i).build());
            }
            try {
                client.deleteObjects(b -> b.bucket(CONTAINER)
                        .delete(d -> d.objects(keys)));
                throw new AssertionError("expected SlowDown");
            } catch (S3Exception e) {
                assertThat(e.statusCode()).isEqualTo(503);
                assertThat(e.awsErrorDetails().errorCode())
                        .isEqualTo("SlowDown");
            }

            // a small one fits, and the budget is whole again afterwards
            client.deleteObjects(b -> b.bucket(CONTAINER)
                    .delete(d -> d.objects(keys.subList(0, 10))));
        }
        assertBudgetWhole();
    }

    /**
     * A form just under the whole budget fits only if every request before
     * it gave back all it took.
     */
    private void assertBudgetWhole() throws Exception {
        // A success may be answered a moment before its request gives the
        // budget back.
        int status = 0;
        for (int attempt = 0; attempt < 20 && status != 204; ++attempt) {
            if (attempt > 0) {
                Thread.sleep(50);
            }
            status = postForm("whole", 63 * 1024).statusCode();
        }
        assertThat(status).isEqualTo(204);
    }

    /** An unsigned form uploading {@code size} bytes as {@code key}. */
    private HttpResponse<String> postForm(String key, int size)
            throws Exception {
        String form = "--" + BOUNDARY + "\r\n" +
                "Content-Disposition: form-data; name=\"key\"\r\n\r\n" +
                key + "\r\n" +
                "--" + BOUNDARY + "\r\n" +
                "Content-Disposition: form-data; name=\"file\";" +
                " filename=\"f\"\r\n\r\n" +
                "x".repeat(size) + "\r\n" +
                "--" + BOUNDARY + "--\r\n";
        return httpClient.send(HttpRequest.newBuilder(
                URI.create(base() + "/" + CONTAINER))
                .header("Content-Type",
                        "multipart/form-data; boundary=" + BOUNDARY)
                .POST(HttpRequest.BodyPublishers.ofString(form))
                .build(), HttpResponse.BodyHandlers.ofString());
    }
}
