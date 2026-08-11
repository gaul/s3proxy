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
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Random;

import org.gaul.s3proxy.auth.AuthenticationType;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;

import software.amazon.awssdk.services.s3.model.BucketCannedACL;

/**
 * A form POST is bounded and buffered in memory, so accepting one must not
 * depend on the temporary directory: with Jetty's default of writing every
 * file part to disk, a proxy whose temporary directory is unwritable -- a
 * hardened service, a container with a read-only filesystem -- answered every
 * upload with a parse error that blamed the form.  Isolated because pointing
 * java.io.tmpdir at a directory that does not exist would fail any concurrent
 * test that creates a temporary file while it runs.
 */
@Isolated
public final class PostObjectTemporaryDirectoryTest {
    private static final String BOUNDARY = "----------s3proxytest";

    private S3Proxy s3Proxy;
    private BlobStore blobStore;
    private String containerName;
    private String bucketUri;

    @BeforeEach
    public void setUp() throws Exception {
        blobStore = TestUtils.createTransientBlobStore();
        containerName = "container-" + new Random().nextInt(Integer.MAX_VALUE);
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
        bucketUri = "http://127.0.0.1:" + s3Proxy.getPort() + "/" +
                containerName;
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
    }

    @Test
    public void testPostNeedsNoTemporaryDirectory() throws Exception {
        String tmpdir = System.getProperty("java.io.tmpdir");
        System.setProperty("java.io.tmpdir", "/nonexistent-s3proxy-" +
                new Random().nextInt(Integer.MAX_VALUE));
        HttpResponse<String> response;
        try {
            var out = new ByteArrayOutputStream();
            out.write(("--" + BOUNDARY + "\r\nContent-Disposition:" +
                    " form-data; name=\"key\"\r\n\r\nfoo.txt\r\n" +
                    "--" + BOUNDARY + "\r\nContent-Disposition: form-data;" +
                    " name=\"file\"; filename=\"payload.txt\"\r\n\r\nbar\r\n" +
                    "--" + BOUNDARY + "--\r\n")
                    .getBytes(StandardCharsets.UTF_8));
            response = HttpClient.newHttpClient().send(
                    HttpRequest.newBuilder(URI.create(bucketUri))
                            .header("Content-Type",
                                    "multipart/form-data; boundary=" +
                                    BOUNDARY)
                            .POST(HttpRequest.BodyPublishers.ofByteArray(
                                    out.toByteArray()))
                            .build(), HttpResponse.BodyHandlers.ofString());
        } finally {
            System.setProperty("java.io.tmpdir", tmpdir);
        }
        assertThat(response.statusCode()).isEqualTo(204);
        assertThat(blobStore.blobExists(containerName, "foo.txt")).isTrue();
    }
}
