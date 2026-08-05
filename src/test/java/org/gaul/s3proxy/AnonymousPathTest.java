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

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Random;

import com.google.common.io.ByteSource;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.domain.Blob;
import org.gaul.s3proxy.blobstore.domain.BlobAccess;
import org.gaul.s3proxy.blobstore.options.CreateContainerOptions;
import org.gaul.s3proxy.blobstore.options.PutOptions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * A read nobody signed names its bucket and key the same way a signed one
 * does.  The two used to part company here: doHandle decoded the request URI
 * and refused a name no bucket can have, while the anonymous path split the
 * URI as it arrived and asked the backend about whatever it found.
 */
public final class AnonymousPathTest {
    /** Spelled with an escape for the space and three more for the umlaut. */
    private static final String BLOB_NAME = "notes/a file über.txt";
    private static final String ENCODED_NAME =
            "notes/a%20file%20%C3%BCber.txt";
    private static final String CONTENT = "public";

    private S3Proxy s3Proxy;
    private BlobStore blobStore;
    private String containerName;
    private String baseUri;
    private final HttpClient httpClient = HttpClient.newHttpClient();

    @BeforeEach
    public void setUp() throws Exception {
        blobStore = TestUtils.createTransientBlobStore();
        containerName =
                "container-" + new Random().nextInt(Integer.MAX_VALUE);
        blobStore.createContainer(containerName, CreateContainerOptions.NONE);
        put(containerName, BLOB_NAME);

        s3Proxy = S3Proxy.builder()
                .blobStore(blobStore)
                .awsAuthentication(AuthenticationType.AWS_V2_OR_V4,
                        "identity", "credential")
                .endpoint(URI.create("http://127.0.0.1:0"))
                .build();
        s3Proxy.start();
        while (!s3Proxy.getState().equals("STARTED")) {
            Thread.sleep(10);
        }
        baseUri = "http://127.0.0.1:" + s3Proxy.getPort() + "/";
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
    }

    /** A public object is readable whatever its key needs escaping for. */
    @Test
    public void testAnonymousReadDecodesTheKey() throws Exception {
        HttpResponse<String> response = get(containerName + "/" +
                ENCODED_NAME);
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).isEqualTo(CONTENT);
    }

    /** HEAD reads the name the same way. */
    @Test
    public void testAnonymousHeadDecodesTheKey() throws Exception {
        HttpResponse<Void> response = httpClient.send(
                HttpRequest.newBuilder(URI.create(baseUri + containerName +
                        "/" + ENCODED_NAME))
                        .method("HEAD", HttpRequest.BodyPublishers.noBody())
                        .build(),
                HttpResponse.BodyHandlers.discarding());
        assertThat(response.statusCode()).isEqualTo(200);
    }

    /**
     * A name no bucket can have is refused rather than looked up, which is
     * what the authenticated path answers for the same name.  A backend of
     * its own mind about the name would otherwise serve anonymously what it
     * would not serve to a caller who signed.
     */
    @Test
    public void testAnonymousReadRefusesAnInvalidBucketName()
            throws Exception {
        blobStore.createContainer("ab", CreateContainerOptions.NONE);
        put("ab", "blob");

        HttpResponse<String> response = get("ab/blob");
        assertThat(response.statusCode()).isEqualTo(404);
        assertThat(response.body()).contains("<Code>NoSuchBucket</Code>");
    }

    private void put(String container, String blobName) throws Exception {
        ByteSource payload = ByteSource.wrap(
                CONTENT.getBytes(StandardCharsets.UTF_8));
        blobStore.putBlob(container, Blob.builder(blobName)
                .payload(payload).contentLength(payload.size()).build(),
                PutOptions.NONE);
        blobStore.setBlobAccess(container, blobName, BlobAccess.PUBLIC_READ);
    }

    private HttpResponse<String> get(String path) throws Exception {
        return httpClient.send(
                HttpRequest.newBuilder(URI.create(baseUri + path)).GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString());
    }
}
