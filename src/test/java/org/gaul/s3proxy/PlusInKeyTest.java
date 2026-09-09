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

import org.gaul.s3proxy.auth.AuthenticationType;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.BucketCannedACL;
import software.amazon.awssdk.services.s3.model.ObjectCannedACL;

/**
 * A "+" in a URI path is a literal character of the key, not a space: the
 * form grammar that says otherwise governs a request body, not a path, and
 * the escaper that writes these keys out already spells a space %20 and a
 * plus %2B.  Decoding the path with URLDecoder did not mirror it, so a
 * request for "a+b" looked for "a b" -- an object nobody stored, and under a
 * BlobStoreLocator that scopes buckets by pattern a name other than the one
 * the signature covered.
 */
public final class PlusInKeyTest {
    private static final String PLUS_KEY = "a+b";
    private static final String SPACE_KEY = "a b";
    private static final String PLUS_CONTENT = "stored-under-a-plus";
    private static final String SPACE_CONTENT = "stored-under-a-space";

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
        blobStore.createContainer(containerName);
        blobStore.setContainerAccess(containerName,
                BucketCannedACL.PUBLIC_READ);
        put(PLUS_KEY, PLUS_CONTENT);
        put(SPACE_KEY, SPACE_CONTENT);

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
        baseUri = "http://127.0.0.1:" + s3Proxy.getPort() + "/";
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
    }

    /** A bare plus in the path names the object stored with a plus. */
    @Test
    public void testBarePlusNamesThePlusKey() throws Exception {
        HttpResponse<String> response = get(containerName + "/a+b");
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).isEqualTo(PLUS_CONTENT);
    }

    /** So does the escaped spelling the proxy's own escaper writes. */
    @Test
    public void testEscapedPlusNamesThePlusKey() throws Exception {
        HttpResponse<String> response = get(containerName + "/a%2Bb");
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).isEqualTo(PLUS_CONTENT);
    }

    /** A space is spelled %20, and only %20 reaches the key holding one. */
    @Test
    public void testEscapedSpaceNamesTheSpaceKey() throws Exception {
        HttpResponse<String> response = get(containerName + "/a%20b");
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).isEqualTo(SPACE_CONTENT);
    }

    /**
     * The converse of the first case, and the behaviour that changed: a plus
     * no longer reaches the object whose key holds a space.
     */
    @Test
    public void testBarePlusDoesNotNameTheSpaceKey() throws Exception {
        blobStore.removeBlob(containerName, PLUS_KEY);
        HttpResponse<String> response = get(containerName + "/a+b");
        System.err.println("plus without a plus key: " +
                response.statusCode() + " " + response.body());
        assertThat(response.statusCode()).isEqualTo(404);
        assertThat(response.body()).contains("NoSuchKey");
    }

    /**
     * Listing writes the keys back out through the escaper this decoding
     * mirrors, so what a listing says is what a fetch will accept.
     */
    @Test
    public void testListingRoundTrips() throws Exception {
        HttpResponse<String> listing = get(containerName +
                "?encoding-type=url");
        assertThat(listing.statusCode()).isEqualTo(200);
        assertThat(listing.body()).contains("<Key>a%2Bb</Key>");
        assertThat(listing.body()).contains("<Key>a%20b</Key>");

        assertThat(get(containerName + "/a%2Bb").body())
                .isEqualTo(PLUS_CONTENT);
        assertThat(get(containerName + "/a%20b").body())
                .isEqualTo(SPACE_CONTENT);
    }

    private void put(String blobName, String content) throws Exception {
        TestUtils.putBlob(blobStore, containerName, blobName, ByteSource.wrap(
                content.getBytes(StandardCharsets.UTF_8)));
        blobStore.setBlobAccess(containerName, blobName,
                ObjectCannedACL.PUBLIC_READ);
    }

    private HttpResponse<String> get(String pathAndQuery) throws Exception {
        return httpClient.send(
                HttpRequest.newBuilder(URI.create(baseUri + pathAndQuery))
                        .GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }
}
