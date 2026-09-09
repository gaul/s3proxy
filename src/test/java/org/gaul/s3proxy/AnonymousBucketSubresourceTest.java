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

/**
 * What an unsigned request may ask of a public-read bucket.  A bucket ACL
 * granting READ carries exactly s3:ListBucket, s3:ListBucketVersions and
 * s3:ListBucketMultipartUploads -- the mapping AWS documents for an ACL
 * permission granted on a bucket -- so those three listings are answered and
 * nothing else is.  Reading an encryption or versioning configuration answers
 * to a permission no ACL grant carries; both were served here, and
 * ?uploads was not served at all but answered a plain object listing, which
 * tells the caller about a different thing than it asked for.
 */
public final class AnonymousBucketSubresourceTest {
    private static final String KEY = "object";

    private S3Proxy s3Proxy;
    private BlobStore blobStore;
    private String publicBucket;
    private String privateBucket;
    private String baseUri;
    private final HttpClient httpClient = HttpClient.newHttpClient();

    @BeforeEach
    public void setUp() throws Exception {
        blobStore = TestUtils.createTransientBlobStore();
        var random = new Random();
        publicBucket = "public-" + random.nextInt(Integer.MAX_VALUE);
        privateBucket = "private-" + random.nextInt(Integer.MAX_VALUE);
        blobStore.createContainer(publicBucket);
        blobStore.createContainer(privateBucket);
        blobStore.setContainerAccess(publicBucket,
                BucketCannedACL.PUBLIC_READ);
        TestUtils.putBlob(blobStore, publicBucket, KEY,
                ByteSource.wrap("content".getBytes(StandardCharsets.UTF_8)));

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

    /** ListBucket, the plain listing READ carries. */
    @Test
    public void testPlainListingIsAnswered() throws Exception {
        HttpResponse<String> response = get(publicBucket);
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).contains("<ListBucketResult");
        assertThat(response.body()).contains(KEY);
    }

    /** ListBucketVersions, which READ carries as well. */
    @Test
    public void testVersionsIsAnswered() throws Exception {
        HttpResponse<String> response = get(publicBucket + "?versions");
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).contains("<ListVersionsResult");
    }

    /**
     * ListBucketMultipartUploads, the third.  It used to fall through to the
     * plain listing, answering an object list to a request for uploads.
     */
    @Test
    public void testUploadsIsAnswered() throws Exception {
        HttpResponse<String> response = get(publicBucket + "?uploads");
        System.err.println("anonymous ?uploads: " + response.statusCode() +
                " " + response.body());
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).contains("<ListMultipartUploadsResult");
        assertThat(response.body()).doesNotContain("<ListBucketResult");
    }

    /** GetBucketVersioning answers to a permission no ACL grant carries. */
    @Test
    public void testVersioningIsRefused() throws Exception {
        HttpResponse<String> response = get(publicBucket + "?versioning");
        System.err.println("anonymous ?versioning: " + response.statusCode() +
                " " + response.body());
        assertThat(response.statusCode()).isEqualTo(403);
        assertThat(response.body()).contains("AccessDenied");
        // Refused rather than quietly answered with the object listing.
        assertThat(response.body()).doesNotContain("<ListBucketResult");
    }

    /** And neither does GetBucketEncryption. */
    @Test
    public void testEncryptionIsRefused() throws Exception {
        HttpResponse<String> response = get(publicBucket + "?encryption");
        assertThat(response.statusCode()).isEqualTo(403);
        assertThat(response.body()).contains("AccessDenied");
        assertThat(response.body()).doesNotContain("<ListBucketResult");
    }

    /** A private bucket answers none of them. */
    @Test
    public void testPrivateBucketRefusesEveryListing() throws Exception {
        String[] queries = {
            "", "?versions", "?uploads", "?versioning", "?encryption",
        };
        for (String query : queries) {
            HttpResponse<String> response = get(privateBucket + query);
            assertThat(response.statusCode())
                    .withFailMessage("private bucket answered %s with %d",
                            query, response.statusCode())
                    .isEqualTo(403);
        }
    }

    private HttpResponse<String> get(String pathAndQuery) throws Exception {
        return httpClient.send(
                HttpRequest.newBuilder(URI.create(baseUri + pathAndQuery))
                        .GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }
}
