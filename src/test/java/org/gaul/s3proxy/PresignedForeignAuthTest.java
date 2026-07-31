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
import java.time.Duration;
import java.util.Random;

import com.google.common.io.ByteSource;
import com.google.common.net.HttpHeaders;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.domain.Blob;
import org.gaul.s3proxy.blobstore.options.CreateContainerOptions;
import org.gaul.s3proxy.blobstore.options.PutOptions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.presigner.S3Presigner;
import software.amazon.awssdk.services.s3.presigner.model.GetObjectPresignRequest;

/**
 * A presigned URL signs through the query string, so an Authorization header
 * naming some other scheme -- a bearer token the client holds for an unrelated
 * service -- is not addressed to this proxy.  S3 ignores it and honours the
 * query string; refusing the request instead breaks a client that talks to
 * both through one HTTP stack.
 */
public final class PresignedForeignAuthTest {
    private static final String CONTENT = "blob-content";
    private static final String BLOB_NAME = "test";

    private S3Proxy s3Proxy;
    private BlobStore blobStore;
    private String containerName;
    private URI presignedGet;
    private final HttpClient httpClient = HttpClient.newHttpClient();

    @BeforeEach
    public void setUp() throws Exception {
        TestUtils.S3ProxyLaunchInfo info = TestUtils.startS3Proxy(
                "s3proxy.conf");
        s3Proxy = info.getS3Proxy();
        blobStore = info.getBlobStore();

        containerName = "container-" + new Random().nextInt(Integer.MAX_VALUE);
        blobStore.createContainer(containerName, CreateContainerOptions.NONE);
        ByteSource payload = ByteSource.wrap(
                CONTENT.getBytes(StandardCharsets.UTF_8));
        blobStore.putBlob(containerName, Blob.builder(BLOB_NAME)
                .payload(payload).contentLength(payload.size()).build(),
                PutOptions.NONE);

        var creds = StaticCredentialsProvider.create(AwsBasicCredentials.create(
                info.getS3Identity(), info.getS3Credential()));
        URI endpoint = URI.create(info.getEndpoint().toString() +
                info.getServicePath());
        try (S3Presigner presigner = S3Presigner.builder()
                .credentialsProvider(creds)
                .region(Region.US_EAST_1)
                .endpointOverride(endpoint)
                .serviceConfiguration(S3Configuration.builder()
                        .pathStyleAccessEnabled(true).build())
                .build()) {
            presignedGet = presigner.presignGetObject(
                    GetObjectPresignRequest.builder()
                            .signatureDuration(Duration.ofHours(1))
                            .getObjectRequest(b -> b.bucket(containerName)
                                    .key(BLOB_NAME))
                            .build()).url().toURI();
        }
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
        if (blobStore != null && containerName != null) {
            blobStore.removeBlob(containerName, BLOB_NAME);
            blobStore.deleteContainer(containerName);
        }
    }

    @Test
    public void testPresignedUrlAlone() throws Exception {
        HttpResponse<String> response = get(null);
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).isEqualTo(CONTENT);
    }

    @Test
    public void testPresignedUrlWithForeignAuthorizationHeader()
            throws Exception {
        HttpResponse<String> response = get("Bearer some-other-app-token");
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).isEqualTo(CONTENT);
    }

    /** Another scheme entirely, to show the check is not Bearer-specific. */
    @Test
    public void testPresignedUrlWithBasicAuthorizationHeader()
            throws Exception {
        HttpResponse<String> response = get("Basic dXNlcjpwYXNzd29yZA==");
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).isEqualTo(CONTENT);
    }

    /**
     * A header naming our own scheme is ours to check, so a malformed one is
     * an error rather than a signal to read the query string instead.
     */
    @Test
    public void testPresignedUrlWithMalformedAwsHeader() throws Exception {
        HttpResponse<String> response = get("AWS4-HMAC-SHA256 not-a-signature");
        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.body()).contains("InvalidArgument");
    }

    /** A foreign header must not turn an unsigned request into a signed one. */
    @Test
    public void testForeignAuthorizationHeaderWithoutPresigning()
            throws Exception {
        var uri = URI.create(presignedGet.toString().split("\\?")[0]);
        HttpResponse<String> response = httpClient.send(
                HttpRequest.newBuilder(uri)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer token")
                        .GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(403);
    }

    private HttpResponse<String> get(String authorization) throws Exception {
        var builder = HttpRequest.newBuilder(presignedGet).GET();
        if (authorization != null) {
            builder.header(HttpHeaders.AUTHORIZATION, authorization);
        }
        return httpClient.send(builder.build(),
                HttpResponse.BodyHandlers.ofString());
    }
}
