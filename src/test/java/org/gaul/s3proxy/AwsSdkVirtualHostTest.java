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
import java.net.URL;
import java.time.Duration;

import com.google.common.io.ByteSource;

import org.apache.http.HttpHost;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.domain.Blob;
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
 * Exercise AWS V4 signatures for virtual host (DNS / host) style requests,
 * where the bucket is carried in the Host header rather than the path.  The
 * proxy must compute the signature over the request path <em>without</em> the
 * bucket prepended; see commit 9d21a73 and
 * <a href="https://github.com/gaul/s3proxy/issues/845">issue 845</a>.
 */
public final class AwsSdkVirtualHostTest {
    private static final ByteSource BYTE_SOURCE =
            ByteSource.wrap(new byte[1]);

    private S3Proxy s3Proxy;
    private BlobStore blobStore;
    private URI endpoint;
    private String virtualHost;
    private AwsBasicCredentials awsCreds;
    private String containerName;

    @BeforeEach
    public void setUp() throws Exception {
        TestUtils.S3ProxyLaunchInfo info = TestUtils.startS3Proxy(
                "s3proxy-virtual-host.conf");
        awsCreds = AwsBasicCredentials.create(info.getS3Identity(),
                info.getS3Credential());
        blobStore = info.getBlobStore();
        s3Proxy = info.getS3Proxy();
        endpoint = info.getEndpoint();
        virtualHost = info.getProperties().getProperty(
                S3ProxyConstants.PROPERTY_VIRTUAL_HOST);
        assertThat(virtualHost).isNotEmpty();

        containerName = AwsSdkTest.createRandomContainerName();
        info.getBlobStore().createContainer(containerName);
        Blob blob = Blob.builder("foo")
                .payload(BYTE_SOURCE).contentLength(BYTE_SOURCE.size()).build();
        info.getBlobStore().putBlob(containerName, blob);
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
        if (blobStore != null) {
            blobStore.deleteContainer(containerName);
        }
    }

    @Test
    public void testAwsV4VirtualHostUrlSigning() throws Exception {
        int port = endpoint.getPort();
        URL url;
        try (S3Presigner presigner = S3Presigner.builder()
                .credentialsProvider(StaticCredentialsProvider.create(awsCreds))
                .region(Region.US_EAST_1)
                .endpointOverride(URI.create(
                        "http://" + virtualHost + ":" + port))
                .serviceConfiguration(S3Configuration.builder()
                        .pathStyleAccessEnabled(false)
                        .build())
                .build()) {
            url = presigner.presignGetObject(
                    GetObjectPresignRequest.builder()
                            .signatureDuration(Duration.ofHours(1))
                            .getObjectRequest(b -> b.bucket(containerName)
                                    .key("foo"))
                            .build()).url();
        }

        // The SDK must address the bucket as a Host subdomain so that the
        // signed canonical URI is the bare object path "/foo".
        assertThat(url.getHost()).isEqualTo(containerName + "." + virtualHost);
        assertThat(url.getPath()).isEqualTo("/foo");

        // Replay the signed request to the proxy's loopback address while
        // sending the bucket-subdomain Host header that was signed.  This
        // avoids resolving bucket.s3.test in DNS.
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpHost target = new HttpHost("127.0.0.1", port, "http");
            HttpGet request = new HttpGet(
                    url.getPath() + "?" + url.getQuery());
            request.setHeader("Host", url.getAuthority());
            try (CloseableHttpResponse response =
                    httpClient.execute(target, request)) {
                assertThat(response.getStatusLine().getStatusCode())
                        .isEqualTo(HttpStatus.SC_OK);
                assertThat(EntityUtils.toByteArray(response.getEntity()))
                        .isEqualTo(BYTE_SOURCE.read());
            }
        }
    }
}
