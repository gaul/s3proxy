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

import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import org.gaul.s3proxy.auth.AuthenticationType;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.ForwardingBlobStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.BucketCannedACL;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;

/**
 * A store either performs the encryption the x-amz-server-side-encryption
 * family names or must not be handed those headers, and which of the two it
 * is does not depend on who is asking.  doHandle refuses them to a store that
 * cannot encrypt; the anonymous path did not ask, so an unsigned write to a
 * public-write bucket asked for encryption, was answered success, and left
 * the plaintext stored.
 */
public final class AnonymousServerSideEncryptionTest {
    private static final String CONTAINER = "public-container";
    private static final String CONTENT = "anonymous-upload";
    private static final String CUSTOMER_ALGORITHM =
            "x-amz-server-side-encryption-customer-algorithm";

    /** A backend that does not encrypt, as the interface's default says. */
    private static final class NoEncryptionBlobStore
            extends ForwardingBlobStore {
        NoEncryptionBlobStore(BlobStore delegate) {
            super(delegate);
        }

        @Override
        public boolean supportsServerSideEncryption() {
            return false;
        }

        /** One that does not understand the fields drops them. */
        @Override
        public PutObjectResponse putBlob(PutObjectRequest request,
                InputStream payload) {
            return super.putBlob(request.toBuilder()
                    .serverSideEncryption((String) null)
                    .ssekmsKeyId(null)
                    .sseCustomerAlgorithm(null)
                    .sseCustomerKey(null)
                    .sseCustomerKeyMD5(null)
                    .build(), payload);
        }
    }

    private S3Proxy s3Proxy;
    private BlobStore blobStore;
    private String baseUri;
    private final HttpClient httpClient = HttpClient.newHttpClient();

    @BeforeEach
    public void setUp() throws Exception {
        blobStore = new NoEncryptionBlobStore(
                TestUtils.createTransientBlobStore());
        blobStore.createContainer(CONTAINER);
        blobStore.setContainerAccess(CONTAINER,
                BucketCannedACL.PUBLIC_READ_WRITE);

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

    /** The write the bucket grants, asking for nothing the store cannot do. */
    @Test
    public void testAnonymousPutWithoutEncryptionSucceeds() throws Exception {
        HttpResponse<String> response = put("plain");
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(blobStore.blobExists(CONTAINER, "plain")).isTrue();
    }

    /**
     * Asking a store that cannot encrypt is refused, and nothing is stored:
     * a success here would be a claim of an encryption nobody performed.
     */
    @Test
    public void testAnonymousPutWithEncryptionRefused() throws Exception {
        HttpResponse<String> response = put("encrypted",
                "x-amz-server-side-encryption", "AES256");
        System.err.println("anonymous SSE: " + response.statusCode() + " " +
                response.body());
        assertThat(response.statusCode()).isEqualTo(501);
        assertThat(response.body()).contains("NotImplemented");
        assertThat(blobStore.blobExists(CONTAINER, "encrypted")).isFalse();
    }

    /** The customer-key family is refused the same way. */
    @Test
    public void testAnonymousPutWithCustomerKeyRefused() throws Exception {
        HttpResponse<String> response = put("customer-key",
                CUSTOMER_ALGORITHM, "AES256");
        assertThat(response.statusCode()).isEqualTo(501);
        assertThat(blobStore.blobExists(CONTAINER, "customer-key")).isFalse();
    }

    /** So is a read presenting them, which would read around the key. */
    @Test
    public void testAnonymousGetWithCustomerKeyRefused() throws Exception {
        put("readable");
        HttpResponse<String> response = httpClient.send(
                HttpRequest.newBuilder(URI.create(baseUri + CONTAINER +
                                "/readable"))
                        .header(CUSTOMER_ALGORITHM, "AES256")
                        .GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(501);
    }

    private HttpResponse<String> put(String key, String... headers)
            throws Exception {
        var builder = HttpRequest.newBuilder(
                        URI.create(baseUri + CONTAINER + "/" + key))
                .PUT(HttpRequest.BodyPublishers.ofString(CONTENT));
        for (int i = 0; i < headers.length; i += 2) {
            builder.header(headers[i], headers[i + 1]);
        }
        return httpClient.send(builder.build(),
                HttpResponse.BodyHandlers.ofString());
    }
}
