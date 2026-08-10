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

package org.gaul.s3proxy.azureblob;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;

import com.azure.core.http.HttpHeaderName;
import com.azure.core.http.HttpHeaders;
import com.azure.core.http.HttpMethod;
import com.azure.core.http.HttpRequest;
import com.azure.core.http.HttpResponse;
import com.azure.storage.blob.models.BlobStorageException;

import org.junit.jupiter.api.Test;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import software.amazon.awssdk.services.s3.model.S3Exception;

/**
 * Azure refuses a keyless read of a blob resting under a customer-provided
 * key with 409 BlobUsesCustomerSpecifiedEncryption.  S3Proxy refuses to
 * write such blobs, but they can exist out of band, and S3 phrases the
 * same refusal as 400 InvalidRequest, which is what S3 clients key their
 * retry-with-key logic off.  Azurite cannot store a blob under a customer
 * key, so the translation is exercised on a synthesized service error.
 */
public final class AzureBlobStoreTranslateTest {
    @Test
    public void testKeylessReadOfCustomerKeyBlob() {
        RuntimeException translated = AzureBlobStore.translate(
                azureException(409, "BlobUsesCustomerSpecifiedEncryption"),
                "container", "key");

        assertThat(translated).isInstanceOfSatisfying(S3Exception.class,
                e -> {
                    assertThat(e.statusCode()).isEqualTo(400);
                    assertThat(e.awsErrorDetails().errorCode())
                            .isEqualTo("InvalidRequest");
                    assertThat(e.awsErrorDetails().errorMessage()).contains(
                            "stored using a form of Server Side Encryption");
                });
    }

    /** An Azure service error as the SDK would raise it. */
    private static BlobStorageException azureException(int statusCode,
            String errorCode) {
        var headers = new HttpHeaders().set(
                HttpHeaderName.fromString("x-ms-error-code"), errorCode);
        var request = new HttpRequest(HttpMethod.HEAD,
                "https://account.blob.example.com/container/key");
        var response = new HttpResponse(request) {
            @Override
            public int getStatusCode() {
                return statusCode;
            }

            // The abstract method is deprecated but must be implemented.
            @SuppressWarnings("deprecation")
            @Override
            public String getHeaderValue(String name) {
                return headers.getValue(HttpHeaderName.fromString(name));
            }

            @Override
            public HttpHeaders getHeaders() {
                return headers;
            }

            @Override
            public Flux<ByteBuffer> getBody() {
                return Flux.empty();
            }

            @Override
            public Mono<byte[]> getBodyAsByteArray() {
                return Mono.just(new byte[0]);
            }

            @Override
            public Mono<String> getBodyAsString() {
                return Mono.just("");
            }

            @Override
            public Mono<String> getBodyAsString(Charset charset) {
                return Mono.just("");
            }
        };
        return new BlobStorageException(
                "customer key required", response, /*value=*/ null);
    }
}
