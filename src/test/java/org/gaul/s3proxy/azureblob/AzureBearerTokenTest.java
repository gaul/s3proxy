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
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import com.azure.core.http.HttpHeaderName;
import com.azure.core.http.HttpHeaders;
import com.azure.core.http.HttpRequest;
import com.azure.core.http.HttpResponse;
import com.google.common.base.Supplier;
import com.google.common.base.Suppliers;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.Credentials;
import org.junit.jupiter.api.Test;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import software.amazon.awssdk.services.s3.model.CopyObjectRequest;

/**
 * With {@code auth} set to {@code bearer} the session token is a Microsoft
 * Entra access token, presented as a bearer token.  These watch the
 * Authorization header each request carries rather than what the service
 * answers -- which is refused here on purpose, since only what was presented
 * is in question.  Nothing in a Credentials says how long the token lasts,
 * so S3Proxy asks the supplier again for every request.  The Azure client
 * sends bearer tokens only to an https endpoint, so the requests go to an
 * HttpClient supplied here rather than over a socket.
 */
public final class AzureBearerTokenTest {
    private final List<String> authorizations =
            Collections.synchronizedList(new ArrayList<String>());
    private final List<String> urls =
            Collections.synchronizedList(new ArrayList<String>());

    /** The token the supplier holds now is the one that is presented. */
    @Test
    public void testRequestCarriesTheBearerToken() {
        Supplier<Credentials> creds = Suppliers.ofInstance(new Credentials(
                /*identity=*/ "", /*credential=*/ "", "token"));

        try (BlobStore blobStore = store(creds)) {
            listRefusedByTheServer(blobStore);
        }

        assertThat(authorizations).containsExactly("Bearer token");
    }

    /** A token the supplier replaces gives way to its successor mid-flight. */
    @Test
    public void testBearerTokenFollowsTheSupplier() {
        var minted = new AtomicInteger();
        Supplier<Credentials> creds = () -> new Credentials(
                /*identity=*/ "", /*credential=*/ "",
                "token-" + minted.incrementAndGet());

        try (BlobStore blobStore = store(creds)) {
            listRefusedByTheServer(blobStore);
            listRefusedByTheServer(blobStore);
        }

        assertThat(authorizations).hasSize(2);
        assertThat(authorizations.get(0)).startsWith("Bearer token-");
        assertThat(authorizations.get(1)).isNotEqualTo(authorizations.get(0));
    }

    /**
     * A copy signs its source with a user delegation key, which the store
     * asks the service for under the same bearer token.
     */
    @Test
    public void testCopyAsksForAUserDelegationKey() {
        Supplier<Credentials> creds = Suppliers.ofInstance(new Credentials(
                /*identity=*/ "", /*credential=*/ "", "token"));

        try (BlobStore blobStore = store(creds)) {
            assertThat(catchThrowable(() -> blobStore.copyBlob(
                    CopyObjectRequest.builder()
                            .sourceBucket("from").sourceKey("blob")
                            .destinationBucket("to").destinationKey("blob")
                            .build()))).isNotNull();
        }

        assertThat(urls).hasSize(1);
        assertThat(urls.get(0)).contains("comp=userdelegationkey");
        assertThat(authorizations).containsExactly("Bearer token");
    }

    /** The jclouds spelling is not one of the modes. */
    @Test
    public void testUnknownAuthIsRefused() {
        Supplier<Credentials> creds = Suppliers.ofInstance(new Credentials(
                /*identity=*/ "", /*credential=*/ "", "token"));

        assertThatThrownBy(() -> new AzureBlobStore(creds,
                "https://127.0.0.1/devstoreaccount1", /*eTagMode=*/ "opaque",
                /*auth=*/ "azureAd"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("azureAd");
    }

    /** A mode named outright must find its credential, not fall through. */
    @Test
    public void testAuthMustMatchTheCredentials() {
        Supplier<Credentials> noToken = Suppliers.ofInstance(new Credentials(
                /*identity=*/ "account", /*credential=*/ "key"));
        Supplier<Credentials> noKey = Suppliers.ofInstance(new Credentials(
                /*identity=*/ "", /*credential=*/ "", "token"));

        assertThatThrownBy(() -> new AzureBlobStore(noToken,
                "https://127.0.0.1/devstoreaccount1", /*eTagMode=*/ "opaque",
                /*auth=*/ "bearer"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("session token");
        assertThatThrownBy(() -> new AzureBlobStore(noKey,
                "https://127.0.0.1/devstoreaccount1", /*eTagMode=*/ "opaque",
                /*auth=*/ "key"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("identity");
    }

    /**
     * Lists once, expecting the refusal the handler answers with: the
     * request is made for the sake of the header it carries.
     */
    private static void listRefusedByTheServer(BlobStore blobStore) {
        assertThat(catchThrowable(blobStore::list)).isNotNull();
    }

    private BlobStore store(Supplier<Credentials> creds) {
        return new AzureBlobStore(creds, "https://127.0.0.1/devstoreaccount1",
                /*eTagMode=*/ "opaque", /*auth=*/ "bearer", /*versioning=*/ false,
                this::refuse);
    }

    /** Records the Authorization header a request carries and refuses it. */
    private Mono<HttpResponse> refuse(HttpRequest request) {
        urls.add(request.getUrl().toString());
        authorizations.add(request.getHeaders().getValue(
                HttpHeaderName.AUTHORIZATION));
        return Mono.just(new Refusal(request));
    }

    /** The 403 Azure answers a request whose token it does not accept. */
    private static final class Refusal extends HttpResponse {
        private static final byte[] BODY = (
                "<?xml version=\"1.0\" encoding=\"utf-8\"?><Error>" +
                "<Code>AuthenticationFailed</Code><Message>token seen" +
                "</Message></Error>").getBytes(StandardCharsets.UTF_8);

        private final HttpHeaders headers = new HttpHeaders()
                .set(HttpHeaderName.fromString("x-ms-error-code"),
                        "AuthenticationFailed")
                .set(HttpHeaderName.CONTENT_TYPE, "application/xml");

        Refusal(HttpRequest request) {
            super(request);
        }

        @Override
        public int getStatusCode() {
            return 403;
        }

        // Abstract still, though superseded by the HttpHeaderName overload.
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
            return Flux.just(ByteBuffer.wrap(BODY));
        }

        @Override
        public Mono<byte[]> getBodyAsByteArray() {
            return Mono.just(BODY);
        }

        @Override
        public Mono<String> getBodyAsString() {
            return getBodyAsString(StandardCharsets.UTF_8);
        }

        @Override
        public Mono<String> getBodyAsString(Charset charset) {
            return Mono.just(new String(BODY, charset));
        }
    }
}
