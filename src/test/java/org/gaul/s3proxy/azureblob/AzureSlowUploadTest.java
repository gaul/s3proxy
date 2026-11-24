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

import java.io.ByteArrayInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

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
import reactor.core.scheduler.Schedulers;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;

/**
 * The body of an upload is read from its client with blocking reads, and
 * the client decides how long each one takes.  A client that sends slowly,
 * or stops sending, may hold up its own upload but nobody else's.  The
 * requests go to an HttpClient supplied here, which reads every body to its
 * end as the service does.
 */
public final class AzureSlowUploadTest {
    private static final byte[] BODY = "body".getBytes(StandardCharsets.UTF_8);

    /**
     * As many uploads stall as Reactor's shared pool for blocking work has
     * threads, which is where the bodies were once read: the next upload
     * then waited for one of the stalled clients.
     */
    @Test
    public void testStalledUploadsDoNotHoldUpAnother() throws Exception {
        int stalled = Schedulers.DEFAULT_BOUNDED_ELASTIC_SIZE;
        var reading = new CountDownLatch(stalled);
        var resume = new CountDownLatch(1);
        var executor = Executors.newCachedThreadPool();
        Supplier<Credentials> creds = Suppliers.ofInstance(new Credentials(
                /*identity=*/ "account", /*credential=*/ "a2V5"));

        try (BlobStore blobStore = new AzureBlobStore(creds,
                "http://127.0.0.1/account", /*eTagMode=*/ "opaque",
                /*auth=*/ "key", /*versioning=*/ false,
                AzureSlowUploadTest::store)) {
            var uploads = new ArrayList<Future<PutObjectResponse>>();
            for (int i = 0; i < stalled; ++i) {
                uploads.add(executor.submit(() -> put(blobStore, "slow",
                        new StalledInputStream(reading, resume))));
            }
            assertThat(reading.await(30, TimeUnit.SECONDS))
                    .as("every stalled upload is being read").isTrue();

            var other = executor.submit(() -> put(blobStore, "other",
                    new ByteArrayInputStream(BODY)));
            assertThat(other.get(30, TimeUnit.SECONDS).eTag()).isNotNull();

            resume.countDown();
            for (var upload : uploads) {
                assertThat(upload.get(30, TimeUnit.SECONDS).eTag())
                        .isNotNull();
            }
        } finally {
            resume.countDown();
            executor.shutdownNow();
        }
    }

    private static PutObjectResponse put(BlobStore blobStore,
            String container, InputStream body) {
        return blobStore.putBlob(PutObjectRequest.builder()
                .bucket(container).key("blob")
                .contentLength((long) BODY.length)
                .build(), body);
    }

    /** Answers 201 once it has read all of the request's body. */
    private static Mono<HttpResponse> store(HttpRequest request) {
        return request.getBody().then(Mono.just(new Created(request)));
    }

    /** A client that has more to send, but not before it is resumed. */
    private static final class StalledInputStream extends FilterInputStream {
        private final CountDownLatch reading;
        private final CountDownLatch resume;

        StalledInputStream(CountDownLatch reading, CountDownLatch resume) {
            super(new ByteArrayInputStream(BODY));
            this.reading = reading;
            this.resume = resume;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            reading.countDown();
            try {
                resume.await();
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                throw new InterruptedIOException();
            }
            return super.read(b, off, len);
        }
    }

    /** The 201 Azure answers a Put Blob. */
    private static final class Created extends HttpResponse {
        private final HttpHeaders headers = new HttpHeaders()
                .set(HttpHeaderName.ETAG, "\"0x1\"")
                .set(HttpHeaderName.fromString(
                        "x-ms-request-server-encrypted"), "true");

        Created(HttpRequest request) {
            super(request);
        }

        @Override
        public int getStatusCode() {
            return 201;
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
    }
}
