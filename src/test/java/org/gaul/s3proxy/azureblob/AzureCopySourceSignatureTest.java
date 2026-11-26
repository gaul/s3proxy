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
import static org.assertj.core.api.Assertions.catchThrowable;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.azure.core.http.HttpHeaderName;
import com.azure.core.http.HttpHeaders;
import com.azure.core.http.HttpRequest;
import com.azure.core.http.HttpResponse;
import com.azure.storage.blob.models.BlobErrorCode;
import com.azure.storage.blob.models.BlobStorageException;
import com.google.common.base.Suppliers;
import com.google.common.base.Throwables;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.Credentials;
import org.gaul.s3proxy.blobstore.UploadNames;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.junit.jupiter.api.Test;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import software.amazon.awssdk.services.s3.model.CopyObjectRequest;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.services.s3.model.UploadPartCopyRequest;

/**
 * A copy names its source to Azure by a signed URL in a header, and a store
 * that authenticates with a shared access signature signs it with the one
 * it presents everywhere else.  Azure quotes a header it rejects in its
 * error document, which the client makes the message of its exception.
 * These refuse the copy that way and read what leaves the store, as Jetty
 * logs it: the refusal, without the signature.
 */
public final class AzureCopySourceSignatureTest {
    private static final HttpHeaderName COPY_SOURCE =
            HttpHeaderName.fromString("x-ms-copy-source");
    private static final HttpHeaderName ERROR_CODE =
            HttpHeaderName.fromString("x-ms-error-code");
    private static final CopyObjectRequest COPY = CopyObjectRequest.builder()
            .sourceBucket("from").sourceKey("blob")
            .destinationBucket("to").destinationKey("blob")
            .build();

    private final List<String> copySources =
            Collections.synchronizedList(new ArrayList<String>());
    /** How the service refuses a copy, quoting the source it was handed. */
    private int refusalStatus = 400;
    private String refusalCode = "InvalidHeaderValue";
    /** As Azurite before 3.38.0 answers Put Blob From URL. */
    private boolean putBlobFromUrlNotImplemented;

    /** Put Blob From URL, which is how an object is copied. */
    @Test
    public void testRefusedCopy() {
        Throwable thrown;
        try (BlobStore blobStore = store()) {
            thrown = catchThrowable(() -> blobStore.copyBlob(COPY));
        }

        assertThat(copySources).hasSize(1);
        assertRefusedWithoutTheSignature(thrown);
    }

    /** Copy Blob, which is how an object is copied where that is missing. */
    @Test
    public void testRefusedFallbackCopy() {
        putBlobFromUrlNotImplemented = true;

        Throwable thrown;
        try (BlobStore blobStore = store()) {
            thrown = catchThrowable(() -> blobStore.copyBlob(COPY));
        }

        assertThat(copySources).hasSize(2);
        assertRefusedWithoutTheSignature(thrown);
    }

    /** Put Block From URL, which is how a part is copied. */
    @Test
    public void testRefusedPartCopy() {
        var mpu = new MultipartUpload(UploadNames.newUploadId("blob"),
                CreateMultipartUploadRequest.builder()
                        .bucket("to").key("blob")
                        .build());

        Throwable thrown;
        try (BlobStore blobStore = store()) {
            thrown = catchThrowable(() -> blobStore.copyMultipartPart(mpu,
                    UploadPartCopyRequest.builder()
                            .sourceBucket("from").sourceKey("blob")
                            .destinationBucket("to").destinationKey("blob")
                            .uploadId(mpu.id()).partNumber(1)
                            .build()));
        }

        assertThat(copySources).hasSize(1);
        assertRefusedWithoutTheSignature(thrown);
    }

    /**
     * A refusal the store translates keeps Azure's as its cause, which is
     * logged wherever the translation is.
     */
    @Test
    public void testRefusedCopyThatIsTranslated() {
        refusalStatus = 403;
        refusalCode = "CannotVerifyCopySource";

        Throwable thrown;
        try (BlobStore blobStore = store()) {
            thrown = catchThrowable(() -> blobStore.copyBlob(COPY));
        }

        assertThat(copySources).hasSize(1);
        assertThat(copySources.get(0)).contains("sig=secret");
        assertThat(thrown).isInstanceOfSatisfying(S3Exception.class,
                e -> assertThat(e.statusCode()).isEqualTo(403));
        assertThat(thrown).hasCauseInstanceOf(BlobStorageException.class);
        assertThat(Throwables.getStackTraceAsString(thrown))
                .contains("CannotVerifyCopySource")
                .doesNotContain("sig=secret");
    }

    /**
     * The service was handed the signature and refused the copy, and the
     * refusal says which it was but not what the service quoted.
     */
    private void assertRefusedWithoutTheSignature(Throwable thrown) {
        assertThat(copySources).allSatisfy(
                copySource -> assertThat(copySource).contains("sig=secret"));
        // S3's word for the refusal, carrying Azure's for the log
        assertThat(thrown).isInstanceOfSatisfying(S3Exception.class, e -> {
            assertThat(e.statusCode()).isEqualTo(400);
            assertThat(e.awsErrorDetails().errorCode())
                    .isEqualTo("InvalidRequest");
        });
        assertThat(thrown.getCause()).isInstanceOfSatisfying(
                BlobStorageException.class, bse -> {
                    assertThat(bse.getStatusCode()).isEqualTo(400);
                    assertThat(bse.getErrorCode()).isEqualTo(
                            BlobErrorCode.INVALID_HEADER_VALUE);
                });
        assertThat(Throwables.getStackTraceAsString(thrown))
                .contains("InvalidHeaderValue")
                .doesNotContain("sig=secret");
    }

    private BlobStore store() {
        return new AzureBlobStore(Suppliers.ofInstance(new Credentials(
                /*identity=*/ "", /*credential=*/ "",
                "sv=2026-02-06&sig=secret")),
                "http://127.0.0.1/devstoreaccount1", /*eTagMode=*/ "opaque",
                /*auth=*/ null, /*versioning=*/ false, this::answer);
    }

    /** Stands in for the service: refuses a copy as Azure would. */
    private Mono<HttpResponse> answer(HttpRequest request) {
        String copySource = request.getHeaders().getValue(COPY_SOURCE);
        if (copySource == null) {
            // The multipart stub, which a part copy looks for first.
            return Mono.just(new Answer(request, 200, new HttpHeaders()
                    .set(HttpHeaderName.fromString(
                            "x-ms-meta-s3proxy_target_blob_name"), "YmxvYg"),
                    /*body=*/ ""));
        }
        copySources.add(copySource);
        if (putBlobFromUrlNotImplemented && request.getHeaders().getValue(
                HttpHeaderName.fromString("x-ms-blob-type")) != null) {
            return Mono.just(new Answer(request, 501, new HttpHeaders()
                    .set(ERROR_CODE, "APINotImplemented"),
                    "<?xml version=\"1.0\" encoding=\"utf-8\"?><Error>" +
                    "<Code>APINotImplemented</Code><Message>Current API is" +
                    " not implemented yet.</Message></Error>"));
        }
        return Mono.just(new Answer(request, refusalStatus, new HttpHeaders()
                .set(ERROR_CODE, refusalCode),
                "<?xml version=\"1.0\" encoding=\"utf-8\"?><Error><Code>" +
                refusalCode + "</Code><Message>The value for one of the" +
                " HTTP headers is not in the correct format.</Message>" +
                "<HeaderName>x-ms-copy-source</HeaderName><HeaderValue>" +
                copySource.replace("&", "&amp;") + "</HeaderValue></Error>"));
    }

    /** What the service answers, with an XML body if it has one. */
    private static final class Answer extends HttpResponse {
        private final int statusCode;
        private final HttpHeaders headers;
        private final byte[] body;

        Answer(HttpRequest request, int statusCode, HttpHeaders headers,
                String body) {
            super(request);
            this.statusCode = statusCode;
            this.headers = headers
                    .set(HttpHeaderName.CONTENT_TYPE, "application/xml");
            this.body = body.getBytes(StandardCharsets.UTF_8);
        }

        @Override
        public int getStatusCode() {
            return statusCode;
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
            return Flux.just(ByteBuffer.wrap(body));
        }

        @Override
        public Mono<byte[]> getBodyAsByteArray() {
            return Mono.just(body);
        }

        @Override
        public Mono<String> getBodyAsString() {
            return getBodyAsString(StandardCharsets.UTF_8);
        }

        @Override
        public Mono<String> getBodyAsString(Charset charset) {
            return Mono.just(new String(body, charset));
        }
    }
}
