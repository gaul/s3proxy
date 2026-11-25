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
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Properties;

import com.azure.core.http.HttpClient;
import com.azure.core.http.HttpHeaderName;
import com.azure.core.http.HttpHeaders;
import com.azure.core.http.HttpMethod;
import com.azure.core.http.HttpRequest;
import com.azure.core.http.HttpResponse;
import com.azure.storage.blob.BlobServiceClientBuilder;
import com.azure.storage.blob.specialized.BlobLeaseClientBuilder;
import com.azure.storage.common.StorageSharedKeyCredential;
import com.google.common.base.Suppliers;
import com.google.common.io.ByteSource;
import com.google.common.io.Resources;

import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.gaul.s3proxy.TestUtils;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.Constants;
import org.gaul.s3proxy.blobstore.Credentials;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.CompletedPart;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.services.s3.model.UploadPartRequest;

/**
 * Completing an upload on Azure commits a block list, and each way that
 * fails is answered with the code S3 gives it rather than the bare 400 an
 * IllegalArgumentException became, or the 500 of an Azure error passed on.
 * So is a write to a blob that an out-of-band lease holds.  Run
 * against Azurite, on the azureblob lane; a failure only the service
 * can produce is answered in its place by the HttpClient the store is
 * given, which passes every other request on.
 */
public final class AzureCompleteMultipartUploadTest {
    private final HttpClient azurite = HttpClient.createDefault();

    /** What Put Block List is answered with, when not passed on. */
    private volatile @Nullable Refusal commitRefusal;

    private final Properties properties = new Properties();
    private BlobStore blobStore;
    private String container;

    @BeforeEach
    public void setUp() throws IOException {
        assumeTrue(TestUtils.testBlobStoreProvider().equals("azureblob"));
        try (InputStream is = Resources.asByteSource(Resources.getResource(
                System.getProperty("s3proxy.test.conf"))).openStream()) {
            properties.load(is);
        }
        blobStore = new AzureBlobStore(
                Suppliers.ofInstance(new Credentials(
                        properties.getProperty(Constants.PROPERTY_IDENTITY),
                        properties.getProperty(Constants.PROPERTY_CREDENTIAL))),
                properties.getProperty(Constants.PROPERTY_ENDPOINT),
                /*eTagMode=*/ "opaque", /*auth=*/ null, /*versioning=*/ false,
                this::send);
        container = TestUtils.createRandomContainerName();
        blobStore.createContainer(container);
    }

    @AfterEach
    public void tearDown() {
        if (blobStore != null) {
            blobStore.deleteContainer(container);
            blobStore.close();
        }
    }

    /**
     * A part never uploaded, to a key nothing holds: Azure has no blob to
     * list the blocks of and answers 404, which was passed on as a 500.
     */
    @Test
    public void testPartNeverUploadedIsInvalidPart() {
        var mpu = blobStore.initiateMultipartUpload(
                CreateMultipartUploadRequest.builder()
                        .bucket(container).key("key").build());

        assertThatThrownBy(() -> blobStore.completeMultipartUpload(mpu,
                complete(1)))
                .isInstanceOfSatisfying(S3Exception.class, e -> {
                    assertThat(e.statusCode()).isEqualTo(400);
                    assertThat(e.awsErrorDetails().errorCode())
                            .isEqualTo("InvalidPart");
                });
    }

    /** A bucket name S3 takes and Azure does not. */
    @Test
    public void testNameAzureRefusesIsInvalidBucketName() {
        for (String name : List.of(container + ".dot",
                container + "--dash")) {
            assertThatThrownBy(() -> blobStore.createContainer(name))
                    .as(name)
                    .isInstanceOfSatisfying(S3Exception.class, e -> {
                        assertThat(e.statusCode()).isEqualTo(400);
                        assertThat(e.awsErrorDetails().errorCode())
                                .isEqualTo("InvalidBucketName");
                    });
        }
    }

    /**
     * Another operation in the way of the commit, a snapshot being taken,
     * makes Azure answer it 409; S3's word for it is OperationAborted.
     */
    @Test
    public void testCommitConflictIsOperationAborted() {
        commitRefusal = new Refusal(409, "SnapshotOperationRateExceeded");

        assertThatThrownBy(() -> blobStore.completeMultipartUpload(
                uploadOnePart(), complete(1)))
                .isInstanceOfSatisfying(S3Exception.class, e -> {
                    assertThat(e.statusCode()).isEqualTo(409);
                    assertThat(e.awsErrorDetails().errorCode())
                            .isEqualTo("OperationAborted");
                });
    }

    /** The container gone between finding the upload and committing it. */
    @Test
    public void testContainerGoneAtCommitIsNoSuchUpload() {
        commitRefusal = new Refusal(404, "ContainerNotFound");

        assertThatThrownBy(() -> blobStore.completeMultipartUpload(
                uploadOnePart(), complete(1)))
                .isInstanceOfSatisfying(S3Exception.class, e -> {
                    assertThat(e.statusCode()).isEqualTo(404);
                    assertThat(e.awsErrorDetails().errorCode())
                            .isEqualTo("NoSuchUpload");
                });
    }

    /**
     * A lease taken out of band holds the blob, and S3Proxy, which takes
     * none, cannot name it: Azure refuses each write 412 LeaseIdMissing,
     * which was passed on as a 500.  S3 has no leases; its word for a write
     * that lost to another holder is OperationAborted.
     */
    @Test
    public void testLeasedBlobIsOperationAborted() throws Exception {
        byte[] content = "leased".getBytes(StandardCharsets.UTF_8);
        TestUtils.putBlob(blobStore, container, "key",
                ByteSource.wrap(content));
        var lease = new BlobLeaseClientBuilder()
                .blobClient(new BlobServiceClientBuilder()
                        .endpoint(properties.getProperty(
                                Constants.PROPERTY_ENDPOINT))
                        .credential(new StorageSharedKeyCredential(
                                properties.getProperty(
                                        Constants.PROPERTY_IDENTITY),
                                properties.getProperty(
                                        Constants.PROPERTY_CREDENTIAL)))
                        .buildClient()
                        .getBlobContainerClient(container)
                        .getBlobClient("key"))
                .buildClient();
        lease.acquireLease(/*duration=*/ -1);
        try {
            for (ThrowingCallable write : List.<ThrowingCallable>of(
                    () -> TestUtils.putBlob(blobStore, container, "key",
                            ByteSource.wrap(content)),
                    this::uploadOnePart)) {
                assertThatThrownBy(write)
                        .isInstanceOfSatisfying(S3Exception.class, e -> {
                            assertThat(e.statusCode()).isEqualTo(409);
                            assertThat(e.awsErrorDetails().errorCode())
                                    .isEqualTo("OperationAborted");
                        });
            }
        } finally {
            lease.breakLease();
        }
    }

    private MultipartUpload uploadOnePart() {
        var mpu = blobStore.initiateMultipartUpload(
                CreateMultipartUploadRequest.builder()
                        .bucket(container).key("key").build());
        byte[] content = "part".getBytes(StandardCharsets.UTF_8);
        blobStore.uploadMultipartPart(mpu, UploadPartRequest.builder()
                .bucket(container).key("key").uploadId(mpu.id())
                .partNumber(1).contentLength((long) content.length).build(),
                new ByteArrayInputStream(content));
        return mpu;
    }

    private CompleteMultipartUploadRequest complete(int partNumber) {
        return CompleteMultipartUploadRequest.builder()
                .bucket(container).key("key")
                .multipartUpload(m -> m.parts(CompletedPart.builder()
                        .partNumber(partNumber).build()))
                .build();
    }

    private Mono<HttpResponse> send(HttpRequest request) {
        Refusal refusal = commitRefusal;
        String query = request.getUrl().getQuery();
        if (refusal != null && request.getHttpMethod() == HttpMethod.PUT &&
                query != null && query.contains("comp=blocklist")) {
            return Mono.just(refusal.toResponse(request));
        }
        return azurite.send(request);
    }

    /** An Azure error, by status and x-ms-error-code. */
    private record Refusal(int statusCode, String errorCode) {
        HttpResponse toResponse(HttpRequest request) {
            byte[] body = ("<?xml version=\"1.0\" encoding=\"utf-8\"?>" +
                    "<Error><Code>" + errorCode + "</Code><Message>refused" +
                    "</Message></Error>").getBytes(StandardCharsets.UTF_8);
            var headers = new HttpHeaders()
                    .set(HttpHeaderName.fromString("x-ms-error-code"),
                            errorCode)
                    .set(HttpHeaderName.CONTENT_TYPE, "application/xml");
            return new HttpResponse(request) {
                @Override
                public int getStatusCode() {
                    return statusCode;
                }

                // Abstract still, though superseded by the HttpHeaderName
                // overload.
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
            };
        }
    }
}
