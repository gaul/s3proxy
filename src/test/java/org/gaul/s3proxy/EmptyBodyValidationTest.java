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
import java.util.Random;

import org.gaul.s3proxy.auth.AuthenticationType;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.ForwardingBlobStore;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.awssdk.services.s3.model.UploadPartRequest;
import software.amazon.awssdk.services.s3.model.UploadPartResponse;

/**
 * An empty body is checked against the checksum sent with it.  The check
 * runs as the body is read, and a store handed no bytes to store may never
 * read: the one here does not, standing in for a backend SDK that skips the
 * stream of a zero-length upload.
 */
public final class EmptyBodyValidationTest {
    /** CRC32 of no bytes, and a value that is not. */
    private static final String RIGHT = "AAAAAA==";
    private static final String WRONG = "AAAAAQ==";

    private S3Proxy s3Proxy;
    private String bucket;
    private String baseUri;
    private final HttpClient httpClient = HttpClient.newHttpClient();

    @BeforeEach
    public void setUp() throws Exception {
        BlobStore blobStore = TestUtils.createTransientBlobStore();
        bucket = "bucket-" + new Random().nextInt(Integer.MAX_VALUE);
        blobStore.createContainer(bucket);
        BlobStore unreading = new ForwardingBlobStore(blobStore) {
            @Override
            public PutObjectResponse putBlob(PutObjectRequest request,
                    InputStream payload) {
                return super.putBlob(request, request.contentLength() == 0 ?
                        InputStream.nullInputStream() : payload);
            }

            @Override
            public UploadPartResponse uploadMultipartPart(MultipartUpload mpu,
                    UploadPartRequest request, InputStream is) {
                return super.uploadMultipartPart(mpu, request,
                        request.contentLength() == 0 ?
                        InputStream.nullInputStream() : is);
            }
        };

        s3Proxy = S3Proxy.builder()
                .stopTimeout(0)
                .blobStore(unreading)
                .awsAuthentication(AuthenticationType.NONE, null, null)
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

    @Test
    public void testEmptyObject() throws Exception {
        var wrong = put(bucket + "/empty", WRONG);
        assertThat(wrong.statusCode()).isEqualTo(400);
        assertThat(wrong.body()).contains("BadDigest");
        assertThat(put(bucket + "/empty", RIGHT).statusCode()).isEqualTo(200);
    }

    @Test
    public void testEmptyPart() throws Exception {
        var create = httpClient.send(
                HttpRequest.newBuilder(URI.create(baseUri + bucket +
                        "/key?uploads"))
                        .POST(HttpRequest.BodyPublishers.noBody()).build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(create.statusCode()).isEqualTo(200);
        String uploadId = create.body().replaceAll(
                "(?s).*<UploadId>(.*)</UploadId>.*", "$1");
        String part = bucket + "/key?partNumber=1&uploadId=" + uploadId;

        var wrong = put(part, WRONG);
        assertThat(wrong.statusCode()).isEqualTo(400);
        assertThat(wrong.body()).contains("BadDigest");
        assertThat(put(part, RIGHT).statusCode()).isEqualTo(200);
    }

    private HttpResponse<String> put(String pathAndQuery, String crc32)
            throws Exception {
        return httpClient.send(
                HttpRequest.newBuilder(URI.create(baseUri + pathAndQuery))
                        .header("x-amz-checksum-crc32", crc32)
                        .PUT(HttpRequest.BodyPublishers.noBody())
                        .build(),
                HttpResponse.BodyHandlers.ofString());
    }
}
