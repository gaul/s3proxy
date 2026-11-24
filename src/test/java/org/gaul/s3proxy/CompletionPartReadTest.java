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
import java.util.Base64;
import java.util.concurrent.atomic.AtomicInteger;

import com.google.common.hash.Hashing;

import org.gaul.s3proxy.auth.AuthenticationType;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.ForwardingBlobStore;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;

/**
 * A completion that the request alone refuses is refused before the parts
 * are read or assembled.  On the stores that keep their parts, reading them
 * costs the whole upload, and a completion bound to fail -- a part's
 * checksum left out, an If-None-Match: * over an existing object -- could be
 * repeated by whoever held its URL, each paying that again.
 */
public final class CompletionPartReadTest {
    private static final String CONTAINER = "container";
    private static final byte[] PART =
            "part\n".getBytes(StandardCharsets.UTF_8);
    /** S3 refuses a part under 5 MB unless it is the last one. */
    private static final byte[] FIRST_PART = new byte[5 * 1024 * 1024];

    private S3Proxy s3Proxy;
    private Counting blobStore;
    private String base;
    private final HttpClient httpClient = HttpClient.newHttpClient();

    /** Counts the parts read back and the completions handed on. */
    private static final class Counting extends ForwardingBlobStore {
        private final AtomicInteger partReads = new AtomicInteger();
        private final AtomicInteger completions = new AtomicInteger();

        Counting(BlobStore delegate) {
            super(delegate);
        }

        @Override
        public ResponseInputStream<GetObjectResponse> getMultipartPart(
                MultipartUpload mpu, int partNumber) {
            partReads.incrementAndGet();
            return super.getMultipartPart(mpu, partNumber);
        }

        @Override
        public CompleteMultipartUploadResponse completeMultipartUpload(
                MultipartUpload mpu, CompleteMultipartUploadRequest request) {
            completions.incrementAndGet();
            return super.completeMultipartUpload(mpu, request);
        }
    }

    @BeforeEach
    public void setUp() throws Exception {
        BlobStore backing = TestUtils.createTransientBlobStore();
        backing.createContainer(CONTAINER);
        blobStore = new Counting(backing);
        s3Proxy = S3Proxy.builder()
                .stopTimeout(0)
                .blobStore(blobStore)
                .awsAuthentication(AuthenticationType.NONE, null, null)
                .endpoint(URI.create("http://127.0.0.1:0"))
                .build();
        s3Proxy.start();
        while (!s3Proxy.getState().equals("STARTED")) {
            Thread.sleep(10);
        }
        base = "http://127.0.0.1:" + s3Proxy.getPort() + "/" + CONTAINER;
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
    }

    @Test
    public void testMissingPartChecksumRefusedWithoutReading()
            throws Exception {
        String uploadId = initiate("object", "SHA256");
        String eTag1 = uploadPart("object", uploadId, 1, FIRST_PART);
        String eTag2 = uploadPart("object", uploadId, 2, PART);

        // the first part names its checksum, the second leaves it out
        String xml = "<CompleteMultipartUpload>" +
                "<Part><PartNumber>1</PartNumber><ETag>" + eTag1 +
                "</ETag><ChecksumSHA256>" + Base64.getEncoder()
                        .encodeToString(Hashing.sha256().hashBytes(FIRST_PART)
                                .asBytes()) + "</ChecksumSHA256></Part>" +
                "<Part><PartNumber>2</PartNumber><ETag>" + eTag2 +
                "</ETag></Part></CompleteMultipartUpload>";
        HttpResponse<String> response = send(HttpRequest.newBuilder(
                URI.create(base + "/object?uploadId=" + uploadId))
                .POST(HttpRequest.BodyPublishers.ofString(xml)));
        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.body()).contains("InvalidRequest");
        assertThat(blobStore.partReads.get()).isZero();
        assertThat(blobStore.completions.get()).isZero();
    }

    @Test
    public void testFailedIfNoneMatchRefusedWithoutAssembling()
            throws Exception {
        assertThat(send(HttpRequest.newBuilder(URI.create(base + "/object"))
                .PUT(HttpRequest.BodyPublishers.ofString("existing")))
                .statusCode()).isEqualTo(200);
        String uploadId = initiate("object", /*algorithm=*/ null);
        String eTag = uploadPart("object", uploadId, 1, PART);

        HttpResponse<String> response = send(HttpRequest.newBuilder(
                URI.create(base + "/object?uploadId=" + uploadId))
                .header("If-None-Match", "*")
                .POST(HttpRequest.BodyPublishers.ofString(
                        completionXml(eTag))));
        assertThat(response.statusCode()).isEqualTo(412);
        assertThat(blobStore.completions.get()).isZero();
    }

    private String initiate(String key, String algorithm) throws Exception {
        var request = HttpRequest.newBuilder(
                URI.create(base + "/" + key + "?uploads"))
                .POST(HttpRequest.BodyPublishers.noBody());
        if (algorithm != null) {
            request.header("x-amz-checksum-algorithm", algorithm);
        }
        String body = send(request).body();
        return body.substring(body.indexOf("<UploadId>") + 10,
                body.indexOf("</UploadId>"));
    }

    private String uploadPart(String key, String uploadId, int partNumber,
            byte[] content) throws Exception {
        return send(HttpRequest.newBuilder(URI.create(base + "/" + key +
                "?partNumber=" + partNumber + "&uploadId=" + uploadId))
                .PUT(HttpRequest.BodyPublishers.ofByteArray(content)))
                .headers().firstValue("ETag").orElseThrow();
    }

    private static String completionXml(String eTag) {
        return "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber>" +
                "<ETag>" + eTag + "</ETag></Part></CompleteMultipartUpload>";
    }

    private HttpResponse<String> send(HttpRequest.Builder request)
            throws Exception {
        return httpClient.send(request.build(),
                HttpResponse.BodyHandlers.ofString());
    }
}
