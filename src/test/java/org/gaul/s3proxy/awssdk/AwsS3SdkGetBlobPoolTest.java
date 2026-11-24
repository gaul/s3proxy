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

package org.gaul.s3proxy.awssdk;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;

import org.gaul.s3proxy.S3Proxy;
import org.gaul.s3proxy.TestUtils;
import org.gaul.s3proxy.auth.AuthenticationType;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.Credentials;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.http.SdkHttpConfigurationOption;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.UploadPartRequest;

/**
 * The stream a read answers with keeps a pooled connection until it is
 * closed, and the frontend writes such a stream back to the same store when
 * it copies a part on the backend's behalf.  However many reads are open,
 * that write must find a connection: when it waited for one of theirs, as
 * many copies as the pool has connections each held one and waited for
 * another, and the store answered nobody until the SDK gave up.  The backend
 * here is another S3Proxy, which is S3-compatible enough and needs nothing
 * installed.
 */
public final class AwsS3SdkGetBlobPoolTest {
    private static final String CONTAINER = "container";
    private static final byte[] CONTENT =
            "content".getBytes(StandardCharsets.UTF_8);

    private S3Proxy backend;
    private BlobStore store;

    @BeforeEach
    public void setUp() throws Exception {
        BlobStore transientStore = TestUtils.createTransientBlobStore();
        transientStore.createContainer(CONTAINER);
        backend = S3Proxy.builder()
                .stopTimeout(0)
                .blobStore(transientStore)
                .awsAuthentication(AuthenticationType.AWS_V2_OR_V4,
                        "identity", "credential")
                .endpoint(URI.create("http://127.0.0.1:0"))
                .build();
        backend.start();
        while (!backend.getState().equals("STARTED")) {
            Thread.sleep(10);
        }
        store = new AwsS3SdkBlobStore(
                () -> new Credentials("identity", "credential"),
                "http://127.0.0.1:" + backend.getPort(), "us-east-1",
                /*conditionalWrites=*/ "native",
                /*chunkedEncodingEnabled=*/ "true",
                /*stripETagQuotes=*/ "false");
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (store != null) {
            store.close();
        }
        if (backend != null) {
            backend.stop();
        }
    }

    @Test
    public void testOpenReadsLeaveAConnectionToWriteThemBack()
            throws Exception {
        store.putBlob(PutObjectRequest.builder()
                .bucket(CONTAINER)
                .key("key")
                .contentLength((long) CONTENT.length)
                .build(), new ByteArrayInputStream(CONTENT));

        // as many as the SDK pools connections when told nothing else
        int connections = SdkHttpConfigurationOption.GLOBAL_HTTP_DEFAULTS.get(
                SdkHttpConfigurationOption.MAX_CONNECTIONS);
        var blobs = new ArrayList<ResponseInputStream<GetObjectResponse>>();
        try {
            for (int i = 0; i < connections; ++i) {
                blobs.add(store.getBlob(GetObjectRequest.builder()
                        .bucket(CONTAINER)
                        .key("key")
                        .build()));
            }

            store.putBlob(PutObjectRequest.builder()
                    .bucket(CONTAINER)
                    .key("copy")
                    .contentLength((long) CONTENT.length)
                    .build(), blobs.get(0));
            assertThat(store.blobExists(CONTAINER, "copy")).isTrue();

            // the write the frontend makes of a part's copy source
            var mpu = store.initiateMultipartUpload(
                    CreateMultipartUploadRequest.builder()
                            .bucket(CONTAINER).key("upload").build());
            var part = store.uploadMultipartPart(mpu,
                    UploadPartRequest.builder()
                            .partNumber(1)
                            .contentLength((long) CONTENT.length)
                            .build(), blobs.get(1));
            assertThat(part.eTag()).isNotNull();
        } finally {
            for (var blob : blobs) {
                blob.close();
            }
        }
    }
}
