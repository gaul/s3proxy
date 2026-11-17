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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;

import org.gaul.s3proxy.S3Proxy;
import org.gaul.s3proxy.TestUtils;
import org.gaul.s3proxy.auth.AuthenticationType;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.Credentials;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.S3Exception;

/**
 * Conditional writes judged by the store, for an S3-compatible backend that
 * does not judge them itself ({@code s3proxy.aws-s3.conditional-writes=
 * emulated}).  The backend here is another S3Proxy, which is S3-compatible
 * enough and needs nothing installed.
 */
public final class AwsS3SdkEmulatedConditionalWritesTest {
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
                /*conditionalWrites=*/ "emulated",
                /*chunkedEncodingEnabled=*/ "true",
                /*stripETagQuotes=*/ "false");
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (backend != null) {
            backend.stop();
        }
    }

    /** Create-if-absent creates what is absent, and only that. */
    @Test
    public void testIfNoneMatchStarOnAbsentKey() throws Exception {
        put("fresh", b -> b.ifNoneMatch("*"));
        assertThat(store.blobExists(CONTAINER, "fresh")).isTrue();

        assertThatThrownBy(() -> put("fresh", b -> b.ifNoneMatch("*")))
                .isInstanceOfSatisfying(S3Exception.class,
                        e -> assertThat(e.statusCode()).isEqualTo(412));
    }

    /** An ETag no object carries does not stand in the way of a new key. */
    @Test
    public void testIfNoneMatchETagOnAbsentKey() throws Exception {
        put("fresh", b -> b.ifNoneMatch("\"0123456789abcdef\""));
        assertThat(store.blobExists(CONTAINER, "fresh")).isTrue();
    }

    /** If-Match has nothing to match on a key that is not there. */
    @Test
    public void testIfMatchOnAbsentKey() throws Exception {
        assertThatThrownBy(() -> put("absent", b -> b.ifMatch("*")))
                .isInstanceOfSatisfying(S3Exception.class,
                        e -> assertThat(e.statusCode()).isEqualTo(412));
        assertThatThrownBy(() -> put("absent",
                b -> b.ifMatch("\"0123456789abcdef\"")))
                .isInstanceOf(NoSuchKeyException.class);
        assertThat(store.blobExists(CONTAINER, "absent")).isFalse();
    }

    private void put(String key,
            java.util.function.Consumer<PutObjectRequest.Builder> condition) {
        var request = PutObjectRequest.builder().bucket(CONTAINER).key(key)
                .contentLength((long) CONTENT.length);
        condition.accept(request);
        store.putBlob(request.build(), new ByteArrayInputStream(CONTENT));
    }
}
