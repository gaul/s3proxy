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

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.ForwardingBlobStore;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.BucketVersioningStatus;
import software.amazon.awssdk.services.s3.model.GetBucketVersioningRequest;
import software.amazon.awssdk.services.s3.model.GetBucketVersioningResponse;
import software.amazon.awssdk.services.s3.model.MFADelete;
import software.amazon.awssdk.services.s3.model.MFADeleteStatus;
import software.amazon.awssdk.services.s3.model.PutBucketVersioningRequest;
import software.amazon.awssdk.services.s3.model.PutBucketVersioningResponse;

/**
 * Covers the MFA delete fields the versioning requests carry: what the
 * store reports rides out on the configuration, what the client sends
 * reaches the store along with the x-amz-mfa header, and turning MFA
 * delete on is still refused rather than promised.
 */
public final class BucketVersioningMfaTest {
    private static final String XMLNS =
            "http://s3.amazonaws.com/doc/2006-03-01/";

    private RecordingBlobStore blobStore;
    private S3Proxy s3Proxy;
    private String container;

    @BeforeEach
    public void setUp() throws Exception {
        blobStore = new RecordingBlobStore(
                TestUtils.createTransientBlobStore());
        container = TestUtils.createRandomContainerName();
        blobStore.createContainer(container);
        s3Proxy = S3Proxy.builder()
                .stopTimeout(0)
                .endpoint(URI.create("http://127.0.0.1:0"))
                .blobStore(blobStore)
                .build();
        s3Proxy.start();
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
        if (blobStore != null) {
            blobStore.close();
        }
    }

    @Test
    public void testRelaysTheStoresMfaDelete() throws Exception {
        HttpResponse<String> response = send(HttpRequest.newBuilder(
                URI.create(versioningUrl())).GET());

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).contains("<MfaDelete>Disabled</MfaDelete>");
    }

    @Test
    public void testCarriesMfaDeleteAndTheMfaHeader() throws Exception {
        HttpResponse<String> response = send(HttpRequest.newBuilder(
                URI.create(versioningUrl()))
                .header(AwsHttpHeaders.MFA, "arn:aws:iam::1:mfa/root 123456")
                .PUT(HttpRequest.BodyPublishers.ofString(
                        configuration("Enabled", "Disabled"))));

        assertThat(response.statusCode()).isEqualTo(200);
        PutBucketVersioningRequest recorded = blobStore.lastPut();
        assertThat(recorded).isNotNull();
        assertThat(recorded.versioningConfiguration().status())
                .isEqualTo(BucketVersioningStatus.ENABLED);
        assertThat(recorded.versioningConfiguration().mfaDelete())
                .isEqualTo(MFADelete.DISABLED);
        assertThat(recorded.mfa())
                .isEqualTo("arn:aws:iam::1:mfa/root 123456");
    }

    @Test
    public void testTurningMfaDeleteOnIsRefused() throws Exception {
        HttpResponse<String> response = send(HttpRequest.newBuilder(
                URI.create(versioningUrl()))
                .PUT(HttpRequest.BodyPublishers.ofString(
                        configuration("Enabled", "Enabled"))));

        assertThat(response.statusCode()).isEqualTo(501);
        assertThat(response.body()).contains("NotImplemented");
        // Refused before the store could act on half of it.
        assertThat(blobStore.lastPut()).isNull();
    }

    private String versioningUrl() {
        return "http://127.0.0.1:" + s3Proxy.getPort() + "/" + container +
                "?versioning";
    }

    private static String configuration(String status, String mfaDelete) {
        return "<VersioningConfiguration xmlns=\"" + XMLNS + "\">" +
                "<Status>" + status + "</Status>" +
                "<MfaDelete>" + mfaDelete + "</MfaDelete>" +
                "</VersioningConfiguration>";
    }

    private static HttpResponse<String> send(HttpRequest.Builder builder)
            throws Exception {
        return HttpClient.newHttpClient().send(builder.build(),
                HttpResponse.BodyHandlers.ofString());
    }

    /**
     * Reports MFA delete the way a service that has it would, and keeps
     * the last configuration written so the test can see what reached the
     * store.
     */
    private static final class RecordingBlobStore extends ForwardingBlobStore {
        @Nullable
        private PutBucketVersioningRequest lastPut;

        RecordingBlobStore(BlobStore delegate) {
            super(delegate);
        }

        @Nullable
        PutBucketVersioningRequest lastPut() {
            return lastPut;
        }

        @Override
        public GetBucketVersioningResponse getBucketVersioning(
                GetBucketVersioningRequest request) {
            return delegate().getBucketVersioning(request).toBuilder()
                    .mfaDelete(MFADeleteStatus.DISABLED)
                    .build();
        }

        @Override
        public PutBucketVersioningResponse putBucketVersioning(
                PutBucketVersioningRequest request) {
            lastPut = request;
            return delegate().putBucketVersioning(request);
        }
    }
}
