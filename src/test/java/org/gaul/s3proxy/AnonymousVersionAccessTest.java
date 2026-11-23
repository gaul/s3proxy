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
import java.util.Random;

import com.google.common.io.ByteSource;

import org.gaul.s3proxy.auth.AuthenticationType;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.BucketCannedACL;
import software.amazon.awssdk.services.s3.model.BucketVersioningStatus;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.ObjectCannedACL;

/**
 * Each version of an object carries an access of its own, and an anonymous
 * read naming one answers to that version's.  It answered to the current
 * version's instead, so publishing a key handed out every private version
 * that had gone before it to anyone who named one.
 */
public final class AnonymousVersionAccessTest {
    private static final String KEY = "key";
    private static final String[] METHODS = {"GET", "HEAD"};

    private S3Proxy s3Proxy;
    private BlobStore blobStore;
    private String containerName;
    private String baseUri;
    private final HttpClient httpClient = HttpClient.newHttpClient();

    @BeforeEach
    public void setUp() throws Exception {
        blobStore = TestUtils.createTransientBlobStore();
        containerName =
                "container-" + new Random().nextInt(Integer.MAX_VALUE);
        blobStore.createContainer(containerName);
        blobStore.putBucketVersioning(containerName,
                BucketVersioningStatus.ENABLED);

        s3Proxy = S3Proxy.builder()
                .stopTimeout(0)
                .blobStore(blobStore)
                .awsAuthentication(AuthenticationType.AWS_V2_OR_V4,
                        "identity", "credential")
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

    /** A public current version does not publish the ones beneath it. */
    @Test
    public void testPrivateVersionUnderPublicCurrent() throws Exception {
        String draft = put("draft", ObjectCannedACL.PRIVATE);
        String published = put("published", ObjectCannedACL.PUBLIC_READ);

        for (String method : METHODS) {
            assertThat(send(method, draft).statusCode()).as(method)
                    .isEqualTo(403);
            assertThat(send(method, published).statusCode()).as(method)
                    .isEqualTo(200);
            assertThat(send(method, null).statusCode()).as(method)
                    .isEqualTo(200);
        }
        assertThat(send("GET", draft).body())
                .contains("<Code>AccessDenied</Code>")
                .doesNotContain("draft");
        assertThat(send("GET", published).body()).isEqualTo("published");
    }

    /** Nor does a private current version withdraw a public one. */
    @Test
    public void testPublicVersionUnderPrivateCurrent() throws Exception {
        String published = put("published", ObjectCannedACL.PUBLIC_READ);
        String draft = put("draft", ObjectCannedACL.PRIVATE);

        for (String method : METHODS) {
            assertThat(send(method, published).statusCode()).as(method)
                    .isEqualTo(200);
            assertThat(send(method, draft).statusCode()).as(method)
                    .isEqualTo(403);
            assertThat(send(method, null).statusCode()).as(method)
                    .isEqualTo(403);
        }
        assertThat(send("GET", published).body()).isEqualTo("published");
    }

    /**
     * A private bucket answers a version it does not have, and a delete
     * marker, as it answers a private version: which of them a key holds is
     * what listing its versions would say.
     */
    @Test
    public void testPrivateBucketHidesWhichVersionsExist() throws Exception {
        put("published", ObjectCannedACL.PUBLIC_READ);
        String marker = deleteMarker();

        for (String method : METHODS) {
            assertThat(send(method, "v9999999999999999").statusCode())
                    .as(method).isEqualTo(403);
            HttpResponse<String> response = send(method, marker);
            assertThat(response.statusCode()).as(method).isEqualTo(403);
            assertThat(response.headers().firstValue("x-amz-delete-marker"))
                    .as(method).isEmpty();
        }
    }

    /** Nor does it say that it keeps no versions at all. */
    @Test
    public void testPrivateBucketHidesThatItKeepsNoVersions()
            throws Exception {
        String unversioned = containerName + "-unversioned";
        blobStore.createContainer(unversioned);
        TestUtils.putBlob(blobStore, unversioned, KEY, ByteSource.wrap(
                "draft".getBytes(StandardCharsets.UTF_8)));

        for (String method : METHODS) {
            assertThat(send(method, unversioned, "null").statusCode())
                    .as(method).isEqualTo(403);
        }
    }

    /** A bucket anyone may list has no versions to hide. */
    @Test
    public void testPublicReadBucketReportsMissingVersion() throws Exception {
        blobStore.setContainerAccess(containerName,
                BucketCannedACL.PUBLIC_READ);
        String draft = put("draft", ObjectCannedACL.PRIVATE);
        put("published", ObjectCannedACL.PUBLIC_READ);
        String marker = deleteMarker();

        assertThat(send("GET", draft).statusCode()).isEqualTo(403);
        HttpResponse<String> response = send("GET", "v9999999999999999");
        assertThat(response.statusCode()).isEqualTo(404);
        assertThat(response.body()).contains("<Code>NoSuchVersion</Code>");
        assertThat(send("GET", marker).statusCode()).isEqualTo(405);
    }

    /**
     * Asking for a part asks after the version named as well.  A GET looked
     * to the current version for whether the object was multipart, and so
     * answered for a private version to the reader of a public one.
     */
    @Test
    public void testPartNumberAnswersForVersionNamed() throws Exception {
        String published = put("published", ObjectCannedACL.PUBLIC_READ);
        putMultipart();

        HttpResponse<String> response = send("GET",
                published + "&partNumber=1");
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).isEqualTo("published");
    }

    private String put(String content, ObjectCannedACL acl) throws Exception {
        ByteSource payload = ByteSource.wrap(
                content.getBytes(StandardCharsets.UTF_8));
        return blobStore.putBlob(
                TestUtils.putRequest(containerName, KEY, payload).toBuilder()
                        .acl(acl)
                        .build(),
                payload.openStream()).versionId();
    }

    /** Writes a private current version in two parts. */
    private void putMultipart() throws Exception {
        ByteSource part = ByteSource.wrap(
                "part".getBytes(StandardCharsets.UTF_8));
        var mpu = blobStore.initiateMultipartUpload(
                TestUtils.createRequest(containerName, KEY));
        TestUtils.uploadPart(blobStore, mpu, 1, part.openStream(),
                part.size());
        TestUtils.uploadPart(blobStore, mpu, 2, part.openStream(),
                part.size());
        blobStore.completeMultipartUpload(mpu, TestUtils.completeRequest(mpu,
                blobStore.listMultipartUpload(mpu)));
    }

    private String deleteMarker() {
        return blobStore.removeBlob(DeleteObjectRequest.builder()
                .bucket(containerName)
                .key(KEY)
                .build()).versionId();
    }

    private HttpResponse<String> send(String method,
            @Nullable String versionId) throws Exception {
        return send(method, containerName, versionId);
    }

    private HttpResponse<String> send(String method, String container,
            @Nullable String versionId) throws Exception {
        String uri = baseUri + container + "/" + KEY;
        if (versionId != null) {
            uri += "?versionId=" + versionId;
        }
        return httpClient.send(
                HttpRequest.newBuilder(URI.create(uri))
                        .method(method, HttpRequest.BodyPublishers.noBody())
                        .build(),
                HttpResponse.BodyHandlers.ofString());
    }
}
