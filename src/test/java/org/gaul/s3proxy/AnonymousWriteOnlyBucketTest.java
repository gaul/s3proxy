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
import java.util.List;

import com.google.common.io.ByteSource;

import org.gaul.s3proxy.auth.AuthenticationType;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.Constants;
import org.gaul.s3proxy.blobstore.ForwardingBlobStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.BucketCannedACL;
import software.amazon.awssdk.services.s3.model.GetBucketAclRequest;
import software.amazon.awssdk.services.s3.model.GetBucketAclResponse;
import software.amazon.awssdk.services.s3.model.Grant;
import software.amazon.awssdk.services.s3.model.Grantee;
import software.amazon.awssdk.services.s3.model.Permission;
import software.amazon.awssdk.services.s3.model.Type;

/**
 * A drop box: a bucket whose ACL grants AllUsers WRITE and not READ, so that
 * anyone may put into it and only its owner may list it.  No canned ACL says
 * that, so a store that keeps real grants reports such a bucket's access as
 * private and its policy as what it is.  An anonymous write answers to the
 * WRITE grant and an anonymous listing to READ, each on its own.
 */
public final class AnonymousWriteOnlyBucketTest {
    private static final byte[] CONTENT =
            "content".getBytes(StandardCharsets.UTF_8);

    private S3Proxy s3Proxy;
    private BlobStore blobStore;
    private String dropBox;
    private String privateBucket;
    private String baseUri;
    private final HttpClient httpClient = HttpClient.newHttpClient();

    @BeforeEach
    public void setUp() throws Exception {
        blobStore = TestUtils.createTransientBlobStore();
        dropBox = TestUtils.createRandomContainerName();
        privateBucket = TestUtils.createRandomContainerName();
        blobStore.createContainer(dropBox);
        blobStore.createContainer(privateBucket);
        TestUtils.putBlob(blobStore, dropBox, "present",
                ByteSource.wrap(CONTENT));

        // Stand in for a backend that holds the grants themselves: the
        // transient store keeps only a canned access, which cannot say this.
        BlobStore withGrants = new ForwardingBlobStore(blobStore) {
            @Override
            public GetBucketAclResponse getContainerAcl(
                    GetBucketAclRequest request) {
                if (!dropBox.equals(request.bucket())) {
                    return super.getContainerAcl(request);
                }
                return GetBucketAclResponse.builder()
                        .owner(o -> o.id(Constants.OWNER_ID))
                        .grants(List.of(
                                grant(Type.CANONICAL_USER, /*uri=*/ null,
                                        Permission.FULL_CONTROL),
                                grant(Type.GROUP, Constants.ALL_USERS_URI,
                                        Permission.WRITE)))
                        .build();
            }
        };

        s3Proxy = S3Proxy.builder()
                .stopTimeout(0)
                .blobStore(withGrants)
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
        if (blobStore != null) {
            blobStore.close();
        }
    }

    /** WRITE is to put and to delete, and the drop box grants it. */
    @Test
    public void testDropBoxTakesAnonymousWrites() throws Exception {
        assertThat(put(dropBox, "dropped").statusCode()).isEqualTo(200);
        assertThat(blobStore.blobExists(dropBox, "dropped")).isTrue();

        assertThat(send("DELETE", dropBox + "/dropped").statusCode())
                .isEqualTo(204);
        assertThat(blobStore.blobExists(dropBox, "dropped")).isFalse();
    }

    /** READ is to list, and the drop box does not grant it. */
    @Test
    public void testDropBoxRefusesAnonymousReads() throws Exception {
        assertThat(blobStore.getContainerAccess(dropBox))
                .isEqualTo(BucketCannedACL.PRIVATE);

        for (String query : new String[] {"", "?versions", "?uploads"}) {
            HttpResponse<String> listing = send("GET", dropBox + query);
            assertThat(listing.statusCode()).as(query).isEqualTo(403);
            assertThat(listing.body()).as(query).doesNotContain("present");
        }
        assertThat(send("HEAD", dropBox).statusCode()).isEqualTo(403);
        // Nor does it tell the keys it holds from the ones it does not.
        for (String method : new String[] {"GET", "HEAD"}) {
            assertThat(send(method, dropBox + "/present").statusCode())
                    .as(method).isEqualTo(403);
            assertThat(send(method, dropBox + "/missing").statusCode())
                    .as(method).isEqualTo(403);
        }
    }

    /** A bucket that grants AllUsers nothing goes on refusing them. */
    @Test
    public void testPrivateBucketRefusesAnonymousWrites() throws Exception {
        assertThat(put(privateBucket, "dropped").statusCode())
                .isEqualTo(403);
        assertThat(blobStore.blobExists(privateBucket, "dropped")).isFalse();
        assertThat(send("DELETE", privateBucket + "/dropped").statusCode())
                .isEqualTo(403);
    }

    /** The canned spelling of the grant is read as it was before. */
    @Test
    public void testPublicReadWriteBucketTakesAnonymousWrites()
            throws Exception {
        blobStore.setContainerAccess(privateBucket,
                BucketCannedACL.PUBLIC_READ_WRITE);
        assertThat(put(privateBucket, "dropped").statusCode())
                .isEqualTo(200);
        assertThat(send("GET", privateBucket).statusCode()).isEqualTo(200);

        blobStore.setContainerAccess(privateBucket,
                BucketCannedACL.PUBLIC_READ);
        assertThat(put(privateBucket, "refused").statusCode())
                .isEqualTo(403);
    }

    private static Grant grant(Type type, String uri, Permission permission) {
        return Grant.builder()
                .grantee(Grantee.builder()
                        .type(type)
                        .id(type == Type.CANONICAL_USER ?
                                Constants.OWNER_ID : null)
                        .uri(uri)
                        .build())
                .permission(permission)
                .build();
    }

    private HttpResponse<String> put(String container, String key)
            throws Exception {
        return httpClient.send(
                HttpRequest.newBuilder(URI.create(baseUri + container + "/" +
                        key))
                        .PUT(HttpRequest.BodyPublishers.ofByteArray(CONTENT))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> send(String method, String path)
            throws Exception {
        return httpClient.send(
                HttpRequest.newBuilder(URI.create(baseUri + path))
                        .method(method, HttpRequest.BodyPublishers.noBody())
                        .build(),
                HttpResponse.BodyHandlers.ofString());
    }
}
