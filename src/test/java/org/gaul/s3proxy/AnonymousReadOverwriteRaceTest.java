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

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import org.gaul.s3proxy.auth.AuthenticationType;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.ForwardingBlobStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.ObjectCannedACL;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

/**
 * An unsigned read asks for the object's ACL and then reads the object, and
 * the owner's PUT can land between the two.  Replacing a public object with
 * a private one there had the read answer with the private object, which no
 * ACL ever made public.  The store here makes that interleaving happen on
 * every read, where the real one needs a race to be won.
 */
public final class AnonymousReadOverwriteRaceTest {
    private static final String KEY = "object";
    private static final String PUBLIC_CONTENT = "public content";
    private static final String PRIVATE_CONTENT = "private content";

    private S3Proxy s3Proxy;
    private BlobStore backing;
    private OverwritingBlobStore blobStore;
    private String containerName;
    private URI objectUri;
    private final HttpClient httpClient = HttpClient.newHttpClient();

    /**
     * Answers for an object's access and, before the caller can act on the
     * answer, overwrites the object with a private one.
     */
    private static final class OverwritingBlobStore
            extends ForwardingBlobStore {
        private boolean overwrite;

        OverwritingBlobStore(BlobStore blobStore) {
            super(blobStore);
        }

        @Override
        public ObjectCannedACL getBlobAccess(String container, String name) {
            ObjectCannedACL access = super.getBlobAccess(container, name);
            if (overwrite) {
                put(delegate(), container, name, PRIVATE_CONTENT,
                        ObjectCannedACL.PRIVATE);
            }
            return access;
        }
    }

    @BeforeEach
    public void setUp() throws Exception {
        backing = TestUtils.createTransientBlobStore();
        blobStore = new OverwritingBlobStore(backing);
        containerName = TestUtils.createRandomContainerName();
        backing.createContainer(containerName);
        put(backing, containerName, KEY, PUBLIC_CONTENT,
                ObjectCannedACL.PUBLIC_READ);

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
        objectUri = URI.create("http://127.0.0.1:" + s3Proxy.getPort() + "/" +
                containerName + "/" + KEY);
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
    }

    private static void put(BlobStore blobStore, String container,
            String name, String content, ObjectCannedACL acl) {
        byte[] bytes = content.getBytes(StandardCharsets.UTF_8);
        blobStore.putBlob(PutObjectRequest.builder()
                        .bucket(container).key(name)
                        .contentLength((long) bytes.length)
                        .metadata(Map.of("content", content))
                        .acl(acl)
                        .build(),
                new ByteArrayInputStream(bytes));
    }

    private HttpResponse<String> send(String method, String query,
            String... headers) throws Exception {
        var request = HttpRequest.newBuilder(
                URI.create(objectUri + query))
                .method(method, HttpRequest.BodyPublishers.noBody());
        if (headers.length > 0) {
            request.headers(headers);
        }
        return httpClient.send(request.build(),
                HttpResponse.BodyHandlers.ofString());
    }

    /** Nothing written in between: the public object is served. */
    @Test
    public void testPublicObjectIsServed() throws Exception {
        HttpResponse<String> get = send("GET", "");
        assertThat(get.statusCode()).isEqualTo(200);
        assertThat(get.body()).isEqualTo(PUBLIC_CONTENT);

        HttpResponse<String> head = send("HEAD", "");
        assertThat(head.statusCode()).isEqualTo(200);
        assertThat(head.headers().firstValue("x-amz-meta-content"))
                .hasValue(PUBLIC_CONTENT);
    }

    @Test
    public void testGetDoesNotServeThePrivateObject() throws Exception {
        blobStore.overwrite = true;

        HttpResponse<String> response = send("GET", "");

        assertRefused(response);
        assertThat(response.body()).contains("<Code>AccessDenied</Code>");
    }

    @Test
    public void testHeadDoesNotDescribeThePrivateObject() throws Exception {
        blobStore.overwrite = true;

        assertRefused(send("HEAD", ""));
    }

    /** Its part count is read before the object is. */
    @Test
    public void testPartNumberDoesNotDescribeThePrivateObject()
            throws Exception {
        blobStore.overwrite = true;

        assertRefused(send("GET", "?partNumber=1"));
    }

    /** A condition would be answered with the private object's ETag. */
    @Test
    public void testConditionDoesNotDescribeThePrivateObject()
            throws Exception {
        blobStore.overwrite = true;

        HttpResponse<String> response = send("GET", "", "If-None-Match", "*");

        assertRefused(response);
        assertThat(response.headers().firstValue("ETag")).isEmpty();
    }

    private void assertRefused(HttpResponse<String> response)
            throws Exception {
        // the interleaving did happen: the private object is what is there
        try (var blob = backing.getBlob(containerName, KEY)) {
            assertThat(new String(blob.readAllBytes(), StandardCharsets.UTF_8))
                    .isEqualTo(PRIVATE_CONTENT);
        }
        assertThat(response.statusCode()).isEqualTo(403);
        assertThat(response.body()).doesNotContain(PRIVATE_CONTENT);
        assertThat(response.headers().firstValue("x-amz-meta-content"))
                .isEmpty();
    }
}
