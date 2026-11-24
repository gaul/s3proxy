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
import org.gaul.s3proxy.blobstore.ForwardingBlobStore;
import org.gaul.s3proxy.blobstore.S3Exceptions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.BucketCannedACL;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.s3.model.ObjectCannedACL;

/**
 * A backend holds the store's credentials to its own rules.  S3 answers a
 * caller who may not list the bucket AccessDenied for the ACL of a missing
 * key, and says in the message who was refused what.  An anonymous read
 * relayed that refusal, so a missing key was answered differently from a
 * private one and anyone could learn which keys the bucket held, along with
 * the identity the store uses.  So did relaying a refusal of the bucket's
 * ACL, which is asked after only once a key is found missing, and a refusal
 * of the ACL of a key that is there.
 */
public final class AnonymousStoreRefusalTest {
    private static final String REFUSAL =
            "User: arn:aws:iam::111122223333:user/backend is not authorized" +
            " to perform: ";

    /** A backend that refuses its caller what the test says it does. */
    private static final class RefusingBlobStore extends ForwardingBlobStore {
        private volatile boolean mayList = true;
        private volatile boolean mayReadBucketAcl = true;
        private volatile boolean mayReadObjectAcl = true;

        RefusingBlobStore(BlobStore delegate) {
            super(delegate);
        }

        @Override
        public BucketCannedACL getContainerAccess(String container) {
            if (!mayReadBucketAcl) {
                throw S3Exceptions.accessDenied(REFUSAL + "s3:GetBucketAcl",
                        /*cause=*/ null);
            }
            return super.getContainerAccess(container);
        }

        @Override
        public ObjectCannedACL getBlobAccess(String container, String name) {
            ObjectCannedACL access;
            try {
                access = super.getBlobAccess(container, name);
            } catch (NoSuchKeyException e) {
                if (mayList) {
                    throw e;
                }
                throw S3Exceptions.accessDenied(REFUSAL + "s3:ListBucket", e);
            }
            if (!mayReadObjectAcl) {
                throw S3Exceptions.accessDenied(REFUSAL + "s3:GetObjectAcl",
                        /*cause=*/ null);
            }
            return access;
        }
    }

    private S3Proxy s3Proxy;
    private RefusingBlobStore blobStore;
    private String containerName;
    private String baseUri;
    private final HttpClient httpClient = HttpClient.newHttpClient();

    @BeforeEach
    public void setUp() throws Exception {
        blobStore = new RefusingBlobStore(
                TestUtils.createTransientBlobStore());
        containerName =
                "container-" + new Random().nextInt(Integer.MAX_VALUE);
        blobStore.createContainer(containerName);
        TestUtils.putBlob(blobStore, containerName, "present",
                ByteSource.wrap("private".getBytes(StandardCharsets.UTF_8)));

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

    /** Credentials that may not list are refused a missing key's ACL. */
    @Test
    public void testStoreThatMayNotListHidesWhichKeysExist()
            throws Exception {
        blobStore.mayList = false;
        assertMissingAnswersAsPresent();
    }

    /** The bucket's ACL is asked after only once a key is found missing. */
    @Test
    public void testStoreRefusedBucketAclHidesWhichKeysExist()
            throws Exception {
        blobStore.mayReadBucketAcl = false;
        assertMissingAnswersAsPresent();
    }

    /** Credentials that may list are refused only a present key's ACL. */
    @Test
    public void testStoreRefusedObjectAclHidesWhichKeysExist()
            throws Exception {
        blobStore.mayReadObjectAcl = false;
        assertMissingAnswersAsPresent();
    }

    private void assertMissingAnswersAsPresent() throws Exception {
        for (String method : new String[] {"GET", "HEAD"}) {
            HttpResponse<String> present = send(method, "present");
            HttpResponse<String> missing = send(method, "missing");
            assertThat(present.statusCode()).as(method).isEqualTo(403);
            assertThat(missing.statusCode()).as(method).isEqualTo(403);
            assertThat(withoutRequestId(missing.body())).as(method)
                    .isEqualTo(withoutRequestId(present.body()))
                    .doesNotContain("111122223333");
        }
        assertThat(send("GET", "missing").body())
                .contains("<Code>AccessDenied</Code>");
    }

    private static String withoutRequestId(String body) {
        return body.replaceAll("<RequestId>.*</RequestId>", "");
    }

    private HttpResponse<String> send(String method, String key)
            throws Exception {
        return httpClient.send(
                HttpRequest.newBuilder(URI.create(baseUri + containerName +
                        "/" + key))
                        .method(method, HttpRequest.BodyPublishers.noBody())
                        .build(),
                HttpResponse.BodyHandlers.ofString());
    }
}
