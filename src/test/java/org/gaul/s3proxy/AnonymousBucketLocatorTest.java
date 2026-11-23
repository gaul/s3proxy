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
import java.nio.file.FileSystems;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;

import com.google.common.io.ByteSource;

import org.gaul.s3proxy.auth.AuthenticationType;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.middleware.GlobBlobStoreLocator;
import org.gaul.s3proxy.middleware.GlobBlobStoreLocator.GlobTarget;
import org.gaul.s3proxy.middleware.Middlewares;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.BucketCannedACL;
import software.amazon.awssdk.services.s3.model.ObjectCannedACL;

/**
 * A bucket the {@link BlobStoreLocator} assigns to a store is served from
 * that store to an unsigned request as it is to a signed one.  The unsigned
 * path went to the store the proxy was built with whatever the locator said
 * -- with several properties files, the last one's -- so the assigned store's
 * middlewares, a read-only one say, and its ACLs applied to the bucket's
 * owner and to nobody else.
 */
public final class AnonymousBucketLocatorTest {
    private static final String IDENTITY = "identity";
    private static final String CREDENTIAL = "credential";
    private static final String LOCATED_BUCKET = "located-bucket";
    /** Matches no glob, so the locator answers with the identity's store. */
    private static final String OTHER_BUCKET = "other-bucket";
    private static final String KEY = "key";

    private S3Proxy s3Proxy;
    /** The store the proxy is built with. */
    private BlobStore defaultBlobStore;
    /** The store the locator gives the identity. */
    private BlobStore identityBlobStore;
    /** The store the locator assigns {@code located-*} to. */
    private BlobStore locatedBlobStore;
    private String baseUri;
    private final HttpClient httpClient = HttpClient.newHttpClient();

    @BeforeEach
    public void setUp() throws Exception {
        defaultBlobStore = TestUtils.createTransientBlobStore();
        identityBlobStore = TestUtils.createTransientBlobStore();
        locatedBlobStore = TestUtils.createTransientBlobStore();

        s3Proxy = S3Proxy.builder()
                .stopTimeout(0)
                .blobStore(defaultBlobStore)
                .awsAuthentication(AuthenticationType.AWS_V2_OR_V4,
                        IDENTITY, CREDENTIAL)
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
    public void testReadIsServedFromLocatedBlobStore() throws Exception {
        setGlobBlobStoreLocator(locatedBlobStore);
        putPublicBlob(locatedBlobStore, LOCATED_BUCKET, "located");

        HttpResponse<String> response = send("GET", LOCATED_BUCKET);
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).isEqualTo("located");
    }

    /**
     * The default store holds a bucket of the same name which anyone may
     * write to; the located one, which is the one the bucket is assigned to,
     * does not allow it.
     */
    @Test
    public void testWriteIsJudgedByLocatedBlobStore() throws Exception {
        setGlobBlobStoreLocator(locatedBlobStore);
        locatedBlobStore.createContainer(LOCATED_BUCKET);
        defaultBlobStore.createContainer(LOCATED_BUCKET);
        defaultBlobStore.setContainerAccess(LOCATED_BUCKET,
                BucketCannedACL.PUBLIC_READ_WRITE);

        assertThat(send("PUT", LOCATED_BUCKET).statusCode()).isEqualTo(403);
        assertThat(defaultBlobStore.blobExists(LOCATED_BUCKET, KEY))
                .isFalse();
        assertThat(locatedBlobStore.blobExists(LOCATED_BUCKET, KEY))
                .isFalse();
    }

    /**
     * Both stores keep their objects in one place, as two properties files
     * naming one backend do, and the bucket lets anyone write.  The one the
     * bucket is assigned to is read-only, and stays so for a request which
     * carries no signature.
     */
    @Test
    public void testWriteToReadOnlyLocatedBlobStoreIsRefused()
            throws Exception {
        var properties = new Properties();
        properties.setProperty(
                S3ProxyConstants.PROPERTY_READ_ONLY_BLOBSTORE, "true");
        setGlobBlobStoreLocator(Middlewares.wrap(defaultBlobStore, properties,
                unused -> TestUtils.createTransientBlobStore()));
        putPublicBlob(defaultBlobStore, LOCATED_BUCKET, "original");
        defaultBlobStore.setContainerAccess(LOCATED_BUCKET,
                BucketCannedACL.PUBLIC_READ_WRITE);

        assertThat(send("PUT", LOCATED_BUCKET).statusCode()).isEqualTo(501);
        assertThat(send("DELETE", LOCATED_BUCKET).statusCode())
                .isEqualTo(501);
        assertThat(send("GET", LOCATED_BUCKET).body()).isEqualTo("original");
    }

    /**
     * A bucket no glob matches is served to its owner from the store of the
     * owner's identity, and to an unsigned request from the same one.
     */
    @Test
    public void testUnlocatedBucketIsServedFromIdentityBlobStore()
            throws Exception {
        setGlobBlobStoreLocator(locatedBlobStore);
        putPublicBlob(identityBlobStore, OTHER_BUCKET, "identity");
        putPublicBlob(defaultBlobStore, OTHER_BUCKET, "default");

        HttpResponse<String> response = send("GET", OTHER_BUCKET);
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).isEqualTo("identity");
    }

    /**
     * With several identities and no glob for the bucket, nothing says whose
     * it is, so the unsigned request stays with the proxy's own store rather
     * than moving to whichever identity came first.
     */
    @Test
    public void testUnlocatedBucketOfSeveralIdentitiesLeavesDefault()
            throws Exception {
        s3Proxy.setBlobStoreLocator(new GlobBlobStoreLocator(
                Map.of(IDENTITY, new AccessGrant(CREDENTIAL, identityBlobStore),
                        "other-identity", new AccessGrant("other-credential",
                                locatedBlobStore)),
                Map.of()));
        putPublicBlob(identityBlobStore, OTHER_BUCKET, "identity");
        putPublicBlob(defaultBlobStore, OTHER_BUCKET, "default");

        HttpResponse<String> response = send("GET", OTHER_BUCKET);
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).isEqualTo("default");
    }

    /** A locator which answers only for identities leaves the default. */
    @Test
    public void testIdentityOnlyLocatorLeavesDefaultBlobStore()
            throws Exception {
        putPublicBlob(defaultBlobStore, OTHER_BUCKET, "default");

        HttpResponse<String> response = send("GET", OTHER_BUCKET);
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).isEqualTo("default");
    }

    private void setGlobBlobStoreLocator(BlobStore located) {
        s3Proxy.setBlobStoreLocator(new GlobBlobStoreLocator(
                Map.of(IDENTITY,
                        new AccessGrant(CREDENTIAL, identityBlobStore)),
                Map.of(FileSystems.getDefault().getPathMatcher(
                        "glob:located-*"),
                        new GlobTarget(Optional.of(IDENTITY), located))));
    }

    private static void putPublicBlob(BlobStore blobStore, String bucket,
            String content) throws Exception {
        blobStore.createContainer(bucket);
        TestUtils.putBlob(blobStore, bucket, KEY,
                ByteSource.wrap(content.getBytes(StandardCharsets.UTF_8)));
        blobStore.setBlobAccess(bucket, KEY, ObjectCannedACL.PUBLIC_READ);
    }

    private HttpResponse<String> send(String method, String bucket)
            throws Exception {
        return httpClient.send(
                HttpRequest.newBuilder(URI.create(baseUri + bucket + "/" +
                        KEY))
                        .method(method, method.equals("PUT") ?
                                HttpRequest.BodyPublishers.ofString("data") :
                                HttpRequest.BodyPublishers.noBody())
                        .build(),
                HttpResponse.BodyHandlers.ofString());
    }
}
