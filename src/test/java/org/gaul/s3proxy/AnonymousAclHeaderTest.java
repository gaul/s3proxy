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
import java.util.Random;

import org.gaul.s3proxy.auth.AuthenticationType;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.BucketCannedACL;
import software.amazon.awssdk.services.s3.model.ObjectCannedACL;

/**
 * An anonymous PUT reaches the store on the bucket's AllUsers WRITE grant
 * alone, which says the caller may add an object and nothing more.  The
 * dispatcher refuses ?acl and x-amz-copy-source there for that reason, but
 * x-amz-acl -- the header spelling of ?acl, and the one handlePutBlob
 * actually reads -- rode past, so anyone who could write to a public-write
 * bucket could also publish what it wrote.  A header naming private asks for
 * the access the object gets anyway and still goes through.
 */
public final class AnonymousAclHeaderTest {
    private static final String KEY = "object";
    private static final String CONTENT = "anonymous-upload";

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
        blobStore.setContainerAccess(containerName,
                BucketCannedACL.PUBLIC_READ_WRITE);

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

    /** The write the bucket grants, with nothing else asked for. */
    @Test
    public void testAnonymousPutWithoutAclSucceeds() throws Exception {
        HttpResponse<String> response = put(/*cannedAcl=*/ null);
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(blobStore.getBlobAccess(containerName, KEY))
                .isEqualTo(ObjectCannedACL.PRIVATE);
    }

    /** The same write, asking only for the access it would get anyway. */
    @Test
    public void testAnonymousPutWithPrivateAclSucceeds() throws Exception {
        HttpResponse<String> response = put("private");
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(blobStore.getBlobAccess(containerName, KEY))
                .isEqualTo(ObjectCannedACL.PRIVATE);
    }

    /** Publishing what it wrote is not among what bucket WRITE grants. */
    @Test
    public void testAnonymousPutWithPublicReadAclRejected() throws Exception {
        HttpResponse<String> response = put("public-read");
        System.err.println("anonymous public-read: " + response.statusCode() +
                " " + response.body());
        assertThat(response.statusCode()).isEqualTo(403);
        assertThat(response.body()).contains("AccessDenied");
        // Refused outright rather than stored with the access it asked for,
        // or stored private while reporting success.
        assertThat(blobStore.blobExists(containerName, KEY)).isFalse();
    }

    /** Any other canned ACL is refused the same way, named or not. */
    @Test
    public void testAnonymousPutWithOtherAclRejected() throws Exception {
        assertThat(put("authenticated-read").statusCode()).isEqualTo(403);
        assertThat(put("bucket-owner-full-control").statusCode())
                .isEqualTo(403);
        assertThat(blobStore.blobExists(containerName, KEY)).isFalse();
    }

    private HttpResponse<String> put(String cannedAcl) throws Exception {
        var builder = HttpRequest.newBuilder(
                        URI.create(baseUri + containerName + "/" + KEY))
                .PUT(HttpRequest.BodyPublishers.ofString(CONTENT));
        if (cannedAcl != null) {
            builder.header(AwsHttpHeaders.ACL, cannedAcl);
        }
        return httpClient.send(builder.build(),
                HttpResponse.BodyHandlers.ofString());
    }
}
