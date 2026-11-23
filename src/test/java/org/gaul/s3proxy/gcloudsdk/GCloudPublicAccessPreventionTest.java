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

package org.gaul.s3proxy.gcloudsdk;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import com.google.common.base.Suppliers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.Credentials;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.BucketCannedACL;
import software.amazon.awssdk.services.s3.model.ObjectCannedACL;

/**
 * Public access prevention overrides the entries for allUsers and leaves
 * them in the ACLs.  GCS refuses an anonymous request to such a bucket,
 * while the store's own requests carry credentials the prevention does not
 * apply to, so what the store reports as public is all that keeps S3Proxy
 * from answering one.  The emulator the other tests run against knows no
 * such setting, so the store is given a bucket resource that has it here.
 */
public final class GCloudPublicAccessPreventionTest {
    private static final String BUCKET_PATH = "/storage/v1/b/bucket";
    private static final String OBJECT = """
            {"kind":"storage#object","bucket":"bucket","name":"public",\
            "generation":"1","metageneration":"1","size":"1",\
            "etag":"CAE=","md5Hash":"xvmCfRHTDFg+uRtCA6yhcQ==",\
            "contentType":"text/plain",\
            "updated":"2026-01-01T00:00:00.000Z"}""";
    private static final String PUBLIC_ENTRY =
            "{\"entity\":\"allUsers\",\"role\":\"%s\"}";

    private final List<String> requests = new CopyOnWriteArrayList<>();

    private HttpServer server;
    private volatile String publicAccessPrevention = "inherited";

    @BeforeEach
    public void setUp() throws IOException {
        server = HttpServer.create(new InetSocketAddress(
                InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", this::handle);
        server.start();
    }

    @AfterEach
    public void tearDown() {
        server.stop(0);
    }

    /** Without the prevention, the entries say what is public. */
    @Test
    public void testPublicAclsArePublic() {
        try (BlobStore blobStore = store()) {
            assertThat(blobStore.getContainerAccess("bucket"))
                    .isEqualTo(BucketCannedACL.PUBLIC_READ_WRITE);
            assertThat(blobStore.getBlobAccess("bucket", "public"))
                    .isEqualTo(ObjectCannedACL.PUBLIC_READ);
            assertThat(blobStore.getBlobAccess("bucket", "public",
                    /*versionId=*/ "1"))
                    .isEqualTo(ObjectCannedACL.PUBLIC_READ);
            assertThat(blobStore.getBlobAccess("bucket", "private"))
                    .isEqualTo(ObjectCannedACL.PRIVATE);
        }
    }

    /** With it, the same entries make nothing public. */
    @Test
    public void testPublicAccessPreventionOverridesPublicAcls() {
        publicAccessPrevention = "enforced";
        try (BlobStore blobStore = store()) {
            assertThat(blobStore.getContainerAccess("bucket"))
                    .isEqualTo(BucketCannedACL.PRIVATE);
            assertThat(blobStore.getBlobAccess("bucket", "public",
                    /*versionId=*/ "1"))
                    .isEqualTo(ObjectCannedACL.PRIVATE);

            requests.clear();
            assertThat(blobStore.getBlobAccess("bucket", "public"))
                    .isEqualTo(ObjectCannedACL.PRIVATE);
            // no later than an object without the entry is refused
            var overridden = List.copyOf(requests);
            requests.clear();
            assertThat(blobStore.getBlobAccess("bucket", "private"))
                    .isEqualTo(ObjectCannedACL.PRIVATE);
            assertThat(requests).hasSameSizeAs(overridden);
        }
    }

    private BlobStore store() {
        return new GCloudBlobStore(Suppliers.ofInstance(
                new Credentials("project", /*credential=*/ "")),
                "http://127.0.0.1:" + server.getAddress().getPort());
    }

    private void handle(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
        requests.add(path);
        exchange.getRequestBody().close();
        String response;
        if (path.equals(BUCKET_PATH)) {
            response = "{\"kind\":\"storage#bucket\",\"id\":\"bucket\"," +
                    "\"name\":\"bucket\",\"iamConfiguration\":{" +
                    "\"uniformBucketLevelAccess\":{\"enabled\":false}," +
                    "\"publicAccessPrevention\":\"" +
                    publicAccessPrevention + "\"}}";
        } else if (path.equals(BUCKET_PATH + "/acl")) {
            response = "{\"kind\":\"storage#bucketAccessControls\"," +
                    "\"items\":[" + PUBLIC_ENTRY.formatted("WRITER") + "]}";
        } else if (path.equals(BUCKET_PATH + "/o/public/acl")) {
            response = "{\"kind\":\"storage#objectAccessControls\"," +
                    "\"items\":[" + PUBLIC_ENTRY.formatted("READER") + "]}";
        } else if (path.equals(BUCKET_PATH + "/o/private/acl")) {
            response = "{\"kind\":\"storage#objectAccessControls\"," +
                    "\"items\":[]}";
        } else {
            response = OBJECT;
        }
        byte[] body = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type",
                "application/json; charset=UTF-8");
        exchange.sendResponseHeaders(200, body.length);
        try (var out = exchange.getResponseBody()) {
            out.write(body);
        }
    }
}
