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

package org.gaul.s3proxy.openstackswift;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import com.google.common.base.Suppliers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.Credentials;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.BucketCannedACL;
import software.amazon.awssdk.services.s3.model.NoSuchBucketException;

/**
 * A public-read bucket is one anyone may list, and s3proxy lists it to an
 * anonymous client with its own token.  Swift's X-Container-Read grants
 * reading objects and listing them apart, so only an ACL holding both may be
 * reported as public-read.  The Swift here is a stand-in that answers the
 * login and a container's HEAD, which is all getContainerAccess asks.
 */
public final class ContainerReadAclTest {
    private static final String ACCOUNT_PATH = "/v1/AUTH_test/";

    /** Container name to its X-Container-Read; empty for no ACL. */
    private final Map<String, String> readAcls = new ConcurrentHashMap<>();

    private HttpServer server;
    private BlobStore blobStore;

    @BeforeEach
    public void setUp() throws IOException {
        server = HttpServer.create(new InetSocketAddress(
                InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", this::handle);
        server.start();
        blobStore = new OpenStackSwiftBlobStore(
                Suppliers.ofInstance(new Credentials("test:tester",
                        "testing")),
                endpoint() + "/auth/v1.0", "test", "Default", "Default",
                /*region=*/ "");
    }

    @AfterEach
    public void tearDown() {
        blobStore.close();
        server.stop(0);
    }

    /** What setContainerAccess writes for public-read. */
    @Test
    public void testReadAndListingsIsPublicRead() {
        assertThat(access(".r:*,.rlistings"))
                .isEqualTo(BucketCannedACL.PUBLIC_READ);
        assertThat(access(".rlistings, .r:*"))
                .isEqualTo(BucketCannedACL.PUBLIC_READ);
        assertThat(access("test:tester,.r:*,.rlistings"))
                .isEqualTo(BucketCannedACL.PUBLIC_READ);
    }

    /** Objects shared by name: readable by anyone, listed to nobody. */
    @Test
    public void testReadWithoutListingsIsPrivate() {
        assertThat(access(".r:*")).isEqualTo(BucketCannedACL.PRIVATE);
        assertThat(access(".r:*,test:tester"))
                .isEqualTo(BucketCannedACL.PRIVATE);
    }

    @Test
    public void testListingsWithoutReadIsPrivate() {
        assertThat(access(".rlistings")).isEqualTo(BucketCannedACL.PRIVATE);
    }

    /** A grant to some referrers is not a grant to all of them. */
    @Test
    public void testReferrerContainingWildcardIsPrivate() {
        assertThat(access(".r:*.example.com,.rlistings"))
                .isEqualTo(BucketCannedACL.PRIVATE);
        assertThat(access(".r:example.com,.rlistings"))
                .isEqualTo(BucketCannedACL.PRIVATE);
    }

    @Test
    public void testNoAclIsPrivate() {
        assertThat(access("")).isEqualTo(BucketCannedACL.PRIVATE);
        assertThat(access("test:tester")).isEqualTo(BucketCannedACL.PRIVATE);
        assertThat(OpenStackSwiftBlobStore.isPublicRead(null)).isFalse();
    }

    @Test
    public void testMissingContainerIsNoSuchBucket() {
        assertThatThrownBy(() -> blobStore.getContainerAccess("missing"))
                .isInstanceOf(NoSuchBucketException.class);
    }

    /** The access reported for a container whose read ACL is the one given. */
    private BucketCannedACL access(String readAcl) {
        readAcls.put("container", readAcl);
        return blobStore.getContainerAccess("container");
    }

    private String endpoint() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    private void handle(HttpExchange exchange) throws IOException {
        try (exchange) {
            String path = exchange.getRequestURI().getPath();
            var headers = exchange.getResponseHeaders();
            if (path.equals("/auth/v1.0")) {
                headers.set("X-Auth-Token", "AUTH_tk");
                headers.set("X-Storage-Url", endpoint() + "/v1/AUTH_test");
                exchange.sendResponseHeaders(200, -1);
                return;
            }
            String readAcl = path.startsWith(ACCOUNT_PATH) ? readAcls.get(
                    path.substring(ACCOUNT_PATH.length())) : null;
            if (readAcl == null) {
                exchange.sendResponseHeaders(404, -1);
                return;
            }
            headers.set("X-Container-Object-Count", "0");
            if (!readAcl.isEmpty()) {
                headers.set("X-Container-Read", readAcl);
            }
            exchange.sendResponseHeaders(204, -1);
        }
    }
}
