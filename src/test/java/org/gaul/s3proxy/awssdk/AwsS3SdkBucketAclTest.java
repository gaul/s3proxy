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

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

import com.google.common.base.Suppliers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.Credentials;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.BucketCannedACL;

/**
 * The canned access the store reads out of a bucket's grants.  S3 grants
 * AllUsers READ, which is to list the bucket, apart from WRITE, which is to
 * put into it, and the anonymous path lists whatever is not private: so the
 * grants the service answers are scripted here and the name they are boiled
 * down to must not say more than they do.
 */
public final class AwsS3SdkBucketAclTest {
    private static final String ALL_USERS =
            "http://acs.amazonaws.com/groups/global/AllUsers";

    private HttpServer server;
    private volatile String grants = "";

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

    @Test
    public void testOwnerOnlyIsPrivate() throws Exception {
        assertThat(access()).isEqualTo(BucketCannedACL.PRIVATE);
    }

    @Test
    public void testAllUsersReadIsPublicRead() throws Exception {
        grants = allUsers("READ");
        assertThat(access()).isEqualTo(BucketCannedACL.PUBLIC_READ);
    }

    @Test
    public void testAllUsersReadAndWriteIsPublicReadWrite() throws Exception {
        grants = allUsers("READ") + allUsers("WRITE");
        assertThat(access()).isEqualTo(BucketCannedACL.PUBLIC_READ_WRITE);
    }

    @Test
    public void testAllUsersFullControlIsPublicReadWrite() throws Exception {
        grants = allUsers("FULL_CONTROL");
        assertThat(access()).isEqualTo(BucketCannedACL.PUBLIC_READ_WRITE);
    }

    /**
     * A drop box: anyone may put into it and only its owner may list it.
     * Called public-read-write, it was listed to anyone who asked.
     */
    @Test
    public void testAllUsersWriteWithoutReadIsPrivate() throws Exception {
        grants = allUsers("WRITE");
        assertThat(access()).isEqualTo(BucketCannedACL.PRIVATE);
    }

    private BucketCannedACL access() throws Exception {
        try (BlobStore blobStore = new AwsS3SdkBlobStore(
                Suppliers.ofInstance(new Credentials("identity",
                        "credential")),
                "http://127.0.0.1:" + server.getAddress().getPort(),
                "us-east-1", /*conditionalWrites=*/ "native",
                /*chunkedEncodingEnabled=*/ "true",
                /*stripETagQuotes=*/ "false")) {
            return blobStore.getContainerAccess("bucket");
        }
    }

    private static String allUsers(String permission) {
        return "<Grant><Grantee xmlns:xsi=" +
                "\"http://www.w3.org/2001/XMLSchema-instance\"" +
                " xsi:type=\"Group\"><URI>" + ALL_USERS + "</URI></Grantee>" +
                "<Permission>" + permission + "</Permission></Grant>";
    }

    private void handle(HttpExchange exchange) throws IOException {
        try (var in = exchange.getRequestBody()) {
            in.readAllBytes();
        }
        byte[] body = ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
                "<AccessControlPolicy" +
                " xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">" +
                "<Owner><ID>owner</ID></Owner><AccessControlList>" +
                "<Grant><Grantee xmlns:xsi=" +
                "\"http://www.w3.org/2001/XMLSchema-instance\"" +
                " xsi:type=\"CanonicalUser\"><ID>owner</ID></Grantee>" +
                "<Permission>FULL_CONTROL</Permission></Grant>" +
                grants + "</AccessControlList></AccessControlPolicy>")
                .getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/xml");
        exchange.sendResponseHeaders(200, body.length);
        try (var out = exchange.getResponseBody()) {
            out.write(body);
        }
    }
}
