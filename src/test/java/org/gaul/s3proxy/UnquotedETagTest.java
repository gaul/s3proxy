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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.BucketCannedACL;
import software.amazon.awssdk.services.s3.model.ObjectCannedACL;

/**
 * An ETag travels quoted on the wire and a client may spell one in a
 * conditional header either way.  The store puts the quotes back on both
 * sides before comparing; the metadata path a HEAD takes normalised only the
 * stored side, so a bare ETag matched on a GET and failed on a HEAD -- the
 * two verbs answering one request differently.
 */
public final class UnquotedETagTest {
    private static final String KEY = "object";
    private static final String CONTENT = "content";

    private S3Proxy s3Proxy;
    private String baseUri;
    private String quotedETag;
    private String bareETag;
    private final HttpClient httpClient = HttpClient.newHttpClient();

    @BeforeEach
    public void setUp() throws Exception {
        BlobStore blobStore = TestUtils.createTransientBlobStore();
        String container = "container-" + new Random().nextInt(
                Integer.MAX_VALUE);
        blobStore.createContainer(container);
        blobStore.setContainerAccess(container, BucketCannedACL.PUBLIC_READ);
        TestUtils.putBlob(blobStore, container, KEY,
                ByteSource.wrap(CONTENT.getBytes(StandardCharsets.UTF_8)));
        blobStore.setBlobAccess(container, KEY, ObjectCannedACL.PUBLIC_READ);

        String eTag = blobStore.blobMetadata(container, KEY).eTag();
        bareETag = eTag.replace("\"", "");
        quotedETag = "\"" + bareETag + "\"";

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
        baseUri = "http://127.0.0.1:" + s3Proxy.getPort() + "/" + container +
                "/" + KEY;
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
    }

    /** A bare If-Match holds on both verbs, as a quoted one does. */
    @Test
    public void testUnquotedIfMatchAgrees() throws Exception {
        assertThat(status("HEAD", "If-Match", bareETag)).isEqualTo(200);
        assertThat(status("GET", "If-Match", bareETag)).isEqualTo(200);
    }

    /** And a bare If-None-Match answers 304 on both. */
    @Test
    public void testUnquotedIfNoneMatchAgrees() throws Exception {
        assertThat(status("HEAD", "If-None-Match", bareETag)).isEqualTo(304);
        assertThat(status("GET", "If-None-Match", bareETag)).isEqualTo(304);
    }

    /** The quoted spelling is unchanged, on both verbs. */
    @Test
    public void testQuotedSpellingUnchanged() throws Exception {
        assertThat(status("HEAD", "If-Match", quotedETag)).isEqualTo(200);
        assertThat(status("GET", "If-Match", quotedETag)).isEqualTo(200);
        assertThat(status("HEAD", "If-None-Match", quotedETag)).isEqualTo(304);
        assertThat(status("GET", "If-None-Match", quotedETag)).isEqualTo(304);
    }

    /** An ETag that is not the object's still fails, either spelling. */
    @Test
    public void testWrongETagStillFails() throws Exception {
        assertThat(status("HEAD", "If-Match", "not-the-etag"))
                .isEqualTo(412);
        assertThat(status("GET", "If-Match", "\"not-the-etag\""))
                .isEqualTo(412);
        assertThat(status("HEAD", "If-None-Match", "not-the-etag"))
                .isEqualTo(200);
        assertThat(status("GET", "If-None-Match", "\"not-the-etag\""))
                .isEqualTo(200);
    }

    /** The wildcard keeps its own meaning rather than becoming a literal. */
    @Test
    public void testWildcardStillMatchesAnyObject() throws Exception {
        assertThat(status("HEAD", "If-Match", "*")).isEqualTo(200);
        assertThat(status("GET", "If-Match", "*")).isEqualTo(200);
        assertThat(status("HEAD", "If-None-Match", "*")).isEqualTo(304);
        assertThat(status("GET", "If-None-Match", "*")).isEqualTo(304);
    }

    private int status(String method, String header, String value)
            throws Exception {
        var builder = HttpRequest.newBuilder(URI.create(baseUri))
                .header(header, value);
        if (method.equals("HEAD")) {
            builder.method("HEAD", HttpRequest.BodyPublishers.noBody());
        } else {
            builder.GET();
        }
        return httpClient.send(builder.build(),
                HttpResponse.BodyHandlers.ofString()).statusCode();
    }
}
