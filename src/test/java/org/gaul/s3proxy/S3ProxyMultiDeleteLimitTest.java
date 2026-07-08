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
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import org.jclouds.ContextBuilder;
import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.BlobStoreContext;
import org.jclouds.logging.slf4j.config.SLF4JLoggingModule;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

public final class S3ProxyMultiDeleteLimitTest {
    private BlobStoreContext context;
    private S3Proxy s3Proxy;

    @AfterEach
    public void tearDown() throws Exception {
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
        if (context != null) {
            context.close();
        }
    }

    @Test
    public void testMultiDeleteBodyExceedingLimitRejected() throws Exception {
        context = ContextBuilder.newBuilder("transient")
                .credentials("identity", "credential")
                .modules(List.of(new SLF4JLoggingModule()))
                .build(BlobStoreContext.class);
        BlobStore blobStore = context.getBlobStore();
        String container = "container-" + new Random().nextInt(Integer.MAX_VALUE);
        blobStore.createContainerInLocation(null, container);

        long limit = 1024;
        s3Proxy = S3Proxy.builder()
                .endpoint(URI.create("http://127.0.0.1:0"))
                .v4MaxNonChunkedRequestSize(limit)
                .blobStore(blobStore)
                .build();
        s3Proxy.start();

        // A MultiObjectDelete body larger than the configured limit must be
        // rejected before it is buffered, rather than exhausting the heap.
        // The size check runs before parsing, so the body content is
        // irrelevant.
        byte[] body = new byte[(int) limit * 2];
        Arrays.fill(body, (byte) 'x');
        String url = "http://127.0.0.1:" + s3Proxy.getPort() + "/" +
                container + "?delete";
        HttpResponse<String> response = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(URI.create(url))
                        .header("Content-Type", "application/xml")
                        .POST(HttpRequest.BodyPublishers.ofByteArray(body))
                        .build(),
                HttpResponse.BodyHandlers.ofString());

        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.body()).contains("MaxMessageLengthExceeded");
    }
}
