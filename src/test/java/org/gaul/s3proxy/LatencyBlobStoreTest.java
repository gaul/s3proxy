/*
 * Copyright 2014-2025 Andrew Gaul <andrew@gaul.org>
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

import com.google.common.io.ByteSource;
import org.jclouds.ContextBuilder;
import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.BlobStoreContext;
import org.jclouds.blobstore.domain.Blob;
import org.jclouds.io.Payload;
import org.jclouds.io.Payloads;
import org.jclouds.logging.slf4j.config.SLF4JLoggingModule;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.*;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

public final class LatencyBlobStoreTest {
    private BlobStoreContext context;
    private BlobStore delegate;
    private String containerName;

    @Before
    public void setUp() throws Exception {
        containerName = createRandomContainerName();

        context = ContextBuilder
                .newBuilder("transient")
                .credentials("identity", "credential")
                .modules(List.of(new SLF4JLoggingModule()))
                .build(BlobStoreContext.class);
        delegate = context.getBlobStore();
        delegate.createContainerInLocation(null, containerName);
    }

    @After
    public void tearDown() throws Exception {
        if (context != null) {
            delegate.deleteContainer(containerName);
            context.close();
        }
    }

    @Test
    public void testLoadProperties() throws Exception {
        String propertiesString = "s3proxy.latency-blobstore.*.latency=1000\n" +
                "s3proxy.latency-blobstore.put.speed=10";
        InputStream stream = new ByteArrayInputStream(propertiesString.getBytes());
        Properties properties = new Properties();
        properties.load(stream);

        Map<String, Long> latencies = LatencyBlobStore.parseLatencies(properties);
        Map<String, Long> speeds = LatencyBlobStore.parseSpeeds(properties);

        assertThat(latencies.containsKey("*")).isTrue();
        assertThat(latencies.get("*")).isEqualTo(1000L);
        assertThat(speeds.containsKey("put")).isTrue();
        assertThat(speeds.get("put")).isEqualTo(10);
        assertThat(speeds.containsKey("*")).isFalse();
    }

    @Test
    public void testAllLatency() {
        BlobStore latencyBlobStore = LatencyBlobStore.newLatencyBlobStore(delegate,
                Map.ofEntries(Map.entry("*", 1000L)), Map.ofEntries());

        long timeTaken = time(() -> latencyBlobStore.containerExists(containerName));
        assertThat(timeTaken).isGreaterThanOrEqualTo(1000L);
    }

    @Test
    public void testSpecificLatency() {
        BlobStore latencyBlobStore = LatencyBlobStore.newLatencyBlobStore(delegate,
                Map.ofEntries(Map.entry("*", 0L),
                        Map.entry("container-exists", 1000L)), Map.ofEntries());

        long timeTaken = time(() -> latencyBlobStore.containerExists(containerName));
        assertThat(timeTaken).isGreaterThanOrEqualTo(1000L);
    }

    @Test
    public void testAllSpeed() throws Exception {
        BlobStore latencyBlobStore = LatencyBlobStore.newLatencyBlobStore(delegate,
                Map.ofEntries(), Map.ofEntries(Map.entry("*", 1L)));

        String blobName = createRandomBlobName();
        ByteSource content = TestUtils.randomByteSource().slice(0, 1024);
        Payload payload = Payloads.newByteSourcePayload(content);
        payload.getContentMetadata().setContentLength(content.size());
        Blob blob = latencyBlobStore.blobBuilder(blobName).payload(payload).build();

        long timeTaken = time(() -> latencyBlobStore.putBlob(containerName, blob));
        assertThat(timeTaken).isGreaterThanOrEqualTo(1000L);
    }

    @Test
    public void testSpecificSpeed() throws Exception {
        BlobStore latencyBlobStore = LatencyBlobStore.newLatencyBlobStore(delegate,
                Map.ofEntries(), Map.ofEntries(Map.entry("*", 1000L),
                        Map.entry("put", 1L)));

        String blobName = createRandomBlobName();
        ByteSource content = TestUtils.randomByteSource().slice(0, 1024);
        Payload payload = Payloads.newByteSourcePayload(content);
        payload.getContentMetadata().setContentLength(content.size());
        Blob blob = latencyBlobStore.blobBuilder(blobName).payload(payload).build();

        long timeTaken = time(() -> latencyBlobStore.putBlob(containerName, blob));
        assertThat(timeTaken).isGreaterThanOrEqualTo(1000L);
    }

    @Test
    public void testInvalidLatency() {
        assertThatIllegalArgumentException().isThrownBy(() -> LatencyBlobStore.newLatencyBlobStore(delegate,
                Map.ofEntries(Map.entry("*", -1000L)), Map.ofEntries()));
    }

    @Test
    public void testInvalidSpeed() {
        assertThatIllegalArgumentException().isThrownBy(() -> LatencyBlobStore.newLatencyBlobStore(delegate,
                Map.ofEntries(), Map.ofEntries(Map.entry("*", 0L))));
        assertThatIllegalArgumentException().isThrownBy(() -> LatencyBlobStore.newLatencyBlobStore(delegate,
                Map.ofEntries(), Map.ofEntries(Map.entry("*", -1000L))));
    }

    @Test
    public void testLatencyAndSpeed() throws Exception {
        BlobStore latencyBlobStore = LatencyBlobStore.newLatencyBlobStore(delegate,
                Map.ofEntries(Map.entry("*", 1000L)), Map.ofEntries(Map.entry("put", 1L)));

        String blobName = createRandomBlobName();
        ByteSource content = TestUtils.randomByteSource().slice(0, 1024);
        Payload payload = Payloads.newByteSourcePayload(content);
        payload.getContentMetadata().setContentLength(content.size());
        Blob blob = latencyBlobStore.blobBuilder(blobName).payload(payload).build();

        long timeTaken = time(() -> latencyBlobStore.putBlob(containerName, blob));
        assertThat(timeTaken).isGreaterThanOrEqualTo(2000L);
    }

    @Test
    public void testLatencyAndSpeedWithEmptyContent() throws Exception {
        BlobStore latencyBlobStore = LatencyBlobStore.newLatencyBlobStore(delegate,
                Map.ofEntries(Map.entry("put", 1000L)), Map.ofEntries(Map.entry("put", 1L)));

        String blobName = createRandomBlobName();
        ByteSource content = TestUtils.randomByteSource().slice(0, 0);
        Payload payload = Payloads.newByteSourcePayload(content);
        payload.getContentMetadata().setContentLength(content.size());
        Blob blob = latencyBlobStore.blobBuilder(blobName).payload(payload).build();

        long timeTaken = time(() -> latencyBlobStore.putBlob(containerName, blob));
        assertThat(timeTaken).isGreaterThanOrEqualTo(1000L);
    }

    @Test
    public void testMultipleOperations() throws Exception {
        BlobStore latencyBlobStore = LatencyBlobStore.newLatencyBlobStore(delegate,
                Map.ofEntries(Map.entry("*", 1000L)), Map.ofEntries(Map.entry("get", 1L)));

        String blobName = createRandomBlobName();
        ByteSource content = TestUtils.randomByteSource().slice(0, 1024);
        Payload payload = Payloads.newByteSourcePayload(content);
        payload.getContentMetadata().setContentLength(content.size());
        Blob blob = latencyBlobStore.blobBuilder(blobName).payload(payload).build();

        long timeTaken = time(() -> {
            latencyBlobStore.putBlob(containerName, blob);
            consume(latencyBlobStore.getBlob(containerName, blobName));
        });
        assertThat(timeTaken).isGreaterThanOrEqualTo(3000L);
    }

    @Test
    public void testSimultaneousOperations() throws Exception {
        BlobStore latencyBlobStore = LatencyBlobStore.newLatencyBlobStore(delegate,
                Map.ofEntries(Map.entry("*", 1000L)), Map.ofEntries(Map.entry("get", 1L)));

        String blobName = createRandomBlobName();
        ByteSource content = TestUtils.randomByteSource().slice(0, 1024);
        Payload payload = Payloads.newByteSourcePayload(content);
        payload.getContentMetadata().setContentLength(content.size());
        Blob blob = latencyBlobStore.blobBuilder(blobName).payload(payload).build();
        latencyBlobStore.putBlob(containerName, blob);

        ExecutorService executorService = null;
        try {
            executorService = Executors.newFixedThreadPool(5);

            List<Callable<Object>> tasks = new ArrayList<>();
            for (int i = 0; i < 5; i++) {
                tasks.add(Executors.callable(() -> consume(latencyBlobStore.getBlob(containerName, blobName))));
            }

            final ExecutorService service = executorService;
            long timeTaken = time(() -> {
                try {
                    service.invokeAll(tasks);
                } catch (Exception e) {
                    // Ignore
                }
            });
            assertThat(timeTaken).isGreaterThanOrEqualTo(2000L);
        } finally {
            if (executorService != null) {
                executorService.shutdown();
            }
        }
    }

    private static String createRandomContainerName() {
        return "container-" + new Random().nextInt(Integer.MAX_VALUE);
    }

    private static String createRandomBlobName() {
        return "blob-" + new Random().nextInt(Integer.MAX_VALUE);
    }

    private static long time(Runnable runnable) {
        long startTime = System.currentTimeMillis();
        runnable.run();
        return System.currentTimeMillis() - startTime;
    }

    private static void consume(Blob blob) {
        try (InputStream stream = blob.getPayload().openStream()) {
            stream.readAllBytes();
        } catch (IOException ioe) {
            // Ignore
        }
    }
}
