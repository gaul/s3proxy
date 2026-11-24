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

package org.gaul.s3proxy.azureblob;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import reactor.core.publisher.Flux;

public final class ByteBufferFluxInputStreamTest {
    @Test
    public void testReadsAcrossBuffers() throws Exception {
        var body = Flux.just("ab", "", "cde", "f").map(s ->
                ByteBuffer.wrap(s.getBytes(StandardCharsets.UTF_8)));
        try (var in = new ByteBufferFluxInputStream(body)) {
            assertThat(in.read()).isEqualTo('a');
            assertThat(new String(in.readAllBytes(), StandardCharsets.UTF_8))
                    .isEqualTo("bcdef");
            assertThat(in.read()).isEqualTo(-1);
        }
    }

    /**
     * A reader that stops early cancels the download, which is what lets
     * its connection go, and is asked for no more than a few buffers.
     */
    @Test
    public void testCloseCancelsTheDownload() throws Exception {
        var cancelled = new AtomicBoolean();
        var produced = new AtomicInteger();
        var body = Flux.range(0, 1_000_000)
                .map(i -> {
                    produced.incrementAndGet();
                    return ByteBuffer.wrap(new byte[] {i.byteValue()});
                })
                .doOnCancel(() -> cancelled.set(true));
        var in = new ByteBufferFluxInputStream(body);
        assertThat(in.read()).isEqualTo(0);
        in.close();

        assertThat(cancelled).isTrue();
        assertThat(produced.get()).isLessThan(100);
        assertThatThrownBy(in::read).isInstanceOf(IOException.class);
    }

    /**
     * A download that breaks off is never taken for one that ended: the
     * reader is given an IOException, not the end of the stream.  Reactor
     * may raise it before every buffer ahead of the failure is read.
     */
    @Test
    public void testFailureIsAnIOException() throws Exception {
        var body = Flux.concat(
                Flux.just(ByteBuffer.wrap(new byte[] {1})),
                Flux.<ByteBuffer>error(new IllegalStateException("reset")));
        try (var in = new ByteBufferFluxInputStream(body)) {
            assertThatThrownBy(in::readAllBytes)
                    .isInstanceOf(IOException.class)
                    .hasStackTraceContaining("reset");
        }
    }
}
