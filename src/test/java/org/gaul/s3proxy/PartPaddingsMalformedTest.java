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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.List;

import org.gaul.s3proxy.crypto.Constants;
import org.gaul.s3proxy.crypto.PartPaddings;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.http.AbortableInputStream;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.HeadObjectResponse;

/**
 * The size in a part padding is read from the stored object, not from the
 * request, so a corrupt or forged one steers the backward walk that finds the
 * remaining parts.  A negative size left the accounting standing still: the
 * walk never ended and issued a backend read on every turn, so one GET of one
 * object hung a request thread and read from the backend without limit.  Sizes
 * the object cannot hold are refused instead, and the walk of a well-formed
 * object is unchanged.
 */
public final class PartPaddingsMalformedTest {
    /** Enough turns to tell a bounded walk from an unbounded one. */
    private static final int CAP = 10_000;
    private static final String CONTAINER = "container";
    private static final String BLOB = "blob";

    /** A padding block naming a part number and a plaintext size. */
    private static byte[] padding(int part, long size) {
        var bb = ByteBuffer.allocate(Constants.PADDING_BLOCK_SIZE);
        bb.put(Constants.DELIMITER);
        bb.put(new byte[Constants.PADDING_IV_LENGTH]);
        bb.putInt(part);
        bb.putLong(size);
        bb.putShort(Constants.VERSION);
        return bb.array();
    }

    /** Answers the given paddings in order, and counts how often it is asked. */
    private static final class PaddingStore
            extends AbstractUnsupportedBlobStore {
        private final List<byte[]> paddings;
        private int calls;

        PaddingStore(byte[]... paddings) {
            this.paddings = List.of(paddings);
        }

        @Override
        public ResponseInputStream<GetObjectResponse> getBlob(
                GetObjectRequest request) {
            if (calls >= CAP) {
                throw new IllegalStateException(
                        "walk did not terminate: " + calls + " reads");
            }
            byte[] padding = paddings.get(
                    Math.min(calls, paddings.size() - 1));
            ++calls;
            return new ResponseInputStream<>(GetObjectResponse.builder()
                    .contentLength((long) padding.length).build(),
                    AbortableInputStream.create(
                            new ByteArrayInputStream(padding)));
        }
    }

    private static HeadObjectResponse head(long size) {
        return HeadObjectResponse.builder().contentLength(size).build();
    }

    /**
     * A size that exactly cancels the padding block each turn adds.  The walk
     * used to make no progress and never stop.
     */
    @Test
    public void testSizeCancellingTheBlockIsRefused() {
        var store = new PaddingStore(
                padding(/*part=*/ 2, -Constants.PADDING_BLOCK_SIZE));
        assertThatThrownBy(() -> PartPaddings.read(store, head(1024),
                CONTAINER, BLOB))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("negative length");
        assertThat(store.calls).isLessThan(CAP);
    }

    /** Any negative size, not only the one that cancels exactly. */
    @Test
    public void testNegativeSizeIsRefused() {
        var store = new PaddingStore(padding(2, -1));
        assertThatThrownBy(() -> PartPaddings.read(store, head(1024),
                CONTAINER, BLOB))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("negative length");
    }

    /** A size larger than the object that is supposed to contain it. */
    @Test
    public void testSizeLargerThanTheObjectIsRefused() {
        var store = new PaddingStore(padding(2, Long.MAX_VALUE));
        assertThatThrownBy(() -> PartPaddings.read(store, head(1024),
                CONTAINER, BLOB))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("bytes left to hold it");
    }

    /**
     * A second part claiming more than the bytes the first left unaccounted
     * for, which would range past the front of the object.
     */
    @Test
    public void testPartOverrunningTheRemainderIsRefused() {
        var store = new PaddingStore(
                padding(/*part=*/ 2, 100),
                padding(/*part=*/ 1, 10_000));
        assertThatThrownBy(() -> PartPaddings.read(store, head(1024),
                CONTAINER, BLOB))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("bytes left to hold it");
    }

    /** A padding shorter than the fields it is read for. */
    @Test
    public void testShortPaddingIsRefused() {
        var store = new PaddingStore(new byte[8]);
        assertThatThrownBy(() -> PartPaddings.read(store, head(1024),
                CONTAINER, BLOB))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("fewer than the");
    }

    /**
     * The walk of a well-formed two-part object, which the refusals above
     * must leave alone: 100 bytes of ciphertext and a padding, twice.
     */
    @Test
    public void testWellFormedMultipartStillWalks() throws Exception {
        long partSize = 100;
        long total = 2 * (partSize + Constants.PADDING_BLOCK_SIZE);
        var store = new PaddingStore(
                padding(/*part=*/ 2, partSize),
                padding(/*part=*/ 1, partSize));

        PartPaddings paddings = PartPaddings.read(store, head(total),
                CONTAINER, BLOB);

        assertThat(paddings.isEncrypted()).isTrue();
        assertThat(paddings.size()).isEqualTo(2);
        assertThat(paddings.getUnencryptedSize()).isEqualTo(2 * partSize);
        assertThat(paddings.getEncryptedSize()).isEqualTo(total);
        assertThat(store.calls).isEqualTo(2);
    }

    /** A single-part object is read from its one padding, as before. */
    @Test
    public void testWellFormedSinglePartStillWalks() throws Exception {
        long partSize = 100;
        long total = partSize + Constants.PADDING_BLOCK_SIZE;
        var store = new PaddingStore(padding(/*part=*/ 1, partSize));

        PartPaddings paddings = PartPaddings.read(store, head(total),
                CONTAINER, BLOB);

        assertThat(paddings.isEncrypted()).isTrue();
        assertThat(paddings.size()).isEqualTo(1);
        assertThat(paddings.getUnencryptedSize()).isEqualTo(partSize);
        assertThat(store.calls).isEqualTo(1);
    }
}
