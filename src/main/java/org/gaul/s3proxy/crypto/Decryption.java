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

package org.gaul.s3proxy.crypto;

import static java.util.Objects.requireNonNull;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.TreeMap;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.google.common.io.ByteStreams;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.domain.Blob;
import org.gaul.s3proxy.blobstore.domain.BlobMetadata;
import org.gaul.s3proxy.blobstore.options.GetOptions;
import org.jspecify.annotations.Nullable;

public class Decryption {
    private final SecretKey encryptionKey;
    private TreeMap<Integer, PartPadding> partList = new TreeMap<>();
    private long outputOffset;
    private long outputLength;
    private boolean skipFirstBlock;
    private long unencryptedSize;
    private long encryptedSize;
    private long startAt;
    private int skipParts;
    private long skipPartBytes;
    private boolean isEncrypted;

    public Decryption(SecretKeySpec key, BlobStore blobStore,
        @Nullable BlobMetadata meta,
        long offset, long length) throws IOException {
        encryptionKey = key;
        outputLength = length;
        isEncrypted = true;

        // if blob does not exist or size is smaller than the part padding
        // then the file is considered not encrypted.  An empty object encrypts
        // to exactly one 64-byte padding block, so a 64-byte blob is still a
        // (zero-length) encrypted object; the delimiter check below rejects a
        // genuinely unencrypted 64-byte blob.
        Long metaSize = meta == null ? null : meta.size();
        if (meta == null || metaSize == null ||
            metaSize < Constants.PADDING_BLOCK_SIZE) {
            blobIsNotEncrypted(offset);
            return;
        }
        String container = requireNonNull(meta.container());

        // get the 64 byte of part padding from the end of the blob
        var options = GetOptions.builder()
            .range(metaSize - Constants.PADDING_BLOCK_SIZE,
                metaSize - 1)
            .build();
        Blob blob = requireNonNull(
            blobStore.getBlob(container, meta.name(), options));

        // read the padding structure
        PartPadding lastPartPadding = PartPadding.readPartPaddingFromBlob(blob);
        if (!Arrays.equals(
            lastPartPadding.getDelimiter().getBytes(StandardCharsets.UTF_8),
            Constants.DELIMITER)) {
            blobIsNotEncrypted(offset);
            return;
        }

        // detect multipart
        if (lastPartPadding.getPart() > 1 &&
            metaSize >
                (lastPartPadding.getSize() + Constants.PADDING_BLOCK_SIZE)) {
            unencryptedSize = lastPartPadding.getSize();
            encryptedSize =
                lastPartPadding.getSize() + Constants.PADDING_BLOCK_SIZE;

            // note that parts are in reversed order
            int part = 1;

            // add the last part to the list
            partList.put(part, lastPartPadding);

            // loop part by part from end to the beginning
            // to build a list of all blocks
            while (encryptedSize < metaSize) {
                // get the next block
                // rewind by the current encrypted block size
                // minus the encryption padding
                long startAt = (metaSize - encryptedSize) -
                    Constants.PADDING_BLOCK_SIZE;
                long endAt = metaSize - encryptedSize - 1;
                options = GetOptions.builder().range(startAt, endAt).build();
                blob = requireNonNull(blobStore.getBlob(container, meta.name(),
                    options));

                part++;

                // read the padding structure
                PartPadding partPadding =
                    PartPadding.readPartPaddingFromBlob(blob);

                // add the part to the list
                this.partList.put(part, partPadding);

                // update the encrypted size
                encryptedSize = encryptedSize +
                    (partPadding.getSize() + Constants.PADDING_BLOCK_SIZE);
                unencryptedSize = this.unencryptedSize + partPadding.getSize();
            }

        } else {
            // add the single part to the list
            partList.put(1, lastPartPadding);

            // update the unencrypted size
            unencryptedSize = metaSize - Constants.PADDING_BLOCK_SIZE;

            // update the encrypted size
            encryptedSize = metaSize;
        }

        // calculate the offset
        calculateOffset(offset);

        // if there is a offset and no length set the output length
        if (offset > 0 && length <= 0) {
            outputLength = unencryptedSize - offset;
        }

        // clamp an explicit length whose range runs past the end of the
        // object so the reported length matches the bytes actually returned;
        // S3 truncates such a range rather than padding it.
        if (offset < unencryptedSize &&
            outputLength > unencryptedSize - offset) {
            outputLength = unencryptedSize - offset;
        }
    }

    private void blobIsNotEncrypted(long offset) {
        isEncrypted = false;
        startAt = offset;
    }

    // calculate the tail bytes we need to read
    // because we know the unencryptedSize we can return startAt offset
    public final long calculateTail() {
        long offset = unencryptedSize - outputLength;
        calculateOffset(offset);

        return startAt;
    }

    public final long getEncryptedSize() {
        return encryptedSize;
    }

    public final long getUnencryptedSize() {
        return unencryptedSize;
    }

    public final long calculateEndAt(long endAt) {
        // need to have always one more
        endAt++;

        // handle multipart
        if (partList.size() > 1) {
            long plaintextSize = 0;

            // always skip 1 part at the end
            int partCounter = 1;

            // we need the map in reversed order
            for (var part : partList.descendingMap().entrySet()) {
                // check the parts that are between offset and end
                plaintextSize = plaintextSize + part.getValue().getSize();
                if (endAt > plaintextSize) {
                    partCounter++;
                } else {
                    break;
                }
            }

            // add the paddings of all parts
            endAt = endAt + ((long) Constants.PADDING_BLOCK_SIZE * partCounter);
        } else {
            // we need to read one AES block more in AES CFB mode
            long rest = endAt % Constants.AES_BLOCK_SIZE;
            if (rest > 0) {
                endAt = endAt + Constants.AES_BLOCK_SIZE;
            }
        }

        return endAt;
    }

    // open the streams and pipes
    public final InputStream openStream(InputStream is) throws IOException {
        // if the blob is not encrypted return the unencrypted stream
        if (!isEncrypted) {
            return is;
        }

        // pass input stream through decryption
        InputStream dis = new DecryptionInputStream(is, encryptionKey, partList,
            skipParts, skipPartBytes);

        // skip some bytes if necessary
        long offset = outputOffset;
        if (this.skipFirstBlock) {
            offset = offset + Constants.AES_BLOCK_SIZE;
        }
        dis.skipNBytes(offset);

        // trim the stream to a specific length if needed
        return outputLength >= 0 ? ByteStreams.limit(dis, outputLength) : dis;
    }

    private void calculateOffset(long offset) {
        startAt = 0;
        skipParts = 0;

        // handle multipart
        if (partList.size() > 1) {

            // init counters
            long plaintextSize = 0;
            long encryptedSize = 0;
            long partOffset;
            long partStartAt = 0;

            // we need the map in reversed order
            for (var part : partList.descendingMap().entrySet()) {
                // compute the plaintext size of the current part
                plaintextSize = plaintextSize + part.getValue().getSize();

                // check if the offset is located in another part
                if (offset > plaintextSize) {
                    // compute the encrypted size of the skipped part
                    encryptedSize = encryptedSize + part.getValue().getSize() +
                        Constants.PADDING_BLOCK_SIZE;

                    // compute offset in this part
                    partOffset = offset - plaintextSize;

                    // skip the first block in CFB mode
                    skipFirstBlock = partOffset >= 16;

                    // compute the offset of the output
                    outputOffset = partOffset % Constants.AES_BLOCK_SIZE;

                    // skip this part
                    skipParts++;

                    // we always need to read one previous AES block in CFB mode
                    // if we read from offset
                    if (partOffset > Constants.AES_BLOCK_SIZE) {
                        long rest = partOffset % Constants.AES_BLOCK_SIZE;
                        partStartAt =
                            (partOffset - Constants.AES_BLOCK_SIZE) - rest;
                    } else {
                        partStartAt = 0;
                    }
                } else {
                    // start at a specific byte position
                    // while respecting other parts
                    startAt = encryptedSize + partStartAt;

                    // skip part bytes if we are not starting
                    // from the beginning of a part
                    skipPartBytes = partStartAt;
                    break;
                }
            }
        }

        // handle single part
        if (skipParts == 0) {
            // skip the first block in CFB mode
            skipFirstBlock = offset >= 16;

            // compute the offset of the output
            outputOffset = offset % Constants.AES_BLOCK_SIZE;

            // we always need to read one previous AES block in CFB mode
            // if we read from offset
            if (offset > Constants.AES_BLOCK_SIZE) {
                long rest = offset % Constants.AES_BLOCK_SIZE;
                startAt = (offset - Constants.AES_BLOCK_SIZE) - rest;
            }

            // skip part bytes if we are not starting
            // from the beginning of a part
            skipPartBytes = startAt;
        }
    }

    public final long getStartAt() {
        return startAt;
    }

    public final boolean isEncrypted() {
        return isEncrypted;
    }

    public final long getContentLength() {
        if (outputLength > 0) {
            return outputLength;
        } else {
            return unencryptedSize;
        }
    }
}
