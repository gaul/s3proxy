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

package org.gaul.s3proxy.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.TreeMap;

import javax.annotation.concurrent.ThreadSafe;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.google.common.io.ByteStreams;

import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.domain.Blob;
import org.jclouds.blobstore.domain.BlobMetadata;
import org.jclouds.blobstore.options.GetOptions;

@ThreadSafe
public class Decryption {
    private final SecretKey encryptionKey;
    private TreeMap<Integer, PartPadding> partList;
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
        BlobMetadata meta,
        long offset, long length) throws IOException {
        encryptionKey = key;
        outputLength = length;
        isEncrypted = true;

        // if blob does not exist or size is smaller than the part padding
        // then the file is considered not encrypted
        if (meta == null || meta.getSize() <= 64) {
            blobIsNotEncrypted(offset);
            return;
        }

        // get the 64 byte of part padding from the end of the blob
        var options = new GetOptions();
        options.range(meta.getSize() - Constants.PADDING_BLOCK_SIZE,
            meta.getSize());
        Blob blob =
            blobStore.getBlob(meta.getContainer(), meta.getName(), options);

        // read the padding structure
        PartPadding lastPartPadding = PartPadding.readPartPaddingFromBlob(blob);
        if (!Arrays.equals(
            lastPartPadding.getDelimiter().getBytes(StandardCharsets.UTF_8),
            Constants.DELIMITER)) {
            blobIsNotEncrypted(offset);
            return;
        }

        partList = new TreeMap<>();

        // detect multipart
        if (lastPartPadding.getPart() > 1 &&
            meta.getSize() >
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
            while (encryptedSize < meta.getSize()) {
                // get the next block
                // rewind by the current encrypted block size
                // minus the encryption padding
                options = new GetOptions();
                long startAt = (meta.getSize() - encryptedSize) -
                    Constants.PADDING_BLOCK_SIZE;
                long endAt = meta.getSize() - encryptedSize - 1;
                options.range(startAt, endAt);
                blob = blobStore.getBlob(meta.getContainer(), meta.getName(),
                    options);

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
            unencryptedSize = meta.getSize() - Constants.PADDING_BLOCK_SIZE;

            // update the encrypted size
            encryptedSize = meta.getSize();
        }

        // calculate the offset
        calculateOffset(offset);

        // if there is a offset and no length set the output length
        if (offset > 0 && length <= 0) {
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
        ByteStreams.skipFully(dis, offset);

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
