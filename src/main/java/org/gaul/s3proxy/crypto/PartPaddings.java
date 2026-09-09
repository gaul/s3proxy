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
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.NavigableMap;
import java.util.TreeMap;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.SdkRequests;
import org.jspecify.annotations.Nullable;

import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.HeadObjectResponse;

/**
 * The padding blocks of one encrypted object, and the sizes they add up to.
 *
 * <p>Each part is stored as its ciphertext followed by a 64-byte padding
 * block naming that part's IV and plaintext size, so a part's padding can
 * only be found once the sizes of every part after it are known.  Reading
 * them therefore means walking backwards from the end of the object, one
 * backend read per part -- a cost that belongs to the object rather than to
 * any one request, which is why this is a value a caller can hold on to and
 * hand to every {@link Decryption} of the same object.
 *
 * <p>Parts are numbered from the end: 1 is the last part of the object and
 * {@link #size} the first, the order the walk discovers them in and the
 * order {@link DecryptionInputStream} steps through them.
 */
public final class PartPaddings {
    private static final PartPaddings NOT_ENCRYPTED = new PartPaddings(
            Collections.emptyNavigableMap(), /*unencryptedSize=*/ 0,
            /*encryptedSize=*/ 0, /*encrypted=*/ false);

    private final NavigableMap<Integer, PartPadding> parts;
    private final long unencryptedSize;
    private final long encryptedSize;
    private final boolean encrypted;

    private PartPaddings(NavigableMap<Integer, PartPadding> parts,
            long unencryptedSize, long encryptedSize, boolean encrypted) {
        this.parts = parts;
        this.unencryptedSize = unencryptedSize;
        this.encryptedSize = encryptedSize;
        this.encrypted = encrypted;
    }

    /**
     * Refuse a part whose padding claims a length the object cannot hold.
     * The field is read from the stored object rather than from the request,
     * so a corrupt or forged padding steers the walk below: a negative length
     * leaves the accounting standing still or running backwards, which is a
     * loop that never ends and one backend read on every turn of it, and a
     * length past what remains ranges outside the object.  Refusing both
     * leaves every turn consuming at least one whole padding block, so the
     * walk ends after at most one read per block the object holds.
     *
     * @param remaining bytes not yet accounted for by the parts already read,
     *     which this part's ciphertext and its own padding must fit inside
     */
    private static void checkPartSize(long size, long remaining,
            String blobName) throws IOException {
        if (size < 0) {
            throw malformed(blobName, "a part of negative length " + size);
        }
        if (size > remaining - Constants.PADDING_BLOCK_SIZE) {
            throw malformed(blobName, "a part of length " + size +
                    " with only " + remaining + " bytes left to hold it");
        }
    }

    private static IOException malformed(String blobName, String detail) {
        return new IOException("Encrypted object " + blobName +
                " has malformed part padding: " + detail + ".");
    }

    /**
     * Reads an object's paddings, answering an unencrypted object where it
     * finds none.  A blob that does not exist or is smaller than a single
     * padding cannot be encrypted; an empty object encrypts to exactly one
     * 64-byte padding, so a 64-byte blob is still a (zero-length) encrypted
     * object and the delimiter below is what tells the two apart.
     */
    public static PartPaddings read(BlobStore blobStore,
            @Nullable HeadObjectResponse meta, String container,
            String blobName) throws IOException {
        Long metaSize = meta == null ? null : meta.contentLength();
        if (meta == null || metaSize == null ||
                metaSize < Constants.PADDING_BLOCK_SIZE) {
            return NOT_ENCRYPTED;
        }

        // get the 64 byte of part padding from the end of the blob
        var blob = requireNonNull(blobStore.getBlob(
                GetObjectRequest.builder()
                        .bucket(container)
                        .key(blobName)
                        .range(SdkRequests.range(
                                metaSize - Constants.PADDING_BLOCK_SIZE,
                                metaSize - 1))
                        .build()));

        // read the padding structure
        PartPadding lastPartPadding = PartPadding.readPartPadding(blob);
        if (!Arrays.equals(
                lastPartPadding.getDelimiter().getBytes(
                        StandardCharsets.UTF_8),
                Constants.DELIMITER)) {
            return NOT_ENCRYPTED;
        }

        checkPartSize(lastPartPadding.getSize(), metaSize, blobName);

        var partList = new TreeMap<Integer, PartPadding>();
        long unencryptedSize;
        long encryptedSize;

        // detect multipart
        if (lastPartPadding.getPart() > 1 &&
                metaSize >
                    (lastPartPadding.getSize() +
                        Constants.PADDING_BLOCK_SIZE)) {
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
                // What the parts read so far have not accounted for.  Less
                // than one padding block of it cannot be another part, and
                // ranging for one anyway would ask for a negative offset.
                long remaining = metaSize - encryptedSize;
                if (remaining < Constants.PADDING_BLOCK_SIZE) {
                    throw malformed(blobName, "a trailing " + remaining +
                            " bytes too short to be a part");
                }

                // get the next block
                // rewind by the current encrypted block size
                // minus the encryption padding
                long startAt = remaining - Constants.PADDING_BLOCK_SIZE;
                long endAt = metaSize - encryptedSize - 1;
                blob = requireNonNull(blobStore.getBlob(
                        GetObjectRequest.builder()
                                .bucket(container)
                                .key(blobName)
                                .range(SdkRequests.range(startAt, endAt))
                                .build()));

                part++;

                // read the padding structure
                PartPadding partPadding = PartPadding.readPartPadding(blob);
                checkPartSize(partPadding.getSize(), remaining, blobName);

                // add the part to the list
                partList.put(part, partPadding);

                // update the encrypted size
                encryptedSize = encryptedSize +
                    (partPadding.getSize() + Constants.PADDING_BLOCK_SIZE);
                unencryptedSize = unencryptedSize + partPadding.getSize();
            }
        } else {
            // add the single part to the list
            partList.put(1, lastPartPadding);

            // update the unencrypted size
            unencryptedSize = metaSize - Constants.PADDING_BLOCK_SIZE;

            // update the encrypted size
            encryptedSize = metaSize;
        }

        return new PartPaddings(
                Collections.unmodifiableNavigableMap(partList),
                unencryptedSize, encryptedSize, /*encrypted=*/ true);
    }

    /** The paddings, numbered from the end of the object. */
    public NavigableMap<Integer, PartPadding> getParts() {
        return parts;
    }

    public long getUnencryptedSize() {
        return unencryptedSize;
    }

    public long getEncryptedSize() {
        return encryptedSize;
    }

    public boolean isEncrypted() {
        return encrypted;
    }

    /** How many paddings this holds, which is what makes it costly to keep. */
    public int size() {
        return parts.size();
    }
}
