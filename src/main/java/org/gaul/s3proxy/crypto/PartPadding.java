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
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import javax.crypto.spec.IvParameterSpec;

import org.gaul.s3proxy.blobstore.domain.Blob;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class PartPadding {
    private static final Logger logger =
        LoggerFactory.getLogger(PartPadding.class);

    private final String delimiter;
    private final IvParameterSpec iv;
    private final int part;
    private final long size;

    private PartPadding(String delimiter, IvParameterSpec iv, int part,
            long size) {
        this.delimiter = delimiter;
        this.iv = iv;
        this.part = part;
        this.size = size;
    }

    public static PartPadding readPartPaddingFromBlob(Blob blob)
            throws IOException {
        try (var is = requireNonNull(blob.getPayload())) {
            byte[] paddingBytes = is.readAllBytes();
            ByteBuffer bb = ByteBuffer.wrap(paddingBytes);

            byte[] delimiterBytes =
                new byte[Constants.PADDING_DELIMITER_LENGTH];
            bb.get(delimiterBytes);
            String delimiter =
                new String(delimiterBytes, StandardCharsets.UTF_8);

            byte[] ivBytes = new byte[Constants.PADDING_IV_LENGTH];
            bb.get(ivBytes);
            var iv = new IvParameterSpec(ivBytes);

            int part = bb.getInt();
            long size = bb.getLong();
            short version = bb.getShort();

            logger.debug("delimiter {}", delimiter);
            logger.debug("iv {}", Arrays.toString(ivBytes));
            logger.debug("part {}", part);
            logger.debug("size {}", size);
            logger.debug("version {}", version);

            return new PartPadding(delimiter, iv, part, size);
        }
    }

    public String getDelimiter() {
        return delimiter;
    }

    public IvParameterSpec getIv() {
        return iv;
    }

    public int getPart() {
        return part;
    }

    public long getSize() {
        return size;
    }
}
