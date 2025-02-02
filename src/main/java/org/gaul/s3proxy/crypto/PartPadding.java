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
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import javax.crypto.spec.IvParameterSpec;

import org.jclouds.blobstore.domain.Blob;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PartPadding {
    private static final Logger logger =
        LoggerFactory.getLogger(PartPadding.class);

    private String delimiter;
    private IvParameterSpec iv;
    private int part;
    private long size;
    private short version;

    public static PartPadding readPartPaddingFromBlob(Blob blob)
            throws IOException {
        var partPadding = new PartPadding();

        try (var is = blob.getPayload().openStream()) {
            byte[] paddingBytes = is.readAllBytes();
            ByteBuffer bb = ByteBuffer.wrap(paddingBytes);

            byte[] delimiterBytes =
                new byte[Constants.PADDING_DELIMITER_LENGTH];
            bb.get(delimiterBytes);
            partPadding.delimiter =
                new String(delimiterBytes, StandardCharsets.UTF_8);

            byte[] ivBytes = new byte[Constants.PADDING_IV_LENGTH];
            bb.get(ivBytes);
            partPadding.iv = new IvParameterSpec(ivBytes);

            partPadding.part = bb.getInt();
            partPadding.size = bb.getLong();
            partPadding.version = bb.getShort();

            logger.debug("delimiter {}", partPadding.delimiter);
            logger.debug("iv {}", Arrays.toString(ivBytes));
            logger.debug("part {}", partPadding.part);
            logger.debug("size {}", partPadding.size);
            logger.debug("version {}", partPadding.version);

            return partPadding;
        }
    }

    public final String getDelimiter() {
        return delimiter;
    }

    public final IvParameterSpec getIv() {
        return iv;
    }

    public final int getPart() {
        return part;
    }

    public final long getSize() {
        return size;
    }
}
