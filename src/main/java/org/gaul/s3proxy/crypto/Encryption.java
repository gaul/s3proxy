/*
 * Copyright 2014-2021 Andrew Gaul <andrew@gaul.org>
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

import java.io.InputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.nio.ByteBuffer;
import java.security.SecureRandom;

import javax.annotation.concurrent.ThreadSafe;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.io.IOUtils;

@ThreadSafe
public class Encryption extends Thread {
    private final InputStream cis;
    private final IvParameterSpec iv;
    private final PipedInputStream pipeIn;
    private final PipedOutputStream pipeOut;
    private final int part;

    public Encryption(SecretKeySpec key, InputStream isRaw, int partNumber)
        throws Exception {
        this.setName(Encryption.class.getSimpleName() + "-" + this.getId());
        this.setPriority(Thread.MIN_PRIORITY);
        iv = generateIV();
        pipeIn = new PipedInputStream();
        pipeOut = new PipedOutputStream(pipeIn);

        Cipher cipher = Cipher.getInstance(Constants.AES_CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        cis = new CipherInputStream(isRaw, cipher);
        part = partNumber;
    }

    @Override
    public final void run() {
        try {
            long size = IOUtils.copyLarge(cis, pipeOut);
            pipeOut.write(padding(iv, part, size));
            pipeOut.flush();
            pipeOut.close();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public final InputStream openStream() {
        this.start();
        return pipeIn;
    }

    private IvParameterSpec generateIV() {
        byte[] iv = new byte[Constants.AES_BLOCK_SIZE];
        SecureRandom randomSecureRandom = new SecureRandom();
        randomSecureRandom.nextBytes(iv);

        return new IvParameterSpec(iv);
    }

    // Padding (64 byte)
    // Delimiter (8 byte)
    // IV (16 byte)
    // Part (4 byte)
    // Size (8 byte)
    // Version (2 byte)
    // Reserved (26 byte)
    private byte[] padding(IvParameterSpec iv, int part, long size) {
        ByteBuffer bb = ByteBuffer.allocate(Constants.PADDING_BLOCK_SIZE);
        bb.put(Constants.DELIMITER);
        bb.put(iv.getIV());
        bb.putInt(part);
        bb.putLong(size);
        bb.putShort(Constants.VERSION);

        return bb.array();
    }
}
