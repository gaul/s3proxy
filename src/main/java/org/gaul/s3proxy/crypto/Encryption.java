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
import java.security.SecureRandom;

import javax.annotation.concurrent.ThreadSafe;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

@ThreadSafe
public class Encryption {
    private final InputStream cis;
    private final IvParameterSpec iv;
    private final int part;

    public Encryption(SecretKeySpec key, InputStream isRaw, int partNumber)
            throws Exception {
        iv = generateIV();

        Cipher cipher = Cipher.getInstance(Constants.AES_CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        cis = new CipherInputStream(isRaw, cipher);
        part = partNumber;
    }

    public final InputStream openStream() throws IOException {
        return new EncryptionInputStream(cis, part, iv);
    }

    private IvParameterSpec generateIV() {
        byte[] iv = new byte[Constants.AES_BLOCK_SIZE];
        var randomSecureRandom = new SecureRandom();
        randomSecureRandom.nextBytes(iv);

        return new IvParameterSpec(iv);
    }
}
