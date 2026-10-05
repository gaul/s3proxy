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

package org.gaul.s3proxy.sts;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * A temporary credential's session token.  The token is the whole of the
 * session: S3Proxy keeps no record of the credentials it issues, so
 * everything a later request needs to verify the caller -- the temporary
 * access key id, the expiry, the policy -- travels inside it, encrypted and
 * authenticated with a key derived from the secret of the identity that
 * minted it.  Any S3Proxy configured with that identity can verify the token,
 * and changing or removing the identity's secret revokes every token minted
 * with it.
 *
 * <p>The temporary secret access key is not in the token at all.  It is
 * derived from the parent secret and the temporary access key id, so the
 * server recomputes it while the client has only to remember it.
 *
 * <p>Both keys come from the parent secret by HKDF, which is only as strong
 * as that secret: a temporary secret, or a token, lets whoever holds it test
 * guesses at the parent secret offline.  Identities that mint temporary
 * credentials need long random secrets.
 *
 * <p>Layout, before base64url encoding:
 * <pre>
 *   version (1) | parent id length (2) | parent id | nonce (12) |
 *   AES-256-GCM(claims) with the version and parent id as associated data
 * </pre>
 * The parent access key id rides in the clear so the verifier knows whose
 * secret to derive the key from; it is not secret, and the GCM tag binds it.
 */
public record SessionToken(String parentAccessKeyId, String accessKeyId,
        Instant expiration, String name, String policy) {
    /** AWS temporary access key ids start ASIA; so do these. */
    private static final String ACCESS_KEY_PREFIX = "ASIA";
    private static final byte VERSION = 1;
    private static final int NONCE_LENGTH = 12;
    private static final int TAG_BITS = 128;
    private static final int SECRET_BYTES = 30;
    private static final int MAX_PARENT_ID_LENGTH = 1024;
    private static final byte[] TOKEN_KEY_INFO =
            "s3proxy-sts-token-v1".getBytes(StandardCharsets.UTF_8);
    private static final byte[] SECRET_KEY_INFO =
            "s3proxy-sts-secret-v1".getBytes(StandardCharsets.UTF_8);
    private static final byte[] SALT_PREFIX =
            "s3proxy-sts-v1:".getBytes(StandardCharsets.UTF_8);
    private static final char[] ACCESS_KEY_ALPHABET =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray();

    public SessionToken {
        Objects.requireNonNull(parentAccessKeyId);
        Objects.requireNonNull(accessKeyId);
        Objects.requireNonNull(expiration);
        Objects.requireNonNull(name);
        Objects.requireNonNull(policy);
    }

    /** A fresh temporary access key id, AWS-shaped: ASIA and 16 more. */
    public static String newAccessKeyId(SecureRandom random) {
        var builder = new StringBuilder(ACCESS_KEY_PREFIX);
        for (int i = 0; i < 16; i++) {
            builder.append(ACCESS_KEY_ALPHABET[
                    random.nextInt(ACCESS_KEY_ALPHABET.length)]);
        }
        return builder.toString();
    }

    /**
     * The secret access key belonging to a temporary access key id: an HMAC
     * of the id under a key derived from the parent secret, rendered as the
     * 40 base64 characters an AWS secret has.
     */
    public static String secretAccessKey(String parentAccessKeyId,
            String accessKeyId, String parentSecret) {
        byte[] key = deriveKey(parentAccessKeyId, parentSecret,
                SECRET_KEY_INFO);
        byte[] mac = hmac(key, accessKeyId.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(
                Arrays.copyOf(mac, SECRET_BYTES));
    }

    /** Encrypt and encode the token under a key derived from parentSecret. */
    public String encode(String parentSecret, SecureRandom random) {
        byte[] parentId = parentAccessKeyId.getBytes(StandardCharsets.UTF_8);
        if (parentId.length > MAX_PARENT_ID_LENGTH) {
            throw new IllegalArgumentException("parent id too long");
        }
        byte[] header = ByteBuffer.allocate(3 + parentId.length)
                .put(VERSION)
                .putShort((short) parentId.length)
                .put(parentId)
                .array();
        byte[] nonce = new byte[NONCE_LENGTH];
        random.nextBytes(nonce);

        byte[] ciphertext;
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(
                    deriveKey(parentAccessKeyId, parentSecret,
                            TOKEN_KEY_INFO), "AES"),
                    new GCMParameterSpec(TAG_BITS, nonce));
            cipher.updateAAD(header);
            ciphertext = cipher.doFinal(serializeClaims());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
        byte[] token = ByteBuffer.allocate(header.length + nonce.length +
                ciphertext.length)
                .put(header)
                .put(nonce)
                .put(ciphertext)
                .array();
        return Base64.getUrlEncoder().withoutPadding().encodeToString(token);
    }

    /**
     * The access key id of the identity that minted a token, read without
     * verifying anything: the caller needs it to find the secret that
     * {@link #decode} then checks the token against.
     *
     * @throws IllegalArgumentException if the token is not one of ours
     */
    public static String parentAccessKeyId(String token) {
        byte[] bytes = decodeBase64(token);
        return new String(bytes, 3, parentIdLength(bytes),
                StandardCharsets.UTF_8);
    }

    /**
     * Verify and decrypt a token minted with parentSecret.  Expiry is the
     * caller's to check: a token that has expired still decodes.
     *
     * @throws IllegalArgumentException if the token is malformed, was not
     *     minted with this secret, or has been altered
     */
    public static SessionToken decode(String token, String parentSecret) {
        byte[] bytes = decodeBase64(token);
        int parentIdLength = parentIdLength(bytes);
        int headerLength = 3 + parentIdLength;
        if (bytes.length < headerLength + NONCE_LENGTH + TAG_BITS / 8) {
            throw new IllegalArgumentException("token too short");
        }
        String parentId = new String(bytes, 3, parentIdLength,
                StandardCharsets.UTF_8);
        byte[] plaintext;
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(
                    deriveKey(parentId, parentSecret, TOKEN_KEY_INFO),
                    "AES"),
                    new GCMParameterSpec(TAG_BITS, bytes, headerLength,
                            NONCE_LENGTH));
            cipher.updateAAD(bytes, 0, headerLength);
            int offset = headerLength + NONCE_LENGTH;
            plaintext = cipher.doFinal(bytes, offset, bytes.length - offset);
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("token does not verify", e);
        }
        return deserializeClaims(parentId, plaintext);
    }

    private byte[] serializeClaims() {
        var bytes = new ByteArrayOutputStream();
        try (var out = new DataOutputStream(bytes)) {
            out.writeUTF(accessKeyId);
            out.writeLong(expiration.getEpochSecond());
            out.writeUTF(name);
            // writeUTF caps a string at 64 KiB of modified UTF-8, well past
            // the policy length GetFederationToken accepts.
            out.writeUTF(policy);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        return bytes.toByteArray();
    }

    private static SessionToken deserializeClaims(String parentId,
            byte[] plaintext) {
        try (var in = new DataInputStream(
                new ByteArrayInputStream(plaintext))) {
            String accessKeyId = in.readUTF();
            Instant expiration = Instant.ofEpochSecond(in.readLong());
            String name = in.readUTF();
            String policy = in.readUTF();
            if (in.available() != 0) {
                throw new IllegalArgumentException("trailing token claims");
            }
            return new SessionToken(parentId, accessKeyId, expiration, name,
                    policy);
        } catch (IOException e) {
            throw new IllegalArgumentException("malformed token claims", e);
        }
    }

    private static byte[] decodeBase64(String token) {
        byte[] bytes;
        try {
            bytes = Base64.getUrlDecoder().decode(token);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("token is not base64url", e);
        }
        if (bytes.length < 3 || bytes[0] != VERSION) {
            throw new IllegalArgumentException("unknown token version");
        }
        return bytes;
    }

    private static int parentIdLength(byte[] bytes) {
        int length = ((bytes[1] & 0xff) << 8) | (bytes[2] & 0xff);
        if (length == 0 || length > MAX_PARENT_ID_LENGTH ||
                bytes.length < 3 + length) {
            throw new IllegalArgumentException("malformed token header");
        }
        return length;
    }

    /**
     * HKDF-SHA256 (RFC 5869) of the parent secret, expanded to one 32-byte
     * block, which is all the AES-256 and HMAC keys here need.  Distinct
     * info labels give independent keys from the one secret.  The salt
     * names the parent, so that identities sharing a secret do not share
     * keys.
     */
    private static byte[] deriveKey(String parentAccessKeyId,
            String parentSecret, byte[] info) {
        byte[] id = parentAccessKeyId.getBytes(StandardCharsets.UTF_8);
        byte[] salt = Arrays.copyOf(SALT_PREFIX, SALT_PREFIX.length +
                id.length);
        System.arraycopy(id, 0, salt, SALT_PREFIX.length, id.length);
        byte[] prk = hmac(salt, parentSecret.getBytes(
                StandardCharsets.UTF_8));
        byte[] block = Arrays.copyOf(info, info.length + 1);
        block[info.length] = 1;
        return hmac(prk, block);
    }

    private static byte[] hmac(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public String toString() {
        // The policy and name are the caller's own, but the token is a
        // bearer credential's half; keep the record's default rendering from
        // ever pretending to be one in a log line.
        return "SessionToken[parentAccessKeyId=" + parentAccessKeyId +
                ", accessKeyId=" + accessKeyId +
                ", expiration=" + expiration + ", name=" + name + "]";
    }
}
