/*
 * Copyright 2014-2020 Andrew Gaul <andrew@gaul.org>
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

import java.util.List;

import javax.annotation.Nullable;

import com.google.common.base.Splitter;
import com.google.common.collect.ImmutableMap;

final class S3AuthorizationHeader {
    private static final ImmutableMap<String, String> DIGEST_MAP =
            ImmutableMap.<String, String>builder()
            .put("SHA256", "SHA-256")
            .put("SHA1", "SHA-1")
            .put("MD5", "MD5")
            .build();
    private static final String SIGNATURE_FIELD = "Signature=";
    private static final String CREDENTIAL_FIELD = "Credential=";

    // TODO: these fields should have accessors
    // CHECKSTYLE:OFF
    final AuthenticationType authenticationType;
    @Nullable final String hmacAlgorithm;
    @Nullable final String hashAlgorithm;
    @Nullable final String region;
    @Nullable final String date;
    @Nullable final String service;
    final String identity;
    final String signature;
    // CHECKSTYLE:ON

    S3AuthorizationHeader(String header) {
        if (header.startsWith("AWS ")) {
            authenticationType = AuthenticationType.AWS_V2;
            hmacAlgorithm = null;
            hashAlgorithm = null;
            region = null;
            date = null;
            service = null;
            List<String> fields = Splitter.on(' ').splitToList(header);
            if (fields.size() != 2) {
                throw new IllegalArgumentException("Invalid header");
            }
            List<String> identityTuple = Splitter.on(':').splitToList(
                    fields.get(1));
            if (identityTuple.size() != 2) {
                throw new IllegalArgumentException("Invalid header");
            }
            identity = identityTuple.get(0);
            signature = identityTuple.get(1);
        } else if (header.startsWith("AWS4-HMAC")) {
            authenticationType = AuthenticationType.AWS_V4;
            signature = extractSignature(header);

            int credentialIndex = header.indexOf(CREDENTIAL_FIELD);
            if (credentialIndex < 0) {
                throw new IllegalArgumentException("Invalid header");
            }
            int credentialEnd = header.indexOf(',', credentialIndex);
            if (credentialEnd < 0) {
                throw new IllegalArgumentException("Invalid header");
            }
            String credential = header.substring(credentialIndex +
                    CREDENTIAL_FIELD.length(), credentialEnd);
            List<String> fields = Splitter.on('/').splitToList(credential);
            if (fields.size() != 5) {
                throw new IllegalArgumentException(
                        "Invalid Credential: " + credential);
            }
            identity = fields.get(0);
            date = fields.get(1);
            region = fields.get(2);
            service = fields.get(3);
            String awsSignatureVersion = header.substring(
                    0, header.indexOf(' '));
            hashAlgorithm = DIGEST_MAP.get(Splitter.on('-').splitToList(
                    awsSignatureVersion).get(2));
            hmacAlgorithm = "Hmac" + Splitter.on('-').splitToList(
                    awsSignatureVersion).get(2);
        } else {
            throw new IllegalArgumentException("Invalid header");
        }
    }

    @Override
    public String toString() {
        return "Identity: " + identity +
                "; Signature: " + signature +
                "; HMAC algorithm: " + hmacAlgorithm +
                "; Hash algorithm: " + hashAlgorithm +
                "; region: " + region +
                "; date: " + date +
                "; service " + service;
    }

    private static String extractSignature(String header) {
        int signatureIndex = header.indexOf(SIGNATURE_FIELD);
        if (signatureIndex < 0) {
            throw new IllegalArgumentException("Invalid signature");
        }
        signatureIndex += SIGNATURE_FIELD.length();
        int signatureEnd = header.indexOf(',', signatureIndex);
        if (signatureEnd < 0) {
            return header.substring(signatureIndex);
        } else {
            return header.substring(signatureIndex, signatureEnd);
        }
    }
}
