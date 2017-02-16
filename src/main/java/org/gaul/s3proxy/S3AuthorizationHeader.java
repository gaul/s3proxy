/*
 * Copyright 2014-2017 Andrew Gaul <andrew@gaul.org>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.gaul.s3proxy;

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
    final String hmacAlgorithm;
    final String hashAlgorithm;
    final String region;
    final String date;
    final String service;
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
            String[] fields = header.split(" ");
            if (fields.length != 2) {
                throw new IllegalArgumentException("Invalid header");
            }
            String[] identityTuple = fields[1].split(":");
            if (identityTuple.length != 2) {
                throw new IllegalArgumentException("Invalid header");
            }
            identity = identityTuple[0];
            signature = identityTuple[1];
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
            String[] fields = credential.split("/");
            if (fields.length != 5) {
                throw new IllegalArgumentException(
                        "Invalid Credential: " + credential);
            }
            identity = fields[0];
            date = fields[1];
            region = fields[2];
            service = fields[3];
            String awsSignatureVersion = header.substring(
                    0, header.indexOf(' '));
            hashAlgorithm = DIGEST_MAP.get(awsSignatureVersion.split("-")[2]);
            hmacAlgorithm = "Hmac" + awsSignatureVersion.split("-")[2];
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
