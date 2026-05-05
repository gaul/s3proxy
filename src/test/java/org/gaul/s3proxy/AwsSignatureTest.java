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

package org.gaul.s3proxy;

import static org.assertj.core.api.Assertions.assertThat;

import com.google.common.io.BaseEncoding;

import org.junit.jupiter.api.Test;

public final class AwsSignatureTest {

    /**
     * AWS-published test vector for SigV4 signing-key derivation:
     * https://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html
     * (the "Deriving the signing key" example).
     */
    @Test
    public void deriveSigningKeyV4MatchesAwsReferenceVector() throws Exception {
        var auth = new S3AuthorizationHeader(
                "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20150830/" +
                "us-east-1/iam/aws4_request, " +
                "SignedHeaders=host, Signature=ignored");
        byte[] signingKey = AwsSignature.deriveSigningKeyV4(auth,
                "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY");
        assertThat(BaseEncoding.base16().lowerCase().encode(signingKey))
                .isEqualTo("c4afb1cc5771d871763a393e44b7035" +
                        "71b55cc28424d1a5e86da6ed3c154a4b9");
    }

    @Test
    public void deriveSigningKeyV4IsDeterministic() throws Exception {
        var auth = new S3AuthorizationHeader(
                "AWS4-HMAC-SHA256 Credential=AKID/20260101/us-east-1/s3/" +
                "aws4_request, SignedHeaders=host, Signature=ignored");
        byte[] first = AwsSignature.deriveSigningKeyV4(auth, "secret");
        byte[] second = AwsSignature.deriveSigningKeyV4(auth, "secret");
        assertThat(first).isEqualTo(second);
    }

    @Test
    public void deriveSigningKeyV4VariesByDate() throws Exception {
        var auth1 = new S3AuthorizationHeader(
                "AWS4-HMAC-SHA256 Credential=AKID/20260101/us-east-1/s3/" +
                "aws4_request, SignedHeaders=host, Signature=ignored");
        var auth2 = new S3AuthorizationHeader(
                "AWS4-HMAC-SHA256 Credential=AKID/20260102/us-east-1/s3/" +
                "aws4_request, SignedHeaders=host, Signature=ignored");
        byte[] day1 = AwsSignature.deriveSigningKeyV4(auth1, "secret");
        byte[] day2 = AwsSignature.deriveSigningKeyV4(auth2, "secret");
        assertThat(day1).isNotEqualTo(day2);
    }

    @Test
    public void deriveSigningKeyV4VariesByRegion() throws Exception {
        var east = new S3AuthorizationHeader(
                "AWS4-HMAC-SHA256 Credential=AKID/20260101/us-east-1/s3/" +
                "aws4_request, SignedHeaders=host, Signature=ignored");
        var west = new S3AuthorizationHeader(
                "AWS4-HMAC-SHA256 Credential=AKID/20260101/us-west-2/s3/" +
                "aws4_request, SignedHeaders=host, Signature=ignored");
        assertThat(AwsSignature.deriveSigningKeyV4(east, "secret"))
                .isNotEqualTo(AwsSignature.deriveSigningKeyV4(west, "secret"));
    }

    @Test
    public void deriveSigningKeyV4VariesBySecret() throws Exception {
        var auth = new S3AuthorizationHeader(
                "AWS4-HMAC-SHA256 Credential=AKID/20260101/us-east-1/s3/" +
                "aws4_request, SignedHeaders=host, Signature=ignored");
        assertThat(AwsSignature.deriveSigningKeyV4(auth, "secret-1"))
                .isNotEqualTo(AwsSignature.deriveSigningKeyV4(auth, "secret-2"));
    }
}
