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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

public final class S3AuthorizationHeaderTest {

    @Test
    public void parsesAwsV2Header() {
        var header = new S3AuthorizationHeader("AWS access-key:abc123/sig=");
        assertThat(header.getAuthenticationType())
                .isEqualTo(AuthenticationType.AWS_V2);
        assertThat(header.getIdentity()).isEqualTo("access-key");
        assertThat(header.getSignature()).isEqualTo("abc123/sig=");
        assertThat(header.getHmacAlgorithm()).isNull();
        assertThat(header.getHashAlgorithm()).isNull();
        assertThat(header.getRegion()).isNull();
        assertThat(header.getDate()).isNull();
        assertThat(header.getService()).isNull();
    }

    @Test
    public void parsesAwsV4Sha256Header() {
        var raw = "AWS4-HMAC-SHA256 " +
                "Credential=AKIAIOSFODNN7EXAMPLE/20260101/us-east-1/s3/" +
                "aws4_request, SignedHeaders=host;x-amz-date, " +
                "Signature=abc123";
        var header = new S3AuthorizationHeader(raw);
        assertThat(header.getAuthenticationType())
                .isEqualTo(AuthenticationType.AWS_V4);
        assertThat(header.getIdentity()).isEqualTo("AKIAIOSFODNN7EXAMPLE");
        assertThat(header.getDate()).isEqualTo("20260101");
        assertThat(header.getRegion()).isEqualTo("us-east-1");
        assertThat(header.getService()).isEqualTo("s3");
        assertThat(header.getHmacAlgorithm()).isEqualTo("HmacSHA256");
        assertThat(header.getHashAlgorithm()).isEqualTo("SHA-256");
        assertThat(header.getSignature()).isEqualTo("abc123");
    }

    @Test
    public void parsesAwsV4Sha1Header() {
        var raw = "AWS4-HMAC-SHA1 " +
                "Credential=key/20260101/us-west-2/s3/aws4_request, " +
                "SignedHeaders=host, Signature=deadbeef";
        var header = new S3AuthorizationHeader(raw);
        assertThat(header.getHmacAlgorithm()).isEqualTo("HmacSHA1");
        assertThat(header.getHashAlgorithm()).isEqualTo("SHA-1");
        assertThat(header.getRegion()).isEqualTo("us-west-2");
    }

    @Test
    public void signatureCanBeTheLastField() {
        // No trailing comma after Signature= -- extractSignature must handle
        // both "Signature=…," and "Signature=…" at end-of-string.
        var raw = "AWS4-HMAC-SHA256 " +
                "Credential=k/20260101/us-east-1/s3/aws4_request, " +
                "SignedHeaders=host, Signature=zzz";
        var header = new S3AuthorizationHeader(raw);
        assertThat(header.getSignature()).isEqualTo("zzz");
    }

    @Test
    public void rejectsUnknownAuthScheme() {
        assertThatThrownBy(() -> new S3AuthorizationHeader("Bearer token"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Invalid header");
    }

    @Test
    public void rejectsAwsV2WithoutColon() {
        assertThatThrownBy(
                () -> new S3AuthorizationHeader("AWS access-key-no-colon"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    public void rejectsAwsV2WithExtraSpaces() {
        assertThatThrownBy(() -> new S3AuthorizationHeader(
                "AWS too many parts here"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Invalid header");
    }

    @Test
    public void rejectsAwsV4WithoutSpace() {
        assertThatThrownBy(
                () -> new S3AuthorizationHeader("AWS4-HMAC-SHA256"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    public void rejectsAwsV4UnsupportedAlgorithm() {
        var raw = "AWS4-HMAC-SHA512 " +
                "Credential=k/20260101/us-east-1/s3/aws4_request, " +
                "SignedHeaders=host, Signature=zzz";
        assertThatThrownBy(() -> new S3AuthorizationHeader(raw))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Unsupported signing algorithm");
    }

    @Test
    public void rejectsAwsV4WithoutCredentialField() {
        var raw = "AWS4-HMAC-SHA256 SignedHeaders=host, Signature=zzz";
        assertThatThrownBy(() -> new S3AuthorizationHeader(raw))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    public void rejectsAwsV4MalformedCredential() {
        // Only 3 slash-separated parts in Credential= rather than 5.
        var raw = "AWS4-HMAC-SHA256 Credential=k/20260101/s3, " +
                "SignedHeaders=host, Signature=zzz";
        assertThatThrownBy(() -> new S3AuthorizationHeader(raw))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid Credential");
    }

    @Test
    public void rejectsAwsV4WithoutSignatureField() {
        var raw = "AWS4-HMAC-SHA256 " +
                "Credential=k/20260101/us-east-1/s3/aws4_request, " +
                "SignedHeaders=host";
        assertThatThrownBy(() -> new S3AuthorizationHeader(raw))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid signature");
    }
}
