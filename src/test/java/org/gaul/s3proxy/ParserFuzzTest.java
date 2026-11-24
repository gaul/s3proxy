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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import com.code_intelligence.jazzer.mutation.annotation.NotNull;

import org.gaul.s3proxy.auth.PostPolicy;
import org.gaul.s3proxy.auth.S3AuthorizationHeader;
import org.gaul.s3proxy.blobstore.SdkRequests;
import org.gaul.s3proxy.blobstore.UploadNames;
import org.gaul.s3proxy.checksum.ChunkedInputStream;
import org.gaul.s3proxy.sts.SessionPolicy;
import org.gaul.s3proxy.sts.SessionToken;

import software.amazon.awssdk.awscore.exception.AwsServiceException;

/**
 * Parsers of request input, each given arbitrary input.  A parser may
 * refuse its input only with an exception the handler answers as a client
 * error; any other is a 500.  Without JAZZER_FUZZ these run the saved
 * inputs only.
 */
public final class ParserFuzzTest {
    /** Whether the handler answers this exception as the client's fault. */
    static boolean isClientError(Throwable t) {
        return t instanceof IllegalArgumentException ||
                t instanceof IllegalStateException ||
                t instanceof UnsupportedOperationException ||
                (t instanceof AwsServiceException ase &&
                        ase.statusCode() < 500);
    }

    private static void refusedAsClientError(Runnable parse) {
        try {
            parse.run();
        } catch (RuntimeException re) {
            if (!isClientError(re)) {
                throw re;
            }
        }
    }

    @FuzzTest
    void range(@NotNull String range) {
        refusedAsClientError(() -> SdkRequests.parseRange(range));
    }

    @FuzzTest
    void postPolicy(byte @NotNull [] base64) {
        refusedAsClientError(() -> PostPolicy.parse(base64));
    }

    @FuzzTest
    void sessionPolicy(@NotNull String document) {
        refusedAsClientError(() -> SessionPolicy.parse(document));
    }

    @FuzzTest
    void sessionToken(@NotNull String token) {
        refusedAsClientError(() -> SessionToken.decode(token, "secret"));
    }

    @FuzzTest
    void authorizationHeader(@NotNull String header) {
        refusedAsClientError(() -> new S3AuthorizationHeader(header));
    }

    @FuzzTest
    void uploadKeyEscaping(@NotNull String key) {
        assertThat(UploadNames.unescapeKey(UploadNames.escapeKey(key)))
                .isEqualTo(key);
    }

    /**
     * An aws-chunked body: it may be refused with an IOException, which the
     * handler reports as a truncated or malformed body, and never otherwise.
     */
    @FuzzTest
    void awsChunked(FuzzedDataProvider data) throws IOException {
        String trailer = data.pickValue(List.of(
                "", "x-amz-checksum-crc32", "x-amz-checksum-crc64nvme",
                "x-amz-checksum-sha256"));
        byte[] body = data.consumeRemainingAsBytes();
        try (InputStream is = new ChunkedInputStream(
                new ByteArrayInputStream(body), 64 * 1024,
                trailer.isEmpty() ? null : trailer)) {
            is.transferTo(OutputStream.nullOutputStream());
        } catch (IOException ioe) {
            // a malformed body
        } catch (RuntimeException re) {
            if (!isClientError(re)) {
                throw new AssertionError(new String(body,
                        StandardCharsets.ISO_8859_1), re);
            }
        }
    }
}
