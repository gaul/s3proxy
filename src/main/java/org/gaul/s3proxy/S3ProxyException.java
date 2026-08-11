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

import static java.util.Objects.requireNonNull;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import org.jspecify.annotations.Nullable;

import software.amazon.awssdk.awscore.exception.AwsErrorDetails;
import software.amazon.awssdk.services.s3.model.S3Exception;

/**
 * An S3 error the proxy itself raises, e.g. refusing a malformed or
 * unauthorized request.  Extends the SDK's S3Exception so frontend and
 * backend errors flow through the one renderer, adding the ordered XML
 * elements some error documents carry beside Code and Message, e.g.
 * StringToSign on SignatureDoesNotMatch.
 */
@SuppressWarnings("serial")
public final class S3ProxyException extends S3Exception {
    private final transient S3ErrorCode error;
    private final transient Map<String, String> elements;
    private final String rawMessage;

    public S3ProxyException(S3ErrorCode error) {
        this(error, error.getMessage(), (Throwable) null, Map.of());
    }

    public S3ProxyException(S3ErrorCode error, String message) {
        this(error, message, (Throwable) null, Map.of());
    }

    public S3ProxyException(S3ErrorCode error, @Nullable Throwable cause) {
        this(error, error.getMessage(), cause, Map.of());
    }

    public S3ProxyException(S3ErrorCode error, String message,
            @Nullable Throwable cause) {
        this(error, message, cause, Map.of());
    }

    public S3ProxyException(S3ErrorCode error, String message,
            @Nullable Throwable cause, Map<String, String> elements) {
        super(builder(error, requireNonNull(message), cause));
        this.error = error;
        // Keep the caller's order: these become sibling XML elements, and a
        // reader looks for them in the order the error was written to tell.
        this.elements = Collections.unmodifiableMap(
                new LinkedHashMap<>(elements));
        this.rawMessage = message;
    }

    private static S3Exception.Builder builder(S3ErrorCode error,
            String message, @Nullable Throwable cause) {
        S3Exception.Builder builder = S3Exception.builder();
        builder.message(message);
        builder.cause(cause);
        builder.statusCode(error.getHttpStatusCode());
        builder.awsErrorDetails(AwsErrorDetails.builder()
                .errorCode(error.getErrorCode())
                .errorMessage(message)
                .build());
        return builder;
    }

    public S3ErrorCode getError() {
        return error;
    }

    Map<String, String> getElements() {
        return elements;
    }

    /**
     * The message with the elements folded in, for logs and stack traces
     * that have only the one string to show; the error document renders
     * {@link AwsErrorDetails#errorMessage} and the elements separately.
     */
    @Override
    public String getMessage() {
        var builder = new StringBuilder().append(rawMessage);
        if (!elements.isEmpty()) {
            builder.append(" ").append(elements);
        }
        return builder.toString();
    }
}
