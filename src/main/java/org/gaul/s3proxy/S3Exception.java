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

import static java.util.Objects.requireNonNull;

import java.util.Map;

import com.google.common.collect.ImmutableMap;

@SuppressWarnings("serial")
public final class S3Exception extends Exception {
    private final S3ErrorCode error;
    private final Map<String, String> elements;

    S3Exception(S3ErrorCode error) {
        this(error, error.getMessage(), (Throwable) null,
                ImmutableMap.<String, String>of());
    }

    S3Exception(S3ErrorCode error, String message) {
        this(error, message, (Throwable) null,
                ImmutableMap.<String, String>of());
    }

    S3Exception(S3ErrorCode error, Throwable cause) {
        this(error, error.getMessage(), cause,
                ImmutableMap.<String, String>of());
    }

    S3Exception(S3ErrorCode error, String message, Throwable cause) {
        this(error, message, cause, ImmutableMap.<String, String>of());
    }

    S3Exception(S3ErrorCode error, String message, Throwable cause,
                Map<String, String> elements) {
        super(requireNonNull(message), cause);
        this.error = requireNonNull(error);
        this.elements = ImmutableMap.copyOf(elements);
    }

    S3ErrorCode getError() {
        return error;
    }

    Map<String, String> getElements() {
        return elements;
    }

    @Override
    public String getMessage() {
        StringBuilder builder = new StringBuilder().append(super.getMessage());
        if (!elements.isEmpty()) {
            builder.append(" ").append(elements);
        }
        return builder.toString();
    }
}
