/*
 * Copyright 2009-2025 The Apache Software Foundation
 * Copyright 2026 Andrew Gaul <andrew@gaul.org>
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

package org.gaul.s3proxy.blobstore;

import org.jspecify.annotations.Nullable;

public final class HttpResponseException extends RuntimeException {

    private final transient HttpResponse response;

    public HttpResponseException(HttpResponse response) {
        this(formatMessage(response), response, null);
    }

    public HttpResponseException(String message, HttpResponse response) {
        this(message, response, null);
    }

    public HttpResponseException(HttpResponse response,
            @Nullable Throwable cause) {
        this(formatMessage(response), response, cause);
    }

    private HttpResponseException(String message, HttpResponse response,
            @Nullable Throwable cause) {
        super(message, cause);
        this.response = response;
    }

    public HttpResponse getResponse() {
        return response;
    }

    private static String formatMessage(HttpResponse response) {
        return "failed with response: HTTP/1.1 " + response.statusCode();
    }
}
