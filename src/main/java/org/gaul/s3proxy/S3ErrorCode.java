/*
 * Copyright 2014 Andrew Gaul <andrew@gaul.org>
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

import javax.servlet.http.HttpServletResponse;

import com.google.common.base.CaseFormat;
import com.google.common.base.Preconditions;

/**
 * List of S3 error codes.  Reference:
 * http://docs.aws.amazon.com/AmazonS3/latest/API/ErrorResponses.html
 */
enum S3ErrorCode {
    BUCKET_ALREADY_OWNED_BY_YOU(HttpServletResponse.SC_CONFLICT,
            "Your previous request to create the named bucket" +
            " succeeded and you already own it."),
    BUCKET_NOT_EMPTY(HttpServletResponse.SC_CONFLICT, "Conflict"),
    INVALID_ARGUMENT(HttpServletResponse.SC_BAD_REQUEST, "Bad Request"),
    INVALID_BUCKET_NAME(HttpServletResponse.SC_BAD_REQUEST, "Bad Request"),
    INVALID_DIGEST(HttpServletResponse.SC_BAD_REQUEST, "Bad Request"),
    INVALID_LOCATION_CONSTRAINT(HttpServletResponse.SC_BAD_REQUEST,
            "The specified location constraint is not valid. For" +
            " more information about Regions, see How to Select" +
            " a Region for Your Buckets."),
    INVALID_REQUEST(HttpServletResponse.SC_BAD_REQUEST, "Bad Request"),
    METHOD_NOT_ALLOWED(HttpServletResponse.SC_METHOD_NOT_ALLOWED,
            "Method Not Allowed"),
    MISSING_CONTENT_LENGTH(HttpServletResponse.SC_LENGTH_REQUIRED,
            "Length Required"),
    NO_SUCH_BUCKET(HttpServletResponse.SC_NOT_FOUND, "Not Found"),
    NO_SUCH_KEY(HttpServletResponse.SC_NOT_FOUND, "Not Found"),
    REQUEST_TIMEOUT(HttpServletResponse.SC_BAD_REQUEST, "Bad Request"),
    SIGNATURE_DOES_NOT_MATCH(HttpServletResponse.SC_FORBIDDEN, "Forbidden");

    private final String errorCode;
    private final int httpStatusCode;
    private final String message;

    private S3ErrorCode(int httpStatusCode, String message) {
        this.errorCode = CaseFormat.UPPER_UNDERSCORE.to(CaseFormat.UPPER_CAMEL,
                name());
        this.httpStatusCode = httpStatusCode;
        this.message = Preconditions.checkNotNull(message);
    }

    public String getErrorCode() {
        return errorCode;
    }

    public int getHttpStatusCode() {
        return httpStatusCode;
    }

    public String getMessage() {
        return message;
    }

    @Override
    public String toString() {
        return getHttpStatusCode() + " " + getErrorCode() + " " + getMessage();
    }
}
