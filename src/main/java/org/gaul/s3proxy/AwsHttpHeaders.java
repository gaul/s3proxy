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

final class AwsHttpHeaders {
    static final String ACL = "x-amz-acl";
    static final String CONTENT_SHA256 = "x-amz-content-sha256";
    static final String COPY_SOURCE = "x-amz-copy-source";
    static final String COPY_SOURCE_IF_MATCH = "x-amz-copy-source-if-match";
    static final String COPY_SOURCE_IF_MODIFIED_SINCE =
            "x-amz-copy-source-if-modified-since";
    static final String COPY_SOURCE_IF_NONE_MATCH =
            "x-amz-copy-source-if-none-match";
    static final String COPY_SOURCE_IF_UNMODIFIED_SINCE =
            "x-amz-copy-source-if-unmodified-since";
    static final String COPY_SOURCE_RANGE = "x-amz-copy-source-range";
    static final String DATE = "x-amz-date";
    static final String DECODED_CONTENT_LENGTH =
            "x-amz-decoded-content-length";
    static final String METADATA_DIRECTIVE = "x-amz-metadata-directive";
    static final String REQUEST_ID = "x-amz-request-id";
    static final String STORAGE_CLASS = "x-amz-storage-class";

    private AwsHttpHeaders() {
        throw new AssertionError("intentionally unimplemented");
    }
}
