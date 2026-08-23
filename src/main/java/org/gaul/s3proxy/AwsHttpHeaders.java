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

public final class AwsHttpHeaders {
    public static final String ACL = "x-amz-acl";
    public static final String API_VERSION = "x-amz-api-version";
    public static final String BUCKET_OBJECT_LOCK_ENABLED =
            "x-amz-bucket-object-lock-enabled";
    public static final String BUCKET_REGION = "x-amz-bucket-region";
    public static final String CHECKSUM_ALGORITHM = "x-amz-checksum-algorithm";
    public static final String CHECKSUM_CRC32 = "x-amz-checksum-crc32";
    public static final String CHECKSUM_CRC32C = "x-amz-checksum-crc32c";
    public static final String CHECKSUM_CRC64NVME = "x-amz-checksum-crc64nvme";
    public static final String CHECKSUM_MODE = "x-amz-checksum-mode";
    public static final String CHECKSUM_SHA1 = "x-amz-checksum-sha1";
    public static final String CHECKSUM_SHA256 = "x-amz-checksum-sha256";
    public static final String CHECKSUM_TYPE = "x-amz-checksum-type";
    public static final String CONTENT_SHA256 = "x-amz-content-sha256";
    public static final String COPY_SOURCE = "x-amz-copy-source";
    public static final String COPY_SOURCE_IF_MATCH =
            "x-amz-copy-source-if-match";
    public static final String COPY_SOURCE_IF_MODIFIED_SINCE =
            "x-amz-copy-source-if-modified-since";
    public static final String COPY_SOURCE_IF_NONE_MATCH =
            "x-amz-copy-source-if-none-match";
    public static final String COPY_SOURCE_IF_UNMODIFIED_SINCE =
            "x-amz-copy-source-if-unmodified-since";
    public static final String COPY_SOURCE_RANGE = "x-amz-copy-source-range";
    public static final String COPY_SOURCE_SERVER_SIDE_ENCRYPTION_CUSTOMER_ALGORITHM =
            "x-amz-copy-source-server-side-encryption-customer-algorithm";
    public static final String COPY_SOURCE_SERVER_SIDE_ENCRYPTION_CUSTOMER_KEY =
            "x-amz-copy-source-server-side-encryption-customer-key";
    public static final String COPY_SOURCE_SERVER_SIDE_ENCRYPTION_CUSTOMER_KEY_MD5 =
            "x-amz-copy-source-server-side-encryption-customer-key-md5";
    public static final String COPY_SOURCE_VERSION_ID =
            "x-amz-copy-source-version-id";
    public static final String DATE = "x-amz-date";
    public static final String DECODED_CONTENT_LENGTH =
            "x-amz-decoded-content-length";
    public static final String DELETE_MARKER = "x-amz-delete-marker";
    public static final String IF_MATCH_LAST_MODIFIED_TIME =
            "x-amz-if-match-last-modified-time";
    public static final String IF_MATCH_SIZE = "x-amz-if-match-size";
    public static final String METADATA_DIRECTIVE = "x-amz-metadata-directive";
    public static final String MFA = "x-amz-mfa";
    public static final String OBJECT_ATTRIBUTES = "x-amz-object-attributes";
    public static final String REQUEST_ID = "x-amz-request-id";
    public static final String SDK_CHECKSUM_ALGORITHM =
            "x-amz-sdk-checksum-algorithm";
    public static final String SERVER_SIDE_ENCRYPTION =
            "x-amz-server-side-encryption";
    public static final String SERVER_SIDE_ENCRYPTION_AWS_KMS_KEY_ID =
            "x-amz-server-side-encryption-aws-kms-key-id";
    public static final String SERVER_SIDE_ENCRYPTION_BUCKET_KEY_ENABLED =
            "x-amz-server-side-encryption-bucket-key-enabled";
    public static final String SERVER_SIDE_ENCRYPTION_CONTEXT =
            "x-amz-server-side-encryption-context";
    public static final String SERVER_SIDE_ENCRYPTION_CUSTOMER_ALGORITHM =
            "x-amz-server-side-encryption-customer-algorithm";
    public static final String SERVER_SIDE_ENCRYPTION_CUSTOMER_KEY =
            "x-amz-server-side-encryption-customer-key";
    public static final String SERVER_SIDE_ENCRYPTION_CUSTOMER_KEY_MD5 =
            "x-amz-server-side-encryption-customer-key-md5";
    public static final String STORAGE_CLASS = "x-amz-storage-class";
    public static final String TRAILER = "x-amz-trailer";
    public static final String TRANSFER_ENCODING = "x-amz-te";
    public static final String USER_AGENT = "x-amz-user-agent";
    public static final String VERSION_ID = "x-amz-version-id";

    private AwsHttpHeaders() {
        throw new AssertionError("intentionally unimplemented");
    }
}
