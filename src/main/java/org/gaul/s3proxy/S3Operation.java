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

/** Enumeration of S3 operations for metrics tracking. */
public enum S3Operation {
    LIST_BUCKETS("ListBuckets"),
    LIST_OBJECTS_V2("ListObjectsV2"),
    GET_OBJECT("GetObject"),
    PUT_OBJECT("PutObject"),
    DELETE_OBJECT("DeleteObject"),
    DELETE_OBJECTS("DeleteObjects"),
    CREATE_BUCKET("CreateBucket"),
    DELETE_BUCKET("DeleteBucket"),
    HEAD_BUCKET("HeadBucket"),
    HEAD_OBJECT("HeadObject"),
    COPY_OBJECT("CopyObject"),
    CREATE_MULTIPART_UPLOAD("CreateMultipartUpload"),
    UPLOAD_PART("UploadPart"),
    UPLOAD_PART_COPY("UploadPartCopy"),
    COMPLETE_MULTIPART_UPLOAD("CompleteMultipartUpload"),
    ABORT_MULTIPART_UPLOAD("AbortMultipartUpload"),
    LIST_MULTIPART_UPLOADS("ListMultipartUploads"),
    LIST_PARTS("ListParts"),
    GET_OBJECT_ACL("GetObjectAcl"),
    PUT_OBJECT_ACL("PutObjectAcl"),
    GET_BUCKET_ACL("GetBucketAcl"),
    PUT_BUCKET_ACL("PutBucketAcl"),
    GET_BUCKET_LOCATION("GetBucketLocation"),
    GET_BUCKET_POLICY("GetBucketPolicy"),
    OPTIONS_OBJECT("OptionsObject"),
    UNKNOWN("Unknown");

    private final String value;

    S3Operation(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
