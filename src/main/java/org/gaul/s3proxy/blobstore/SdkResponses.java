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

package org.gaul.s3proxy.blobstore;

import org.jspecify.annotations.Nullable;

import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.CopyObjectResponse;
import software.amazon.awssdk.services.s3.model.CopyObjectResult;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;

/**
 * Factories for the SDK responses backends fabricate when their service
 * reports less than S3 does.  The aws-s3-sdk backend returns its service's
 * responses verbatim instead.
 */
public final class SdkResponses {
    private SdkResponses() {
    }

    /** A response carrying only the stored object's ETag. */
    public static PutObjectResponse putResponse(@Nullable String eTag) {
        return PutObjectResponse.builder()
                .eTag(eTag)
                .build();
    }

    /** A response carrying only the completed object's ETag. */
    public static CompleteMultipartUploadResponse completeResponse(
            @Nullable String eTag) {
        return CompleteMultipartUploadResponse.builder()
                .eTag(eTag)
                .build();
    }

    /** A response carrying only the copied object's ETag. */
    public static CopyObjectResponse copyResponse(@Nullable String eTag) {
        return CopyObjectResponse.builder()
                .copyObjectResult(CopyObjectResult.builder()
                        .eTag(eTag)
                        .build())
                .build();
    }
}
