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

package org.gaul.s3proxy.blobstore.domain;

import org.jspecify.annotations.Nullable;

import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadResponse;

/**
 * One in-progress multipart upload: its id and the request that created
 * it, whose metadata stores that assemble the final object themselves
 * read back at completion.  A store whose backend answered the creation
 * carries that answer too, e.g. the server-side encryption it applied;
 * carriers reconstructed for the upload's later requests have none.
 */
public record MultipartUpload(
        String id,
        CreateMultipartUploadRequest request,
        @Nullable CreateMultipartUploadResponse response) {

    public MultipartUpload(String id, CreateMultipartUploadRequest request) {
        this(id, request, null);
    }

    public String containerName() {
        return request.bucket();
    }

    public String blobName() {
        return request.key();
    }
}
