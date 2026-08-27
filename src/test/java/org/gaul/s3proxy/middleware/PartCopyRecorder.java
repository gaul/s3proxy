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

package org.gaul.s3proxy.middleware;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.ForwardingBlobStore;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;

import software.amazon.awssdk.services.s3.model.UploadPartCopyRequest;
import software.amazon.awssdk.services.s3.model.UploadPartCopyResponse;

/**
 * A backend that copies a part server-side, recording what it was asked for
 * rather than copying anything.  Only the three SDK stores really do copy
 * and none is reachable from a unit test, so what a wrapper renames on the
 * way down is measured here instead.
 */
final class PartCopyRecorder extends ForwardingBlobStore {
    private MultipartUpload mpu;
    private UploadPartCopyRequest request;

    PartCopyRecorder(BlobStore delegate) {
        super(delegate);
    }

    MultipartUpload mpu() {
        return mpu;
    }

    UploadPartCopyRequest request() {
        return request;
    }

    @Override
    public boolean supportsCopyMultipartPart() {
        return true;
    }

    @Override
    public UploadPartCopyResponse copyMultipartPart(MultipartUpload mpu,
            UploadPartCopyRequest request) {
        this.mpu = mpu;
        this.request = request;
        return UploadPartCopyResponse.builder().build();
    }
}
