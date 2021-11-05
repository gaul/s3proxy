/*
 * Copyright 2014-2021 Andrew Gaul <andrew@gaul.org>
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

import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.domain.Blob;
import org.jclouds.blobstore.domain.MultipartPart;
import org.jclouds.blobstore.domain.MultipartUpload;
import org.jclouds.blobstore.options.PutOptions;
import org.jclouds.blobstore.util.ForwardingBlobStore;
import org.jclouds.io.Payload;

/** This class is a BlobStore wrapper which requires the Content-MD5 header. */
final class RequiredMD5BlobStore extends ForwardingBlobStore {
    private RequiredMD5BlobStore(BlobStore blobStore) {
        super(blobStore);
    }

    static BlobStore newRequiredMD5BlobStore(BlobStore blobStore) {
        return new RequiredMD5BlobStore(blobStore);
    }

    @Override
    public String putBlob(String containerName, Blob blob) {
        if (blob.getMetadata().getContentMetadata().getContentMD5AsHashCode() ==
                null) {
            throw new IllegalArgumentException("Content-MD5 header required");
        }
        return super.putBlob(containerName, blob);
    }

    @Override
    public String putBlob(final String containerName, Blob blob,
            final PutOptions options) {
        if (blob.getMetadata().getContentMetadata().getContentMD5AsHashCode() ==
                null) {
            throw new IllegalArgumentException("Content-MD5 header required");
        }
        return super.putBlob(containerName, blob, options);
    }

    @Override
    public MultipartPart uploadMultipartPart(MultipartUpload mpu,
            int partNumber, Payload payload) {
        if (payload.getContentMetadata().getContentMD5AsHashCode() == null) {
            throw new IllegalArgumentException("Content-MD5 header required");
        }
        return super.uploadMultipartPart(mpu, partNumber, payload);
    }
}
