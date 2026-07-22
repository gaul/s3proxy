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

import java.io.InputStream;
import java.util.List;

import com.google.common.hash.HashCode;

import org.gaul.s3proxy.blobstore.domain.Blob;
import org.gaul.s3proxy.blobstore.domain.BlobAccess;
import org.gaul.s3proxy.blobstore.domain.BlobMetadata;
import org.gaul.s3proxy.blobstore.domain.ContainerAccess;
import org.gaul.s3proxy.blobstore.domain.MultipartPart;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.gaul.s3proxy.blobstore.domain.PageSet;
import org.gaul.s3proxy.blobstore.domain.StorageMetadata;
import org.gaul.s3proxy.blobstore.options.CopyOptions;
import org.gaul.s3proxy.blobstore.options.CreateContainerOptions;
import org.gaul.s3proxy.blobstore.options.GetOptions;
import org.gaul.s3proxy.blobstore.options.ListContainerOptions;
import org.gaul.s3proxy.blobstore.options.PutOptions;
import org.jspecify.annotations.Nullable;

/** Synchronous access to a BlobStore such as Amazon S3. */
public interface BlobStore extends AutoCloseable {
    /** Releases backend resources such as SDK clients.  No-op by default. */
    @Override
    default void close() {
    }

    PageSet<? extends StorageMetadata> list();

    PageSet<? extends StorageMetadata> list(String container,
            ListContainerOptions options);

    boolean containerExists(String container);

    boolean createContainer(String container, CreateContainerOptions options);

    ContainerAccess getContainerAccess(String container);

    void setContainerAccess(String container, ContainerAccess access);

    default void clearContainer(String container,
            ListContainerOptions options) {
        ListContainerOptions opts = options;
        while (true) {
            PageSet<? extends StorageMetadata> page = list(container, opts);
            for (StorageMetadata sm : page) {
                String name = sm.name();
                if (name != null) {
                    removeBlob(container, name);
                }
            }
            String marker = page.nextMarker();
            if (marker == null) {
                return;
            }
            opts = options.toBuilder().afterMarker(marker).build();
        }
    }

    default void deleteContainer(String container) {
        try {
            clearContainer(container,
                    ListContainerOptions.NONE);
        } catch (ContainerNotFoundException e) {
            return;
        }
        deleteContainerIfEmpty(container);
    }

    boolean deleteContainerIfEmpty(String container);

    boolean blobExists(String container, String name);

    String putBlob(String container, Blob blob, PutOptions options);

    String copyBlob(String fromContainer, String fromName, String toContainer,
            String toName, CopyOptions options);

    @Nullable
    BlobMetadata blobMetadata(String container, String name);

    @Nullable
    Blob getBlob(String container, String name, GetOptions options);

    void removeBlob(String container, String name);

    default void removeBlobs(String container, Iterable<String> names) {
        for (String name : names) {
            removeBlob(container, name);
        }
    }

    BlobAccess getBlobAccess(String container, String name);

    void setBlobAccess(String container, String name, BlobAccess access);

    MultipartUpload initiateMultipartUpload(String container, BlobMetadata blob,
            PutOptions options);

    void abortMultipartUpload(MultipartUpload mpu);

    String completeMultipartUpload(MultipartUpload mpu,
            List<MultipartPart> parts);

    /**
     * Uploads a part of a multipart upload, consuming and closing
     * {@code is}.
     *
     * @param contentMD5 MD5 of the part content, used for integrity
     *        validation where the backend supports it
     */
    MultipartPart uploadMultipartPart(MultipartUpload mpu, int partNumber,
            InputStream is, long contentLength, @Nullable HashCode contentMD5);

    List<MultipartPart> listMultipartUpload(MultipartUpload mpu);

    List<MultipartUpload> listMultipartUploads(String container);

    long getMinimumMultipartPartSize();
}
