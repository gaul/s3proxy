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
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.gaul.s3proxy.blobstore.options.CreateContainerOptions;
import org.gaul.s3proxy.blobstore.options.ListContainerOptions;
import org.gaul.s3proxy.blobstore.options.ListVersionsOptions;
import org.gaul.s3proxy.blobstore.options.PutOptions;
import org.jspecify.annotations.Nullable;

import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.services.s3.model.BucketVersioningStatus;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.CompletedPart;
import software.amazon.awssdk.services.s3.model.CopyObjectRequest;
import software.amazon.awssdk.services.s3.model.CopyObjectResponse;
import software.amazon.awssdk.services.s3.model.DeleteObjectResponse;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.HeadObjectRequest;
import software.amazon.awssdk.services.s3.model.HeadObjectResponse;
import software.amazon.awssdk.services.s3.model.ListBucketsResponse;
import software.amazon.awssdk.services.s3.model.ListObjectVersionsResponse;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Response;
import software.amazon.awssdk.services.s3.model.NoSuchBucketException;
import software.amazon.awssdk.services.s3.model.Part;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.awssdk.services.s3.model.S3Object;
import software.amazon.awssdk.services.s3.model.UploadPartCopyRequest;
import software.amazon.awssdk.services.s3.model.UploadPartCopyResponse;
import software.amazon.awssdk.services.s3.model.UploadPartResponse;

/** Synchronous access to a BlobStore such as Amazon S3. */
public interface BlobStore extends AutoCloseable {
    /** Releases backend resources such as SDK clients.  No-op by default. */
    @Override
    default void close() {
    }

    ListBucketsResponse list();

    /**
     * Lists one page of a container.  The page's nextContinuationToken
     * carries the marker naming where the next page resumes, or null when
     * the listing is complete; isTruncated says the same thing.
     */
    ListObjectsV2Response list(String container,
            ListContainerOptions options);

    boolean containerExists(String container);

    boolean createContainer(String container, CreateContainerOptions options);

    ContainerAccess getContainerAccess(String container);

    void setContainerAccess(String container, ContainerAccess access);

    default void clearContainer(String container,
            ListContainerOptions options) {
        ListContainerOptions opts = options;
        while (true) {
            ListObjectsV2Response page = list(container, opts);
            for (S3Object object : page.contents()) {
                removeBlob(container, object.key());
            }
            String marker = page.nextContinuationToken();
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
        } catch (NoSuchBucketException e) {
            return;
        }
        deleteContainerIfEmpty(container);
    }

    boolean deleteContainerIfEmpty(String container);

    boolean blobExists(String container, String name);

    PutObjectResponse putBlob(String container, Blob blob, PutOptions options);

    /**
     * Copies one object onto another server-side.  Replacement metadata --
     * user metadata and the Content-* headers -- applies only when the
     * request's metadataDirective is REPLACE; otherwise the source's
     * metadata carries over.  A non-null sourceVersionId is only meaningful
     * on a store that {@link #supportsVersioning}.
     */
    CopyObjectResponse copyBlob(CopyObjectRequest request);

    /**
     * Reads the metadata of the version the request names, or of the
     * current version when its versionId is null.  Returns null when the
     * object does not exist; throws {@link
     * S3Exceptions#noSuchKeyDeleteMarker} carrying the marker's version
     * when the current "version" is a delete marker, and {@link
     * S3Exceptions#noSuchVersion} when the named version does not exist.
     * A non-null versionId is only meaningful on a store that {@link
     * #supportsVersioning}; the others throw
     * UnsupportedOperationException.
     */
    @Nullable
    HeadObjectResponse blobMetadata(HeadObjectRequest request);

    /** Reads the current object's metadata. */
    @Nullable
    default HeadObjectResponse blobMetadata(String container, String name) {
        return blobMetadata(HeadObjectRequest.builder()
                .bucket(container)
                .key(name)
                .build());
    }

    /**
     * Reads one object: the response riding on its payload stream, or null
     * when the object does not exist.  The caller consumes and closes the
     * stream.  The request's range rides verbatim as the Range header
     * form, e.g. bytes=0-9; a non-null versionId is only meaningful on a
     * store that {@link #supportsVersioning}.
     */
    @Nullable
    ResponseInputStream<GetObjectResponse> getBlob(GetObjectRequest request);

    /** Reads the current object in full. */
    @Nullable
    default ResponseInputStream<GetObjectResponse> getBlob(String container,
            String name) {
        return getBlob(GetObjectRequest.builder()
                .bucket(container)
                .key(name)
                .build());
    }

    void removeBlob(String container, String name);

    /**
     * Deletes one version, or acts as an ordinary delete when
     * {@code versionId} is null -- which on a versioning-enabled container
     * creates a delete marker rather than removing data.  Only meaningful
     * on a store that {@link #supportsVersioning}; the default
     * implementation throws UnsupportedOperationException.
     */
    default DeleteObjectResponse removeBlob(String container, String name,
            @Nullable String versionId) {
        throw new UnsupportedOperationException("versioning not supported");
    }

    /**
     * Whether this store supports object versioning.  Only a store that
     * reports true honors the read and copy requests' versionIds, the
     * versioned removeBlob overload, and the operations below; the default
     * implementations throw UnsupportedOperationException.
     */
    default boolean supportsVersioning() {
        return false;
    }

    /**
     * Reads the container's versioning state, or null when the container has
     * never been versioned.
     */
    @Nullable
    default BucketVersioningStatus getContainerVersioning(String container) {
        throw new UnsupportedOperationException("versioning not supported");
    }

    default void setContainerVersioning(String container,
            BucketVersioningStatus status) {
        throw new UnsupportedOperationException("versioning not supported");
    }

    /** Lists a container's object versions and delete markers. */
    default ListObjectVersionsResponse listVersions(String container,
            ListVersionsOptions options) {
        throw new UnsupportedOperationException("versioning not supported");
    }

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

    CompleteMultipartUploadResponse completeMultipartUpload(
            MultipartUpload mpu, List<CompletedPart> parts);

    /**
     * Uploads a part of a multipart upload, consuming and closing
     * {@code is}.
     *
     * @param contentMD5 MD5 of the part content, used for integrity
     *        validation where the backend supports it
     */
    UploadPartResponse uploadMultipartPart(MultipartUpload mpu,
            int partNumber, InputStream is, long contentLength,
            @Nullable HashCode contentMD5);

    /**
     * Whether {@link #copyMultipartPart} copies server-side on the backend.
     * Wrappers that transform payloads, e.g. encryption, must not report
     * true since a backend copy would bypass the transformation.
     */
    default boolean supportsCopyMultipartPart() {
        return false;
    }

    /**
     * Copies a source object range into a part of a multipart upload
     * server-side, without streaming the payload through the caller.
     * Throwing UnsupportedOperationException tells the caller to fall back
     * to streamed emulation, e.g. when the backend discovers at runtime
     * that the service does not implement the copy operation.  The
     * request's copySourceRange rides verbatim (bytes=first-last, or null
     * to copy the entire object) and the backend enforces its own
     * validation and the copy-source conditions; a non-null
     * sourceVersionId is only meaningful on a store that {@link
     * #supportsVersioning}.
     */
    default UploadPartCopyResponse copyMultipartPart(MultipartUpload mpu,
            UploadPartCopyRequest request) {
        throw new UnsupportedOperationException(
                "backend does not support server-side part copies");
    }

    List<Part> listMultipartUpload(MultipartUpload mpu);

    List<software.amazon.awssdk.services.s3.model.MultipartUpload>
            listMultipartUploads(String container);

    long getMinimumMultipartPartSize();
}
