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
import java.util.Date;
import java.util.List;

import com.google.common.hash.HashCode;

import org.gaul.s3proxy.blobstore.domain.Blob;
import org.gaul.s3proxy.blobstore.domain.BlobAccess;
import org.gaul.s3proxy.blobstore.domain.BlobMetadata;
import org.gaul.s3proxy.blobstore.domain.ContainerAccess;
import org.gaul.s3proxy.blobstore.domain.MultipartPart;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.gaul.s3proxy.blobstore.options.CopyOptions;
import org.gaul.s3proxy.blobstore.options.CreateContainerOptions;
import org.gaul.s3proxy.blobstore.options.GetOptions;
import org.gaul.s3proxy.blobstore.options.ListContainerOptions;
import org.gaul.s3proxy.blobstore.options.ListVersionsOptions;
import org.gaul.s3proxy.blobstore.options.PutOptions;
import org.jspecify.annotations.Nullable;

import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.services.s3.model.BucketVersioningStatus;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.CopyObjectResponse;
import software.amazon.awssdk.services.s3.model.DeleteObjectResponse;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.HeadObjectResponse;
import software.amazon.awssdk.services.s3.model.ListBucketsResponse;
import software.amazon.awssdk.services.s3.model.ListObjectVersionsResponse;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Response;
import software.amazon.awssdk.services.s3.model.NoSuchBucketException;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.awssdk.services.s3.model.S3Object;

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

    CopyObjectResponse copyBlob(String fromContainer, String fromName,
            String toContainer, String toName, CopyOptions options);

    @Nullable
    HeadObjectResponse blobMetadata(String container, String name);

    /**
     * Reads the metadata of one version, or of the current version when
     * {@code versionId} is null.  Returns null when the object does not
     * exist; throws {@link S3Exceptions#noSuchKeyDeleteMarker} carrying the
     * marker's version when the current "version" is a delete marker, and
     * {@link S3Exceptions#noSuchVersion} when the named version does not
     * exist.  Only meaningful on a store that {@link #supportsVersioning};
     * the default implementation throws UnsupportedOperationException.
     */
    @Nullable
    default HeadObjectResponse blobMetadata(String container, String name,
            @Nullable String versionId) {
        throw new UnsupportedOperationException("versioning not supported");
    }

    /**
     * Reads one object: the response riding on its payload stream, or null
     * when the object does not exist.  The caller consumes and closes the
     * stream.
     */
    @Nullable
    ResponseInputStream<GetObjectResponse> getBlob(String container,
            String name, GetOptions options);

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
     * reports true honors {@link GetOptions#versionId}, {@link
     * CopyOptions#sourceVersionId}, the versioned blobMetadata and
     * removeBlob overloads, and the operations below; the default
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

    CompleteMultipartUploadResponse completeMultipartUpload(MultipartUpload mpu,
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
     * that the service does not implement the copy operation.
     *
     * @param sourceVersionId version of the source object to copy, or null
     *        for the current version; only meaningful on a store that
     *        {@link #supportsVersioning}
     * @param copySourceRange raw x-amz-copy-source-range value, e.g.
     *        bytes=first-last, or null to copy the entire object; the
     *        backend enforces its own validation and the copy-source
     *        conditions
     */
    default MultipartPart copyMultipartPart(MultipartUpload mpu,
            int partNumber, String sourceContainer, String sourceName,
            @Nullable String sourceVersionId,
            @Nullable String copySourceRange, @Nullable String ifMatch,
            @Nullable String ifNoneMatch, @Nullable Date ifModifiedSince,
            @Nullable Date ifUnmodifiedSince) {
        throw new UnsupportedOperationException(
                "backend does not support server-side part copies");
    }

    List<MultipartPart> listMultipartUpload(MultipartUpload mpu);

    List<MultipartUpload> listMultipartUploads(String container);

    long getMinimumMultipartPartSize();
}
