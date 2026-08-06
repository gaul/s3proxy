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

import java.util.Collection;
import java.util.Date;

import org.gaul.s3proxy.blobstore.domain.BlobMetadata;
import org.jspecify.annotations.Nullable;

import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.http.AbortableInputStream;
import software.amazon.awssdk.services.s3.model.Bucket;
import software.amazon.awssdk.services.s3.model.CommonPrefix;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.CopyObjectResponse;
import software.amazon.awssdk.services.s3.model.CopyObjectResult;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.HeadObjectResponse;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Response;
import software.amazon.awssdk.services.s3.model.ObjectStorageClass;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.awssdk.services.s3.model.S3Object;
import software.amazon.awssdk.services.s3.model.StorageClass;

/**
 * Factories for the SDK responses backends fabricate when their service
 * reports less than S3 does.  The aws-s3-sdk backend returns its service's
 * responses verbatim instead.
 */
public final class SdkResponses {
    private SdkResponses() {
    }

    /**
     * The response view of a request-shaped metadata carrier, for backends
     * that assemble one internally before answering a read.
     */
    @SuppressWarnings("deprecation")
    public static GetObjectResponse toGetResponse(BlobMetadata metadata,
            @Nullable String contentRange) {
        var contentMetadata = metadata.contentMetadata();
        return GetObjectResponse.builder()
                .metadata(metadata.userMetadata())
                .cacheControl(contentMetadata.cacheControl())
                .contentDisposition(contentMetadata.contentDisposition())
                .contentEncoding(contentMetadata.contentEncoding())
                .contentLanguage(contentMetadata.contentLanguage())
                .contentLength(contentMetadata.contentLength())
                .contentType(contentMetadata.contentType())
                .expires(contentMetadata.expires() == null ? null :
                        contentMetadata.expires().toInstant())
                .eTag(metadata.eTag())
                .lastModified(metadata.lastModified() == null ? null :
                        metadata.lastModified().toInstant())
                .storageClass(metadata.storageClass() == null ? null :
                        metadata.storageClass().toString())
                .versionId(metadata.versionId())
                .contentRange(contentRange)
                .build();
    }

    /** A GET result: the response riding on its payload stream. */
    public static ResponseInputStream<GetObjectResponse> getResponse(
            GetObjectResponse response, java.io.InputStream stream) {
        return new ResponseInputStream<>(response,
                AbortableInputStream.create(stream));
    }

    /**
     * The HEAD view of a GET response, for backends and frontend paths that
     * derive one from the other; the accessors match field for field.
     */
    @SuppressWarnings("deprecation")
    public static HeadObjectResponse toHead(GetObjectResponse response) {
        return HeadObjectResponse.builder()
                .cacheControl(response.cacheControl())
                .contentDisposition(response.contentDisposition())
                .contentEncoding(response.contentEncoding())
                .contentLanguage(response.contentLanguage())
                .contentLength(response.contentLength())
                .contentType(response.contentType())
                .eTag(response.eTag())
                .expires(response.expires())
                .lastModified(response.lastModified())
                .metadata(response.metadata())
                .storageClass(response.storageClassAsString())
                .versionId(response.versionId())
                .build();
    }

    /** A listed bucket, converting the legacy Date form. */
    public static Bucket bucket(String name, @Nullable Date creationDate) {
        return Bucket.builder()
                .name(name)
                .creationDate(creationDate == null ? null :
                        creationDate.toInstant())
                .build();
    }

    /** A listed object, converting the legacy Date and StorageClass forms. */
    public static S3Object objectEntry(String key, @Nullable String eTag,
            @Nullable Date lastModified, @Nullable Long size,
            @Nullable StorageClass storageClass) {
        return S3Object.builder()
                .key(key)
                .eTag(eTag)
                .lastModified(lastModified == null ? null :
                        lastModified.toInstant())
                .size(size)
                .storageClass(storageClass == null ? null :
                        ObjectStorageClass.fromValue(storageClass.toString()))
                .build();
    }

    public static CommonPrefix commonPrefix(String prefix) {
        return CommonPrefix.builder().prefix(prefix).build();
    }

    /**
     * One page of an object listing.  The next-marker convention rides in
     * nextContinuationToken: null when the listing is complete, otherwise
     * the value the next request's marker names.
     */
    public static ListObjectsV2Response objectsPage(
            Collection<S3Object> contents,
            Collection<CommonPrefix> commonPrefixes,
            @Nullable String nextContinuationToken) {
        return ListObjectsV2Response.builder()
                .contents(contents)
                .commonPrefixes(commonPrefixes)
                .nextContinuationToken(nextContinuationToken)
                .isTruncated(nextContinuationToken != null)
                .build();
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
