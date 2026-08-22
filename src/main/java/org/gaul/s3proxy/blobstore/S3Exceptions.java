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

import java.util.Map;

import org.jspecify.annotations.Nullable;

import software.amazon.awssdk.awscore.exception.AwsErrorDetails;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.http.SdkHttpResponse;
import software.amazon.awssdk.services.s3.model.BucketAlreadyOwnedByYouException;
import software.amazon.awssdk.services.s3.model.NoSuchBucketException;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.s3.model.S3Exception;

/**
 * Factories for the AWS SDK exceptions the BlobStore SPI throws.  Backends
 * that are not S3 fabricate S3-shaped errors here, while the aws-s3-sdk
 * backend rethrows the SDK's own exceptions, so upstream error codes,
 * messages and headers reach the client verbatim.  The frontend renders
 * {@link AwsErrorDetails#errorCode} and {@link AwsErrorDetails#errorMessage}
 * when present and falls back to mapping the bare status code otherwise.
 */
public final class S3Exceptions {
    private static final String DELETE_MARKER_HEADER = "x-amz-delete-marker";
    private static final String VERSION_ID_HEADER = "x-amz-version-id";

    private S3Exceptions() {
    }

    public static NoSuchBucketException noSuchBucket(String container,
            @Nullable String message) {
        return noSuchBucket(container, message, /*cause=*/ null);
    }

    public static NoSuchBucketException noSuchBucket(String container,
            @Nullable String message, @Nullable Throwable cause) {
        return NoSuchBucketException.builder()
                .message("%s not found: %s".formatted(container, message))
                .cause(cause)
                .statusCode(404)
                .awsErrorDetails(details(404, "NoSuchBucket",
                        "The specified bucket does not exist", Map.of()))
                .build();
    }

    /**
     * The 409 CreateBucket answers when the caller already owns the
     * bucket, which S3 reports rather than treating the create as
     * idempotent.
     */
    public static BucketAlreadyOwnedByYouException bucketAlreadyOwnedByYou(
            String container) {
        return BucketAlreadyOwnedByYouException.builder()
                .message("bucket %s already owned by caller".formatted(
                        container))
                .statusCode(409)
                .awsErrorDetails(details(409, "BucketAlreadyOwnedByYou",
                        "Your previous request to create the named bucket" +
                                " succeeded and you already own it.",
                        Map.of()))
                .build();
    }

    /** The 409 DeleteBucket answers while anything remains in the bucket. */
    public static S3Exception bucketNotEmpty(String container) {
        return (S3Exception) S3Exception.builder()
                .message("container %s is not empty".formatted(container))
                .statusCode(409)
                .awsErrorDetails(details(409, "BucketNotEmpty",
                        "The bucket you tried to delete is not empty",
                        Map.of()))
                .build();
    }

    public static NoSuchKeyException noSuchKey(String container,
            @Nullable String key, @Nullable String message) {
        return noSuchKey(container, key, message, /*cause=*/ null);
    }

    public static NoSuchKeyException noSuchKey(String container,
            @Nullable String key, @Nullable String message,
            @Nullable Throwable cause) {
        return NoSuchKeyException.builder()
                .message("%s not found in container %s: %s".formatted(key,
                        container, message))
                .cause(cause)
                .statusCode(404)
                .awsErrorDetails(details(404, "NoSuchKey",
                        "The specified key does not exist.", Map.of()))
                .build();
    }

    /**
     * The current "version" of the key is a delete marker, which answers
     * NoSuchKey but says so in headers: the error carries
     * x-amz-delete-marker and the marker's x-amz-version-id as S3 sends
     * them.
     */
    public static NoSuchKeyException noSuchKeyDeleteMarker(String container,
            String key, String deleteMarkerVersionId,
            @Nullable String message) {
        return NoSuchKeyException.builder()
                .message("%s not found in container %s: %s".formatted(key,
                        container, message))
                .statusCode(404)
                .awsErrorDetails(details(404, "NoSuchKey",
                        "The specified key does not exist.",
                        Map.of(DELETE_MARKER_HEADER, "true",
                                VERSION_ID_HEADER, deleteMarkerVersionId)))
                .build();
    }

    /** S3 models no typed NoSuchVersion exception; match on the code. */
    public static S3Exception noSuchVersion(String container,
            @Nullable String key, @Nullable String versionId,
            @Nullable String message) {
        return (S3Exception) S3Exception.builder()
                .message("version %s of %s not found in container %s: %s"
                        .formatted(versionId, key, container, message))
                .statusCode(404)
                .awsErrorDetails(details(404, "NoSuchVersion",
                        "The specified version does not exist.", Map.of()))
                .build();
    }

    /**
     * The 404 a bucket answers ?encryption with before any configuration
     * has been put, spelled with the code S3 uses for it.
     */
    public static S3Exception serverSideEncryptionConfigurationNotFound(
            String container) {
        return (S3Exception) S3Exception.builder()
                .message("no encryption configuration on container %s"
                        .formatted(container))
                .statusCode(404)
                .awsErrorDetails(details(404,
                        "ServerSideEncryptionConfigurationNotFoundError",
                        "The server side encryption configuration was not" +
                                " found",
                        Map.of()))
                .build();
    }

    /**
     * A 400 saying what about the request was wrong.  A status code alone
     * would not: the frontend answers a bare 400 with BadDigest, which tells
     * the caller to retry a request that will never be accepted.
     */
    public static S3Exception invalidArgument(String message) {
        return (S3Exception) S3Exception.builder()
                .message(message)
                .statusCode(400)
                .awsErrorDetails(details(400, "InvalidArgument", message,
                        Map.of()))
                .build();
    }

    /**
     * A 400 for a request malformed as a whole rather than in one
     * argument, e.g. reading an object stored under a customer key
     * without presenting one.  S3 answers these InvalidRequest.
     */
    public static S3Exception invalidRequest(String message) {
        return (S3Exception) S3Exception.builder()
                .message(message)
                .statusCode(400)
                .awsErrorDetails(details(400, "InvalidRequest", message,
                        Map.of()))
                .build();
    }

    /**
     * An error carrying only a status code, which the frontend maps to an
     * S3 error document by status.  Used by backends whose service reported
     * a failure with no S3 error code to pass through.
     */
    public static S3Exception fromStatusCode(int statusCode) {
        return fromStatusCode(statusCode, /*cause=*/ null);
    }

    public static S3Exception fromStatusCode(int statusCode,
            @Nullable Throwable cause) {
        return fromStatusCode(statusCode, /*eTag=*/ null, Map.of(), cause);
    }

    /**
     * Like {@link #fromStatusCode(int)} but carrying response headers, e.g.
     * the ETag a 304 Not Modified must echo or x-amz-delete-marker on a
     * versioned backend's refusal to read a delete marker.
     */
    public static S3Exception fromStatusCode(int statusCode,
            @Nullable String eTag, Map<String, String> headers,
            @Nullable Throwable cause) {
        var httpResponse = SdkHttpResponse.builder().statusCode(statusCode);
        if (eTag != null) {
            httpResponse.putHeader("ETag", eTag);
        }
        headers.forEach(httpResponse::putHeader);
        return (S3Exception) S3Exception.builder()
                .message("failed with response: HTTP/1.1 " + statusCode)
                .cause(cause)
                .statusCode(statusCode)
                .awsErrorDetails(AwsErrorDetails.builder()
                        .sdkHttpResponse(httpResponse.build())
                        .build())
                .build();
    }

    /** The exception's S3 error code, or null when it carries none. */
    @Nullable
    public static String errorCode(AwsServiceException exception) {
        var details = exception.awsErrorDetails();
        if (details == null) {
            return null;
        }
        String code = details.errorCode();
        return code == null || code.isEmpty() ? null : code;
    }

    /** The service response riding on the exception, or null. */
    @Nullable
    public static SdkHttpResponse httpResponse(AwsServiceException exception) {
        var details = exception.awsErrorDetails();
        return details == null ? null : details.sdkHttpResponse();
    }

    private static AwsErrorDetails details(int statusCode, String errorCode,
            String errorMessage, Map<String, String> headers) {
        var httpResponse = SdkHttpResponse.builder().statusCode(statusCode);
        headers.forEach(httpResponse::putHeader);
        return AwsErrorDetails.builder()
                .errorCode(errorCode)
                .errorMessage(errorMessage)
                .sdkHttpResponse(httpResponse.build())
                .build();
    }
}
