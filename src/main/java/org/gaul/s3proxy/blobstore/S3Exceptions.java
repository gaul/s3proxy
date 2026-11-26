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
import software.amazon.awssdk.services.s3.model.BucketAlreadyExistsException;
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

    /**
     * The 409 CreateBucket answers when the name is taken by someone other
     * than the caller, on a store whose bucket names are shared by all of
     * its accounts.
     */
    public static BucketAlreadyExistsException bucketAlreadyExists(
            String container) {
        return BucketAlreadyExistsException.builder()
                .message("bucket %s already exists".formatted(container))
                .statusCode(409)
                .awsErrorDetails(details(409, "BucketAlreadyExists",
                        "The requested bucket name is not available." +
                                " The bucket namespace is shared by all" +
                                " users of the system. Please select a" +
                                " different name and try again.",
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

    /** S3's answer to an upload ID that names no upload in progress. */
    public static S3Exception noSuchUpload(String uploadId) {
        String message = "The specified upload does not exist. The upload" +
                " ID may be invalid, or the upload may have been aborted or" +
                " completed.";
        return (S3Exception) S3Exception.builder()
                .message(message + " (" + uploadId + ")")
                .statusCode(404)
                .awsErrorDetails(details(404, "NoSuchUpload", message,
                        Map.of()))
                .build();
    }

    /**
     * A 400 saying what about the request was wrong.  A status code alone
     * would not: the frontend answers a bare 400 with InvalidRequest, which
     * names no argument.
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
     * The 400 BadDigest for a body that does not hash to the Content-MD5
     * the caller sent.  Named rather than left to a bare 400, which the
     * frontend answers InvalidRequest: a client may retry BadDigest, since
     * the body may have been damaged on the way, and must not retry a
     * request refused for what it asked.
     */
    public static S3Exception badDigest(@Nullable Throwable cause) {
        return withCode(400, "BadDigest",
                "The Content-MD5 you specified did not match what we" +
                " received.", cause);
    }

    /**
     * The 400 InvalidPart for a part a completion names that the upload
     * does not hold.
     */
    public static S3Exception invalidPart(int partNumber) {
        return withCode(400, "InvalidPart",
                "One or more of the specified parts could not be found." +
                "  The part may not have been uploaded, or the specified" +
                " entity tag may not match the part's entity tag.  Part " +
                partNumber + " is not among the upload's parts.",
                /*cause=*/ null);
    }

    /**
     * An error of any S3 code, for a backend failure that has an S3
     * equivalent no other method here names: a rate limit, an outage, a
     * conflict.  The cause rides along for the log.
     */
    public static S3Exception withCode(int statusCode, String errorCode,
            String message, @Nullable Throwable cause) {
        return (S3Exception) S3Exception.builder()
                .message(message)
                .statusCode(statusCode)
                .awsErrorDetails(details(statusCode, errorCode, message,
                        Map.of()))
                .cause(cause)
                .build();
    }

    /**
     * A 500 for a credential supplier that yields no session token to a
     * backend authenticating with one, which is the operator's to fix
     * rather than the client's.  The detail is the exception's message,
     * for the log, and the client is told only that the request failed on
     * this side.  It is thrown from inside the backend's SDK, which may
     * wrap it, and the frontend finds it along the cause chain; it has no
     * cause of its own, since the Azure client throws the cause of an
     * exception that has one in its place.
     */
    public static S3Exception noSessionToken() {
        return misconfigured("Credential supplier named no session token");
    }

    /**
     * The S3 error a backend's refusal is by its status alone, for one the
     * backend's own error code did not already name; null for a status with
     * no S3 counterpart.  A refusal passed on untranslated reaches the
     * client as a 500 InternalError, which blames this side for what the
     * request asked and which every SDK retries.
     */
    @Nullable
    public static S3Exception fromBackendStatus(int statusCode,
            @Nullable Throwable cause) {
        return switch (statusCode) {
        case 400 -> withCode(400, "InvalidRequest",
                "The backend refused the request.", cause);
        case 409 -> operationAborted(cause);
        case 411 -> withCode(411, "MissingContentLength",
                "You must provide the Content-Length HTTP header.", cause);
        case 413 -> withCode(400, "EntityTooLarge",
                "Your proposed upload exceeds the maximum allowed object" +
                " size.", cause);
        case 416 -> withCode(416, "InvalidRange",
                "The requested range is not satisfiable", cause);
        case 429 -> slowDown(cause);
        case 502, 503, 504 -> serviceUnavailable(cause);
        default -> null;
        };
    }

    /**
     * S3's 500 InternalError, for a failure on this side that is not S3's:
     * the one object's of several a batch delete reports separately, say.
     */
    public static S3Exception internalError(@Nullable Throwable cause) {
        return withCode(500, "InternalError",
                "We encountered an internal error. Please try again.", cause);
    }

    /**
     * S3's 403 InvalidObjectState, for a read of an object whose storage
     * class keeps it offline until it is restored.
     */
    public static S3Exception invalidObjectState(@Nullable Throwable cause) {
        return withCode(403, "InvalidObjectState",
                "The operation is not valid for the object's storage class",
                cause);
    }

    /**
     * S3's 409 OperationAborted, for a write that lost to another operation
     * on the same object or bucket: one the client may try again.
     */
    public static S3Exception operationAborted(@Nullable Throwable cause) {
        return withCode(409, "OperationAborted",
                "A conflicting conditional operation is currently in" +
                " progress against this resource. Try again.", cause);
    }

    /**
     * S3's 503 SlowDown, for a backend that throttled the request: the code
     * that tells a client to back off before it retries.
     */
    public static S3Exception slowDown(@Nullable Throwable cause) {
        return withCode(503, "SlowDown", "Please reduce your request rate.",
                cause);
    }

    /**
     * S3's 503 ServiceUnavailable, for a backend that could not take the
     * request just now: a 502, 503 or 504 of its own.
     */
    public static S3Exception serviceUnavailable(@Nullable Throwable cause) {
        return withCode(503, "ServiceUnavailable",
                "Service is unable to handle request.", cause);
    }

    /**
     * A 500 InternalError for a fault in how S3Proxy was set up, found while
     * serving a request: the operator's to fix rather than the client's.
     * The detail is the exception's message, for the log, and the client is
     * told only that the request failed on this side.  It carries no cause,
     * for the reason {@link #noSessionToken()} gives.
     */
    public static S3Exception misconfigured(String detail) {
        return (S3Exception) S3Exception.builder()
                .message(detail)
                .statusCode(500)
                .awsErrorDetails(details(500, "InternalError",
                        "We encountered an internal error. Please try again.",
                        Map.of()))
                .build();
    }

    /**
     * A 501 NotImplemented naming what the backend cannot do, for a request
     * S3 itself would honor.  The code is S3's own, where a bare 501 from
     * {@link #fromStatusCode(int)} reaches a client as an unknown error.
     */
    public static S3Exception notImplemented(String message) {
        return (S3Exception) S3Exception.builder()
                .message(message)
                .statusCode(501)
                .awsErrorDetails(details(501, "NotImplemented", message,
                        Map.of()))
                .build();
    }

    /**
     * A 403 saying what the backend refused, for a refusal the caller can
     * act on only by knowing which permission its credential lacks.
     */
    public static S3Exception accessDenied(String message,
            @Nullable Throwable cause) {
        return (S3Exception) S3Exception.builder()
                .message(message)
                .cause(cause)
                .statusCode(403)
                .awsErrorDetails(details(403, "AccessDenied", message,
                        Map.of()))
                .build();
    }

    /**
     * The 412 a condition earns when the object it guards is not the one
     * the caller named.  Prefer this to a bare 412 wherever the refusal
     * can only be a failed precondition: the frontend maps a status alone
     * by looking at the request, which a batch delete's per-key error --
     * written from the code the store gives it -- never reaches.
     */
    public static S3Exception preconditionFailed(@Nullable Throwable cause) {
        String message =
                "At least one of the preconditions you specified did not " +
                "hold.";
        return (S3Exception) S3Exception.builder()
                .message(message)
                .cause(cause)
                .statusCode(412)
                .awsErrorDetails(details(412, "PreconditionFailed", message,
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

    /**
     * The exception's S3 error code or, for one carrying only a status, the
     * code S3 gives that status: how a store's refusal is named wherever the
     * frontend reports one, the response, a DeleteObjects key's Error, or
     * the Error a completion writes after its 200.  Asking only for the
     * code, a key's Error and a late completion called every refusal a
     * store gave as a status alone InternalError, which a client retries,
     * where the response itself said AccessDenied.  Null for a status with
     * no code of its own.
     */
    @Nullable
    public static String errorCodeOrStatus(AwsServiceException exception) {
        String code = errorCode(exception);
        return code != null ? code : errorCodeForStatus(
                exception.statusCode());
    }

    /**
     * The code S3 gives a status, for a refusal that names none.  A 412 is
     * PreconditionFailed here; the response tells it from a 304 Not
     * Modified by the request it answers.
     */
    @Nullable
    public static String errorCodeForStatus(int statusCode) {
        return switch (statusCode) {
        case 400 -> "InvalidRequest";
        case 403 -> "AccessDenied";
        case 405 -> "MethodNotAllowed";
        case 412 -> "PreconditionFailed";
        case 416 -> "InvalidRange";
        // Swift's answer to a body that does not hash to its ETag
        case 422 -> "BadDigest";
        case 500 -> "InternalError";
        case 501 -> "NotImplemented";
        case 503 -> "ServiceUnavailable";
        default -> null;
        };
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
