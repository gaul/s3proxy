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

package org.gaul.s3proxy.sts;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import jakarta.servlet.http.HttpServletRequest;

import org.gaul.s3proxy.AwsHttpHeaders;
import org.gaul.s3proxy.S3ErrorCode;
import org.gaul.s3proxy.S3Operation;
import org.gaul.s3proxy.S3ProxyException;
import org.jspecify.annotations.Nullable;

/**
 * A request made with temporary credentials, and what its session policy
 * lets it do.  The parent identity can reach everything its blob store
 * holds, so the policy alone decides: each operation is mapped to the IAM
 * action S3 would require of it and checked against the policy before the
 * operation runs.
 */
public final class Session {
    private static final String S3_ARN_PREFIX = "arn:aws:s3:::";

    private final SessionToken token;
    private final SessionPolicy policy;

    public Session(SessionToken token, SessionPolicy policy) {
        this.token = Objects.requireNonNull(token);
        this.policy = Objects.requireNonNull(policy);
    }

    public SessionToken token() {
        return token;
    }

    /**
     * Refuse an operation the policy does not allow.  DeleteObjects is the
     * exception: the keys it removes are in the body, so the handler checks
     * each with {@link #authorizeObject} once it has read them.
     */
    public void authorize(S3Operation operation, HttpServletRequest request,
            @Nullable String bucket, @Nullable String key) {
        boolean versioned = request.getParameter("versionId") != null;
        // A canned ACL of private asks for what a write gets anyway, and
        // clients send it as a matter of course; any other grants access.
        String cannedAcl = request.getHeader(AwsHttpHeaders.ACL);
        boolean setsAcl = cannedAcl != null &&
                !cannedAcl.equalsIgnoreCase("private");
        switch (operation) {
        case LIST_BUCKETS -> require("s3:ListAllMyBuckets",
                S3_ARN_PREFIX + "*", Map.of());
        case LIST_OBJECTS_V2 -> requireBucket("s3:ListBucket", bucket,
                listContext(request));
        case LIST_OBJECT_VERSIONS -> requireBucket("s3:ListBucketVersions",
                bucket, listContext(request));
        case LIST_MULTIPART_UPLOADS -> requireBucket(
                "s3:ListBucketMultipartUploads", bucket, Map.of());
        case HEAD_BUCKET -> requireBucket("s3:ListBucket", bucket, Map.of());
        case CREATE_BUCKET -> {
            requireBucket("s3:CreateBucket", bucket, Map.of());
            if (setsAcl) {
                requireBucket("s3:PutBucketAcl", bucket, Map.of());
            }
            if ("true".equalsIgnoreCase(request.getHeader(
                    AwsHttpHeaders.BUCKET_OBJECT_LOCK_ENABLED))) {
                requireBucket("s3:PutBucketObjectLockConfiguration", bucket,
                        Map.of());
                requireBucket("s3:PutBucketVersioning", bucket, Map.of());
            }
        }
        case DELETE_BUCKET -> requireBucket("s3:DeleteBucket", bucket,
                Map.of());
        case GET_BUCKET_ACL -> requireBucket("s3:GetBucketAcl", bucket,
                Map.of());
        case PUT_BUCKET_ACL -> requireBucket("s3:PutBucketAcl", bucket,
                Map.of());
        case GET_BUCKET_LOCATION -> requireBucket("s3:GetBucketLocation",
                bucket, Map.of());
        case GET_BUCKET_POLICY -> requireBucket("s3:GetBucketPolicy", bucket,
                Map.of());
        case GET_BUCKET_ENCRYPTION -> requireBucket(
                "s3:GetEncryptionConfiguration", bucket, Map.of());
        case PUT_BUCKET_ENCRYPTION, DELETE_BUCKET_ENCRYPTION -> requireBucket(
                "s3:PutEncryptionConfiguration", bucket, Map.of());
        case GET_BUCKET_VERSIONING -> requireBucket("s3:GetBucketVersioning",
                bucket, Map.of());
        case PUT_BUCKET_VERSIONING -> requireBucket("s3:PutBucketVersioning",
                bucket, Map.of());
        case GET_OBJECT, HEAD_OBJECT -> requireObject(
                versioned ? "s3:GetObjectVersion" : "s3:GetObject",
                bucket, key);
        case GET_OBJECT_ATTRIBUTES -> {
            // Attributes include the size and checksums, which S3 treats as
            // part of reading the object.
            requireObject(versioned ? "s3:GetObjectVersion" : "s3:GetObject",
                    bucket, key);
            requireObject(versioned ? "s3:GetObjectVersionAttributes" :
                    "s3:GetObjectAttributes", bucket, key);
        }
        case GET_OBJECT_ACL -> requireObject(
                versioned ? "s3:GetObjectVersionAcl" : "s3:GetObjectAcl",
                bucket, key);
        case PUT_OBJECT_ACL -> requireObject(
                versioned ? "s3:PutObjectVersionAcl" : "s3:PutObjectAcl",
                bucket, key);
        case PUT_OBJECT, COPY_OBJECT, CREATE_MULTIPART_UPLOAD -> {
            // A copy's source is the handler's to check, once it has parsed
            // x-amz-copy-source: see authorizeObject.
            requireObject("s3:PutObject", bucket, key);
            if (setsAcl) {
                requireObject("s3:PutObjectAcl", bucket, key);
            }
        }
        case UPLOAD_PART, UPLOAD_PART_COPY, COMPLETE_MULTIPART_UPLOAD ->
            requireObject("s3:PutObject", bucket, key);
        case ABORT_MULTIPART_UPLOAD -> requireObject(
                "s3:AbortMultipartUpload", bucket, key);
        case LIST_PARTS -> requireObject("s3:ListMultipartUploadParts",
                bucket, key);
        case DELETE_OBJECT -> requireObject(
                versioned ? "s3:DeleteObjectVersion" : "s3:DeleteObject",
                bucket, key);
        case DELETE_OBJECTS -> {
            // checked key by key in the handler
        }
        // A CORS preflight is not signed and answers only with the bucket's
        // CORS rules, which are the proxy's configuration, not its data.
        case OPTIONS_OBJECT -> { }
        default -> throw new S3ProxyException(S3ErrorCode.ACCESS_DENIED);
        }
    }

    /**
     * Refuse an object action the policy does not allow, for an object a
     * request names somewhere other than its URI: the source of a copy, a
     * key in a DeleteObjects body.
     */
    public void authorizeObject(String action, String bucket, String key) {
        requireObject(action, bucket, key);
    }

    private void requireBucket(String action, @Nullable String bucket,
            Map<String, String> context) {
        if (bucket == null || bucket.isEmpty()) {
            throw new S3ProxyException(S3ErrorCode.ACCESS_DENIED);
        }
        require(action, S3_ARN_PREFIX + bucket, context);
    }

    private void requireObject(String action, @Nullable String bucket,
            @Nullable String key) {
        if (bucket == null || bucket.isEmpty() || key == null) {
            throw new S3ProxyException(S3ErrorCode.ACCESS_DENIED);
        }
        checkCanonicalKey(key);
        require(action, S3_ARN_PREFIX + bucket + "/" + key, Map.of());
    }

    /**
     * Refuse a key the policy and the store could read as naming different
     * objects.  The policy matches the key as a string, while a filesystem
     * store resolves it as a path: home/alice/../bob/secret matches
     * home/alice/* yet opens home/bob/secret, and home/alice//readonly/x
     * slips past a Deny on home/alice/readonly/* yet opens the file it
     * denies.  A key with an empty, "." or ".." segment means the same thing
     * to both readers only on some stores, so a session may not use one on
     * any.  A trailing slash, as a directory marker carries, is left alone.
     */
    private static void checkCanonicalKey(String key) {
        String[] segments = key.split("/", -1);
        for (int i = 0; i < segments.length; i++) {
            String segment = segments[i];
            boolean trailing = i == segments.length - 1 && i > 0;
            if ((segment.isEmpty() && !trailing) || segment.equals(".") ||
                    segment.equals("..")) {
                throw new S3ProxyException(S3ErrorCode.ACCESS_DENIED,
                        "Temporary credentials may not use keys with" +
                        " empty, \".\" or \"..\" path segments.");
            }
        }
    }

    private void require(String action, String resource,
            Map<String, String> context) {
        if (!policy.isAllowed(action, resource, context)) {
            throw new S3ProxyException(S3ErrorCode.ACCESS_DENIED);
        }
    }

    /**
     * The condition keys a listing supplies.  A parameter the request leaves
     * out supplies no key, so a statement conditioned on it does not apply:
     * a policy allowing only s3:prefix home/alice/* does not allow listing
     * the whole bucket by omitting the prefix.
     */
    private static Map<String, String> listContext(
            HttpServletRequest request) {
        var context = new HashMap<String, String>();
        String prefix = request.getParameter("prefix");
        if (prefix != null) {
            if (!prefix.isEmpty()) {
                checkCanonicalKey(prefix);
            }
            context.put("s3:prefix", prefix);
        }
        String delimiter = request.getParameter("delimiter");
        if (delimiter != null) {
            context.put("s3:delimiter", delimiter);
        }
        return context;
    }
}
