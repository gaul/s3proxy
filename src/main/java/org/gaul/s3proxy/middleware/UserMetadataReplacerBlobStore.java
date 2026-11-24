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

import static com.google.common.base.Preconditions.checkArgument;

import java.io.InputStream;
import java.util.Map;

import com.google.common.collect.ImmutableMap;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.ForwardingBlobStore;
import org.gaul.s3proxy.blobstore.SdkResponses;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.gaul.s3proxy.checksum.FlexChecksum;

import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.CopyObjectRequest;
import software.amazon.awssdk.services.s3.model.CopyObjectResponse;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.HeadObjectRequest;
import software.amazon.awssdk.services.s3.model.HeadObjectResponse;
import software.amazon.awssdk.services.s3.model.ListMultipartUploadsRequest;
import software.amazon.awssdk.services.s3.model.ListMultipartUploadsResponse;
import software.amazon.awssdk.services.s3.model.MetadataDirective;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;

/**
 * BlobStore which maps user metadata keys and values using character
 * replacement.  This is useful for some object stores like Azure which do not
 * allow characters like hyphens.  This munges keys and values during putBlob
 * and unmunges them on getBlob.
 */
final class UserMetadataReplacerBlobStore extends ForwardingBlobStore {
    private final String fromChars;
    private final String toChars;

    private UserMetadataReplacerBlobStore(
            BlobStore blobStore, String fromChars, String toChars) {
        super(blobStore);
        checkArgument(fromChars.length() == toChars.length());
        this.fromChars = fromChars;
        this.toChars = toChars;
    }

    public static BlobStore newUserMetadataReplacerBlobStore(
            BlobStore blobStore, String fromChars, String toChars) {
        return new UserMetadataReplacerBlobStore(blobStore, fromChars, toChars);
    }

    @Override
    public PutObjectResponse putBlob(PutObjectRequest request,
            InputStream payload) {
        return super.putBlob(request.toBuilder()
                .metadata(replaceMetadata(request.metadata(), fromChars,
                        toChars))
                .build(), payload);
    }

    @Override
    public boolean recordChecksumMetadata(String container, String name,
            String eTag, String metadataKey, String value) {
        // reserved, so stored as the handler names it; see replaceMetadata
        return super.recordChecksumMetadata(container, name, eTag,
                metadataKey, value);
    }

    @Override
    public HeadObjectResponse blobMetadata(HeadObjectRequest request) {
        var blobMetadata = super.blobMetadata(request);
        return blobMetadata.toBuilder()
                .metadata(replaceMetadata(blobMetadata.metadata(),
                        /*fromChars=*/ toChars, /*toChars=*/ fromChars))
                .build();
    }

    @Override
    public ResponseInputStream<GetObjectResponse> getBlob(
            GetObjectRequest request) {
        // Nothing may throw between opening the blob and returning it: the
        // caller can only close a stream that it was handed, and one left
        // open holds the backend's file or connection.
        var blob = super.getBlob(request);
        return SdkResponses.getResponse(
                blob.response().toBuilder()
                        .metadata(replaceMetadata(blob.response().metadata(),
                                /*fromChars=*/ toChars, /*toChars=*/ fromChars))
                        .build(),
                blob);
    }

    @Override
    public CopyObjectResponse copyBlob(CopyObjectRequest request) {
        if (request.metadataDirective() == MetadataDirective.REPLACE) {
            // A copy that replaces user metadata must munge the new keys and
            // values the same way putBlob does, so the backend stores the
            // mapped form and getBlob reverses it.  A copy without replacement
            // metadata carries the source's already-munged metadata forward
            // untouched.
            request = request.toBuilder()
                    .metadata(replaceMetadata(request.metadata(), fromChars,
                            toChars))
                    .build();
        }
        return super.copyBlob(request);
    }

    @Override
    public MultipartUpload initiateMultipartUpload(
            CreateMultipartUploadRequest request) {
        var mpu = super.initiateMultipartUpload(request.toBuilder()
                .metadata(replaceMetadata(request.metadata(), fromChars,
                        toChars))
                .build());
        // Answer with the metadata the caller named rather than the stored
        // form: a caller may hand this upload straight back to
        // completeMultipartUpload, which munges it.
        return new MultipartUpload(mpu.id(),
                mpu.request().toBuilder()
                        .metadata(request.metadata())
                        .build(),
                mpu.response());
    }

    @Override
    public CompleteMultipartUploadResponse completeMultipartUpload(
            MultipartUpload mpu, CompleteMultipartUploadRequest request) {
        // A store that assembles the object itself writes the metadata of
        // the upload it is handed here, so munge it the same way putBlob
        // does.  S3ProxyHandler rebuilds that upload from metadata it read
        // back through blobMetadata, i.e., unmunged, and may add a checksum
        // under a key of its own.  That key comes last and prevails over a
        // user key which munges to the same one; reserved names pass as
        // they are, see replaceMetadata.
        return super.completeMultipartUpload(new MultipartUpload(mpu.id(),
                mpu.request().toBuilder()
                        .metadata(replaceMetadata(mpu.request().metadata(),
                                fromChars, toChars))
                        .build(),
                mpu.response()), request);
    }

    /**
     * Maps each key and value of user metadata, but never onto or off the
     * names S3Proxy reserves for checksums it validated itself,
     * {@link FlexChecksum#METADATA_PREFIX}.  The handler drops those names
     * from what a client sends and trusts what comes back under them, so a
     * mapping that turned a client's {@code s3proxy-checksum-sha256} into
     * {@code s3proxy_checksum_sha256} on the way back -- or on the way in,
     * for a store read without this middleware -- reported a checksum of
     * the client's choosing as validated.  A reserved entry passes as it
     * is, and any other keeps its own spelling where the mapping would make
     * it a reserved one.
     *
     * <p>Two keys that differ only in a replaced character become one key;
     * the later of the two is kept rather than fail on the duplicate, which
     * refused the whole request with a 400.
     */
    private static Map<String, String> replaceMetadata(
            Map<String, String> metadata, String fromChars, String toChars) {
        var replaced = ImmutableMap.<String, String>builder();
        for (var entry : metadata.entrySet()) {
            String key = entry.getKey();
            if (isReserved(key)) {
                replaced.put(key, entry.getValue());
                continue;
            }
            String mapped = replaceChars(key, fromChars, toChars);
            replaced.put(isReserved(mapped) ? key : mapped,
                    replaceChars(entry.getValue(), fromChars, toChars));
        }
        return replaced.buildKeepingLast();
    }

    private static boolean isReserved(String key) {
        return key.regionMatches(/*ignoreCase=*/ true, 0,
                FlexChecksum.METADATA_PREFIX, 0,
                FlexChecksum.METADATA_PREFIX.length());
    }

    private static String replaceChars(String value, String fromChars,
            String toChars) {
        var builder = new StringBuilder(/*capacity=*/ value.length());
        for (int i = 0; i < value.length(); ++i) {
            char c = value.charAt(i);
            int idx = fromChars.indexOf(c);
            builder.append(idx < 0 ? c : toChars.charAt(idx));
        }
        return builder.toString();
    }
    // Disable versioning: the metadata rewrite does not extend
    // to the versioned operations.
    @Override
    public boolean supportsVersioning() {
        return false;
    }

    /** Keys are left alone here; only metadata is renamed, so the page is the delegate's. */
    @Override
    public ListMultipartUploadsResponse listMultipartUploads(
            ListMultipartUploadsRequest request) {
        return delegate().listMultipartUploads(request);
    }
}
