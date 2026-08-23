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

package org.gaul.s3proxy.checksum;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.TreeSet;

import jakarta.servlet.http.HttpServletRequest;

import org.gaul.s3proxy.AwsHttpHeaders;
import org.gaul.s3proxy.CompleteMultipartUploadRequest;
import org.gaul.s3proxy.S3ErrorCode;
import org.gaul.s3proxy.S3ProxyException;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.nio2blob.AbstractNio2BlobStore;
import org.jspecify.annotations.Nullable;

import software.amazon.awssdk.checksums.SdkChecksum;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;

/**
 * The flexible-checksum bookkeeping of a multipart upload: which algorithm
 * the completion request's parts declare, the true per-part digests re-read
 * from the hidden part blobs of stub backends, and the composite or
 * full-object checksum the finished object reports.
 */
public final class MpuChecksums {
    /** Values of x-amz-checksum-type and {@link #TYPE_METADATA_KEY}. */
    public static final String COMPOSITE = "COMPOSITE";
    public static final String FULL_OBJECT = "FULL_OBJECT";
    /**
     * User-metadata key remembering on the upload's stub whether a
     * full-object checksum was asked for at initiation; never copied onto
     * the completed object.
     */
    public static final String TYPE_METADATA_KEY =
            FlexChecksum.METADATA_PREFIX + "type";

    private MpuChecksums() {
    }

    /**
     * Which kind of checksum a stored value is.  Only a composite carries the
     * "-&lt;partCount&gt;" suffix, base64 having no use for a hyphen.
     */
    public static String checksumType(String value) {
        return value.indexOf('-') >= 0 ? COMPOSITE : FULL_OBJECT;
    }

    /**
     * Reject malformed x-amz-checksum-* request header values before
     * considering their meaning.  A valid value is either a bare base64
     * digest of the algorithm's length or a composite
     * "&lt;base64&gt;-&lt;partCount&gt;".  Base64 never contains '-', so its
     * presence always marks the composite suffix.  A digest that is not
     * valid base64 of the right length is 400 BadDigest, the same answer a
     * well formed digest that does not match the body gets; a malformed
     * part count describes the request rather than the digest and stays
     * 400 InvalidRequest.
     */
    public static void validateHeaderValues(HttpServletRequest request) {
        for (FlexChecksum checksum : FlexChecksum.values()) {
            String value = request.getHeader(checksum.header());
            if (value == null) {
                continue;
            }
            String base64Part = value;
            int dash = value.indexOf('-');
            if (dash >= 0) {
                base64Part = value.substring(0, dash);
                int count;
                try {
                    count = Integer.parseInt(value.substring(dash + 1));
                } catch (NumberFormatException nfe) {
                    throw new S3ProxyException(S3ErrorCode.INVALID_REQUEST,
                            "Value for " + checksum.header() +
                            " header is invalid.", nfe, Map.of());
                }
                if (count < 1 || count > 10_000) {
                    throw new S3ProxyException(S3ErrorCode.INVALID_REQUEST,
                            "Value for " + checksum.header() +
                            " header is invalid.");
                }
            }
            checksum.decodeValue(base64Part);
        }
    }

    /**
     * The single checksum algorithm the CompleteMultipartUpload request's
     * parts declare, null when no part carries a checksum, rejecting a mix
     * of algorithms.
     */
    @Nullable
    public static FlexChecksum algorithm(CompleteMultipartUploadRequest cmu) {
        if (cmu.parts() == null) {
            return null;
        }
        FlexChecksum algorithm = null;
        for (CompleteMultipartUploadRequest.Part part : cmu.parts()) {
            for (FlexChecksum candidate : FlexChecksum.values()) {
                if (candidate.value(part) != null) {
                    if (algorithm != null && algorithm != candidate) {
                        throw new S3ProxyException(S3ErrorCode.INVALID_REQUEST,
                                "More than one checksum algorithm was" +
                                " supplied for the parts.");
                    }
                    algorithm = candidate;
                }
            }
        }
        return algorithm;
    }

    /**
     * Compute each referenced part's true checksum by re-reading the hidden
     * part blobs that MULTIPART_REQUIRES_STUB backends store, so the result
     * matches the uploaded content no matter what per-part values the
     * completion request asserts (S3 ignores those beyond presence).  The
     * length comes back too, since combining CRCs into a full-object
     * checksum needs it.
     */
    public static Map<Integer, PartChecksum> hashPartContents(
            BlobStore blobStore, String containerName, String blobName,
            String uploadId, FlexChecksum algorithm,
            CompleteMultipartUploadRequest cmu) throws IOException {
        var digests = new HashMap<Integer, PartChecksum>();
        var partNumbers = new TreeSet<Integer>();
        for (CompleteMultipartUploadRequest.Part part : cmu.parts()) {
            partNumbers.add(part.partNumber());
        }
        for (int partNumber : partNumbers) {
            ResponseInputStream<GetObjectResponse> blob;
            try {
                blob = blobStore.getBlob(containerName,
                        AbstractNio2BlobStore.multipartPartName(uploadId,
                                blobName, partNumber));
            } catch (NoSuchKeyException nske) {
                // a missing part is rejected elsewhere; fall back to the
                // client-asserted value
                continue;
            }
            SdkChecksum digest = algorithm.newChecksum();
            long length = 0;
            try (InputStream partIs = blob) {
                byte[] buffer = new byte[16384];
                while (true) {
                    int count = partIs.read(buffer);
                    if (count == -1) {
                        break;
                    }
                    digest.update(buffer, 0, count);
                    length += count;
                }
            }
            digests.put(partNumber, new PartChecksum(
                    digest.getChecksumBytes(), length));
        }
        return digests;
    }

    /**
     * Whether the upload asked for a checksum describing the whole object
     * rather than the parts.  The stub records the choice made at initiation;
     * backends without one have only the completion request to go on, where a
     * value carrying no "-&lt;partCount&gt;" suffix implies a full object.
     */
    public static boolean fullObjectUpload(
            Map<String, String> recordedMetadata,
            HttpServletRequest request, FlexChecksum algorithm) {
        if (!algorithm.supportsFullObject()) {
            return false;
        }
        String recorded = recordedMetadata.get(TYPE_METADATA_KEY);
        if (recorded != null) {
            return recorded.equals(FULL_OBJECT);
        }
        String type = request.getHeader(AwsHttpHeaders.CHECKSUM_TYPE);
        if (type != null) {
            return type.equalsIgnoreCase(FULL_OBJECT);
        }
        String provided = request.getHeader(algorithm.header());
        return provided != null && provided.indexOf('-') < 0;
    }

    /**
     * Enforce the per-part flexible checksums carried by a
     * CompleteMultipartUpload request and compute the composite checksum S3
     * returns for the finished object.  Modern AWS SDKs attach a per-part
     * checksum for every part when the upload was created with a checksum
     * algorithm; S3 rejects the completion when those checksums are missing
     * from some parts or are malformed.  Returns the composite checksum
     * (base64(hash(concatenated part digests)) plus a "-&lt;partCount&gt;"
     * suffix), preferring the true digests in {@code partChecksums} over the
     * client-asserted values.
     */
    @Nullable
    public static Result compute(HttpServletRequest request,
            CompleteMultipartUploadRequest cmu, FlexChecksum algorithm,
            @Nullable Map<Integer, PartChecksum> partChecksums,
            Map<Integer, Long> partSizes, boolean fullObject) {
        // Deduplicate by part number (last wins) and sort ascending so the
        // parts are folded together in canonical order.
        SortedMap<Integer, CompleteMultipartUploadRequest.Part> sorted =
                new TreeMap<>();
        for (CompleteMultipartUploadRequest.Part part : cmu.parts()) {
            sorted.put(part.partNumber(), part);
        }

        // Every part must supply the checksum, matching S3's requirement that
        // a checksum-initiated upload include a per-part checksum for each
        // part.  A composite hashes the concatenated part digests; a full
        // object folds the part CRCs into the CRC of the whole.
        SdkChecksum composite = algorithm.newChecksum();
        byte[] combined = null;
        for (var entry : sorted.entrySet()) {
            String value = algorithm.value(entry.getValue());
            if (value == null) {
                throw new S3ProxyException(S3ErrorCode.INVALID_REQUEST,
                        "The upload was created using a " + algorithm.lower() +
                        " checksum. The complete request must include the" +
                        " checksum for each part. It was missing for part " +
                        entry.getKey() + " in the request.");
            }
            PartChecksum part = partChecksums != null ?
                    partChecksums.get(entry.getKey()) : null;
            byte[] digest = part != null ? part.digest() :
                    algorithm.decodeValue(value);
            if (!fullObject) {
                composite.update(digest);
                continue;
            }
            long length = part != null ? part.length() :
                    partSizes.getOrDefault(entry.getKey(), -1L);
            if (length < 0) {
                // without the part's length the CRCs cannot be folded, so
                // report no checksum rather than a wrong one
                return null;
            }
            combined = combined == null ? digest :
                    algorithm.combine(combined, digest, length);
        }

        String computed;
        if (fullObject) {
            if (combined == null) {
                return null;
            }
            computed = algorithm.encodeRaw(combined);
        } else {
            computed = algorithm.encodeRaw(composite.getChecksumBytes()) +
                    "-" + sorted.size();
        }

        // If the client asserted the expected checksum on the completion
        // request, validate our computation against it.  Only a composite
        // carries the "-<partCount>" suffix; for a composite upload a bare
        // value in this header is the SDK's request-body integrity checksum,
        // which is unrelated to the completed object.
        String provided = request.getHeader(algorithm.header());
        if (provided != null && (fullObject || provided.indexOf('-') >= 0) &&
                !provided.equals(computed)) {
            throw new S3ProxyException(S3ErrorCode.BAD_DIGEST);
        }

        return new Result(algorithm, computed);
    }

    /** The computed checksum of a completed multipart object. */
    public record Result(FlexChecksum algorithm, String value) {
    }

    /** An uploaded part's true digest and length. */
    @SuppressWarnings("ArrayRecordComponent")
    public record PartChecksum(byte[] digest, long length) {
    }
}
