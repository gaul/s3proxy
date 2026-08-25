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

import java.io.InputStream;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.function.Supplier;

import jakarta.servlet.http.HttpServletRequest;

import org.gaul.s3proxy.AwsHttpHeaders;
import org.gaul.s3proxy.CompleteMultipartUploadRequest;
import org.gaul.s3proxy.S3ErrorCode;
import org.gaul.s3proxy.S3ProxyException;
import org.jspecify.annotations.Nullable;

import software.amazon.awssdk.checksums.DefaultChecksumAlgorithm;
import software.amazon.awssdk.checksums.SdkChecksum;
import software.amazon.awssdk.checksums.spi.ChecksumAlgorithm;
import software.amazon.awssdk.services.s3.model.CompletedPart;
import software.amazon.awssdk.services.s3.model.HeadObjectResponse;
import software.amazon.awssdk.services.s3.model.Part;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.UploadPartRequest;

/**
 * An AWS flexible checksum algorithm, carrying the spellings each context
 * uses -- the x-amz-checksum-* header, the XML element, the algorithm name
 * -- and the arithmetic behind them.
 */
// The suppliers are stateless singletons or method references; the
// accumulators they hand out are the mutable part.
@SuppressWarnings("ImmutableEnumChecker")
public enum FlexChecksum {
    CRC32("crc32", "ChecksumCRC32", AwsHttpHeaders.CHECKSUM_CRC32, 4,
            sdk(DefaultChecksumAlgorithm.CRC32), 0xedb88320L),
    CRC32C("crc32c", "ChecksumCRC32C", AwsHttpHeaders.CHECKSUM_CRC32C, 4,
            sdk(DefaultChecksumAlgorithm.CRC32C), 0x82f63b78L),
    // The SDK names CRC64NVME but computes it only through the optional
    // aws-crt native module; Crc64Nvme supplies it instead.
    CRC64NVME("crc64nvme", "ChecksumCRC64NVME",
            AwsHttpHeaders.CHECKSUM_CRC64NVME, 8,
            Crc64Nvme::new, 0x9a6c9329ac4bc9b5L),
    SHA1("sha1", "ChecksumSHA1", AwsHttpHeaders.CHECKSUM_SHA1, 20,
            sdk(DefaultChecksumAlgorithm.SHA1), 0),
    SHA256("sha256", "ChecksumSHA256", AwsHttpHeaders.CHECKSUM_SHA256, 32,
            sdk(DefaultChecksumAlgorithm.SHA256), 0);

    /**
     * Reserved user-metadata key prefix persisting the flexible checksum
     * asserted at upload time so HEAD/GET with x-amz-checksum-mode: ENABLED
     * can return it.  Underscores rather than hyphens since Azure metadata
     * keys must be valid C# identifiers.  Never exposed as x-amz-meta- and
     * stripped from incoming user metadata so clients cannot forge it.
     */
    public static final String METADATA_PREFIX = "s3proxy_checksum_";

    private final String lower;
    private final String element;
    private final String header;
    private final int length;
    private final Supplier<SdkChecksum> checksums;
    /** Reflected CRC polynomial, or zero for a hash that cannot combine. */
    private final long polynomial;

    FlexChecksum(String lower, String element, String header, int length,
            Supplier<SdkChecksum> checksums, long polynomial) {
        this.lower = lower;
        this.element = element;
        this.header = header;
        this.length = length;
        this.checksums = checksums;
        this.polynomial = polynomial;
    }

    private static Supplier<SdkChecksum> sdk(ChecksumAlgorithm algorithm) {
        return () -> SdkChecksum.forAlgorithm(algorithm);
    }

    /**
     * Whether S3 allows this algorithm's multipart checksum to describe
     * the whole object rather than the parts, which needs the CRCs of two
     * ranges to combine into the CRC of their concatenation.
     */
    public boolean supportsFullObject() {
        return polynomial != 0;
    }

    /**
     * The digest of a || b, given their digests and the length of b.
     * Only valid when {@link #supportsFullObject}.
     */
    byte[] combine(byte[] a, byte[] b, long lengthB) {
        long combined = CrcCombine.combine(toLong(a), toLong(b), lengthB,
                polynomial, length * Byte.SIZE);
        var buffer = java.nio.ByteBuffer.allocate(length);
        if (length == Integer.BYTES) {
            buffer.putInt((int) combined);
        } else {
            buffer.putLong(combined);
        }
        return buffer.array();
    }

    /** A big-endian wire digest as an unsigned value. */
    private static long toLong(byte[] digest) {
        long value = 0;
        for (byte b : digest) {
            value = (value << Byte.SIZE) | (b & 0xffL);
        }
        return value;
    }

    public String lower() {
        return lower;
    }

    public String element() {
        return element;
    }

    public String header() {
        return header;
    }

    /**
     * A fresh accumulator for this algorithm.  Its getChecksumBytes
     * answers in the wire byte order S3 base64-encodes, for the CRCs as
     * well as the SHAs, so nothing downstream reorders bytes.
     */
    public SdkChecksum newChecksum() {
        return checksums.get();
    }

    /** The value this algorithm's checksum takes on a completion's part. */
    @Nullable
    public String value(CompleteMultipartUploadRequest.Part part) {
        return switch (this) {
        case CRC32 -> part.checksumCRC32();
        case CRC32C -> part.checksumCRC32C();
        case CRC64NVME -> part.checksumCRC64NVME();
        case SHA1 -> part.checksumSHA1();
        case SHA256 -> part.checksumSHA256();
        };
    }

    /**
     * The value a store that keeps flexible checksums natively reports for
     * this algorithm, or null where it holds none.  Only a backend asked for
     * one -- x-amz-checksum-mode: ENABLED -- answers at all.
     */
    @Nullable
    public String value(HeadObjectResponse response) {
        return switch (this) {
        case CRC32 -> response.checksumCRC32();
        case CRC32C -> response.checksumCRC32C();
        case CRC64NVME -> response.checksumCRC64NVME();
        case SHA1 -> response.checksumSHA1();
        case SHA256 -> response.checksumSHA256();
        };
    }

    /**
     * The value a store reports for an uploaded part, or null where it kept
     * none -- which says the upload was not initiated with an algorithm and
     * the store is not tracking checksums for it.
     */
    @Nullable
    public String value(Part part) {
        return switch (this) {
        case CRC32 -> part.checksumCRC32();
        case CRC32C -> part.checksumCRC32C();
        case CRC64NVME -> part.checksumCRC64NVME();
        case SHA1 -> part.checksumSHA1();
        case SHA256 -> part.checksumSHA256();
        };
    }

    /**
     * Carry a whole object's checksum to the store on the request that
     * writes it, so a store that judges one refuses a body that does not
     * match instead of keeping it.  S3Proxy checks the same value as it
     * forwards the bytes, but only the store decides what a later read
     * finds: a write it has already begun can still land.
     */
    public PutObjectRequest.Builder setOn(
            PutObjectRequest.Builder builder, String value) {
        return switch (this) {
        case CRC32 -> builder.checksumCRC32(value);
        case CRC32C -> builder.checksumCRC32C(value);
        case CRC64NVME -> builder.checksumCRC64NVME(value);
        case SHA1 -> builder.checksumSHA1(value);
        case SHA256 -> builder.checksumSHA256(value);
        };
    }

    /**
     * Carry a part's checksum to the store on the request that uploads it,
     * so a store keeping checksums natively records the digest the client
     * asserted rather than computing its own -- which would mean reading
     * the part a second time.
     */
    public UploadPartRequest.Builder setOn(
            UploadPartRequest.Builder builder, String value) {
        return switch (this) {
        case CRC32 -> builder.checksumCRC32(value);
        case CRC32C -> builder.checksumCRC32C(value);
        case CRC64NVME -> builder.checksumCRC64NVME(value);
        case SHA1 -> builder.checksumSHA1(value);
        case SHA256 -> builder.checksumSHA256(value);
        };
    }

    /**
     * Carry a part's checksum on the completion request, which a store that
     * computes the composite itself checks the parts against.
     */
    public CompletedPart.Builder setOn(
            CompletedPart.Builder builder, String value) {
        return switch (this) {
        case CRC32 -> builder.checksumCRC32(value);
        case CRC32C -> builder.checksumCRC32C(value);
        case CRC64NVME -> builder.checksumCRC64NVME(value);
        case SHA1 -> builder.checksumSHA1(value);
        case SHA256 -> builder.checksumSHA256(value);
        };
    }

    /**
     * Drop every flexible checksum from a write whose bytes change on the
     * way to the store -- encryption, or a store that keeps the length in
     * place of the content.  The value describes what the client sent, so a
     * store that judges it would refuse an object that is perfectly good,
     * the way a Content-MD5 left in place would.
     */
    public static PutObjectRequest.Builder clearOn(
            PutObjectRequest.Builder builder) {
        return builder.checksumCRC32(null).checksumCRC32C(null)
                .checksumCRC64NVME(null).checksumSHA1(null)
                .checksumSHA256(null);
    }

    /** As {@link #clearOn(PutObjectRequest.Builder)}, for one part. */
    public static UploadPartRequest.Builder clearOn(
            UploadPartRequest.Builder builder) {
        return builder.checksumCRC32(null).checksumCRC32C(null)
                .checksumCRC64NVME(null).checksumSHA1(null)
                .checksumSHA256(null);
    }

    /** User-metadata key persisting this checksum with the object. */
    public String metadataKey() {
        return METADATA_PREFIX + lower;
    }

    /** Base64 of a digest already in AWS wire form. */
    String encodeRaw(byte[] digest) {
        return Base64.getEncoder().encodeToString(digest);
    }

    /**
     * Decode a client-asserted checksum value, rejecting values that are
     * not base64 of exactly this algorithm's digest length the way S3
     * does: 400 InvalidRequest rather than a digest mismatch.
     */
    public byte[] decodeValue(String value) {
        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(value);
        } catch (IllegalArgumentException iae) {
            throw new S3ProxyException(S3ErrorCode.BAD_DIGEST,
                    "Value for " + header + " header is invalid.", iae,
                    Map.of());
        }
        if (decoded.length != length) {
            throw new S3ProxyException(S3ErrorCode.BAD_DIGEST,
                    "Value for " + header + " header is invalid.");
        }
        return decoded;
    }

    /**
     * Whether the request asserts this checksum as a header, validating
     * {@code body} against it when it does.  A value that is not base64 is
     * InvalidDigest and a well formed one that does not match is BadDigest.
     */
    public boolean validateHeader(HttpServletRequest request, byte[] body) {
        String value = request.getHeader(header);
        if (value == null) {
            return false;
        }
        byte[] expected;
        try {
            expected = Base64.getDecoder().decode(value);
        } catch (IllegalArgumentException iae) {
            throw new S3ProxyException(S3ErrorCode.INVALID_DIGEST, iae);
        }
        SdkChecksum digest = newChecksum();
        digest.update(body);
        if (!Arrays.equals(expected, digest.getChecksumBytes())) {
            throw new S3ProxyException(S3ErrorCode.BAD_DIGEST);
        }
        return true;
    }

    /**
     * Wrap {@code is} so the body is validated against the client-asserted
     * checksum as the stream is consumed.
     */
    public InputStream wrapValidator(InputStream is, String expectedBase64,
            long contentLength) {
        return new ChecksumValidatingInputStream(is, newChecksum(),
                decodeValue(expectedBase64), contentLength);
    }

    /**
     * The single flexible checksum carried as a regular x-amz-checksum-*
     * request header, or null.  Modern AWS SDKs send these on non-streaming
     * PutObject and UploadPart requests; the aws-chunked trailer variant is
     * validated by ChunkedInputStream instead.  S3 rejects requests
     * asserting more than one algorithm.
     */
    @Nullable
    public static FlexChecksum fromRequest(HttpServletRequest request) {
        FlexChecksum found = null;
        for (FlexChecksum candidate : values()) {
            if (request.getHeader(candidate.header) != null) {
                if (found != null) {
                    throw new S3ProxyException(S3ErrorCode.INVALID_REQUEST,
                            "Expecting a single x-amz-checksum- header.");
                }
                found = candidate;
            }
        }
        return found;
    }

    @Nullable
    public static FlexChecksum fromAlgorithmName(String name) {
        for (FlexChecksum checksum : values()) {
            if (checksum.name().equalsIgnoreCase(name)) {
                return checksum;
            }
        }
        return null;
    }

    @Nullable
    public static FlexChecksum fromHeaderName(String header) {
        for (FlexChecksum checksum : values()) {
            if (checksum.header().equalsIgnoreCase(header)) {
                return checksum;
            }
        }
        return null;
    }

    @Nullable
    public static FlexChecksum fromMetadataKey(String key) {
        for (FlexChecksum checksum : values()) {
            if (checksum.metadataKey().equalsIgnoreCase(key)) {
                return checksum;
            }
        }
        return null;
    }
}
