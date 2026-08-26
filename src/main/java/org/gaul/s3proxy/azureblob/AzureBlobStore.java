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

package org.gaul.s3proxy.azureblob;

import static java.util.Objects.requireNonNull;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import java.util.function.UnaryOperator;

import com.azure.core.credential.AzureNamedKeyCredential;
import com.azure.core.http.HttpHeaderName;
import com.azure.core.http.rest.PagedResponse;
import com.azure.core.http.rest.Response;
import com.azure.core.util.Context;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.storage.blob.BlobServiceAsyncClient;
import com.azure.storage.blob.BlobServiceClient;
import com.azure.storage.blob.BlobServiceClientBuilder;
import com.azure.storage.blob.BlobServiceVersion;
import com.azure.storage.blob.batch.BlobBatchClient;
import com.azure.storage.blob.batch.BlobBatchClientBuilder;
import com.azure.storage.blob.models.AccessTier;
import com.azure.storage.blob.models.BlobBeginCopySourceRequestConditions;
import com.azure.storage.blob.models.BlobErrorCode;
import com.azure.storage.blob.models.BlobHttpHeaders;
import com.azure.storage.blob.models.BlobItem;
import com.azure.storage.blob.models.BlobListDetails;
import com.azure.storage.blob.models.BlobProperties;
import com.azure.storage.blob.models.BlobRange;
import com.azure.storage.blob.models.BlobRequestConditions;
import com.azure.storage.blob.models.BlobStorageException;
import com.azure.storage.blob.models.BlockList;
import com.azure.storage.blob.models.BlockListType;
import com.azure.storage.blob.models.ListBlobContainersOptions;
import com.azure.storage.blob.models.ListBlobsOptions;
import com.azure.storage.blob.models.PublicAccessType;
import com.azure.storage.blob.options.BlobBeginCopyOptions;
import com.azure.storage.blob.options.BlobContainerCreateOptions;
import com.azure.storage.blob.options.BlobUploadFromUrlOptions;
import com.azure.storage.blob.options.BlockBlobCommitBlockListOptions;
import com.azure.storage.blob.options.BlockBlobOutputStreamOptions;
import com.azure.storage.blob.options.BlockBlobSimpleUploadOptions;
import com.azure.storage.blob.options.BlockBlobStageBlockFromUrlOptions;
import com.azure.storage.blob.sas.BlobSasPermission;
import com.azure.storage.blob.sas.BlobServiceSasSignatureValues;
import com.azure.storage.blob.specialized.BlobInputStream;
import com.azure.storage.blob.specialized.BlockBlobAsyncClient;
import com.azure.storage.common.policy.RequestRetryOptions;
import com.azure.storage.common.policy.RetryPolicyType;
import com.google.common.base.Strings;
import com.google.common.base.Supplier;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.ContentMetadata;
import org.gaul.s3proxy.blobstore.Credentials;
import org.gaul.s3proxy.blobstore.CustomerKeys;
import org.gaul.s3proxy.blobstore.MD5;
import org.gaul.s3proxy.blobstore.S3Exceptions;
import org.gaul.s3proxy.blobstore.SdkRequests;
import org.gaul.s3proxy.blobstore.SdkResponses;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.jspecify.annotations.Nullable;

import reactor.core.publisher.Flux;
import reactor.core.scheduler.Schedulers;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.services.s3.model.Bucket;
import software.amazon.awssdk.services.s3.model.BucketCannedACL;
import software.amazon.awssdk.services.s3.model.CommonPrefix;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.CompletedPart;
import software.amazon.awssdk.services.s3.model.CopyObjectRequest;
import software.amazon.awssdk.services.s3.model.CopyObjectResponse;
import software.amazon.awssdk.services.s3.model.CreateBucketRequest;
import software.amazon.awssdk.services.s3.model.CreateBucketResponse;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.Delete;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.DeleteObjectResponse;
import software.amazon.awssdk.services.s3.model.DeleteObjectsRequest;
import software.amazon.awssdk.services.s3.model.DeleteObjectsResponse;
import software.amazon.awssdk.services.s3.model.DeletedObject;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.HeadBucketRequest;
import software.amazon.awssdk.services.s3.model.HeadBucketResponse;
import software.amazon.awssdk.services.s3.model.HeadObjectRequest;
import software.amazon.awssdk.services.s3.model.HeadObjectResponse;
import software.amazon.awssdk.services.s3.model.ListBucketsRequest;
import software.amazon.awssdk.services.s3.model.ListBucketsResponse;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Response;
import software.amazon.awssdk.services.s3.model.MetadataDirective;
import software.amazon.awssdk.services.s3.model.ObjectCannedACL;
import software.amazon.awssdk.services.s3.model.ObjectIdentifier;
import software.amazon.awssdk.services.s3.model.Part;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.awssdk.services.s3.model.S3Error;
import software.amazon.awssdk.services.s3.model.S3Object;
import software.amazon.awssdk.services.s3.model.ServerSideEncryption;
import software.amazon.awssdk.services.s3.model.StorageClass;
import software.amazon.awssdk.services.s3.model.UploadPartCopyRequest;
import software.amazon.awssdk.services.s3.model.UploadPartCopyResponse;
import software.amazon.awssdk.services.s3.model.UploadPartRequest;
import software.amazon.awssdk.services.s3.model.UploadPartResponse;

public final class AzureBlobStore implements BlobStore {
    private static final String STUB_BLOB_PREFIX = ".s3proxy/stubs/";
    private static final long MAXIMUM_MULTIPART_PART_SIZE =
            4000L * 1024 * 1024;
    /**
     * Metadata entry on a stub blob naming the blob the upload completes to.
     * Previously a blob index tag, whose value admits only alphanumerics and
     * " +-.:=_/" within 256 characters -- so a key holding any other
     * character, or any non-ASCII one, could not be recorded and
     * CreateMultipartUpload failed for a key Azure accepts as a blob name.
     */
    private static final String TARGET_BLOB_NAME_METADATA =
            "s3proxy_target_blob_name";
    /**
     * The suffix S3 gives the ETag of an object assembled from parts, and with
     * it the standing signal that the value is not a hash of the content: a
     * client seeing a dash skips its integrity check instead of decoding the
     * ETag as hex.  Azure mints tokens like {@code 0x8DD3F4A5F0B2C1E}, which
     * are neither a hash nor even valid hex, so every object leaves under this
     * suffix and arrives at a condition wearing it.
     */
    private static final String OPAQUE_ETAG_SUFFIX = "-1";
    private static final int STATUS_NOT_FOUND = 404;
    /** How many deletes Azure accepts in one batch request. */
    private static final int MAX_BATCH_DELETES = 256;
    // Azure refuses maxresults past 5000 where S3's max-buckets reaches
    // 10000; a shorter page with a continuation token still answers.
    private static final int MAX_CONTAINER_RESULTS = 5_000;
    // Disable retries since client should retry on errors.
    private static final RequestRetryOptions NO_RETRY_OPTIONS = new RequestRetryOptions(
            RetryPolicyType.FIXED, /*maxTries=*/ 1,
            /*tryTimeoutInSeconds=*/ (Integer) null,
            /*retryDelayInMs=*/ null, /*maxRetryDelayInMs=*/ null,
            /*secondaryHost=*/ null);

    private final BlobServiceClient blobServiceClient;
    private final BlobBatchClient blobBatchClient;
    private final BlobServiceAsyncClient blobServiceAsyncClient;
    private final String endpoint;
    private final Supplier<Credentials> creds;
    /**
     * Report the ETag Azure mints under {@link #OPAQUE_ETAG_SUFFIX} rather
     * than bare.  S3 SDKs decode a dashless ETag as hex and abort the request
     * when they cannot, which Azure's is not.
     */
    private final boolean opaqueETags;

    public AzureBlobStore(
            Supplier<Credentials> creds,
            String endpointUrl) {
        this(creds, endpointUrl, /*eTagMode=*/ "opaque");
    }

    public AzureBlobStore(
            Supplier<Credentials> creds,
            String endpointUrl,
            String eTagMode) {
        this.opaqueETags = switch (eTagMode) {
        case "opaque" -> true;
        case "native" -> false;
        default -> throw new IllegalArgumentException(
                "Invalid ETag mode: " + eTagMode + ".  Supported modes:" +
                " opaque, native");
        };
        // TODO: derive endpoint from Constants.PROPERTY_ENDPOINT when unset,
        // e.g., default to https://<account>.blob.core.windows.net based on
        // the configured identity.
        this.endpoint = endpointUrl;
        this.creds = creds;
        var cred = creds.get();
        var blobServiceClientBuilder = new BlobServiceClientBuilder()
                // The oldest version that carries startFrom on List Blobs,
                // which list depends on.  Pinned rather than left at the
                // SDK's latest so that upgrading the SDK cannot ask a
                // service for a version it has never heard of.
                .serviceVersion(BlobServiceVersion.V2026_02_06)
                .endpoint(endpoint)
                .retryOptions(NO_RETRY_OPTIONS);
        if (!cred.identity().isEmpty() && !cred.credential().isEmpty()) {
            blobServiceClientBuilder.credential(
                new AzureNamedKeyCredential(cred.identity(),
                        cred.credential()));
        } else {
            blobServiceClientBuilder.credential(
                new DefaultAzureCredentialBuilder().build());
        }
        // Build the sync and async clients once from a single builder so they
        // share one credential instance.  Rebuilding the credential per request
        // would defeat token caching and, for DefaultAzureCredential, trigger a
        // fresh IMDS token acquisition on every multipart part upload.
        blobServiceClient = blobServiceClientBuilder.buildClient();
        blobServiceAsyncClient = blobServiceClientBuilder.buildAsyncClient();
        blobBatchClient = new BlobBatchClientBuilder(blobServiceClient)
                .buildClient();
    }

    /**
     * The ETag to report for a blob.  The token Azure mints means nothing to
     * an S3 client and stops some outright, so it travels dressed as the ETag
     * of an object assembled from parts: unverifiable by construction, which
     * is the truth about it.
     */
    String reportETag(String azureETag) {
        if (!opaqueETags) {
            return azureETag;
        }
        return unquote(azureETag) + OPAQUE_ETAG_SUFFIX;
    }

    /**
     * The ETag to hand Azure for a precondition the caller expressed.  A
     * caller echoes back whatever it was given, so the suffix comes off and
     * the service adjudicates against its own token.  Nothing needs reading
     * first, and no window opens between deciding and writing: the condition
     * Azure evaluates is the one the caller asked for.
     */
    @Nullable String backendCondition(@Nullable String eTag) {
        if (!opaqueETags || eTag == null) {
            return eTag;
        }
        String bare = unquote(eTag);
        if (!bare.endsWith(OPAQUE_ETAG_SUFFIX)) {
            return eTag;
        }
        return bare.substring(0,
                bare.length() - OPAQUE_ETAG_SUFFIX.length());
    }

    private static String unquote(String eTag) {
        if (eTag.length() >= 2 && eTag.startsWith("\"") &&
                eTag.endsWith("\"")) {
            return eTag.substring(1, eTag.length() - 1);
        }
        return eTag;
    }

    @Override
    public ListBucketsResponse list() {
        var buckets = ImmutableList.<Bucket>builder();
        for (var container : blobServiceClient.listBlobContainers()) {
            // Azure containers have no creation time.
            buckets.add(SdkResponses.bucket(container.getName(),
                    /*creationDate=*/ null));
        }
        return ListBucketsResponse.builder()
                .buckets(buckets.build())
                .build();
    }

    @Override
    public ListBucketsResponse list(ListBucketsRequest request) {
        var azureOptions = new ListBlobContainersOptions();
        azureOptions.setPrefix(request.prefix());
        if (request.maxBuckets() != null) {
            azureOptions.setMaxResultsPerPage(
                    Math.min(request.maxBuckets(), MAX_CONTAINER_RESULTS));
        }
        // The token is the opaque marker Azure returned, round-tripped by
        // the frontend; a page can come back empty with a marker onward,
        // which firstPageWithEntries follows.
        var pages = blobServiceClient.listBlobContainers(azureOptions,
                /*timeout=*/ null);
        var page = firstPageWithEntries(
                m -> pages.iterableByPage(m).iterator().next(),
                request.continuationToken());
        var buckets = ImmutableList.<Bucket>builder();
        for (var container : page.values()) {
            // Azure containers have no creation time.
            buckets.add(SdkResponses.bucket(container.getName(),
                    /*creationDate=*/ null));
        }
        return ListBucketsResponse.builder()
                .buckets(buckets.build())
                .continuationToken(
                        Strings.emptyToNull(page.continuationToken()))
                .prefix(request.prefix())
                .build();
    }

    @Override
    public ListObjectsV2Response list(ListObjectsV2Request request) {
        String container = request.bucket();
        String startAfter = request.startAfter();
        var client = blobServiceClient.getBlobContainerClient(container);
        var azureOptions = new ListBlobsOptions();
        azureOptions.setPrefix(request.prefix());
        azureOptions.setMaxResultsPerPage(request.maxKeys());
        // start-after names any blob, which is what startFrom takes; the
        // marker takes only a token Azure minted, and handing it a name is
        // the error this parameter exists to avoid.  Pass the continuation
        // token through verbatim: decoding it corrupts one containing '+'
        // (turned into a space) or '%'.
        azureOptions.setStartFrom(startAfter);
        var marker = request.continuationToken();

        var contents = ImmutableList.<S3Object>builder();
        var prefixes = ImmutableList.<CommonPrefix>builder();
        Page<BlobItem> page;
        try {
            var pages = client.listBlobsByHierarchy(
                    request.delimiter(), azureOptions, /*timeout=*/ null);
            page = firstPageWithEntries(
                    m -> pages.iterableByPage(m).iterator().next(), marker,
                    blobs -> afterStartAfter(blobs, startAfter));
        } catch (BlobStorageException bse) {
            throw translate(bse, container, /*key=*/ null);
        }
        for (var blob : page.values()) {
            var properties = blob.getProperties();
            if (blob.isPrefix()) {
                prefixes.add(SdkResponses.commonPrefix(blob.getName()));
            } else {
                contents.add(SdkResponses.objectEntry(blob.getName(),
                        reportETag(properties.getETag()),
                        properties.getLastModified().toInstant(),
                        properties.getContentLength(),
                        fromAccessTier(properties.getAccessTier())));
            }
        }

        return SdkResponses.objectsPage(contents.build(), prefixes.build(),
                page.continuationToken());
    }

    /** The entries of a listing page and the marker onward from it. */
    record Page<T>(List<T> values, @Nullable String continuationToken) { }

    /**
     * The entries of a page with the names start-after excludes dropped from
     * its front.  Azure's startFrom includes the name it is given where S3's
     * start-after excludes it, and a delimiter squashes blobs into a prefix
     * after startFrom has selected them, so a start-after naming a blob
     * inside one brings its prefix back too: listing after {@code boo/}
     * returns {@code boo/} again, the very prefix S3 hands out as the marker
     * to page past that group with.  S3 compares start-after against the name
     * it reports rather than the blob behind it, so both cases are the one
     * rule -- drop what is not greater -- and the entries being sorted, only
     * the front of a page can hold any.
     */
    static List<BlobItem> afterStartAfter(List<BlobItem> blobs,
            @Nullable String startAfter) {
        if (startAfter == null) {
            return blobs;
        }
        int i = 0;
        while (i < blobs.size() &&
                blobs.get(i).getName().compareTo(startAfter) <= 0) {
            ++i;
        }
        return blobs.subList(i, blobs.size());
    }

    static <T> Page<T> firstPageWithEntries(
            Function<@Nullable String, PagedResponse<T>> fetch,
            @Nullable String marker) {
        return firstPageWithEntries(fetch, marker, UnaryOperator.identity());
    }

    /**
     * The first page Azure returns holding anything to report, or the last one
     * when the container is exhausted.  Azure can answer a listing with no
     * blobs at all and a continuation token, which it expects the caller to
     * follow; passing such a page on leaves an S3 client a truncated result
     * with neither Contents nor CommonPrefixes to take its next marker from,
     * so a client that derives one from the last key it saw -- s3cmd does --
     * stops there and reports the prefix as empty.
     * OpenStackSwiftBlobStore.list keeps fetching for the same reason.  A page
     * left empty by {@code keep} is no different: what start-after excludes is
     * nothing the client can resume from either.
     */
    static <T> Page<T> firstPageWithEntries(
            Function<@Nullable String, PagedResponse<T>> fetch,
            @Nullable String marker, UnaryOperator<List<T>> keep) {
        while (true) {
            PagedResponse<T> page = fetch.apply(marker);
            marker = page.getContinuationToken();
            List<T> values = keep.apply(page.getValue());
            if (!values.isEmpty() || marker == null) {
                return new Page<>(values, marker);
            }
        }
    }

    @Override
    public HeadBucketResponse headBucket(HeadBucketRequest request) {
        var client = blobServiceClient.getBlobContainerClient(
                request.bucket());
        if (!client.exists()) {
            throw S3Exceptions.noSuchBucket(request.bucket(), "");
        }
        return HeadBucketResponse.builder().build();
    }

    @Override
    public CreateBucketResponse createContainer(CreateBucketRequest request) {
        if (request.acl() == BucketCannedACL.PUBLIC_READ_WRITE) {
            throw new UnsupportedOperationException(
                    "anonymous write access unsupported in Azure");
        }
        String container = request.bucket();
        var azureOptions = new BlobContainerCreateOptions();
        if (request.acl() == BucketCannedACL.PUBLIC_READ) {
            azureOptions.setPublicAccessType(PublicAccessType.CONTAINER);
        }
        try {
            var response = blobServiceClient
                    .createBlobContainerIfNotExistsWithResponse(
                            container, azureOptions, /*context=*/ null);
            if (response.getStatusCode() != 201) {
                throw S3Exceptions.bucketAlreadyOwnedByYou(container);
            }
            return CreateBucketResponse.builder().build();
        } catch (BlobStorageException bse) {
            throw translate(bse, container, /*key=*/ null);
        }
    }

    @Override
    public void deleteContainer(String container) {
        try {
            blobServiceClient.deleteBlobContainer(container);
        } catch (BlobStorageException bse) {
            if (!bse.getErrorCode().equals(BlobErrorCode.CONTAINER_NOT_FOUND)) {
                throw bse;
            }
        }
    }

    @Override
    public void deleteBucket(String container) {
        var client = blobServiceClient.getBlobContainerClient(container);
        try {
            // An empty page can carry a continuation token onto blobs that do
            // exist, and deleting the container on the strength of it would
            // take them with it.
            var pages = client.listBlobsByHierarchy(
                    /*delimiter=*/ null, /*options=*/ null, /*timeout=*/ null);
            var page = firstPageWithEntries(
                    m -> pages.iterableByPage(m).iterator().next(),
                    /*marker=*/ null);
            if (!page.values().isEmpty()) {
                throw S3Exceptions.bucketNotEmpty(container);
            }
            blobServiceClient.deleteBlobContainer(container);
        } catch (BlobStorageException bse) {
            if (!bse.getErrorCode().equals(BlobErrorCode.CONTAINER_NOT_FOUND)) {
                throw bse;
            }
        }
    }

    @Override
    public boolean blobExists(String container, String key) {
        var client = blobServiceClient.getBlobContainerClient(container)
                .getBlobClient(key);
        return client.exists();
    }

    @Override
    public ResponseInputStream<GetObjectResponse> getBlob(
            GetObjectRequest request) {
        if (request.versionId() != null) {
            throw new UnsupportedOperationException(
                    "versioning not supported");
        }
        String container = request.bucket();
        String key = request.key();
        var client = blobServiceClient.getBlobContainerClient(container)
                .getBlobClient(key);
        // Azure rejects the literal If-None-Match: * with 400
        // UnsatisfiableCondition rather than treating it as "matches any
        // existing blob", so emulate the S3 semantics here: an existing blob
        // fails the precondition (412, which the frontend maps to 304 for
        // GET/HEAD) and a missing blob falls through to 404.
        if ("*".equals(request.ifNoneMatch())) {
            try {
                client.getProperties();
            } catch (BlobStorageException bse) {
                throw translate(bse, container, key);
            }
            throw S3Exceptions.fromStatusCode(412);
        }
        BlobRange azureRange = null;
        var range = SdkRequests.parseRange(request.range());
        if (range != null) {
            if (range.first() == null) {
                // suffix range (bytes=-N): the last N bytes.  Azure has no
                // native suffix range, so resolve it against the blob size.
                // N greater than the size returns the whole blob, matching S3.
                long tail = requireNonNull(range.last());
                long blobSize;
                try {
                    blobSize = client.getProperties().getBlobSize();
                } catch (BlobStorageException bse) {
                    throw translate(bse, container, key);
                }
                long count = Math.min(tail, blobSize);
                azureRange = new BlobRange(blobSize - count, count);
            } else if (range.last() == null) {
                // handle to read from an offset till the end
                azureRange = new BlobRange(range.first());
            } else {
                // handle to read from an offset
                long offset = range.first();
                long length = range.last() - offset + 1;
                azureRange = new BlobRange(offset, length);
            }
        }
        var conditions = new BlobRequestConditions()
                .setIfMatch(backendCondition(request.ifMatch()))
                .setIfModifiedSince(toOffsetDateTime(
                        request.ifModifiedSince()))
                .setIfNoneMatch(backendCondition(request.ifNoneMatch()))
                .setIfUnmodifiedSince(toOffsetDateTime(
                        request.ifUnmodifiedSince()));
        BlobInputStream blobStream;
        try {
            blobStream = client.openInputStream(azureRange, conditions);
        } catch (BlobStorageException bse) {
            if (bse.getStatusCode() ==
                    416) {
                throw S3Exceptions.fromStatusCode(416);
            }
            throw translate(bse, container, key);
        }
        var properties = blobStream.getProperties();
        var expires = properties.getExpiresOn();
        long contentLength;
        if (azureRange == null) {
            contentLength = properties.getBlobSize();
        } else {
            if (azureRange.getCount() == null) {
                contentLength = properties.getBlobSize() -
                        azureRange.getOffset();
            } else {
                // An explicit range whose end lies past the blob returns only
                // the bytes up to the end of the blob, so clamp the reported
                // length to what Azure actually streams; otherwise
                // Content-Length overstates the body and the client stalls
                // waiting for bytes that never come.
                contentLength = Math.min(azureRange.getCount(),
                        properties.getBlobSize() - azureRange.getOffset());
            }
        }
        // Carry the access tier so GET reports x-amz-storage-class
        // consistently with HEAD (blobMetadata).  Get Blob does not always
        // return the tier that Get Blob Properties does (e.g. the emulator
        // omits it), so fall back to a properties fetch only when it is absent.
        var accessTier = properties.getAccessTier();
        if (accessTier == null) {
            accessTier = client.getProperties().getAccessTier();
        }
        @SuppressWarnings("deprecation")
        var builder = GetObjectResponse.builder()
                .metadata(properties.getMetadata())
                .serverSideEncryption(
                        reportedSse(properties.isServerEncrypted()))
                .cacheControl(properties.getCacheControl())
                .contentDisposition(properties.getContentDisposition())
                .contentEncoding(properties.getContentEncoding())
                .contentLanguage(properties.getContentLanguage())
                .contentLength(contentLength)
                .contentType(properties.getContentType())
                .expires(expires == null ? null : expires.toInstant())
                .eTag(reportETag(properties.getETag()))
                .lastModified(properties.getLastModified() == null ? null :
                        properties.getLastModified().toInstant())
                .storageClass(fromAccessTier(accessTier).toString());
        if (azureRange != null) {
            builder.contentRange(
                    "bytes " + azureRange.getOffset() +
                    "-" + (azureRange.getOffset() + contentLength - 1) +
                    "/" + properties.getBlobSize());
        }
        return SdkResponses.getResponse(builder.build(), blobStream);
    }

    @Override
    public boolean supportsServerSideEncryption() {
        // Azure Blob encrypts at rest with service-managed keys and reports
        // the fact on every response, which reportedSse relays as SSE-S3
        // (AES256). SSE-C and SSE-KMS are refused (see refuseUnsupportedSse)
        // rather than silently accepted.
        return true;
    }

    /**
     * Refuse the SSE modes Azure Blob cannot honor: customer-provided keys
     * (we do not encrypt with the caller's key) and KMS in any variant,
     * aws:kms:dsse included. Refusing beats silently storing data the
     * requested key never protected.
     */
    private static void refuseUnsupportedSse(@Nullable String algorithm,
            @Nullable String kmsKeyId, @Nullable String customerAlgorithm,
            @Nullable String customerKey, @Nullable String customerKeyMD5) {
        if (customerAlgorithm != null || customerKey != null ||
                customerKeyMD5 != null || kmsKeyId != null ||
                (algorithm != null && !"AES256".equals(algorithm))) {
            throw S3Exceptions.fromStatusCode(501);
        }
    }

    /**
     * Refuse the customer-key triple on an upload's later requests -- a
     * part, a part copy, the completion.  Uploads on this store never rest
     * under a customer key, their creation refuses one, so any key a later
     * request presents is not applicable, as S3 answers.
     */
    private static void refuseUploadCustomerKey(
            @Nullable String customerAlgorithm, @Nullable String customerKey,
            @Nullable String customerKeyMD5) {
        if (customerAlgorithm != null || customerKey != null ||
                customerKeyMD5 != null) {
            throw S3Exceptions.invalidRequest("The encryption parameters" +
                    " are not applicable to this upload.");
        }
    }

    /**
     * The encryption a response reports the blob resting under: only when
     * Azure answers that the service encrypted the data does the response
     * earn the SSE-S3 (AES256) report.  Blobs from accounts that predate
     * service encryption can answer false.
     */
    private static @Nullable ServerSideEncryption reportedSse(
            @Nullable Boolean serverEncrypted) {
        return Boolean.TRUE.equals(serverEncrypted) ?
                ServerSideEncryption.AES256 : null;
    }

    /**
     * Translate a failure from a write that carried an If-Match.  Azure
     * refuses the write whether the ETag differed or the blob was not there
     * to carry one, where S3 tells those apart: a condition that failed
     * against nothing to have matched, 412 against 404.  So look once more
     * to see which happened.  Only a refusal pays for the second look, and
     * the condition itself is still judged where the write happens.
     */
    private RuntimeException translateWrite(BlobStorageException bse,
            String container, String key, @Nullable String ifMatch) {
        if (ifMatch != null &&
                BlobErrorCode.CONDITION_NOT_MET.equals(bse.getErrorCode()) &&
                !blobExists(container, key)) {
            return S3Exceptions.noSuchKey(container, key, "", bse);
        }
        return translate(bse, container, key);
    }

    @Override
    public PutObjectResponse putBlob(PutObjectRequest request,
            InputStream payload) {
        String container = request.bucket();
        String key = request.key();
        refuseUnsupportedSse(request.serverSideEncryptionAsString(),
                request.ssekmsKeyId(), request.sseCustomerAlgorithm(),
                request.sseCustomerKey(), request.sseCustomerKeyMD5());
        var client = blobServiceClient.getBlobContainerClient(container)
                .getBlobClient(key)
                .getBlockBlobClient();
        try (var is = payload) {
            // TODO: Expires?
            var blobHttpHeaders = new BlobHttpHeaders();
            blobHttpHeaders.setCacheControl(request.cacheControl());
            blobHttpHeaders.setContentDisposition(
                    request.contentDisposition());
            blobHttpHeaders.setContentEncoding(request.contentEncoding());
            blobHttpHeaders.setContentLanguage(request.contentLanguage());
            var hash = request.contentMD5();
            blobHttpHeaders.setContentMd5(hash != null ?
                    Base64.getDecoder().decode(hash) : null);
            blobHttpHeaders.setContentType(request.contentType());

            var metadata = request.metadata();

            AccessTier tier = null;
            if (request.storageClass() != null &&
                    request.storageClass() != StorageClass.STANDARD) {
                tier = toAccessTier(request.storageClass());
            }

            BlobRequestConditions requestConditions = null;
            if (request.ifMatch() != null || request.ifNoneMatch() != null) {
                requestConditions = new BlobRequestConditions()
                        .setIfMatch(backendCondition(request.ifMatch()))
                        .setIfNoneMatch(
                                backendCondition(request.ifNoneMatch()));
            }

            Long contentLength = request.contentLength();
            if (contentLength != null && contentLength >= 0) {
                // Stream the payload to the service as a single Put Blob in
                // bounded-size chunks instead of buffering the entire object
                // in memory.  getBlobOutputStream routes through the SDK's
                // buffered upload path, which accumulates the whole payload
                // (up to the 256 MiB single-upload threshold) on the heap and
                // exhausts it under concurrent large uploads.
                var uploadOptions = new BlockBlobSimpleUploadOptions(
                        chunkedByteBufferFlux(is, contentLength), contentLength)
                        .setHeaders(blobHttpHeaders)
                        .setMetadata(metadata)
                        .setTier(tier)
                        .setRequestConditions(requestConditions);
                var uploaded = client.uploadWithResponse(uploadOptions,
                        /*timeout=*/ null, /*context=*/ null).getValue();
                return SdkResponses.putResponse(reportETag(
                        uploaded.getETag()))
                        .toBuilder()
                        .serverSideEncryption(
                                reportedSse(uploaded.isServerEncrypted()))
                        .build();
            }

            // Content-Length is unknown, so fall back to the output stream,
            // which the SDK buffers before committing.
            var azureOptions = new BlockBlobOutputStreamOptions();
            azureOptions.setMetadata(metadata);
            azureOptions.setHeaders(blobHttpHeaders);
            if (tier != null) {
                azureOptions.setTier(tier);
            }
            if (requestConditions != null) {
                azureOptions.setRequestConditions(requestConditions);
            }
            try (var os = client.getBlobOutputStream(
                    azureOptions, /*context=*/ null)) {
                is.transferTo(os);
            }

            // TODO: racy
            var properties = blobServiceClient
                    .getBlobContainerClient(container)
                    .getBlobClient(key)
                    .getProperties();
            return SdkResponses.putResponse(reportETag(
                    properties.getETag()))
                    .toBuilder()
                    .serverSideEncryption(
                            reportedSse(properties.isServerEncrypted()))
                    .build();
        } catch (BlobStorageException bse) {
            throw translateWrite(bse, container, key, request.ifMatch());
        } catch (IOException ioe) {
            if (ioe.getCause() instanceof BlobStorageException bse) {
                throw translateWrite(bse, container, key, request.ifMatch());
            }
            throw new RuntimeException(ioe);
        }
    }

    /**
     * Read {@code contentLength} bytes from {@code is} as a Flux of
     * bounded-size {@link ByteBuffer}s so that the Azure SDK streams the
     * payload to the service instead of buffering it entirely in memory.
     * The stream is closed by the caller via try-with-resources.
     *
     * Chunks after the first are demanded from the SDK's netty event loop,
     * where Reactor forbids blocking.  Reading {@code is} is always
     * blocking, and when the source is another Azure blob (UploadPartCopy)
     * its read() even calls block() internally, so emit from a scheduler
     * that permits blocking; subscribeOn also forwards downstream requests
     * onto that scheduler.
     *
     * The chunk size alone does not bound heap use: reactor-netty demands
     * reactor.netty.send.maxPrefetchSize chunks, 128 by default, before it
     * writes any of them, so one upload holds 128 at once whenever the
     * caller outruns the socket.  At 4 MiB that was 512 MiB per concurrent
     * upload, and exhausting the heap mid-request surfaced as a stalled
     * connection and a write timeout rather than as an OutOfMemoryError.
     * The whole Flux is a single Put Blob or Put Block request whatever the
     * chunk size, so this is streaming granularity only and shrinking it
     * costs no extra round trips.
     */
    private static Flux<ByteBuffer> chunkedByteBufferFlux(InputStream is,
            long contentLength) {
        final int maxChunkSize = 256 * 1024;
        return Flux.<ByteBuffer, Long>generate(
            () -> 0L,
            (position, sink) -> {
                try {
                    if (position >= contentLength) {
                        sink.complete();
                        return position;
                    }
                    int chunkSize = (int) Math.min(maxChunkSize,
                            contentLength - position);
                    ByteBuffer buffer = ByteBuffer.allocate(chunkSize);
                    byte[] array = buffer.array();
                    int totalRead = 0;
                    while (totalRead < chunkSize) {
                        int read = is.read(array, totalRead,
                                chunkSize - totalRead);
                        if (read == -1) {
                            if (position + totalRead < contentLength) {
                                sink.error(new IOException(
                                    "Stream ended at %d bytes, expected %d".formatted(
                                        position + totalRead, contentLength)));
                                return position + totalRead;
                            }
                            break;
                        }
                        totalRead += read;
                    }
                    if (totalRead == 0) {
                        sink.error(new IOException(
                            "Stream ended at %d bytes, expected %d".formatted(
                                    position, contentLength)));
                        return position;
                    }
                    buffer.position(totalRead);
                    buffer.flip();
                    sink.next(buffer.asReadOnlyBuffer());
                    long nextPosition = position + totalRead;
                    if (nextPosition >= contentLength) {
                        sink.complete();
                    }
                    return nextPosition;
                } catch (IOException e) {
                    sink.error(e);
                    return position;
                }
            },
            position -> {
                // Stream is closed by try-with-resources
            }
        ).subscribeOn(Schedulers.boundedElastic());
    }

    @Override
    public CopyObjectResponse copyBlob(CopyObjectRequest request) {
        refuseUnsupportedSse(request.serverSideEncryptionAsString(),
                request.ssekmsKeyId(), request.sseCustomerAlgorithm(),
                request.sseCustomerKey(), request.sseCustomerKeyMD5());
        // The source never rests under a customer key on this store, so a
        // copy-source triple is judged against none, as S3 does.
        CustomerKeys.enforce(/*storedKeyMD5=*/ null,
                request.copySourceSSECustomerAlgorithm(),
                request.copySourceSSECustomerKey(),
                request.copySourceSSECustomerKeyMD5());
        if (request.sourceVersionId() != null) {
            throw new UnsupportedOperationException(
                    "versioning not supported");
        }
        String fromContainer = request.sourceBucket();
        String fromName = request.sourceKey();
        boolean replace =
                request.metadataDirective() == MetadataDirective.REPLACE;
        if (request.acl() == ObjectCannedACL.PUBLIC_READ) {
            // Matches setBlobAccess: Azure grants read at the container, so a
            // public copy is refused rather than silently made private.
            throw new UnsupportedOperationException("unsupported in Azure");
        }
        var expiryTime = OffsetDateTime.now().plusDays(1);
        var permission = new BlobSasPermission().setReadPermission(true);
        var values = new BlobServiceSasSignatureValues(expiryTime, permission)
                .setStartTime(OffsetDateTime.now());

        var fromClient = blobServiceClient
                .getBlobContainerClient(fromContainer)
                .getBlobClient(fromName);
        var url = fromClient.getBlobUrl();
        String token;
        var cred = creds.get();
        if (!cred.identity().isEmpty() && !cred.credential().isEmpty()) {
            token = fromClient.generateSas(values);
        } else {
            var userDelegationKey = blobServiceClient.getUserDelegationKey(
                    OffsetDateTime.now().minusMinutes(5), expiryTime);
            token = fromClient.generateUserDelegationSas(values, userDelegationKey);
        }

        // TODO: is this the best way to generate a SAS URL?
        var azureOptions = new BlobUploadFromUrlOptions(url + "?" + token);
        var client = blobServiceClient
                .getBlobContainerClient(request.destinationBucket())
                .getBlobClient(request.destinationKey())
                .getBlockBlobClient();

        var headers = new BlobHttpHeaders();
        if (replace) {
            var cacheControl = request.cacheControl();
            if (cacheControl != null) {
                headers.setCacheControl(cacheControl);
            }

            var contentDisposition = request.contentDisposition();
            if (contentDisposition != null) {
                headers.setContentDisposition(contentDisposition);
            }

            var contentEncoding = request.contentEncoding();
            if (contentEncoding != null) {
                headers.setContentEncoding(contentEncoding);
            }

            var contentLanguage = request.contentLanguage();
            if (contentLanguage != null) {
                headers.setContentLanguage(contentLanguage);
            }

            var contentType = request.contentType();
            if (contentType != null) {
                headers.setContentType(contentType);
            }
        }
        azureOptions.setHeaders(headers);

        // Enforce the x-amz-copy-source-if-* preconditions against the source
        // blob.  A failed source condition surfaces as SOURCE_CONDITION_NOT_MET
        // which translate() maps to PreconditionFailed.
        var sourceConditions = new BlobRequestConditions();
        boolean haveSourceConditions = false;
        // Undressed once here: the Put Blob From URL path below and the
        // Copy Blob fallback both hand these straight to the service.
        String ifMatch = backendCondition(request.copySourceIfMatch());
        if (ifMatch != null) {
            sourceConditions.setIfMatch(ifMatch);
            haveSourceConditions = true;
        }
        String ifNoneMatch = backendCondition(request.copySourceIfNoneMatch());
        if (ifNoneMatch != null) {
            sourceConditions.setIfNoneMatch(ifNoneMatch);
            haveSourceConditions = true;
        }
        Instant ifModifiedSince = request.copySourceIfModifiedSince();
        if (ifModifiedSince != null) {
            sourceConditions.setIfModifiedSince(
                    ifModifiedSince.atOffset(ZoneOffset.UTC));
            haveSourceConditions = true;
        }
        Instant ifUnmodifiedSince = request.copySourceIfUnmodifiedSince();
        if (ifUnmodifiedSince != null) {
            sourceConditions.setIfUnmodifiedSince(
                    ifUnmodifiedSince.atOffset(ZoneOffset.UTC));
            haveSourceConditions = true;
        }
        if (haveSourceConditions) {
            azureOptions.setSourceRequestConditions(sourceConditions);
        }

        try {
            var response = client.uploadFromUrlWithResponse(
                    azureOptions, /*timeout=*/ null, /*context=*/ null);

            // TODO: cannot do this as part of uploadFromUrlWithResponse?
            if (replace) {
                client.setMetadata(request.metadata());
            }

            var copied = response.getValue();
            return SdkResponses.copyResponse(reportETag(copied.getETag()),
                    copied.getLastModified() == null ? null :
                            copied.getLastModified().toInstant())
                    .toBuilder()
                    .serverSideEncryption(
                            reportedSse(copied.isServerEncrypted()))
                    .build();
        } catch (BlobStorageException bse) {
            if (bse.getStatusCode() != 501) {
                throw translate(bse, fromContainer, fromName);
            }
            // Azurite does not implement Put Blob From URL (501
            // APINotImplemented); fall back to the classic asynchronous
            // Copy Blob API, which it does implement.  Request metadata
            // replaces the source metadata as with S3's REPLACE directive,
            // but content headers can only be set after the copy.
            try {
                var copyOptions = new BlobBeginCopyOptions(url + "?" + token)
                        .setPollInterval(Duration.ofMillis(10));
                if (replace) {
                    copyOptions.setMetadata(request.metadata());
                }
                if (haveSourceConditions) {
                    var copySourceConditions =
                            new BlobBeginCopySourceRequestConditions();
                    if (ifMatch != null) {
                        copySourceConditions.setIfMatch(ifMatch);
                    }
                    if (ifNoneMatch != null) {
                        copySourceConditions.setIfNoneMatch(ifNoneMatch);
                    }
                    if (ifModifiedSince != null) {
                        copySourceConditions.setIfModifiedSince(
                                ifModifiedSince.atOffset(ZoneOffset.UTC));
                    }
                    if (ifUnmodifiedSince != null) {
                        copySourceConditions.setIfUnmodifiedSince(
                                ifUnmodifiedSince.atOffset(ZoneOffset.UTC));
                    }
                    copyOptions.setSourceRequestConditions(
                            copySourceConditions);
                }
                client.beginCopy(copyOptions).waitForCompletion();
                if (replace) {
                    client.setHttpHeaders(headers);
                }
                var properties = client.getProperties();
                return SdkResponses.copyResponse(
                        reportETag(properties.getETag()),
                        properties.getLastModified() == null ? null :
                                properties.getLastModified().toInstant())
                        .toBuilder()
                        .serverSideEncryption(
                                reportedSse(properties.isServerEncrypted()))
                        .build();
            } catch (BlobStorageException bse2) {
                throw translate(bse2, fromContainer, fromName);
            }
        }
    }

    @Override
    public DeleteObjectResponse removeBlob(DeleteObjectRequest request) {
        // The literal "null" names the null version, which on an
        // unversioned namespace is the object itself.
        if (request.versionId() != null &&
                !request.versionId().equals("null")) {
            throw new UnsupportedOperationException(
                    "versioning not supported");
        }
        if (request.ifMatchSize() != null ||
                request.ifMatchLastModifiedTime() != null) {
            // Azure conditions a delete on the blob's ETag or on a time
            // range, neither of which expresses S3's size or its equality
            // on the exact time.
            throw new UnsupportedOperationException(
                    "conditional delete not supported");
        }
        String ifMatch = backendCondition(request.ifMatch());
        var client = blobServiceClient.getBlobContainerClient(request.bucket())
                .getBlobClient(request.key());
        try {
            if (ifMatch == null) {
                client.delete();
            } else {
                // The service judges the condition as it removes the blob,
                // where the emulated form the other stores get compares
                // against a read that anyone could have overtaken.
                client.deleteWithResponse(
                        /*deleteBlobSnapshotOptions=*/ null,
                        new BlobRequestConditions().setIfMatch(ifMatch),
                        /*timeout=*/ null, Context.NONE);
            }
        } catch (BlobStorageException bse) {
            if (isAbsent(bse)) {
                return DeleteObjectResponse.builder().build();
            }
            if (BlobErrorCode.CONDITION_NOT_MET.equals(bse.getErrorCode())) {
                if (!Boolean.TRUE.equals(client.exists())) {
                    // Azure judges an ETag against a blob that is not there
                    // and fails it, where a delete stays idempotent
                    // everywhere else in S3Proxy: an object already gone
                    // satisfies any condition, so a caller may retry one.
                    // Only this failing path pays for the second look.
                    return DeleteObjectResponse.builder().build();
                }
                // Named rather than left a bare 412: a batch delete reports
                // this one key at a time, where the frontend writes the
                // code the store gives it into that key's Error element.
                throw S3Exceptions.preconditionFailed(bse);
            }
            throw translate(bse, request.bucket(), request.key());
        }
        return DeleteObjectResponse.builder().build();
    }

    /**
     * Deletes the objects a batch at a time, which Azure answers in one
     * request each -- where the interface default would spend a request per
     * object.
     *
     * <p>A batch that any object refused is asked again one object at a
     * time: the batch reports a bare status per subrequest, while the single
     * delete raises the typed failure the frontend turns into that object's
     * error code.  Refusals are rare, so the second pass is too.
     */
    @Override
    public DeleteObjectsResponse removeBlobs(DeleteObjectsRequest request) {
        var objects = request.delete() == null ? List.<ObjectIdentifier>of() :
                request.delete().objects();
        if (objects.isEmpty()) {
            return DeleteObjectsResponse.builder().build();
        }
        var containerClient =
                blobServiceClient.getBlobContainerClient(request.bucket());
        var deleted = new ImmutableList.Builder<DeletedObject>();
        var errors = new ImmutableList.Builder<S3Error>();

        for (List<ObjectIdentifier> chunk :
                Lists.partition(objects, MAX_BATCH_DELETES)) {
            var batch = blobBatchClient.getBlobBatch();
            var responses = new ArrayList<Response<Void>>(chunk.size());
            for (ObjectIdentifier object : chunk) {
                // Name the blob by its full URL rather than by container and
                // name: that overload builds the subrequest path as though
                // the account were in the hostname, which drops the account
                // segment of a path-style endpoint like Azurite's.
                responses.add(batch.deleteBlob(containerClient
                        .getBlobClient(object.key()).getBlobUrl()));
            }

            boolean refused = false;
            try {
                blobBatchClient.submitBatchWithResponse(batch,
                        /*throwOnAnyFailure=*/ false, /*timeout=*/ null,
                        Context.NONE);
                for (Response<Void> response : responses) {
                    int status = response.getStatusCode();
                    // An object already gone satisfies an idempotent delete.
                    if (status / 100 != 2 && status != STATUS_NOT_FOUND) {
                        refused = true;
                        break;
                    }
                }
            } catch (BlobStorageException bse) {
                // The batch as a whole was refused, so no object was deleted.
                refused = true;
            }

            if (refused) {
                var oneByOne = BlobStore.super.removeBlobs(request.toBuilder()
                        .delete(Delete.builder().objects(chunk).build())
                        .build());
                deleted.addAll(oneByOne.deleted());
                errors.addAll(oneByOne.errors());
                continue;
            }
            for (ObjectIdentifier object : chunk) {
                deleted.add(DeletedObject.builder()
                        .key(object.key())
                        .build());
            }
        }

        return DeleteObjectsResponse.builder()
                .deleted(deleted.build())
                .errors(errors.build())
                .build();
    }

    /** Whether the failure only says the blob was not there to delete. */
    private static boolean isAbsent(BlobStorageException bse) {
        BlobErrorCode code = bse.getErrorCode();
        return BlobErrorCode.BLOB_NOT_FOUND.equals(code) ||
                BlobErrorCode.CONTAINER_NOT_FOUND.equals(code);
    }

    @Override
    public HeadObjectResponse blobMetadata(HeadObjectRequest request) {
        if (request.versionId() != null) {
            throw new UnsupportedOperationException(
                    "versioning not supported");
        }
        String container = request.bucket();
        var client = blobServiceClient.getBlobContainerClient(container)
                .getBlobClient(request.key());
        BlobProperties properties;
        try {
            properties = client.getProperties();
        } catch (BlobStorageException bse) {
            throw translate(bse, container, request.key());
        }
        @SuppressWarnings("deprecation")
        HeadObjectResponse head = HeadObjectResponse.builder()
                .metadata(properties.getMetadata())
                .serverSideEncryption(
                        reportedSse(properties.isServerEncrypted()))
                .eTag(reportETag(properties.getETag()))
                .lastModified(properties.getLastModified() == null ? null :
                        properties.getLastModified().toInstant())
                .storageClass(fromAccessTier(
                        properties.getAccessTier()).toString())
                .cacheControl(properties.getCacheControl())
                .contentDisposition(properties.getContentDisposition())
                .contentEncoding(properties.getContentEncoding())
                .contentLanguage(properties.getContentLanguage())
                .contentLength(properties.getBlobSize())
                .contentType(properties.getContentType())
                .expires(properties.getExpiresOn() == null ? null :
                        properties.getExpiresOn().toInstant())
                .build();
        return head;
    }

    @Override
    public BucketCannedACL getContainerAccess(String container) {
        var client = blobServiceClient.getBlobContainerClient(container);
        try {
            var blobAccessType = client.getAccessPolicy().getBlobAccessType();
            return blobAccessType != null && blobAccessType.equals(
                    PublicAccessType.CONTAINER) ?
                    BucketCannedACL.PUBLIC_READ :
                    BucketCannedACL.PRIVATE;
        } catch (BlobStorageException bse) {
            throw translate(bse, container, /*key=*/ null);
        }
    }

    @Override
    public void setContainerAccess(String container, BucketCannedACL access) {
        if (access == BucketCannedACL.PUBLIC_READ_WRITE) {
            // Azure public access is read-only by definition; refuse rather
            // than silently granting less than the caller asked for.
            throw new UnsupportedOperationException(
                    "anonymous write access unsupported in Azure");
        }
        var client = blobServiceClient.getBlobContainerClient(container);
        var publicAccess = access == BucketCannedACL.PUBLIC_READ ?
                PublicAccessType.CONTAINER : null;
        client.setAccessPolicy(publicAccess, List.of());
    }

    @Override
    public ObjectCannedACL getBlobAccess(String container, String key) {
        return ObjectCannedACL.PRIVATE;
    }

    @Override
    public void setBlobAccess(String container, String key, ObjectCannedACL access) {
        throw new UnsupportedOperationException("unsupported in Azure");
    }

    @Override
    public MultipartUpload initiateMultipartUpload(
            CreateMultipartUploadRequest request) {
        refuseUnsupportedSse(request.serverSideEncryptionAsString(),
                request.ssekmsKeyId(), request.sseCustomerAlgorithm(),
                request.sseCustomerKey(), request.sseCustomerKeyMD5());
        String container = request.bucket();
        var containerClient = blobServiceClient.getBlobContainerClient(container);
        try {
            if (!containerClient.exists()) {
                throw S3Exceptions.noSuchBucket(container, "");
            }
        } catch (BlobStorageException bse) {
            throw translate(bse, container, /*key=*/ null);
        }

        var userMetadata = request.metadata();
        for (var key : userMetadata.keySet()) {
            if (!isValidMetadataKey(key)) {
                throw new IllegalArgumentException(
                        "Invalid metadata key: " + key);
            }
        }

        String uploadKey = STUB_BLOB_PREFIX + UUID.randomUUID().toString();
        String targetBlobName = request.key();
        var stubBlobClient = containerClient.getBlobClient(uploadKey).getBlockBlobClient();

        BlobHttpHeaders headers = new BlobHttpHeaders();
        headers.setContentType(request.contentType());
        headers.setContentDisposition(request.contentDisposition());
        headers.setContentEncoding(request.contentEncoding());
        headers.setContentLanguage(request.contentLanguage());
        headers.setCacheControl(request.cacheControl());

        var uploadOptions = new BlockBlobSimpleUploadOptions(
                new ByteArrayInputStream(new byte[0]), 0);
        uploadOptions.setHeaders(headers);
        // Metadata names are case insensitive, so drop any spelling a caller
        // sent of our own before adding it -- two entries differing only in
        // case would collide, and ours must be the one that survives.
        var stubMetadata = new java.util.LinkedHashMap<String, String>();
        stubMetadata.putAll(userMetadata);
        stubMetadata.keySet().removeIf(
                key -> key.equalsIgnoreCase(TARGET_BLOB_NAME_METADATA));
        stubMetadata.put(TARGET_BLOB_NAME_METADATA,
                encodeTargetBlobName(targetBlobName));
        uploadOptions.setMetadata(stubMetadata);
        if (request.storageClass() != null && request.storageClass() != StorageClass.STANDARD) {
            uploadOptions.setTier(toAccessTier(request.storageClass()));
        }

        // The destination rides along with the stub rather than following in a
        // setTags call, so a failure cannot leave a stub whose destination is
        // unknown -- one that listMultipartUploads skips and no abort reaches.
        stubBlobClient.uploadWithResponse(uploadOptions, null, null);

        return new MultipartUpload(uploadKey, request);
    }

    /**
     * A metadata value is signed into an x-ms-meta-* request header, which
     * carries ASCII only: a raw UTF-8 key fails Azure's shared key
     * authentication outright.  base64url keeps any key storable.
     */
    private static String encodeTargetBlobName(String targetBlobName) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(
                targetBlobName.getBytes(StandardCharsets.UTF_8));
    }

    /** Null when the blob is not one of our stubs. */
    @Nullable
    private static String decodeTargetBlobName(
            @Nullable Map<String, String> metadata) {
        if (metadata == null) {
            return null;
        }
        String encoded = metadata.get(TARGET_BLOB_NAME_METADATA);
        if (encoded == null) {
            return null;
        }
        return new String(Base64.getUrlDecoder().decode(encoded),
                StandardCharsets.UTF_8);
    }

    /**
     * The stub carries the caller's metadata alongside our own entry, and
     * completeMultipartUpload copies that map onto the finished blob.  Drop the
     * internal entry so it does not surface as caller metadata.
     */
    private static Map<String, String> withoutTargetBlobName(
            @Nullable Map<String, String> metadata) {
        if (metadata == null) {
            return Map.of();
        }
        var result = new java.util.LinkedHashMap<String, String>();
        for (var entry : metadata.entrySet()) {
            if (!entry.getKey().equalsIgnoreCase(TARGET_BLOB_NAME_METADATA)) {
                result.put(entry.getKey(), entry.getValue());
            }
        }
        return result;
    }

    /**
     * Validates metadata key according to Azure naming rules.
     * Keys must be valid C# identifiers (alphanumeric and underscores).
     */
    private static boolean isValidMetadataKey(String key) {
        if (key == null || key.isEmpty()) {
            return false;
        }
        // Must start with letter or underscore
        if (!Character.isLetter(key.charAt(0)) && key.charAt(0) != '_') {
            return false;
        }
        // Rest must be alphanumeric or underscore
        for (int i = 1; i < key.length(); i++) {
            char c = key.charAt(i);
            if (!Character.isLetterOrDigit(c) && c != '_') {
                return false;
            }
        }
        return true;
    }

    @Override
    public void abortMultipartUpload(MultipartUpload mpu) {
        // Delete the stub blob to remove the upload from listMultipartUploads
        // Note: Uncommitted blocks are automatically removed by Azure after 7 days
        try {
            blobServiceClient
                    .getBlobContainerClient(mpu.containerName())
                    .getBlobClient(mpu.id())
                    .delete();
        } catch (BlobStorageException bse) {
            if (bse.getStatusCode() == 404) {
                throw S3Exceptions.noSuchKey(mpu.containerName(), mpu.id(),
                        "Multipart upload not found: " + mpu.id());
            }
            throw bse;
        }
    }

    @Override
    public CompleteMultipartUploadResponse completeMultipartUpload(MultipartUpload mpu,
            CompleteMultipartUploadRequest request) {
        refuseUploadCustomerKey(request.sseCustomerAlgorithm(),
                request.sseCustomerKey(), request.sseCustomerKeyMD5());
        List<CompletedPart> parts = request.multipartUpload() == null ?
                List.of() : request.multipartUpload().parts();
        String uploadKey = mpu.id();
        String nonce = uploadKey.substring(STUB_BLOB_PREFIX.length());

        var containerClient = blobServiceClient.getBlobContainerClient(mpu.containerName());
        var stubBlobClient = containerClient.getBlobClient(uploadKey);

        BlobProperties stubProperties;
        try {
            stubProperties = stubBlobClient.getProperties();
        } catch (BlobStorageException bse) {
            if (bse.getErrorCode().equals(BlobErrorCode.BLOB_NOT_FOUND)) {
                throw new IllegalArgumentException(
                        "Upload not found: uploadId=" + uploadKey);
            }
            throw bse;
        }

        var stubMetadata = stubProperties.getMetadata();
        String targetBlobName = decodeTargetBlobName(stubMetadata);
        if (targetBlobName == null) {
            throw new IllegalArgumentException(
                    "Stub blob missing target name: uploadId=" + uploadKey);
        }

        var userMetadata = withoutTargetBlobName(stubMetadata);
        var contentMetadata = toContentMetadata(stubProperties);
        var tier = stubProperties.getAccessTier();

        if (parts == null || parts.isEmpty()) {
            throw new IllegalArgumentException("Parts list cannot be empty");
        }

        int previousPartNumber = 0;
        for (var part : parts) {
            int partNumber = part.partNumber();
            if (partNumber <= previousPartNumber) {
                throw new IllegalArgumentException(
                        "Parts must be in strictly ascending order");
            }
            previousPartNumber = partNumber;
        }

        if (parts.size() > 50_000) {
            throw new IllegalArgumentException(
                    "Too many parts: " + parts.size() + " (max 50,000)");
        }

        var client = containerClient
                .getBlobClient(targetBlobName)
                .getBlockBlobClient();

        var blockList = client.listBlocks(BlockListType.UNCOMMITTED);
        var uncommittedBlocks = blockList.getUncommittedBlocks();

        var blockMap = new java.util.HashMap<String, Long>();
        for (var block : uncommittedBlocks) {
            blockMap.put(block.getName(), block.getSizeLong());
        }

        var blockIds = ImmutableList.<String>builder();

        for (int i = 0; i < parts.size(); i++) {
            var part = parts.get(i);
            int partNumber = part.partNumber();

            String blockId = makeBlockId(nonce, partNumber);
            blockIds.add(blockId);

            if (!blockMap.containsKey(blockId)) {
                throw new IllegalArgumentException(
                        "Part " + partNumber + " not found in staged blocks");
            }
        }

        BlobHttpHeaders blobHttpHeaders = new BlobHttpHeaders();
        blobHttpHeaders.setContentType(contentMetadata.contentType());
        blobHttpHeaders.setContentDisposition(contentMetadata.contentDisposition());
        blobHttpHeaders.setContentEncoding(contentMetadata.contentEncoding());
        blobHttpHeaders.setContentLanguage(contentMetadata.contentLanguage());
        blobHttpHeaders.setCacheControl(contentMetadata.cacheControl());

        var options = new BlockBlobCommitBlockListOptions(
                blockIds.build());
        options.setHeaders(blobHttpHeaders);
        if (userMetadata != null && !userMetadata.isEmpty()) {
            options.setMetadata(userMetadata);
        }
        if (tier != null) {
            options.setTier(tier);
        }

        // Support conditional writes (If-Match/If-None-Match)
        if (request.ifMatch() != null || request.ifNoneMatch() != null) {
            options.setRequestConditions(new BlobRequestConditions()
                    .setIfMatch(backendCondition(request.ifMatch()))
                    .setIfNoneMatch(
                            backendCondition(request.ifNoneMatch())));
        }

        try {
            var response = client.commitBlockListWithResponse(
                    options, /*timeout=*/ null, /*context=*/ null);

            stubBlobClient.delete();

            var committed = response.getValue();
            String finalETag = reportETag(committed.getETag());
            return SdkResponses.completeResponse(finalETag)
                    .toBuilder()
                    .serverSideEncryption(
                            reportedSse(committed.isServerEncrypted()))
                    .build();
        } catch (BlobStorageException bse) {
            var errorCode = bse.getErrorCode();
            if (errorCode.equals(BlobErrorCode.BLOB_NOT_FOUND) ||
                    errorCode.equals(BlobErrorCode.CONTAINER_NOT_FOUND)) {
                throw new IllegalArgumentException(
                        "Upload not found: container=" + mpu.containerName() +
                        ", key=" + targetBlobName);
            } else if (bse.getStatusCode() == 409 &&
                    options.getRequestConditions() != null) {
                // Azure reports an unmet If-None-Match: * as 409
                // BlobAlreadyExists rather than 412, but to the caller who
                // asked for the condition it is a failed precondition.
                throw translate(bse, mpu.containerName(), targetBlobName);
            } else if (bse.getStatusCode() == 409) {
                throw new IllegalArgumentException(
                        "Conflict during commit: " + bse.getMessage(), bse);
            } else if (bse.getStatusCode() == 412) {
                throw translateWrite(bse, mpu.containerName(), targetBlobName,
                        request.ifMatch());
            }
            throw bse;
        }
    }

    @Override
    public UploadPartResponse uploadMultipartPart(MultipartUpload mpu,
            UploadPartRequest request, InputStream is) {
        refuseUploadCustomerKey(request.sseCustomerAlgorithm(),
                request.sseCustomerKey(), request.sseCustomerKeyMD5());
        int partNumber = request.partNumber();
        long contentLength = request.contentLength();
        var contentMD5 = SdkRequests.contentMD5(request);

        if (partNumber < 1 || partNumber > 10_000) {
            throw new IllegalArgumentException(
                    "Part number must be between 1 and 10,000, got: " + partNumber);
        }

        if (contentLength > MAXIMUM_MULTIPART_PART_SIZE) {
            throw new IllegalArgumentException(
                    "Part size exceeds maximum of " +
                    MAXIMUM_MULTIPART_PART_SIZE + " bytes: " + contentLength);
        }

        String uploadKey = mpu.id();
        String nonce = uploadKey.substring(STUB_BLOB_PREFIX.length());
        String blockId = makeBlockId(nonce, partNumber);
        var asyncClient = createNonRetryingBlockBlobAsyncClient(
                mpu.containerName(), mpu.blobName());

        byte[] md5Hash;
        var digest = MD5.newDigest();
        try (var dis = new DigestInputStream(is, digest)) {
            Flux<ByteBuffer> body = chunkedByteBufferFlux(dis, contentLength);

            asyncClient.stageBlock(blockId, body, contentLength).block();

            md5Hash = digest.digest();

            if (contentMD5 != null) {
                if (!MessageDigest.isEqual(md5Hash, contentMD5.asBytes())) {
                    throw new IllegalArgumentException("Content-MD5 mismatch");
                }
            }

        } catch (BlobStorageException bse) {
            throw translate(bse, mpu.containerName(), mpu.blobName());
        } catch (IOException ioe) {
            throw new RuntimeException(
                    "Failed to upload part %d for blob '%s' in container '%s': %s".formatted(
                    partNumber, mpu.blobName(), mpu.containerName(), ioe.getMessage()), ioe);
        }

        String eTag = HexFormat.of().formatHex(md5Hash);
        return SdkResponses.uploadedPart(eTag);
    }

    @Override
    public boolean supportsCopyMultipartPart() {
        return true;
    }

    @Override
    public UploadPartCopyResponse copyMultipartPart(MultipartUpload mpu,
            UploadPartCopyRequest request) {
        refuseUploadCustomerKey(request.sseCustomerAlgorithm(),
                request.sseCustomerKey(), request.sseCustomerKeyMD5());
        // The source never rests under a customer key on this store, so a
        // copy-source triple is judged against none, as S3 does.
        CustomerKeys.enforce(/*storedKeyMD5=*/ null,
                request.copySourceSSECustomerAlgorithm(),
                request.copySourceSSECustomerKey(),
                request.copySourceSSECustomerKeyMD5());
        if (request.sourceVersionId() != null) {
            throw new UnsupportedOperationException(
                    "versioning not supported");
        }
        int partNumber = request.partNumber();
        if (partNumber < 1 || partNumber > 10_000) {
            throw new IllegalArgumentException(
                    "Part number must be between 1 and 10,000, got: " +
                    partNumber);
        }
        String ifMatch = request.copySourceIfMatch();
        String ifNoneMatch = request.copySourceIfNoneMatch();
        Instant ifModifiedSince = request.copySourceIfModifiedSince();
        Instant ifUnmodifiedSince = request.copySourceIfUnmodifiedSince();

        String uploadKey = mpu.id();
        String nonce = uploadKey.substring(STUB_BLOB_PREFIX.length());
        String blockId = makeBlockId(nonce, partNumber);

        // The service fetches the source itself, authorized by a read SAS
        // as in copyBlob.
        var expiryTime = OffsetDateTime.now().plusDays(1);
        var permission = new BlobSasPermission().setReadPermission(true);
        var values = new BlobServiceSasSignatureValues(expiryTime, permission)
                .setStartTime(OffsetDateTime.now());
        var fromClient = blobServiceClient
                .getBlobContainerClient(request.sourceBucket())
                .getBlobClient(request.sourceKey());
        String token;
        var cred = creds.get();
        if (!cred.identity().isEmpty() && !cred.credential().isEmpty()) {
            token = fromClient.generateSas(values);
        } else {
            var userDelegationKey = blobServiceClient.getUserDelegationKey(
                    OffsetDateTime.now().minusMinutes(5), expiryTime);
            token = fromClient.generateUserDelegationSas(values,
                    userDelegationKey);
        }

        var options = new BlockBlobStageBlockFromUrlOptions(blockId,
                fromClient.getBlobUrl() + "?" + token)
                .setSourceRange(parseCopySourceRange(
                        request.copySourceRange()));
        if (ifMatch != null || ifNoneMatch != null ||
                ifModifiedSince != null || ifUnmodifiedSince != null) {
            var conditions = new BlobRequestConditions()
                    .setIfMatch(backendCondition(ifMatch))
                    .setIfNoneMatch(backendCondition(ifNoneMatch));
            if (ifModifiedSince != null) {
                conditions.setIfModifiedSince(OffsetDateTime.ofInstant(
                        ifModifiedSince, ZoneOffset.UTC));
            }
            if (ifUnmodifiedSince != null) {
                conditions.setIfUnmodifiedSince(OffsetDateTime.ofInstant(
                        ifUnmodifiedSince, ZoneOffset.UTC));
            }
            options.setSourceRequestConditions(conditions);
        }

        var client = blobServiceClient
                .getBlobContainerClient(mpu.containerName())
                .getBlobClient(mpu.blobName())
                .getBlockBlobClient();
        String eTag;
        try {
            var response = client.stageBlockFromUrlWithResponse(options,
                    /*timeout=*/ null, Context.NONE);
            // Put Block From URL echoes the MD5 of the copied range; match
            // uploadMultipartPart's hex part ETag when present and fall
            // back to the block id, which completeMultipartUpload does not
            // check against part ETags.
            String md5 = response.getHeaders().getValue(
                    HttpHeaderName.CONTENT_MD5);
            eTag = md5 == null ? blockId : HexFormat.of().formatHex(
                    Base64.getDecoder().decode(md5));
        } catch (BlobStorageException bse) {
            throw translate(bse, request.sourceBucket(), request.sourceKey());
        }
        return SdkResponses.copiedPart(eTag, /*lastModified=*/ null,
                /*copySourceVersionId=*/ null);
    }

    /** Parses the strict bytes=first-last form S3 CopyPart requires. */
    @Nullable
    private static BlobRange parseCopySourceRange(@Nullable String range) {
        if (range == null) {
            return null;
        }
        if (range.startsWith("bytes=") && range.indexOf(',') == -1) {
            String[] parts = range.substring("bytes=".length()).split("-", 2);
            if (parts.length == 2 && !parts[0].isEmpty() &&
                    !parts[1].isEmpty()) {
                try {
                    long first = Long.parseLong(parts[0]);
                    long last = Long.parseLong(parts[1]);
                    if (last >= first) {
                        return new BlobRange(first, last - first + 1);
                    }
                } catch (NumberFormatException nfe) {
                    // fall through to the error below
                }
            }
        }
        throw new IllegalArgumentException(
                "The x-amz-copy-source-range value must be of the form " +
                "bytes=first-last");
    }

    /**
     * Returns a BlockBlobAsyncClient with retries disabled for streaming uploads.
     * This allows us to stream directly from non-markable InputStreams without
     * needing temp files or buffering. The S3 client can retry the entire part
     * upload if needed.
     *
     * Reuses the shared async service client so its credential and token cache
     * are shared across part uploads instead of being rebuilt per part.
     */
    private BlockBlobAsyncClient createNonRetryingBlockBlobAsyncClient(
            String container, String blobName) {
        return blobServiceAsyncClient
                .getBlobContainerAsyncClient(container)
                .getBlobAsyncClient(blobName)
                .getBlockBlobAsyncClient();
    }

    @Override
    public List<Part> listMultipartUpload(MultipartUpload mpu) {
        String uploadKey = mpu.id();
        if (!uploadKey.startsWith(STUB_BLOB_PREFIX)) {
            throw S3Exceptions.noSuchKey(mpu.containerName(), uploadKey,
                    "Multipart upload not found: " + uploadKey);
        }

        String nonce = uploadKey.substring(STUB_BLOB_PREFIX.length());

        var containerClient = blobServiceClient.getBlobContainerClient(mpu.containerName());
        var stubBlobClient = containerClient.getBlobClient(uploadKey);

        String targetBlobName;
        try {
            targetBlobName = decodeTargetBlobName(
                    stubBlobClient.getProperties().getMetadata());
        } catch (BlobStorageException bse) {
            if (bse.getErrorCode().equals(BlobErrorCode.BLOB_NOT_FOUND)) {
                throw S3Exceptions.noSuchKey(mpu.containerName(), uploadKey,
                        "Multipart upload not found: " + uploadKey);
            }
            throw bse;
        }
        if (targetBlobName == null) {
            throw S3Exceptions.noSuchKey(mpu.containerName(), uploadKey,
                    "Multipart upload not found: " + uploadKey);
        }

        var client = containerClient
                .getBlobClient(targetBlobName)
                .getBlockBlobClient();

        BlockList blockList;
        try {
            blockList = client.listBlocks(BlockListType.ALL);
        } catch (BlobStorageException bse) {
            if (bse.getStatusCode() == 404) {
                return List.of();
            }
            throw bse;
        }

        var parts = ImmutableList.<Part>builder();

        String noncePrefix = nonce + ":";

        for (var properties : blockList.getUncommittedBlocks()) {
            String encodedBlockId = properties.getName();
            String blockId;
            try {
                blockId = new String(Base64.getDecoder().decode(encodedBlockId),
                        StandardCharsets.UTF_8);
            } catch (IllegalArgumentException e) {
                continue;
            }

            if (!blockId.startsWith(noncePrefix)) {
                continue;
            }

            int partNumber;
            try {
                String partNumberStr = blockId.substring(noncePrefix.length());
                partNumber = Integer.parseInt(partNumberStr);
            } catch (NumberFormatException e) {
                continue;
            }

            String eTag = "";  // listBlocks does not return ETag
            Instant lastModified = null; // listBlocks does not return LastModified
            parts.add(SdkResponses.part(partNumber,
                    properties.getSizeLong(),
                    eTag, lastModified));
        }
        // the block ids carry the part number zero-padded, but they are
        // listed under their base64 spelling, whose alphabet does not sort
        // in the order of the bytes it stands for
        return ImmutableList.sortedCopyOf(
                Comparator.comparingInt(Part::partNumber), parts.build());
    }

    @Override
    public List<software.amazon.awssdk.services.s3.model.MultipartUpload>
            listMultipartUploads(String container) {
        var containerClient = blobServiceClient.getBlobContainerClient(container);

        var builder = ImmutableList.<software.amazon.awssdk.services.s3
                .model.MultipartUpload>builder();

        var options = new ListBlobsOptions();
        options.setPrefix(STUB_BLOB_PREFIX);
        var details = new BlobListDetails();
        details.setRetrieveMetadata(true);
        options.setDetails(details);

        for (var blobItem : containerClient.listBlobs(options, null, null)) {
            // e.g., ".s3proxy/stubs/<uuid>"
            String uploadKey = blobItem.getName();

            String targetBlobName = decodeTargetBlobName(
                    blobItem.getMetadata());
            if (targetBlobName == null) {
                continue;
            }

            // The stub is written when the upload is created; prefer the
            // time it was created over the time it was last written, which
            // are the same until something rewrites it.
            var properties = blobItem.getProperties();
            var initiated = properties.getCreationTime() != null ?
                    properties.getCreationTime() : properties.getLastModified();
            builder.add(SdkResponses.upload(targetBlobName, uploadKey,
                    initiated == null ? null : initiated.toInstant()));
        }

        return builder.build();
    }

    @Override
    public long getMinimumMultipartPartSize() {
        return 1;
    }

    @Nullable
    private static OffsetDateTime toOffsetDateTime(
            @Nullable Instant instant) {
        if (instant == null) {
            return null;
        }
        return instant.atOffset(ZoneOffset.UTC);
    }

    private static AccessTier toAccessTier(StorageClass storageClass) {
        return switch (storageClass) {
        case GLACIER, DEEP_ARCHIVE -> AccessTier.ARCHIVE;
        case STANDARD_IA, ONEZONE_IA -> AccessTier.COOL;
        case GLACIER_IR -> AccessTier.COLD;
        default -> AccessTier.HOT;
        };
    }

    private static StorageClass fromAccessTier(AccessTier tier) {
        if (tier == null) {
            return StorageClass.STANDARD;
        } else if (tier.equals(AccessTier.ARCHIVE)) {
            return StorageClass.DEEP_ARCHIVE;
        } else if (tier.equals(AccessTier.COLD)) {
            return StorageClass.GLACIER_IR;
        } else if (tier.equals(AccessTier.COOL)) {
            return StorageClass.STANDARD_IA;
        } else {
            return StorageClass.STANDARD;
        }
    }

    private static ContentMetadata toContentMetadata(
            BlobProperties properties) {
        var expires = properties.getExpiresOn();
        return ContentMetadata.builder()
                .cacheControl(properties.getCacheControl())
                .contentDisposition(properties.getContentDisposition())
                .contentEncoding(properties.getContentEncoding())
                .contentLanguage(properties.getContentLanguage())
                .contentLength(properties.getBlobSize())
                .contentType(properties.getContentType())
                .expires(expires != null ? expires.toInstant() : null)
                .build();
    }

    /**
     * Creates a deterministic Base64-encoded block ID using the upload nonce
     * and padded part number.
     *
     * "Block IDs are strings of equal length within a blob. Block client code usually uses base-64 encoding to normalize strings into equal lengths."
     * Source: https://learn.microsoft.com/en-us/rest/api/storageservices/understanding-block-blobs--append-blobs--and-page-blobs
     *
     * Format: nonce + ":" + 5-digit padded part number (e.g., "nonce:00001")
     *
     * @param nonce The upload session nonce from the uploadId context
     * @param partNumber The part number (1-10,000)
     * @return Base64-encoded block ID
     */
    private static String makeBlockId(String nonce, int partNumber) {
        String rawId = "%s:%05d".formatted(nonce, partNumber);
        return Base64.getEncoder().encodeToString(
                rawId.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Translate BlobStorageException to an S3-shaped SDK exception,
     * returning the original BlobStorageException unchanged if no
     * translation applies.
     */
    static RuntimeException translate(BlobStorageException bse,
            String container, @Nullable String key) {
        var code = bse.getErrorCode();
        if (code == null) {
            // e.g. errors without an x-ms-error-code response header
            return bse;
        }
        if (code.equals(BlobErrorCode.BLOB_NOT_FOUND)) {
            return S3Exceptions.noSuchKey(container, key, "", bse);
        } else if (code.equals(BlobErrorCode.CONTAINER_NOT_FOUND)) {
            return S3Exceptions.noSuchBucket(container, "", bse);
        } else if (code.equals(BlobErrorCode.CONDITION_NOT_MET) ||
                code.equals(BlobErrorCode.SOURCE_CONDITION_NOT_MET) ||
                code.equals(BlobErrorCode.TARGET_CONDITION_NOT_MET)) {
            return S3Exceptions.fromStatusCode(412, bse);
        } else if (code.equals(BlobErrorCode.BLOB_ALREADY_EXISTS)) {
            return S3Exceptions.fromStatusCode(412, bse);
        } else if (code.equals(BlobErrorCode.INVALID_OPERATION)) {
            return S3Exceptions.fromStatusCode(400, bse);
        } else if (code.equals(BlobErrorCode.MD5MISMATCH) ||
                code.equals(BlobErrorCode.INVALID_MD5)) {
            // The Content-MD5 the caller sent named a body other than the one
            // that arrived, or was not an MD5 at all.  Both are the caller's
            // mistake and S3 answers 400; passing the Azure exception on
            // would report the caller's own bad digest as a server error.
            return S3Exceptions.fromStatusCode(400, bse);
        } else if (bse.getErrorCode().equals(BlobErrorCode.INVALID_RESOURCE_NAME)) {
            return new IllegalArgumentException(
                    "Invalid container name", bse);
        } else if (code.equals(
                BlobErrorCode.BLOB_USES_CUSTOMER_SPECIFIED_ENCRYPTION)) {
            // A blob written out of band with an Azure customer-provided key
            // answers a keyless read 409; S3 answers 400 InvalidRequest,
            // which is what clients key their retry-with-key logic off.
            return S3Exceptions.invalidRequest("The object was stored using" +
                    " a form of Server Side Encryption.  The correct" +
                    " parameters must be provided to retrieve the object.");
        } else if (bse.getStatusCode() == 403 || bse.getStatusCode() == 401) {
            // Surface a permission failure as 403 AccessDenied rather than a
            // generic 500.
            return S3Exceptions.fromStatusCode(403, bse);
        }
        return bse;
    }
}
