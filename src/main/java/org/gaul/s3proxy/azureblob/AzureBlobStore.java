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
import java.security.MessageDigest;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

import com.azure.core.credential.AzureNamedKeyCredential;
import com.azure.core.http.HttpHeaderName;
import com.azure.core.http.rest.PagedResponse;
import com.azure.core.util.Context;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.storage.blob.BlobServiceAsyncClient;
import com.azure.storage.blob.BlobServiceClient;
import com.azure.storage.blob.BlobServiceClientBuilder;
import com.azure.storage.blob.BlobServiceVersion;
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
import com.google.common.base.Supplier;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.hash.HashCode;
import com.google.common.hash.HashFunction;
import com.google.common.hash.Hashing;
import com.google.common.hash.HashingInputStream;
import com.google.common.io.BaseEncoding;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.ContainerNotFoundException;
import org.gaul.s3proxy.blobstore.ContentMetadata;
import org.gaul.s3proxy.blobstore.Credentials;
import org.gaul.s3proxy.blobstore.HttpResponse;
import org.gaul.s3proxy.blobstore.HttpResponseException;
import org.gaul.s3proxy.blobstore.KeyNotFoundException;
import org.gaul.s3proxy.blobstore.domain.Blob;
import org.gaul.s3proxy.blobstore.domain.BlobAccess;
import org.gaul.s3proxy.blobstore.domain.BlobMetadata;
import org.gaul.s3proxy.blobstore.domain.ContainerAccess;
import org.gaul.s3proxy.blobstore.domain.ContainerMetadata;
import org.gaul.s3proxy.blobstore.domain.MultipartPart;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.gaul.s3proxy.blobstore.domain.PageSet;
import org.gaul.s3proxy.blobstore.domain.StorageClass;
import org.gaul.s3proxy.blobstore.domain.StorageMetadata;
import org.gaul.s3proxy.blobstore.domain.StorageType;
import org.gaul.s3proxy.blobstore.options.CopyOptions;
import org.gaul.s3proxy.blobstore.options.CreateContainerOptions;
import org.gaul.s3proxy.blobstore.options.GetOptions;
import org.gaul.s3proxy.blobstore.options.ListContainerOptions;
import org.gaul.s3proxy.blobstore.options.PutOptions;
import org.jspecify.annotations.Nullable;

import reactor.core.publisher.Flux;
import reactor.core.scheduler.Schedulers;

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
    // S3 requires MD5 for ETag and Content-MD5 interoperability.
    @SuppressWarnings("deprecation")
    private static final HashFunction MD5 = Hashing.md5();
    // Disable retries since client should retry on errors.
    private static final RequestRetryOptions NO_RETRY_OPTIONS = new RequestRetryOptions(
            RetryPolicyType.FIXED, /*maxTries=*/ 1,
            /*tryTimeoutInSeconds=*/ (Integer) null,
            /*retryDelayInMs=*/ null, /*maxRetryDelayInMs=*/ null,
            /*secondaryHost=*/ null);

    private final BlobServiceClient blobServiceClient;
    private final BlobServiceAsyncClient blobServiceAsyncClient;
    private final String endpoint;
    private final Supplier<Credentials> creds;
    /**
     * Report the ETag Azure mints under {@link #OPAQUE_ETAG_SUFFIX} rather
     * than bare.  S3 SDKs decode a dashless ETag as hex and abort the request
     * when they cannot, which Azure's is not.
     */
    private final boolean opaqueETags;
    // Azurite responds 501 to Put Block From URL; discovered on first use
    // so the caller can fall back to streamed emulation.
    private volatile boolean nativePartCopyUnsupported;

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
                // TODO: remove after
                // https://github.com/Azure/Azurite/issues/2623 is addressed
                .serviceVersion(BlobServiceVersion.V2025_11_05)
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
    public PageSet<? extends StorageMetadata> list() {
        var set = ImmutableSet.<StorageMetadata>builder();
        for (var container : blobServiceClient.listBlobContainers()) {
            // Azure containers have no creation time.
            set.add(new ContainerMetadata(container.getName(),
                    /*creationDate=*/ null));
        }
        return new PageSet<StorageMetadata>(set.build(), null);
    }

    @Override
    public PageSet<? extends StorageMetadata> list(String container,
            ListContainerOptions options) {
        var client = blobServiceClient.getBlobContainerClient(container);
        var azureOptions = new ListBlobsOptions();
        azureOptions.setPrefix(options.prefix());
        azureOptions.setMaxResultsPerPage(options.maxResults());
        // Pass the continuation token through verbatim: it is the opaque
        // marker Azure returned, round-tripped by the frontend.  Decoding it
        // corrupts tokens containing '+' (turned into a space) or '%'.
        var marker = options.marker();

        var set = ImmutableSet.<StorageMetadata>builder();
        PagedResponse<BlobItem> page;
        try {
            var pages = client.listBlobsByHierarchy(
                    options.delimiter(), azureOptions, /*timeout=*/ null);
            page = firstPageWithEntries(
                    m -> pages.iterableByPage(m).iterator().next(), marker);
        } catch (BlobStorageException bse) {
            throw translate(bse, container, /*key=*/ null);
        }
        for (var blob : page.getValue()) {
            var properties = blob.getProperties();
            if (blob.isPrefix()) {
                set.add(new BlobMetadata(StorageType.RELATIVE_PATH,
                        blob.getName(), Map.of(), /*eTag=*/ null,
                        /*lastModified=*/ null,
                        StorageClass.STANDARD,
                        /*container=*/ null,
                        ContentMetadata.builder().build()));
            } else {
                set.add(new BlobMetadata(StorageType.BLOB, blob.getName(),
                        Map.of(), reportETag(properties.getETag()),
                        toDate(properties.getLastModified()),
                        fromAccessTier(properties.getAccessTier()),
                        /*container=*/ null,
                        ContentMetadata.builder()
                                .contentLength(properties.getContentLength())
                                .build()));
            }
        }

        return new PageSet<StorageMetadata>(set.build(),
                page.getContinuationToken());
    }

    /**
     * The first page Azure returns holding anything, or the last one when the
     * container is exhausted.  Azure can answer a listing with no blobs at all
     * and a continuation token, which it expects the caller to follow; passing
     * such a page on leaves an S3 client a truncated result with neither
     * Contents nor CommonPrefixes to take its next marker from, so a client
     * that derives one from the last key it saw -- s3cmd does -- stops there
     * and reports the prefix as empty.  OpenStackSwiftBlobStore.list keeps
     * fetching for the same reason.
     */
    static PagedResponse<BlobItem> firstPageWithEntries(
            Function<@Nullable String, PagedResponse<BlobItem>> fetch,
            @Nullable String marker) {
        while (true) {
            PagedResponse<BlobItem> page = fetch.apply(marker);
            marker = page.getContinuationToken();
            if (!page.getValue().isEmpty() || marker == null) {
                return page;
            }
        }
    }

    @Override
    public boolean containerExists(String container) {
        var client = blobServiceClient.getBlobContainerClient(container);
        return client.exists();
    }

    @Override
    public boolean createContainer(String container,
            CreateContainerOptions options) {
        var azureOptions = new BlobContainerCreateOptions();
        if (options.publicRead()) {
            azureOptions.setPublicAccessType(PublicAccessType.CONTAINER);
        }
        try {
            var response = blobServiceClient
                    .createBlobContainerIfNotExistsWithResponse(
                            container, azureOptions, /*context=*/ null);
            return switch (response.getStatusCode()) {
            case 201 -> true;
            case 409 -> false;
            default -> false;
            };
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
    public boolean deleteContainerIfEmpty(String container) {
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
            if (!page.getValue().isEmpty()) {
                return false;
            }
            blobServiceClient.deleteBlobContainer(container);
            return true;
        } catch (BlobStorageException bse) {
            if (bse.getErrorCode().equals(BlobErrorCode.CONTAINER_NOT_FOUND)) {
                return true;
            }
            throw bse;
        }
    }

    @Override
    public boolean blobExists(String container, String key) {
        var client = blobServiceClient.getBlobContainerClient(container)
                .getBlobClient(key);
        return client.exists();
    }

    @Override
    @Nullable
    public Blob getBlob(String container, String key, GetOptions options) {
        var client = blobServiceClient.getBlobContainerClient(container)
                .getBlobClient(key);
        // Azure rejects the literal If-None-Match: * with 400
        // UnsatisfiableCondition rather than treating it as "matches any
        // existing blob", so emulate the S3 semantics here: an existing blob
        // fails the precondition (412, which the frontend maps to 304 for
        // GET/HEAD) and a missing blob falls through to 404.
        if ("*".equals(options.ifNoneMatch())) {
            try {
                client.getProperties();
            } catch (BlobStorageException bse) {
                throw translate(bse, container, key);
            }
            throw new HttpResponseException(new HttpResponse(412));
        }
        BlobRange azureRange = null;
        if (!options.ranges().isEmpty()) {
            var ranges = options.ranges().get(0).split("-", 2);

            if (ranges[0].isEmpty()) {
                // suffix range (bytes=-N): the last N bytes.  Azure has no
                // native suffix range, so resolve it against the blob size.
                // N greater than the size returns the whole blob, matching S3.
                long tail = Long.parseLong(ranges[1]);
                long blobSize;
                try {
                    blobSize = client.getProperties().getBlobSize();
                } catch (BlobStorageException bse) {
                    throw translate(bse, container, key);
                }
                long count = Math.min(tail, blobSize);
                azureRange = new BlobRange(blobSize - count, count);
            } else if (ranges[1].isEmpty()) {
                // handle to read from an offset till the end
                long offset = Long.parseLong(ranges[0]);
                azureRange = new BlobRange(offset);
            } else {
                // handle to read from an offset
                long offset = Long.parseLong(ranges[0]);
                long end = Long.parseLong(ranges[1]);
                long length = end - offset + 1;
                azureRange = new BlobRange(offset, length);
            }
        }
        var conditions = new BlobRequestConditions()
                .setIfMatch(backendCondition(options.ifMatch()))
                .setIfModifiedSince(toOffsetDateTime(
                        options.ifModifiedSince()))
                .setIfNoneMatch(backendCondition(options.ifNoneMatch()))
                .setIfUnmodifiedSince(toOffsetDateTime(
                        options.ifUnmodifiedSince()));
        BlobInputStream blobStream;
        try {
            blobStream = client.openInputStream(azureRange, conditions);
        } catch (BlobStorageException bse) {
            if (bse.getStatusCode() ==
                    416) {
                throw new HttpResponseException(
                        "illegal range: " + azureRange, new HttpResponse(416));
            }
            if (BlobErrorCode.BLOB_NOT_FOUND.equals(bse.getErrorCode())) {
                return null;
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
        var builder = Blob.builder(key)
                .userMetadata(properties.getMetadata())
                .payload(blobStream)
                .cacheControl(properties.getCacheControl())
                .contentDisposition(properties.getContentDisposition())
                .contentEncoding(properties.getContentEncoding())
                .contentLanguage(properties.getContentLanguage())
                .contentLength(contentLength)
                .contentType(properties.getContentType())
                .expires(expires != null ? toDate(expires) : null)
                .eTag(reportETag(properties.getETag()))
                .lastModified(toDate(properties.getLastModified()));
        if (azureRange != null) {
            builder.contentRange(
                    "bytes " + azureRange.getOffset() +
                    "-" + (azureRange.getOffset() + contentLength - 1) +
                    "/" + properties.getBlobSize());
        }
        // Carry the access tier so GET reports x-amz-storage-class
        // consistently with HEAD (blobMetadata).  Get Blob does not always
        // return the tier that Get Blob Properties does (e.g. the emulator
        // omits it), so fall back to a properties fetch only when it is absent.
        var accessTier = properties.getAccessTier();
        if (accessTier == null) {
            accessTier = client.getProperties().getAccessTier();
        }
        builder.storageClass(fromAccessTier(accessTier));
        return builder.build();
    }

    @Override
    public String putBlob(String container, Blob blob, PutOptions options) {
        var client = blobServiceClient.getBlobContainerClient(container)
                .getBlobClient(blob.getMetadata().name())
                .getBlockBlobClient();
        try (var is = requireNonNull(blob.getPayload())) {
            // TODO: Expires?
            var blobHttpHeaders = new BlobHttpHeaders();
            var contentMetadata = blob.getMetadata().contentMetadata();
            blobHttpHeaders.setCacheControl(contentMetadata.cacheControl());
            blobHttpHeaders.setContentDisposition(
                    contentMetadata.contentDisposition());
            blobHttpHeaders.setContentEncoding(
                    contentMetadata.contentEncoding());
            blobHttpHeaders.setContentLanguage(
                    contentMetadata.contentLanguage());
            var hash = contentMetadata.contentMD5();
            blobHttpHeaders.setContentMd5(hash != null ? hash.asBytes() : null);
            blobHttpHeaders.setContentType(contentMetadata.contentType());

            var metadata = blob.getMetadata().userMetadata();

            AccessTier tier = null;
            if (blob.getMetadata().storageClass() != StorageClass.STANDARD) {
                tier = toAccessTier(blob.getMetadata().storageClass());
            }

            BlobRequestConditions requestConditions = null;
            if (options != null && (options.ifMatch() != null ||
                    options.ifNoneMatch() != null)) {
                requestConditions = new BlobRequestConditions()
                        .setIfMatch(backendCondition(options.ifMatch()))
                        .setIfNoneMatch(
                                backendCondition(options.ifNoneMatch()));
            }

            Long contentLength = contentMetadata.contentLength();
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
                return reportETag(client.uploadWithResponse(uploadOptions,
                        /*timeout=*/ null, /*context=*/ null)
                        .getValue().getETag());
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
            return reportETag(blobServiceClient
                    .getBlobContainerClient(container)
                    .getBlobClient(blob.getMetadata().name())
                    .getProperties()
                    .getETag());
        } catch (BlobStorageException bse) {
            throw translate(bse, container, blob.getMetadata().name());
        } catch (IOException ioe) {
            if (ioe.getCause() instanceof BlobStorageException bse) {
                throw translate(bse, container, /*key=*/ null);
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
    public String copyBlob(String fromContainer, String fromName,
            String toContainer, String toName, CopyOptions options) {
        if (options.blobAccess() == BlobAccess.PUBLIC_READ) {
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
                .getBlobContainerClient(toContainer)
                .getBlobClient(toName)
                .getBlockBlobClient();

        var headers = new BlobHttpHeaders();
        var contentMetadata = options.contentMetadata();
        if (contentMetadata != null) {
            var cacheControl = contentMetadata.cacheControl();
            if (cacheControl != null) {
                headers.setCacheControl(cacheControl);
            }

            var contentDisposition = contentMetadata.contentDisposition();
            if (contentDisposition != null) {
                headers.setContentDisposition(contentDisposition);
            }

            var contentEncoding = contentMetadata.contentEncoding();
            if (contentEncoding != null) {
                headers.setContentEncoding(contentEncoding);
            }

            var contentLanguage = contentMetadata.contentLanguage();
            if (contentLanguage != null) {
                headers.setContentLanguage(contentLanguage);
            }

            var contentType = contentMetadata.contentType();
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
        String ifMatch = backendCondition(options.ifMatch());
        if (ifMatch != null) {
            sourceConditions.setIfMatch(ifMatch);
            haveSourceConditions = true;
        }
        String ifNoneMatch = backendCondition(options.ifNoneMatch());
        if (ifNoneMatch != null) {
            sourceConditions.setIfNoneMatch(ifNoneMatch);
            haveSourceConditions = true;
        }
        Date ifModifiedSince = options.ifModifiedSince();
        if (ifModifiedSince != null) {
            sourceConditions.setIfModifiedSince(
                    ifModifiedSince.toInstant().atOffset(ZoneOffset.UTC));
            haveSourceConditions = true;
        }
        Date ifUnmodifiedSince = options.ifUnmodifiedSince();
        if (ifUnmodifiedSince != null) {
            sourceConditions.setIfUnmodifiedSince(
                    ifUnmodifiedSince.toInstant().atOffset(ZoneOffset.UTC));
            haveSourceConditions = true;
        }
        if (haveSourceConditions) {
            azureOptions.setSourceRequestConditions(sourceConditions);
        }

        try {
            var response = client.uploadFromUrlWithResponse(
                    azureOptions, /*timeout=*/ null, /*context=*/ null);

            // TODO: cannot do this as part of uploadFromUrlWithResponse?
            var userMetadata = options.userMetadata();
            if (userMetadata != null) {
                client.setMetadata(userMetadata);
            }

            return reportETag(response.getValue().getETag());
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
                var userMetadata = options.userMetadata();
                if (userMetadata != null) {
                    copyOptions.setMetadata(userMetadata);
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
                                ifModifiedSince.toInstant()
                                        .atOffset(ZoneOffset.UTC));
                    }
                    if (ifUnmodifiedSince != null) {
                        copySourceConditions.setIfUnmodifiedSince(
                                ifUnmodifiedSince.toInstant()
                                        .atOffset(ZoneOffset.UTC));
                    }
                    copyOptions.setSourceRequestConditions(
                            copySourceConditions);
                }
                client.beginCopy(copyOptions).waitForCompletion();
                if (contentMetadata != null) {
                    client.setHttpHeaders(headers);
                }
                return reportETag(client.getProperties().getETag());
            } catch (BlobStorageException bse2) {
                throw translate(bse2, fromContainer, fromName);
            }
        }
    }

    @Override
    public void removeBlob(String container, String key) {
        var client = blobServiceClient.getBlobContainerClient(container)
                .getBlobClient(key);
        try {
            client.delete();
        } catch (BlobStorageException bse) {
            if (!bse.getErrorCode().equals(BlobErrorCode.BLOB_NOT_FOUND) &&
                    !bse.getErrorCode().equals(BlobErrorCode.CONTAINER_NOT_FOUND)) {
                throw bse;
            }
        }
    }

    @Override
    @Nullable
    public BlobMetadata blobMetadata(String container, String key) {
        var client = blobServiceClient.getBlobContainerClient(container)
                .getBlobClient(key);
        BlobProperties properties;
        try {
            properties = client.getProperties();
        } catch (BlobStorageException bse) {
            if (bse.getErrorCode().equals(BlobErrorCode.BLOB_NOT_FOUND)) {
                return null;
            }
            throw translate(bse, container, /*key=*/ null);
        }
        return new BlobMetadata(StorageType.BLOB, key,
                properties.getMetadata(),
                reportETag(properties.getETag()),
                toDate(properties.getLastModified()),
                fromAccessTier(properties.getAccessTier()),
                container,
                toContentMetadata(properties));
    }

    @Override
    public ContainerAccess getContainerAccess(String container) {
        var client = blobServiceClient.getBlobContainerClient(container);
        try {
            var blobAccessType = client.getAccessPolicy().getBlobAccessType();
            return blobAccessType != null && blobAccessType.equals(
                    PublicAccessType.CONTAINER) ?
                    ContainerAccess.PUBLIC_READ :
                    ContainerAccess.PRIVATE;
        } catch (BlobStorageException bse) {
            throw translate(bse, container, /*key=*/ null);
        }
    }

    @Override
    public void setContainerAccess(String container, ContainerAccess access) {
        var client = blobServiceClient.getBlobContainerClient(container);
        var publicAccess = access == ContainerAccess.PUBLIC_READ ?
                PublicAccessType.CONTAINER : null;
        client.setAccessPolicy(publicAccess, List.of());
    }

    @Override
    public BlobAccess getBlobAccess(String container, String key) {
        return BlobAccess.PRIVATE;
    }

    @Override
    public void setBlobAccess(String container, String key, BlobAccess access) {
        throw new UnsupportedOperationException("unsupported in Azure");
    }

    @Override
    public MultipartUpload initiateMultipartUpload(String container,
            BlobMetadata blobMetadata, PutOptions options) {
        var containerClient = blobServiceClient.getBlobContainerClient(container);
        try {
            if (!containerClient.exists()) {
                throw new ContainerNotFoundException(container, "");
            }
        } catch (BlobStorageException bse) {
            throw translate(bse, container, /*key=*/ null);
        }

        var userMetadata = blobMetadata.userMetadata();
        if (userMetadata != null && !userMetadata.isEmpty()) {
            for (var key : userMetadata.keySet()) {
                if (!isValidMetadataKey(key)) {
                    throw new IllegalArgumentException(
                            "Invalid metadata key: " + key);
                }
            }
        }

        String uploadKey = STUB_BLOB_PREFIX + UUID.randomUUID().toString();
        String targetBlobName = blobMetadata.name();
        var stubBlobClient = containerClient.getBlobClient(uploadKey).getBlockBlobClient();

        var contentMetadata = blobMetadata.contentMetadata();
        BlobHttpHeaders headers = new BlobHttpHeaders();
        if (contentMetadata != null) {
            headers.setContentType(contentMetadata.contentType());
            headers.setContentDisposition(contentMetadata.contentDisposition());
            headers.setContentEncoding(contentMetadata.contentEncoding());
            headers.setContentLanguage(contentMetadata.contentLanguage());
            headers.setCacheControl(contentMetadata.cacheControl());
        }

        var uploadOptions = new BlockBlobSimpleUploadOptions(
                new ByteArrayInputStream(new byte[0]), 0);
        uploadOptions.setHeaders(headers);
        // Metadata names are case insensitive, so drop any spelling a caller
        // sent of our own before adding it -- two entries differing only in
        // case would collide, and ours must be the one that survives.
        var stubMetadata = new java.util.LinkedHashMap<String, String>();
        if (userMetadata != null) {
            stubMetadata.putAll(userMetadata);
        }
        stubMetadata.keySet().removeIf(
                key -> key.equalsIgnoreCase(TARGET_BLOB_NAME_METADATA));
        stubMetadata.put(TARGET_BLOB_NAME_METADATA,
                encodeTargetBlobName(targetBlobName));
        uploadOptions.setMetadata(stubMetadata);
        if (blobMetadata.storageClass() != null && blobMetadata.storageClass() != StorageClass.STANDARD) {
            uploadOptions.setTier(toAccessTier(blobMetadata.storageClass()));
        }

        // The destination rides along with the stub rather than following in a
        // setTags call, so a failure cannot leave a stub whose destination is
        // unknown -- one that listMultipartUploads skips and no abort reaches.
        stubBlobClient.uploadWithResponse(uploadOptions, null, null);

        return new MultipartUpload(container, targetBlobName,
                uploadKey, blobMetadata, options);
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
                throw new KeyNotFoundException(mpu.containerName(), mpu.id(),
                        "Multipart upload not found: " + mpu.id());
            }
            throw bse;
        }
    }

    @Override
    public String completeMultipartUpload(MultipartUpload mpu,
            List<MultipartPart> parts) {
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
        var putOpts = mpu.putOptions();
        if (putOpts != null && (putOpts.ifMatch() != null ||
                putOpts.ifNoneMatch() != null)) {
            options.setRequestConditions(new BlobRequestConditions()
                    .setIfMatch(backendCondition(putOpts.ifMatch()))
                    .setIfNoneMatch(
                            backendCondition(putOpts.ifNoneMatch())));
        }

        try {
            var response = client.commitBlockListWithResponse(
                    options, /*timeout=*/ null, /*context=*/ null);

            stubBlobClient.delete();

            String finalETag = reportETag(response.getValue().getETag());
            return finalETag;
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
                throw translate(bse, mpu.containerName(), targetBlobName);
            }
            throw bse;
        }
    }

    @Override
    public MultipartPart uploadMultipartPart(MultipartUpload mpu,
            int partNumber, InputStream is, long contentLength,
            @Nullable HashCode contentMD5) {

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
        try (var his = new HashingInputStream(MD5, is)) {
            Flux<ByteBuffer> body = chunkedByteBufferFlux(his, contentLength);

            asyncClient.stageBlock(blockId, body, contentLength).block();

            md5Hash = his.hash().asBytes();

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

        String eTag = BaseEncoding.base16()
                .lowerCase().encode(md5Hash);
        Date lastModified = null;
        return new MultipartPart(partNumber, contentLength, eTag, lastModified);
    }

    @Override
    public boolean supportsCopyMultipartPart() {
        return !nativePartCopyUnsupported;
    }

    @Override
    public MultipartPart copyMultipartPart(MultipartUpload mpu,
            int partNumber, String sourceContainer, String sourceName,
            @Nullable String copySourceRange, @Nullable String ifMatch,
            @Nullable String ifNoneMatch, @Nullable Date ifModifiedSince,
            @Nullable Date ifUnmodifiedSince) {
        if (partNumber < 1 || partNumber > 10_000) {
            throw new IllegalArgumentException(
                    "Part number must be between 1 and 10,000, got: " +
                    partNumber);
        }

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
                .getBlobContainerClient(sourceContainer)
                .getBlobClient(sourceName);
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
                .setSourceRange(parseCopySourceRange(copySourceRange));
        if (ifMatch != null || ifNoneMatch != null ||
                ifModifiedSince != null || ifUnmodifiedSince != null) {
            var conditions = new BlobRequestConditions()
                    .setIfMatch(backendCondition(ifMatch))
                    .setIfNoneMatch(backendCondition(ifNoneMatch));
            if (ifModifiedSince != null) {
                conditions.setIfModifiedSince(OffsetDateTime.ofInstant(
                        ifModifiedSince.toInstant(), ZoneOffset.UTC));
            }
            if (ifUnmodifiedSince != null) {
                conditions.setIfUnmodifiedSince(OffsetDateTime.ofInstant(
                        ifUnmodifiedSince.toInstant(), ZoneOffset.UTC));
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
            eTag = md5 == null ? blockId : BaseEncoding.base16().lowerCase()
                    .encode(Base64.getDecoder().decode(md5));
        } catch (BlobStorageException bse) {
            if (bse.getStatusCode() == 501) {
                nativePartCopyUnsupported = true;
                throw new UnsupportedOperationException(
                        "backend does not implement Put Block From URL", bse);
            }
            throw translate(bse, sourceContainer, sourceName);
        }
        return new MultipartPart(partNumber, /*partSize=*/ -1, eTag, null);
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
    public List<MultipartPart> listMultipartUpload(MultipartUpload mpu) {
        String uploadKey = mpu.id();
        if (!uploadKey.startsWith(STUB_BLOB_PREFIX)) {
            throw new KeyNotFoundException(mpu.containerName(), uploadKey,
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
                throw new KeyNotFoundException(mpu.containerName(), uploadKey,
                        "Multipart upload not found: " + uploadKey);
            }
            throw bse;
        }
        if (targetBlobName == null) {
            throw new KeyNotFoundException(mpu.containerName(), uploadKey,
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

        var parts = ImmutableList.<MultipartPart>builder();

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
            Date lastModified = null; // listBlocks does not return LastModified
            parts.add(new MultipartPart(partNumber, properties.getSizeLong(),
                    eTag, lastModified));
        }
        return parts.build();
    }

    @Override
    public List<MultipartUpload> listMultipartUploads(String container) {
        var containerClient = blobServiceClient.getBlobContainerClient(container);

        var builder = ImmutableList.<MultipartUpload>builder();

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

            builder.add(new MultipartUpload(container, targetBlobName,
                    uploadKey, null, null));
        }

        return builder.build();
    }

    @Override
    public long getMinimumMultipartPartSize() {
        return 1;
    }

    @Nullable
    private static OffsetDateTime toOffsetDateTime(@Nullable Date date) {
        if (date == null) {
            return null;
        }
        return date.toInstant().atOffset(ZoneOffset.UTC);
    }

    private static Date toDate(OffsetDateTime time) {
        return new Date(time.toInstant().toEpochMilli());
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
                .expires(expires != null ? toDate(expires) : null)
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
     * Translate BlobStorageException to a blobstore exception, returning the
     * original BlobStorageException unchanged if no translation applies.
     */
    private RuntimeException translate(BlobStorageException bse,
            String container, @Nullable String key) {
        var code = bse.getErrorCode();
        if (code == null) {
            // e.g. errors without an x-ms-error-code response header
            return bse;
        }
        if (code.equals(BlobErrorCode.BLOB_NOT_FOUND)) {
            var exception = new KeyNotFoundException(container, key, "");
            exception.initCause(bse);
            return exception;
        } else if (code.equals(BlobErrorCode.CONTAINER_NOT_FOUND)) {
            var exception = new ContainerNotFoundException(container, "");
            exception.initCause(bse);
            return exception;
        } else if (code.equals(BlobErrorCode.CONDITION_NOT_MET) ||
                code.equals(BlobErrorCode.SOURCE_CONDITION_NOT_MET) ||
                code.equals(BlobErrorCode.TARGET_CONDITION_NOT_MET)) {
            return new HttpResponseException(new HttpResponse(412), bse);
        } else if (code.equals(BlobErrorCode.BLOB_ALREADY_EXISTS)) {
            return new HttpResponseException(new HttpResponse(412), bse);
        } else if (code.equals(BlobErrorCode.INVALID_OPERATION)) {
            return new HttpResponseException(new HttpResponse(400), bse);
        } else if (bse.getErrorCode().equals(BlobErrorCode.INVALID_RESOURCE_NAME)) {
            return new IllegalArgumentException(
                    "Invalid container name", bse);
        } else if (bse.getStatusCode() == 403 || bse.getStatusCode() == 401) {
            // Surface a permission failure as 403 AccessDenied rather than a
            // generic 500.
            return new HttpResponseException(new HttpResponse(403), bse);
        }
        return bse;
    }
}
