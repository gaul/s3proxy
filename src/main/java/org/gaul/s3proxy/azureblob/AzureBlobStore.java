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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import com.azure.core.credential.AzureNamedKeyCredential;
import com.azure.core.http.rest.PagedResponse;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.storage.blob.BlobServiceAsyncClient;
import com.azure.storage.blob.BlobServiceClient;
import com.azure.storage.blob.BlobServiceClientBuilder;
import com.azure.storage.blob.models.AccessTier;
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
import com.azure.storage.blob.options.BlobContainerCreateOptions;
import com.azure.storage.blob.options.BlobUploadFromUrlOptions;
import com.azure.storage.blob.options.BlockBlobCommitBlockListOptions;
import com.azure.storage.blob.options.BlockBlobOutputStreamOptions;
import com.azure.storage.blob.options.BlockBlobSimpleUploadOptions;
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

import org.gaul.s3proxy.blobstore.BaseBlobStore;
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

public final class AzureBlobStore extends BaseBlobStore {
    private static final String STUB_BLOB_PREFIX = ".s3proxy/stubs/";
    private static final long MAXIMUM_MULTIPART_PART_SIZE =
            4000L * 1024 * 1024;
    private static final String TARGET_BLOB_NAME_TAG = "s3proxy_target_blob_name";
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

    public AzureBlobStore(
            Supplier<Credentials> creds,
            String endpointUrl) {
        // TODO: derive endpoint from Constants.PROPERTY_ENDPOINT when unset,
        // e.g., default to https://<account>.blob.core.windows.net based on
        // the configured identity.
        this.endpoint = endpointUrl;
        this.creds = creds;
        var cred = creds.get();
        var blobServiceClientBuilder = new BlobServiceClientBuilder()
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

    @Override
    public PageSet<? extends StorageMetadata> list() {
        var set = ImmutableSet.<StorageMetadata>builder();
        for (var container : blobServiceClient.listBlobContainers()) {
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
            page = client.listBlobsByHierarchy(
                    options.delimiter(), azureOptions, /*timeout=*/ null)
                    .iterableByPage(marker).iterator().next();
        } catch (BlobStorageException bse) {
            throw translate(bse, container, /*key=*/ null);
        }
        for (var blob : page.getValue()) {
            var properties = blob.getProperties();
            if (blob.isPrefix()) {
                set.add(new BlobMetadata(StorageType.RELATIVE_PATH,
                        blob.getName(), Map.of(), /*eTag=*/ null,
                        /*creationDate=*/ null, /*lastModified=*/ null,
                        StorageClass.STANDARD,
                        /*container=*/ null,
                        ContentMetadata.builder().build()));
            } else {
                set.add(new BlobMetadata(StorageType.BLOB, blob.getName(),
                        Map.of(), properties.getETag(),
                        toDate(properties.getCreationTime()),
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
            var page = client.listBlobsByHierarchy(
                    /*delimiter=*/ null, /*options=*/ null, /*timeout=*/ null)
                    .iterableByPage().iterator().next();
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
                .setIfMatch(options.ifMatch())
                .setIfModifiedSince(toOffsetDateTime(
                        options.ifModifiedSince()))
                .setIfNoneMatch(options.ifNoneMatch())
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
                .eTag(properties.getETag())
                .creationDate(toDate(properties.getCreationTime()))
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
        try (var is = blob.getPayload()) {
            // TODO: Expires?
            var blobHttpHeaders = new BlobHttpHeaders();
            var contentMetadata = blob.getMetadata().getContentMetadata();
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
                        .setIfMatch(options.ifMatch())
                        .setIfNoneMatch(options.ifNoneMatch());
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
                return client.uploadWithResponse(uploadOptions,
                        /*timeout=*/ null, /*context=*/ null)
                        .getValue().getETag();
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
            return blobServiceClient
                    .getBlobContainerClient(container)
                    .getBlobClient(blob.getMetadata().name())
                    .getProperties()
                    .getETag();
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
     */
    private static Flux<ByteBuffer> chunkedByteBufferFlux(InputStream is,
            long contentLength) {
        final int maxChunkSize = 4 * 1024 * 1024;
        return Flux.generate(
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
        );
    }

    @Override
    public String copyBlob(String fromContainer, String fromName,
            String toContainer, String toName, CopyOptions options) {
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
        String ifMatch = options.ifMatch();
        if (ifMatch != null) {
            sourceConditions.setIfMatch(ifMatch);
            haveSourceConditions = true;
        }
        String ifNoneMatch = options.ifNoneMatch();
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

            return response.getValue().getETag();
        } catch (BlobStorageException bse) {
            throw translate(bse, fromContainer, fromName);
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
                properties.getMetadata(), properties.getETag(),
                toDate(properties.getCreationTime()),
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

        var contentMetadata = blobMetadata.getContentMetadata();
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
        if (userMetadata != null && !userMetadata.isEmpty()) {
            uploadOptions.setMetadata(userMetadata);
        }
        if (blobMetadata.storageClass() != null && blobMetadata.storageClass() != StorageClass.STANDARD) {
            uploadOptions.setTier(toAccessTier(blobMetadata.storageClass()));
        }

        stubBlobClient.uploadWithResponse(uploadOptions, null, null);

        var tags = new java.util.HashMap<String, String>();
        tags.put(TARGET_BLOB_NAME_TAG, targetBlobName);
        stubBlobClient.setTags(tags);

        return new MultipartUpload(container, targetBlobName,
                uploadKey, blobMetadata, options);
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
        java.util.Map<String, String> stubTags;
        try {
            stubProperties = stubBlobClient.getProperties();
            stubTags = stubBlobClient.getTags();
        } catch (BlobStorageException bse) {
            if (bse.getErrorCode().equals(BlobErrorCode.BLOB_NOT_FOUND)) {
                throw new IllegalArgumentException(
                        "Upload not found: uploadId=" + uploadKey);
            }
            throw bse;
        }

        String targetBlobName = stubTags.get(TARGET_BLOB_NAME_TAG);
        if (targetBlobName == null) {
            throw new IllegalArgumentException(
                    "Stub blob missing target name tag: uploadId=" + uploadKey);
        }

        var userMetadata = stubProperties.getMetadata();
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
                    .setIfMatch(putOpts.ifMatch())
                    .setIfNoneMatch(putOpts.ifNoneMatch()));
        }

        try {
            var response = client.commitBlockListWithResponse(
                    options, /*timeout=*/ null, /*context=*/ null);

            stubBlobClient.delete();

            String finalETag = response.getValue().getETag();
            return finalETag;
        } catch (BlobStorageException bse) {
            var errorCode = bse.getErrorCode();
            if (errorCode.equals(BlobErrorCode.BLOB_NOT_FOUND) ||
                    errorCode.equals(BlobErrorCode.CONTAINER_NOT_FOUND)) {
                throw new IllegalArgumentException(
                        "Upload not found: container=" + mpu.containerName() +
                        ", key=" + targetBlobName);
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
        String nonce = uploadKey.substring(STUB_BLOB_PREFIX.length());

        var containerClient = blobServiceClient.getBlobContainerClient(mpu.containerName());
        var stubBlobClient = containerClient.getBlobClient(uploadKey);

        String targetBlobName;
        try {
            var stubTags = stubBlobClient.getTags();
            targetBlobName = stubTags.get(TARGET_BLOB_NAME_TAG);
        } catch (BlobStorageException bse) {
            if (bse.getErrorCode().equals(BlobErrorCode.BLOB_NOT_FOUND)) {
                throw new IllegalArgumentException(
                        "Upload not found: uploadId=" + uploadKey);
            }
            throw bse;
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
        details.setRetrieveTags(true);
        options.setDetails(details);

        for (var blobItem : containerClient.listBlobs(options, null, null)) {
            // e.g., ".s3proxy/stubs/<uuid>"
            String uploadKey = blobItem.getName();
            var tags = blobItem.getTags();

            if (tags == null || tags.get(TARGET_BLOB_NAME_TAG) == null) {
                continue;
            }

            String targetBlobName = tags.get(TARGET_BLOB_NAME_TAG);
            builder.add(new MultipartUpload(container, targetBlobName,
                    uploadKey, null, null));
        }

        return builder.build();
    }

    @Override
    public long getMinimumMultipartPartSize() {
        return 1;
    }

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
     * Translate BlobStorageException to a jclouds exception, returning the
     * original BlobStorageException unchanged if no translation applies.
     */
    private RuntimeException translate(BlobStorageException bse,
            String container, @Nullable String key) {
        var code = bse.getErrorCode();
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
