/*
 * Copyright 2014-2025 Andrew Gaul <andrew@gaul.org>
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

import java.io.IOException;
import java.io.InputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import javax.annotation.Nullable;

import com.azure.core.credential.AzureNamedKeyCredential;
import com.azure.core.http.rest.PagedResponse;
import com.azure.identity.DefaultAzureCredentialBuilder;
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
import com.azure.storage.blob.models.BlockListType;
import com.azure.storage.blob.models.ListBlobsOptions;
import com.azure.storage.blob.models.PublicAccessType;
import com.azure.storage.blob.options.BlobContainerCreateOptions;
import com.azure.storage.blob.options.BlobUploadFromUrlOptions;
import com.azure.storage.blob.options.BlockBlobOutputStreamOptions;
import com.azure.storage.blob.sas.BlobSasPermission;
import com.azure.storage.blob.sas.BlobServiceSasSignatureValues;
import com.azure.storage.blob.specialized.BlobInputStream;
import com.azure.storage.common.policy.RequestRetryOptions;
import com.azure.storage.common.policy.RetryPolicyType;
import com.google.common.base.Supplier;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.net.HttpHeaders;
import com.google.common.primitives.Ints;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.ws.rs.core.Response.Status;

import org.jclouds.blobstore.BlobStoreContext;
import org.jclouds.blobstore.ContainerNotFoundException;
import org.jclouds.blobstore.KeyNotFoundException;
import org.jclouds.blobstore.domain.Blob;
import org.jclouds.blobstore.domain.BlobAccess;
import org.jclouds.blobstore.domain.BlobMetadata;
import org.jclouds.blobstore.domain.ContainerAccess;
import org.jclouds.blobstore.domain.MultipartPart;
import org.jclouds.blobstore.domain.MultipartUpload;
import org.jclouds.blobstore.domain.PageSet;
import org.jclouds.blobstore.domain.StorageMetadata;
import org.jclouds.blobstore.domain.StorageType;
import org.jclouds.blobstore.domain.Tier;
import org.jclouds.blobstore.domain.internal.BlobBuilderImpl;
import org.jclouds.blobstore.domain.internal.BlobMetadataImpl;
import org.jclouds.blobstore.domain.internal.PageSetImpl;
import org.jclouds.blobstore.domain.internal.StorageMetadataImpl;
import org.jclouds.blobstore.internal.BaseBlobStore;
import org.jclouds.blobstore.options.CopyOptions;
import org.jclouds.blobstore.options.CreateContainerOptions;
import org.jclouds.blobstore.options.GetOptions;
import org.jclouds.blobstore.options.ListContainerOptions;
import org.jclouds.blobstore.options.PutOptions;
import org.jclouds.blobstore.util.BlobUtils;
import org.jclouds.collect.Memoized;
import org.jclouds.domain.Credentials;
import org.jclouds.domain.Location;
import org.jclouds.http.HttpCommand;
import org.jclouds.http.HttpRequest;
import org.jclouds.http.HttpResponse;
import org.jclouds.http.HttpResponseException;
import org.jclouds.io.ContentMetadata;
import org.jclouds.io.ContentMetadataBuilder;
import org.jclouds.io.Payload;
import org.jclouds.io.PayloadSlicer;
import org.jclouds.providers.ProviderMetadata;

@Singleton
public final class AzureBlobStore extends BaseBlobStore {
    private final BlobServiceClient blobServiceClient;
    private final String endpoint;

    @Inject
    AzureBlobStore(BlobStoreContext context, BlobUtils blobUtils,
            Supplier<Location> defaultLocation,
            @Memoized Supplier<Set<? extends Location>> locations,
            PayloadSlicer slicer,
            @org.jclouds.location.Provider Supplier<Credentials> creds,
            ProviderMetadata provider) {
        super(context, blobUtils, defaultLocation, locations, slicer);
        this.endpoint = provider.getEndpoint();
        var cred = creds.get();
        // Disable retries since client should retry on errors.
        var retryOptions = new RequestRetryOptions(
                RetryPolicyType.FIXED, /*maxTries=*/ 1,
                /*tryTimeoutInSeconds=*/ (Integer) null,
                /*retryDelayInMs=*/ null, /*maxRetryDelayInMs=*/ null,
                /*secondaryHost=*/ null);
        var blobServiceClientBuilder = new BlobServiceClientBuilder();
        if (!cred.identity.isEmpty() && !cred.credential.isEmpty()) {
            blobServiceClientBuilder.credential(
                new AzureNamedKeyCredential(cred.identity, cred.credential));
        } else {
            blobServiceClientBuilder.credential(
                new DefaultAzureCredentialBuilder().build());
        }
        blobServiceClient = blobServiceClientBuilder
                .endpoint(endpoint)
                .retryOptions(retryOptions)
                .buildClient();
    }

    @Override
    public PageSet<? extends StorageMetadata> list() {
        var set = ImmutableSet.<StorageMetadata>builder();
        for (var container : blobServiceClient.listBlobContainers()) {
            set.add(new StorageMetadataImpl(StorageType.CONTAINER, /*id=*/ null,
                    container.getName(), /*location=*/ null, /*uri=*/ null,
                    /*eTag=*/ null, /*creationDate=*/ null,
                    toDate(container.getProperties().getLastModified()),
                    Map.of(), /*size=*/ null,
                    Tier.STANDARD));
        }
        return new PageSetImpl<StorageMetadata>(set.build(), null);
    }

    @Override
    public PageSet<? extends StorageMetadata> list(String container,
            ListContainerOptions options) {
        var client = blobServiceClient.getBlobContainerClient(container);
        var azureOptions = new ListBlobsOptions();
        azureOptions.setPrefix(options.getPrefix());
        azureOptions.setMaxResultsPerPage(options.getMaxResults());
        var marker = options.getMarker() != null ?
                URLDecoder.decode(options.getMarker(), StandardCharsets.UTF_8) :
                null;

        var set = ImmutableSet.<StorageMetadata>builder();
        PagedResponse<BlobItem> page;
        try {
            page = client.listBlobsByHierarchy(
                    options.getDelimiter(), azureOptions, /*timeout=*/ null)
                    .iterableByPage(marker).iterator().next();
        } catch (BlobStorageException bse) {
            translateAndRethrowException(bse, container, /*key=*/ null);
            throw bse;
        }
        for (var blob : page.getValue()) {
            var properties = blob.getProperties();
            if (blob.isPrefix()) {
                set.add(new StorageMetadataImpl(StorageType.RELATIVE_PATH,
                        /*id=*/ null, blob.getName(), /*location=*/ null,
                        /*uri=*/ null, /*eTag=*/ null,
                        /*creationDate=*/ null,
                        /*lastModified=*/ null,
                        Map.of(),
                        /*size=*/ null,
                        Tier.STANDARD));
            } else {
                set.add(new StorageMetadataImpl(StorageType.BLOB,
                        /*id=*/ null, blob.getName(), /*location=*/ null,
                        /*uri=*/ null, properties.getETag(),
                        toDate(properties.getCreationTime()),
                        toDate(properties.getLastModified()),
                        Map.of(),
                        properties.getContentLength(),
                        toTier(properties.getAccessTier())));
            }
        }

        return new PageSetImpl<StorageMetadata>(set.build(),
                page.getContinuationToken());
    }

    @Override
    public boolean containerExists(String container) {
        var client = blobServiceClient.getBlobContainerClient(container);
        return client.exists();
    }

    @Override
    public boolean createContainerInLocation(Location location,
            String container) {
        return createContainerInLocation(location, container,
                new CreateContainerOptions());
    }

    @Override
    public boolean createContainerInLocation(Location location,
            String container, CreateContainerOptions options) {
        var azureOptions = new BlobContainerCreateOptions();
        if (options.isPublicRead()) {
            azureOptions.setPublicAccessType(PublicAccessType.CONTAINER);
        }
        try {
            var response = blobServiceClient
                    .createBlobContainerIfNotExistsWithResponse(
                            container, azureOptions, /*context=*/ null);
            switch (response.getStatusCode()) {
            case 201: return true;
            case 409: return false;
            default: return false;
            }
        } catch (BlobStorageException bse) {
            translateAndRethrowException(bse, container, /*key=*/ null);
            throw bse;
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
        BlobRange azureRange = null;
        if (!options.getRanges().isEmpty()) {
            var ranges = options.getRanges().get(0).split("-", 2);

            if (ranges[0].isEmpty()) {
                // handle to read from the end
                long offset = 0;
                long end = Long.parseLong(ranges[1]);
                long length = end;
                azureRange = new BlobRange(offset, length);
                throw new UnsupportedOperationException(
                        "trailing ranges unsupported");
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
                .setIfMatch(options.getIfMatch())
                .setIfModifiedSince(toOffsetDateTime(
                        options.getIfModifiedSince()))
                .setIfNoneMatch(options.getIfNoneMatch())
                .setIfUnmodifiedSince(toOffsetDateTime(
                        options.getIfUnmodifiedSince()));
        BlobInputStream blobStream;
        try {
            blobStream = client.openInputStream(azureRange, conditions);
        } catch (BlobStorageException bse) {
            translateAndRethrowException(bse, container, key);
            if (bse.getStatusCode() ==
                    Status.REQUESTED_RANGE_NOT_SATISFIABLE.getStatusCode()) {
                throw new HttpResponseException(
                        "illegal range: " + azureRange, null,
                        HttpResponse.builder()
                        .statusCode(Status.REQUESTED_RANGE_NOT_SATISFIABLE
                                .getStatusCode())
                        .build());
            }
            throw bse;
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
                contentLength = azureRange.getCount();
            }
        }
        var blob = new BlobBuilderImpl()
                .name(key)
                .userMetadata(properties.getMetadata())
                .payload(blobStream)
                .cacheControl(properties.getCacheControl())
                .contentDisposition(properties.getContentDisposition())
                .contentEncoding(properties.getContentEncoding())
                .contentLanguage(properties.getContentLanguage())
                .contentLength(contentLength)
                .contentType(properties.getContentType())
                .expires(expires != null ? toDate(expires) : null)
                .build();
        if (azureRange != null) {
            blob.getAllHeaders().put(HttpHeaders.CONTENT_RANGE,
                    "bytes " + azureRange.getOffset() +
                    "-" + (azureRange.getOffset() + contentLength - 1) +
                    "/" + properties.getBlobSize());
        }
        var metadata = blob.getMetadata();
        metadata.setETag(properties.getETag());
        metadata.setCreationDate(toDate(properties.getCreationTime()));
        metadata.setLastModified(toDate(properties.getLastModified()));
        return blob;
    }

    @Override
    public String putBlob(String container, Blob blob) {
        return putBlob(container, blob, new PutOptions());
    }

    @Override
    public String putBlob(String container, Blob blob, PutOptions options) {
        var client = blobServiceClient.getBlobContainerClient(container)
                .getBlobClient(blob.getMetadata().getName())
                .getBlockBlobClient();
        try (var is = blob.getPayload().openStream()) {
            var azureOptions = new BlockBlobOutputStreamOptions();
            azureOptions.setMetadata(blob.getMetadata().getUserMetadata());

            // TODO: Expires?
            var blobHttpHeaders = new BlobHttpHeaders();
            var contentMetadata = blob.getMetadata().getContentMetadata();
            blobHttpHeaders.setCacheControl(contentMetadata.getCacheControl());
            blobHttpHeaders.setContentDisposition(
                    contentMetadata.getContentDisposition());
            blobHttpHeaders.setContentEncoding(
                    contentMetadata.getContentEncoding());
            blobHttpHeaders.setContentLanguage(
                    contentMetadata.getContentLanguage());
            blobHttpHeaders.setContentMd5(
                    contentMetadata.getContentMD5());
            blobHttpHeaders.setContentType(contentMetadata.getContentType());
            azureOptions.setHeaders(blobHttpHeaders);
            if (blob.getMetadata().getTier() != Tier.STANDARD) {
                azureOptions.setTier(toAccessTier(
                        blob.getMetadata().getTier()));
            }

            try (var os = client.getBlobOutputStream(
                    azureOptions, /*context=*/ null)) {
                is.transferTo(os);
            }

            // TODO: racy
            return blobServiceClient
                    .getBlobContainerClient(container)
                    .getBlobClient(blob.getMetadata().getName())
                    .getProperties()
                    .getETag();
        } catch (IOException ioe) {
            var cause = ioe.getCause();
            if (cause != null && cause instanceof BlobStorageException) {
                translateAndRethrowException(
                        (BlobStorageException) cause, container, /*key=*/ null);
            }
            throw new RuntimeException(ioe);
        }
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
        var token = fromClient.generateSas(values);

        // TODO: is this the best way to generate a SAS URL?
        var azureOptions = new BlobUploadFromUrlOptions(url + "?" + token);
        var client = blobServiceClient
                .getBlobContainerClient(toContainer)
                .getBlobClient(toName)
                .getBlockBlobClient();

        var headers = new BlobHttpHeaders();
        var contentMetadata = options.contentMetadata();
        if (contentMetadata != null) {
            var cacheControl = contentMetadata.getCacheControl();
            if (cacheControl != null) {
                headers.setCacheControl(cacheControl);
            }

            var contentDisposition = contentMetadata.getContentDisposition();
            if (contentDisposition != null) {
                headers.setContentDisposition(contentDisposition);
            }

            var contentEncoding = contentMetadata.getContentEncoding();
            if (contentEncoding != null) {
                headers.setContentEncoding(contentEncoding);
            }

            var contentLanguage = contentMetadata.getContentLanguage();
            if (contentLanguage != null) {
                headers.setContentLanguage(contentLanguage);
            }

            var contentType = contentMetadata.getContentType();
            if (contentType != null) {
                headers.setContentType(contentType);
            }
        }
        azureOptions.setHeaders(headers);

        // TODO: setSourceRequestConditions(BlobRequestConditions)
        var response = client.uploadFromUrlWithResponse(
                azureOptions, /*timeout=*/ null, /*context=*/ null);

        // TODO: cannot do this as part of uploadFromUrlWithResponse?
        var userMetadata = options.userMetadata();
        if (userMetadata != null) {
            client.setMetadata(userMetadata);
        }

        return response.getValue().getETag();
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
            translateAndRethrowException(bse, container, /*key=*/ null);
            throw bse;
        }
        return new BlobMetadataImpl(/*id=*/ null, key, /*location=*/ null,
                /*uri=*/ null, properties.getETag(),
                toDate(properties.getCreationTime()),
                toDate(properties.getLastModified()),
                properties.getMetadata(), /*publicUri=*/ null, container,
                toContentMetadata(properties),
                properties.getBlobSize(), toTier(properties.getAccessTier()));
    }

    @Override
    protected boolean deleteAndVerifyContainerGone(String container) {
        blobServiceClient.deleteBlobContainer(container);
        return true;
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
            translateAndRethrowException(bse, container, /*key=*/ null);
            throw bse;
        }
    }

    @Override
    public void setContainerAccess(String container, ContainerAccess access) {
        var client = blobServiceClient.getBlobContainerClient(container);
        var publicAccess = access == ContainerAccess.PUBLIC_READ ?
                PublicAccessType.CONTAINER : PublicAccessType.BLOB;
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
/*
        String uploadId = UUID.randomUUID().toString();
        return MultipartUpload.create(container, blobMetadata.getName(),
                uploadId, blobMetadata, options);
*/
        throw new UnsupportedOperationException();
    }

    @Override
    public void abortMultipartUpload(MultipartUpload mpu) {
        // Azure automatically removes uncommitted blocks after 7 days.
    }

    @Override
    public String completeMultipartUpload(MultipartUpload mpu,
            List<MultipartPart> parts) {
        var client = blobServiceClient
                .getBlobContainerClient(mpu.containerName())
                .getBlobClient(mpu.blobName())
                .getBlockBlobClient();
        var blocks = ImmutableList.<String>builder();
        for (var part : parts) {
            blocks.add(makeBlockId(part.partNumber()));
        }
        var blockBlobItem = client.commitBlockList(blocks.build(),
                /*overwrite=*/ true);
        return blockBlobItem.getETag();
    }

    @Override
    public MultipartPart uploadMultipartPart(MultipartUpload mpu,
            int partNumber, Payload payload) {
        var client = blobServiceClient
                .getBlobContainerClient(mpu.containerName())
                .getBlobClient(mpu.blobName())
                .getBlockBlobClient();
        var blockId = makeBlockId(partNumber);
        var length = payload.getContentMetadata().getContentLength();
        try (var is = payload.openStream()) {
            client.stageBlock(blockId, is, length);
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
        String eTag = "";  // putBlock does not return ETag
        Date lastModified = null;  // putBlob does not return Last-Modified
        return MultipartPart.create(partNumber, length, eTag, lastModified);
    }

    @Override
    public List<MultipartPart> listMultipartUpload(MultipartUpload mpu) {
        var client = blobServiceClient
                .getBlobContainerClient(mpu.containerName())
                .getBlobClient(mpu.blobName())
                .getBlockBlobClient();
        var blockList = client.listBlocks(BlockListType.ALL);
        var parts = ImmutableList.<MultipartPart>builder();
        for (var properties : blockList.getUncommittedBlocks()) {
            int partNumber = Ints.fromByteArray(Base64.getDecoder().decode(
                    properties.getName()));
            String eTag = "";  // listBlocks does not return ETag
            Date lastModified = null; // listBlocks does not return LastModified
            parts.add(MultipartPart.create(partNumber, properties.getSizeLong(),
                    eTag, lastModified));
        }
        return parts.build();
    }

    @Override
    public List<MultipartUpload> listMultipartUploads(String container) {
        var client = blobServiceClient.getBlobContainerClient(container);
        var azureOptions = new ListBlobsOptions();
        var details = new BlobListDetails();
        details.setRetrieveUncommittedBlobs(true);
        azureOptions.setDetails(details);

        var builder = ImmutableList.<MultipartUpload>builder();
        for (var blob : client.listBlobs(azureOptions,
                /*continuationToken=*/ null, /*timeout=*/ null)) {
            var properties = blob.getProperties();
            // only uncommitted blobs lack ETags
            if (properties.getETag() != null) {
                continue;
            }
            // TODO: bogus uploadId
            String uploadId = UUID.randomUUID().toString();
            builder.add(MultipartUpload.create(container, blob.getName(),
                    uploadId, null, null));
        }

        return builder.build();
    }

    @Override
    public long getMinimumMultipartPartSize() {
        return 1;
    }

    @Override
    public long getMaximumMultipartPartSize() {
        return 100 * 1024 * 1024;
    }

    @Override
    public int getMaximumNumberOfParts() {
        return 50 * 1000;
    }

    @Override
    public InputStream streamBlob(String container, String name) {
        throw new UnsupportedOperationException("not yet implemented");
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

    private static AccessTier toAccessTier(Tier tier) {
        switch (tier) {
        case ARCHIVE:
            return AccessTier.ARCHIVE;
        case COOL:
            return AccessTier.COOL;
        case COLD:
            return AccessTier.COLD;
        case STANDARD:
        default:
            return AccessTier.HOT;
        }
    }

    private static Tier toTier(AccessTier tier) {
        if (tier == null) {
            return Tier.STANDARD;
        } else if (tier.equals(AccessTier.ARCHIVE)) {
            return Tier.ARCHIVE;
        } else if (tier.equals(AccessTier.COLD)) {
            return Tier.COLD;
        } else if (tier.equals(AccessTier.COOL)) {
            return Tier.COOL;
        } else {
            return Tier.STANDARD;
        }
    }

    private static ContentMetadata toContentMetadata(
            BlobProperties properties) {
        var expires = properties.getExpiresOn();
        return ContentMetadataBuilder.create()
                .cacheControl(properties.getCacheControl())
                .contentDisposition(properties.getContentDisposition())
                .contentEncoding(properties.getContentEncoding())
                .contentLanguage(properties.getContentLanguage())
                .contentLength(properties.getBlobSize())
                .contentType(properties.getContentType())
                .expires(expires != null ? toDate(expires) : null)
                .build();
    }

    private static String makeBlockId(int partNumber) {
        return Base64.getEncoder().encodeToString(Ints.toByteArray(partNumber));
    }

    /**
     * Translate BlobStorageException to a jclouds exception.  Throws if
     * translated otherwise returns.
     */
    private void translateAndRethrowException(BlobStorageException bse,
            String container, @Nullable String key) {
        var code = bse.getErrorCode();
        if (code.equals(BlobErrorCode.BLOB_NOT_FOUND)) {
            var exception = new KeyNotFoundException(container, key, "");
            exception.initCause(bse);
            throw exception;
        } else if (code.equals(BlobErrorCode.CONTAINER_NOT_FOUND)) {
            var exception = new ContainerNotFoundException(container, "");
            exception.initCause(bse);
            throw exception;
        } else if (code.equals(BlobErrorCode.CONDITION_NOT_MET)) {
            var request = HttpRequest.builder()
                    .method("GET")
                    .endpoint(endpoint)
                    .build();
            var response = HttpResponse.builder()
                    .statusCode(Status.PRECONDITION_FAILED.getStatusCode())
                    .build();
            throw new HttpResponseException(
                    new HttpCommand(request), response, bse);
        } else if (code.equals(BlobErrorCode.INVALID_OPERATION)) {
            var request = HttpRequest.builder()
                    .method("GET")
                    .endpoint(endpoint)
                    .build();
            var response = HttpResponse.builder()
                    .statusCode(Status.BAD_REQUEST.getStatusCode())
                    .build();
            throw new HttpResponseException(
                    new HttpCommand(request), response, bse);
        } else if (bse.getErrorCode().equals(BlobErrorCode.INVALID_RESOURCE_NAME)) {
            throw new IllegalArgumentException(
                    "Invalid container name", bse);
        }
    }
}
