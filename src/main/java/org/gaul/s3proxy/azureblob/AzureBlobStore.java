/*
 * Copyright 2014-2021 Andrew Gaul <andrew@gaul.org>
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
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import com.azure.core.credential.AzureNamedKeyCredential;
import com.azure.storage.blob.BlobServiceClient;
import com.azure.storage.blob.BlobServiceClientBuilder;
import com.azure.storage.blob.models.AccessTier;
import com.azure.storage.blob.models.BlobErrorCode;
import com.azure.storage.blob.models.BlobHttpHeaders;
import com.azure.storage.blob.models.BlobListDetails;
import com.azure.storage.blob.models.BlobProperties;
import com.azure.storage.blob.models.BlobStorageException;
import com.azure.storage.blob.models.BlockListType;
import com.azure.storage.blob.models.ListBlobsOptions;
import com.azure.storage.blob.models.PublicAccessType;
import com.azure.storage.blob.options.BlobContainerCreateOptions;
import com.azure.storage.blob.options.BlockBlobOutputStreamOptions;
import com.google.common.base.Supplier;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.primitives.Ints;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import org.gaul.s3proxy.S3ErrorCode;
import org.jclouds.blobstore.BlobStoreContext;
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
import org.jclouds.io.ContentMetadata;
import org.jclouds.io.ContentMetadataBuilder;
import org.jclouds.io.Payload;
import org.jclouds.io.PayloadSlicer;
import org.jclouds.providers.ProviderMetadata;

@Singleton
public final class AzureBlobStore extends BaseBlobStore {
    private final BlobServiceClient blobServiceClient;

    @Inject
    AzureBlobStore(BlobStoreContext context, BlobUtils blobUtils,
            Supplier<Location> defaultLocation,
            @Memoized Supplier<Set<? extends Location>> locations,
            PayloadSlicer slicer,
            @org.jclouds.location.Provider Supplier<Credentials> creds,
            ProviderMetadata provider) {
        super(context, blobUtils, defaultLocation, locations, slicer);
        var cred = creds.get();
        blobServiceClient = new BlobServiceClientBuilder()
                .credential(new AzureNamedKeyCredential(
                        cred.identity, cred.credential))
                .endpoint(provider.getEndpoint())
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
        var page = client.listBlobsByHierarchy(
                options.getDelimiter(), azureOptions, /*timeout=*/ null)
                .iterableByPage().iterator().next();
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
        var response =
                blobServiceClient.createBlobContainerIfNotExistsWithResponse(
                        container, azureOptions, /*context=*/ null);
        switch (response.getStatusCode()) {
        case 201: return true;
        case 409: return false;
        default: return false;
        }
    }

    @Override
    public void deleteContainer(String container) {
        try {
            blobServiceClient.deleteBlobContainer(container);
        } catch (BlobStorageException bse) {
            if (bse.getErrorCode() != BlobErrorCode.CONTAINER_NOT_FOUND) {
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
    public Blob getBlob(String container, String key, GetOptions options) {
        var client = blobServiceClient.getBlobContainerClient(container)
                .getBlobClient(key);
        var blobStream = client.openInputStream();
        var properties = blobStream.getProperties();
        var expires = properties.getExpiresOn();
        return new BlobBuilderImpl()
                .name(key)
                .userMetadata(properties.getMetadata())
                .payload(blobStream)
                .cacheControl(properties.getCacheControl())
                .contentDisposition(properties.getContentDisposition())
                .contentEncoding(properties.getContentEncoding())
                .contentLanguage(properties.getContentLanguage())
                .contentLength(properties.getBlobSize())
                .contentType(properties.getContentType())
                .expires(expires != null ? toDate(expires) : null)
                .build();
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
            return "";  // TODO: how to get ETag?
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }

    @Override
    public String copyBlob(String fromContainer, String fromName,
            String toContainer, String toName, CopyOptions options) {
        throw new UnsupportedOperationException("not yet implemented");
    }

    @Override
    public void removeBlob(String container, String key) {
        var client = blobServiceClient.getBlobContainerClient(container)
                .getBlobClient(key);
        try {
            client.delete();
        } catch (BlobStorageException bse) {
            if (bse.getErrorCode() != BlobErrorCode.BLOB_NOT_FOUND) {
                throw bse;
            }
        }
    }

    @Override
    public BlobMetadata blobMetadata(String container, String key) {
        var client = blobServiceClient.getBlobContainerClient(container)
                .getBlobClient(key);
        var properties = client.getProperties();
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
        return client.getAccessPolicy().getBlobAccessType() ==
                PublicAccessType.CONTAINER ?
                ContainerAccess.PUBLIC_READ :
                ContainerAccess.PRIVATE;
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
        String uploadId = UUID.randomUUID().toString();
        return MultipartUpload.create(container, blobMetadata.getName(),
                uploadId, blobMetadata, options);
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

    // TODO: handle more error codes
    public static S3ErrorCode toS3ErrorCode(BlobErrorCode code) {
        if (code.equals(BlobErrorCode.BLOB_NOT_FOUND)) {
            return S3ErrorCode.NO_SUCH_KEY;
        } else if (code.equals(BlobErrorCode.CONTAINER_NOT_FOUND)) {
            return S3ErrorCode.NO_SUCH_BUCKET;
        } else {
            return S3ErrorCode.INTERNAL_ERROR;
        }
    }

    private static Date toDate(OffsetDateTime time) {
        return new Date(time.toInstant().toEpochMilli());
    }

    private static AccessTier toAccessTier(Tier tier) {
        switch (tier) {
        case ARCHIVE:
            return AccessTier.ARCHIVE;
        case INFREQUENT:
            return AccessTier.COOL;
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
        } else if (tier.equals(AccessTier.COLD) ||
                tier.equals(AccessTier.COOL)) {
            return Tier.INFREQUENT;
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
}
