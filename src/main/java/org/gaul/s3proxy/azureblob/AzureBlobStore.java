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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URLDecoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
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
import com.google.common.hash.HashFunction;
import com.google.common.hash.Hashing;
import com.google.common.hash.HashingInputStream;
import com.google.common.io.BaseEncoding;
import com.google.common.net.HttpHeaders;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.ws.rs.core.Response.Status;

import org.gaul.s3proxy.PutOptions2;
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

import reactor.core.publisher.Flux;

@Singleton
public final class AzureBlobStore extends BaseBlobStore {
    private static final String STUB_BLOB_PREFIX = ".s3proxy/stubs/";
    private static final String TARGET_BLOB_NAME_TAG = "s3proxy_target_blob_name";
    private static final HashFunction MD5 = Hashing.md5();
    // Disable retries since client should retry on errors.
    private static final RequestRetryOptions NO_RETRY_OPTIONS = new RequestRetryOptions(
            RetryPolicyType.FIXED, /*maxTries=*/ 1,
            /*tryTimeoutInSeconds=*/ (Integer) null,
            /*retryDelayInMs=*/ null, /*maxRetryDelayInMs=*/ null,
            /*secondaryHost=*/ null);

    private final BlobServiceClient blobServiceClient;
    private final String endpoint;
    private final Supplier<Credentials> creds;

    @Inject
    AzureBlobStore(BlobStoreContext context, BlobUtils blobUtils,
            Supplier<Location> defaultLocation,
            @Memoized Supplier<Set<? extends Location>> locations,
            PayloadSlicer slicer,
            @org.jclouds.location.Provider Supplier<Credentials> creds,
            ProviderMetadata provider) {
        super(context, blobUtils, defaultLocation, locations, slicer);
        this.endpoint = provider.getEndpoint();
        this.creds = creds;
        var cred = creds.get();
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
                .retryOptions(NO_RETRY_OPTIONS)
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
            return switch (response.getStatusCode()) {
            case 201 -> true;
            case 409 -> false;
            default -> false;
            };
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
            var hash = contentMetadata.getContentMD5AsHashCode();
            blobHttpHeaders.setContentMd5(hash != null ? hash.asBytes() : null);
            blobHttpHeaders.setContentType(contentMetadata.getContentType());
            azureOptions.setHeaders(blobHttpHeaders);
            if (blob.getMetadata().getTier() != Tier.STANDARD) {
                azureOptions.setTier(toAccessTier(
                        blob.getMetadata().getTier()));
            }

            if (options instanceof PutOptions2) {
                var putOptions2 = (PutOptions2) options;
                String ifMatch = putOptions2.getIfMatch();
                String ifNoneMatch = putOptions2.getIfNoneMatch();
                if (ifMatch != null || ifNoneMatch != null) {
                    azureOptions.setRequestConditions(new BlobRequestConditions()
                            .setIfMatch(ifMatch)
                            .setIfNoneMatch(ifNoneMatch));
                }
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
        String token;
        var cred = creds.get();
        if (!cred.identity.isEmpty() && !cred.credential.isEmpty()) {
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
            if (bse.getErrorCode().equals(BlobErrorCode.BLOB_NOT_FOUND)) {
                return null;
            }
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
        var containerClient = blobServiceClient.getBlobContainerClient(container);
        try {
            if (!containerClient.exists()) {
                throw new ContainerNotFoundException(container, "");
            }
        } catch (BlobStorageException bse) {
            translateAndRethrowException(bse, container, /*key=*/ null);
            throw bse;
        }

        var userMetadata = blobMetadata.getUserMetadata();
        if (userMetadata != null && !userMetadata.isEmpty()) {
            for (var key : userMetadata.keySet()) {
                if (!isValidMetadataKey(key)) {
                    throw new IllegalArgumentException(
                            "Invalid metadata key: " + key);
                }
            }
        }

        String uploadKey = STUB_BLOB_PREFIX + UUID.randomUUID().toString();
        String targetBlobName = blobMetadata.getName();
        var stubBlobClient = containerClient.getBlobClient(uploadKey).getBlockBlobClient();

        var contentMetadata = blobMetadata.getContentMetadata();
        BlobHttpHeaders headers = new BlobHttpHeaders();
        if (contentMetadata != null) {
            headers.setContentType(contentMetadata.getContentType());
            headers.setContentDisposition(contentMetadata.getContentDisposition());
            headers.setContentEncoding(contentMetadata.getContentEncoding());
            headers.setContentLanguage(contentMetadata.getContentLanguage());
            headers.setCacheControl(contentMetadata.getCacheControl());
        }

        var uploadOptions = new BlockBlobSimpleUploadOptions(
                new ByteArrayInputStream(new byte[0]), 0);
        uploadOptions.setHeaders(headers);
        if (userMetadata != null && !userMetadata.isEmpty()) {
            uploadOptions.setMetadata(userMetadata);
        }
        if (blobMetadata.getTier() != null && blobMetadata.getTier() != Tier.STANDARD) {
            uploadOptions.setTier(toAccessTier(blobMetadata.getTier()));
        }

        stubBlobClient.uploadWithResponse(uploadOptions, null, null);

        var tags = new java.util.HashMap<String, String>();
        tags.put(TARGET_BLOB_NAME_TAG, targetBlobName);
        stubBlobClient.setTags(tags);

        return MultipartUpload.create(container, targetBlobName,
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
        blobHttpHeaders.setContentType(contentMetadata.getContentType());
        blobHttpHeaders.setContentDisposition(contentMetadata.getContentDisposition());
        blobHttpHeaders.setContentEncoding(contentMetadata.getContentEncoding());
        blobHttpHeaders.setContentLanguage(contentMetadata.getContentLanguage());
        blobHttpHeaders.setCacheControl(contentMetadata.getCacheControl());

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
        if (mpu.putOptions() instanceof PutOptions2) {
            var putOptions2 = (PutOptions2) mpu.putOptions();
            String ifMatch = putOptions2.getIfMatch();
            String ifNoneMatch = putOptions2.getIfNoneMatch();
            if (ifMatch != null || ifNoneMatch != null) {
                options.setRequestConditions(new BlobRequestConditions()
                        .setIfMatch(ifMatch)
                        .setIfNoneMatch(ifNoneMatch));
            }
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
                translateAndRethrowException(bse, mpu.containerName(), targetBlobName);
            }
            throw bse;
        }
    }

    @Override
    public MultipartPart uploadMultipartPart(MultipartUpload mpu,
            int partNumber, Payload payload) {

        if (partNumber < 1 || partNumber > 10_000) {
            throw new IllegalArgumentException(
                    "Part number must be between 1 and 10,000, got: " + partNumber);
        }

        Long contentLength = payload.getContentMetadata().getContentLength();
        if (contentLength == null) {
            throw new IllegalArgumentException("Content-Length is required");
        }
        if (contentLength < 0) {
            throw new IllegalArgumentException(
                    "Content-Length must be non-negative, got: " + contentLength);
        }

        if (contentLength > getMaximumMultipartPartSize()) {
            throw new IllegalArgumentException(
                    "Part size exceeds maximum of " + getMaximumMultipartPartSize() +
                    " bytes: " + contentLength);
        }


        String uploadKey = mpu.id();
        String nonce = uploadKey.substring(STUB_BLOB_PREFIX.length());
        String blockId = makeBlockId(nonce, partNumber);
        var asyncClient = createNonRetryingBlockBlobAsyncClient(
                mpu.containerName(), mpu.blobName());

        byte[] md5Hash;
        try (var is = payload.openStream();
             var his = new HashingInputStream(MD5, is)) {
            var providedMd5 = payload.getContentMetadata().getContentMD5AsHashCode();

            final int maxChunkSize = 4 * 1024 * 1024;

            Flux<ByteBuffer> body = Flux.generate(
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
                            int read = his.read(array, totalRead,
                                    chunkSize - totalRead);
                            if (read == -1) {
                                if (position + totalRead < contentLength) {
                                    sink.error(new IOException(
                                        String.format("Stream ended at %d bytes, expected %d",
                                            position + totalRead, contentLength)));
                                    return position + totalRead;
                                }
                                break;
                            }
                            totalRead += read;
                        }
                        if (totalRead == 0) {
                            sink.error(new IOException(
                                String.format("Stream ended at %d bytes, expected %d",
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

            asyncClient.stageBlock(blockId, body, contentLength).block();

            md5Hash = his.hash().asBytes();

            if (providedMd5 != null) {
                if (!MessageDigest.isEqual(md5Hash, providedMd5.asBytes())) {
                    throw new IllegalArgumentException("Content-MD5 mismatch");
                }
            }

        } catch (BlobStorageException bse) {
            translateAndRethrowException(bse, mpu.containerName(), mpu.blobName());
            throw new RuntimeException(String.format(
                    "Failed to upload part %d for blob '%s' in container '%s': %s",
                    partNumber, mpu.blobName(), mpu.containerName(), bse.getMessage()), bse);
        } catch (IOException ioe) {
            throw new RuntimeException(String.format(
                    "Failed to upload part %d for blob '%s' in container '%s': %s",
                    partNumber, mpu.blobName(), mpu.containerName(), ioe.getMessage()), ioe);
        }

        String eTag = BaseEncoding.base16()
                .lowerCase().encode(md5Hash);
        Date lastModified = null;
        return MultipartPart.create(partNumber, contentLength, eTag, lastModified);
    }

    /**
     * Creates a BlockBlobAsyncClient with retries disabled for streaming uploads.
     * This allows us to stream directly from non-markable InputStreams without
     * needing temp files or buffering. The S3 client can retry the entire part
     * upload if needed.
     */
    private BlockBlobAsyncClient createNonRetryingBlockBlobAsyncClient(
            String container, String blobName) {
        var cred = creds.get();

        var clientBuilder = new BlobServiceClientBuilder()
                .endpoint(endpoint)
                .retryOptions(NO_RETRY_OPTIONS);

        if (!cred.identity.isEmpty() && !cred.credential.isEmpty()) {
            clientBuilder.credential(
                new AzureNamedKeyCredential(cred.identity, cred.credential));
        } else {
            clientBuilder.credential(new DefaultAzureCredentialBuilder().build());
        }

        return clientBuilder.buildAsyncClient()
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
                return ImmutableList.of();
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
            parts.add(MultipartPart.create(partNumber, properties.getSizeLong(),
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
            builder.add(MultipartUpload.create(container, targetBlobName,
                    uploadKey, null, null));
        }

        return builder.build();
    }

    @Override
    public long getMinimumMultipartPartSize() {
        return 1;
    }

    @Override
    public long getMaximumMultipartPartSize() {
        return 4000L * 1024 * 1024;
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
        return switch (tier) {
        case ARCHIVE -> AccessTier.ARCHIVE;
        case COOL -> AccessTier.COOL;
        case INFREQUENT -> AccessTier.COOL;
        case COLD -> AccessTier.COLD;
        case STANDARD -> AccessTier.HOT;
        };
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
        String rawId = String.format("%s:%05d", nonce, partNumber);
        return Base64.getEncoder().encodeToString(
                rawId.getBytes(StandardCharsets.UTF_8));
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
        } else if (code.equals(BlobErrorCode.BLOB_ALREADY_EXISTS)) {
            var request = HttpRequest.builder()
                    .method("PUT")
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
