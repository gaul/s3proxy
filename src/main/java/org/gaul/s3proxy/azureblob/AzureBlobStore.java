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
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.function.UnaryOperator;

import com.azure.core.credential.AccessToken;
import com.azure.core.credential.AzureNamedKeyCredential;
import com.azure.core.credential.AzureSasCredential;
import com.azure.core.credential.TokenCredential;
import com.azure.core.credential.TokenRequestContext;
import com.azure.core.http.HttpClient;
import com.azure.core.http.HttpHeaderName;
import com.azure.core.http.HttpHeaders;
import com.azure.core.http.HttpPipelineCallContext;
import com.azure.core.http.HttpPipelinePosition;
import com.azure.core.http.policy.AddHeadersFromContextPolicy;
import com.azure.core.http.policy.HttpPipelineSyncPolicy;
import com.azure.core.http.rest.PagedResponse;
import com.azure.core.http.rest.Response;
import com.azure.core.util.Context;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.storage.blob.BlobClient;
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
import com.azure.storage.blob.specialized.BlobClientBase;
import com.azure.storage.blob.specialized.BlobInputStream;
import com.azure.storage.blob.specialized.BlockBlobAsyncClient;
import com.azure.storage.common.policy.RequestRetryOptions;
import com.azure.storage.common.policy.RetryPolicyType;
import com.google.common.base.Strings;
import com.google.common.base.Supplier;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Iterators;
import com.google.common.collect.Lists;
import com.google.common.collect.PeekingIterator;

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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.services.s3.model.Bucket;
import software.amazon.awssdk.services.s3.model.BucketCannedACL;
import software.amazon.awssdk.services.s3.model.BucketVersioningStatus;
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
import software.amazon.awssdk.services.s3.model.DeleteMarkerEntry;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.DeleteObjectResponse;
import software.amazon.awssdk.services.s3.model.DeleteObjectsRequest;
import software.amazon.awssdk.services.s3.model.DeleteObjectsResponse;
import software.amazon.awssdk.services.s3.model.DeletedObject;
import software.amazon.awssdk.services.s3.model.GetBucketVersioningRequest;
import software.amazon.awssdk.services.s3.model.GetBucketVersioningResponse;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.HeadBucketRequest;
import software.amazon.awssdk.services.s3.model.HeadBucketResponse;
import software.amazon.awssdk.services.s3.model.HeadObjectRequest;
import software.amazon.awssdk.services.s3.model.HeadObjectResponse;
import software.amazon.awssdk.services.s3.model.ListBucketsRequest;
import software.amazon.awssdk.services.s3.model.ListBucketsResponse;
import software.amazon.awssdk.services.s3.model.ListObjectVersionsRequest;
import software.amazon.awssdk.services.s3.model.ListObjectVersionsResponse;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Response;
import software.amazon.awssdk.services.s3.model.MetadataDirective;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.s3.model.ObjectCannedACL;
import software.amazon.awssdk.services.s3.model.ObjectIdentifier;
import software.amazon.awssdk.services.s3.model.ObjectVersion;
import software.amazon.awssdk.services.s3.model.Part;
import software.amazon.awssdk.services.s3.model.PutBucketVersioningRequest;
import software.amazon.awssdk.services.s3.model.PutBucketVersioningResponse;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.awssdk.services.s3.model.S3Error;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.services.s3.model.S3Object;
import software.amazon.awssdk.services.s3.model.ServerSideEncryption;
import software.amazon.awssdk.services.s3.model.StorageClass;
import software.amazon.awssdk.services.s3.model.UploadPartCopyRequest;
import software.amazon.awssdk.services.s3.model.UploadPartCopyResponse;
import software.amazon.awssdk.services.s3.model.UploadPartRequest;
import software.amazon.awssdk.services.s3.model.UploadPartResponse;

public final class AzureBlobStore implements BlobStore {
    private static final Logger logger = LoggerFactory.getLogger(
            AzureBlobStore.class);
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
    /** S3's name for the version of an object written while unversioned. */
    private static final String NULL_VERSION_ID = "null";
    /**
     * Metadata marking a blob as an S3 delete marker.  Azure keeps none, so
     * a delete on a versioned store writes an empty blob carrying this,
     * which Azure versions like any other write; the google-cloud-storage
     * store marks its markers the same way.
     */
    private static final String DELETE_MARKER_KEY = "s3proxy_delete_marker";
    /**
     * Metadata marking a blob as S3's "null" version: one written while its
     * container's versioning was Suspended.  Azure versions every write on a
     * versioned account and gives each its own id, so the null version is
     * the newest version carrying this, reported and addressed as "null",
     * alongside the base blob written before the account was versioned,
     * which carries no id at all.
     */
    private static final String NULL_VERSION_KEY = "s3proxy_null_version";
    /**
     * Sorts after every Azure version id: the base blob written while the
     * account was unversioned has none, and is newer than every version
     * Azure lists before it.
     */
    private static final String NEWEST_ORDER = "\uffff";
    /**
     * Container metadata recording that S3 versioning is Suspended on it.
     * Azure versions per account, never per container, so the state S3 keeps
     * per bucket lives here, absent meaning Enabled; every instance of the
     * proxy reading the container sees the same answer.
     */
    private static final String VERSIONING_STATUS_KEY = "s3proxy_versioning";
    /**
     * Azure refuses to delete the current ("root") version of a blob by its
     * version id; the base blob has to be deleted instead.  No SDK constant
     * names this code, so it is interned here.
     */
    private static final BlobErrorCode OPERATION_NOT_ALLOWED_ON_ROOT_BLOB =
            BlobErrorCode.fromString("OperationNotAllowedOnRootBlob");
    /**
     * What Azure answers a delete by version id from a credential lacking
     * deleteBlobVersion -- Storage Blob Data Contributor, or a shared access
     * signature without x.  The code names the version Azure minted rather
     * than the missing permission, and no SDK constant names it.
     */
    private static final BlobErrorCode
            OPERATION_NOT_ALLOWED_ON_AUTOMATIC_SNAPSHOT = BlobErrorCode
                    .fromString("OperationNotAllowedOnAutomaticSnapshot");
    /**
     * How long after logging that a container's null versions cannot be
     * cleaned up the store says so again, rather than on every write.
     */
    private static final Duration CLEANUP_REFUSAL_LOG_INTERVAL =
            Duration.ofMinutes(5);
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
    private final Auth auth;
    /** The signature the client presents, under {@link Auth#SAS} only. */
    private final @Nullable AzureSasCredential sasCredential;
    /**
     * Report the ETag Azure mints under {@link #OPAQUE_ETAG_SUFFIX} rather
     * than bare.  S3 SDKs decode a dashless ETag as hex and abort the request
     * when they cannot, which Azure's is not.
     */
    private final boolean opaqueETags;
    /**
     * Whether to honor S3 versioning against this account.  Azure Blob
     * versioning is enabled per storage account on the management plane
     * (ARM); the data-plane SDK can neither turn it on nor read whether it is
     * on.  So the operator asserts it here -- "versioning is enabled on this
     * account" -- and only then does the store report {@link
     * #supportsVersioning} and map the version-aware operations onto the
     * native blob-version APIs.  Left false, every versioning request is
     * answered NotImplemented exactly as before.
     */
    private final boolean versioning;
    /**
     * When each container last logged that its credential cannot remove
     * the null versions suspended writes replace; see {@link
     * #reportCleanupRefusal}.
     */
    private final Map<String, Instant> cleanupRefusalsLogged =
            new ConcurrentHashMap<>();

    public AzureBlobStore(
            Supplier<Credentials> creds,
            String endpointUrl) {
        this(creds, endpointUrl, /*eTagMode=*/ "opaque");
    }

    public AzureBlobStore(
            Supplier<Credentials> creds,
            String endpointUrl,
            String eTagMode) {
        this(creds, endpointUrl, eTagMode, /*auth=*/ null);
    }

    /**
     * {@code auth} names how the store authenticates: {@code sas} with the
     * shared access signature in the session token, {@code key} with the
     * account name and key in the identity and credential, {@code default}
     * through {@code DefaultAzureCredential}, or {@code bearer} with a
     * Microsoft Entra access token in the session token that the
     * application obtained itself, for example from a sidecar or a token
     * broker that {@code DefaultAzureCredential} cannot read.  Left null,
     * the store uses {@code sas} if there is a session token, {@code key}
     * if there are an identity and a credential, and {@code default}
     * otherwise.
     *
     * <p>S3Proxy 3.x reached Microsoft Entra through jclouds.  Its {@code
     * jclouds.azureblob.auth=azureAd} took a client id and secret in the
     * identity and credential and fetched and renewed tokens itself; that
     * setup moves to {@code default}, where {@code DefaultAzureCredential}
     * does the same from {@code AZURE_TENANT_ID}, {@code AZURE_CLIENT_ID}
     * and {@code AZURE_CLIENT_SECRET}.  {@code bearer} replaces only the
     * setup in which {@code jclouds.oauth.credential-type} was overridden
     * so that the application supplied the access token itself.
     *
     * <p>Nothing in a {@code Credentials} says how long a bearer token
     * lasts, so the supplier is asked again for every request, as it is for
     * a shared access signature.  The store does not renew tokens itself:
     * it is the caller's responsibility that {@code creds} always returns
     * one that is still valid.  The endpoint must be https, since the Azure
     * client refuses to send a bearer token over http.  Server-side copies
     * sign their source URL with a user delegation key, so the token's
     * principal needs a role that includes {@code
     * generateUserDelegationKey}, such as Storage Blob Delegator; without
     * it reads and writes succeed but copies fail.
     */
    public AzureBlobStore(
            Supplier<Credentials> creds,
            String endpointUrl,
            String eTagMode,
            @Nullable String auth) {
        this(creds, endpointUrl, eTagMode, auth, /*versioning=*/ false);
    }

    /**
     * {@code versioning} asserts that the storage account has Blob
     * versioning on, so the store honors S3 versioning rather than answering
     * NotImplemented.
     */
    public AzureBlobStore(
            Supplier<Credentials> creds,
            String endpointUrl,
            String eTagMode,
            @Nullable String auth,
            boolean versioning) {
        this(creds, endpointUrl, eTagMode, auth, versioning,
                /*httpClient=*/ null);
    }

    /** {@code httpClient}, when given, carries the requests: for tests. */
    AzureBlobStore(
            Supplier<Credentials> creds,
            String endpointUrl,
            String eTagMode,
            @Nullable String auth,
            boolean versioning,
            @Nullable HttpClient httpClient) {
        this.versioning = versioning;
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
        var cred = creds.get();
        var blobServiceClientBuilder = new BlobServiceClientBuilder()
                // The oldest version that carries startFrom on List Blobs,
                // which list depends on.  Pinned rather than left at the
                // SDK's latest so that upgrading the SDK cannot ask a
                // service for a version it has never heard of.
                .serviceVersion(BlobServiceVersion.V2026_02_06)
                .endpoint(endpoint)
                .retryOptions(NO_RETRY_OPTIONS);
        if (httpClient != null) {
            blobServiceClientBuilder.httpClient(httpClient);
        }
        this.auth = auth == null ? Auth.infer(cred) : Auth.parse(auth, cred);
        AzureSasCredential sasCredential = null;
        if (this.auth == Auth.BEARER) {
            // The client sends the token as a bearer token, over TLS only,
            // and reads it from the supplier through SuppliedTokenCredential.
            blobServiceClientBuilder.credential(
                    new SuppliedTokenCredential(creds));
        } else if (this.auth == Auth.SAS) {
            // A shared access signature is the one Azure credential that
            // carries an expiry, so the client holds a mutable one that
            // SasRefreshPolicy re-reads from the supplier per request.
            sasCredential = new AzureSasCredential(
                    sasToken(requireNonNull(cred.sessionToken())));
            blobServiceClientBuilder
                    .credential(sasCredential)
                    .addPolicy(new SasRefreshPolicy(creds, sasCredential));
        } else if (this.auth == Auth.KEY) {
            // An account key does not expire, and the builder copies it out
            // of the credential rather than reading it again, so a supplier
            // that rotates one is followed no further than here.
            blobServiceClientBuilder.credential(
                new AzureNamedKeyCredential(cred.identity(),
                        cred.credential()));
        } else {
            // DefaultAzureCredential checks the environment, the workload
            // identity token file, managed identity and the developer tools.
            blobServiceClientBuilder.credential(
                new DefaultAzureCredentialBuilder().build());
        }
        this.sasCredential = sasCredential;
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
     * A shared access signature as the query string it has to become.  Azure
     * hands one out with a leading question mark, which appended as it came
     * would open a second query string.
     */
    private static String sasToken(String sessionToken) {
        return sessionToken.startsWith("?") ? sessionToken.substring(1) :
                sessionToken;
    }

    /**
     * The source URL a copy hands Azure, signed for read so that the service
     * can fetch it itself.  A store authenticating with a shared access
     * signature has no key to sign a fresh one with and so lends the source
     * the signature it presents everywhere else, the last one the supplier
     * named rather than whatever it holds this instant; one holding an account
     * key mints a signature per copy; one presenting a bearer token, or
     * holding nothing at all, borrows the account's own delegation key.
     */
    // TODO: is this the best way to generate a SAS URL?
    private String signedSourceUrl(BlobClient fromClient) {
        var expiryTime = OffsetDateTime.now().plusDays(1);
        var permission = new BlobSasPermission().setReadPermission(true);
        var values = new BlobServiceSasSignatureValues(expiryTime, permission)
                .setStartTime(OffsetDateTime.now());
        String token = switch (auth) {
        case SAS -> requireNonNull(sasCredential).getSignature();
        case KEY -> fromClient.generateSas(values);
        case BEARER, DEFAULT -> {
            var userDelegationKey = blobServiceClient.getUserDelegationKey(
                    OffsetDateTime.now().minusMinutes(5), expiryTime);
            yield fromClient.generateUserDelegationSas(values,
                    userDelegationKey);
        }
        };
        return sasSourceUrl(fromClient.getBlobUrl(), token);
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
        if (versioning) {
            return listLatest(request);
        }
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

    /**
     * ListObjectsV2 on a versioned store.  Azure's ordinary listing names only
     * blobs with a current version, but S3 lists every key whose latest
     * version is an object: a key whose current version was deleted by id
     * still holds the newest remaining one -- which reads of the key serve
     * -- and a key whose current version is a delete marker holds none.  So
     * the listing retrieves every version and reports each key by its
     * latest.
     *
     * <p>A key's versions can straddle Azure's pages, so paging resumes by
     * name, as listVersions does, rather than by Azure's continuation token:
     * the token handed out is the last name reported, which the next page
     * starts after.
     */
    private ListObjectsV2Response listLatest(ListObjectsV2Request request) {
        String container = request.bucket();
        String token = request.continuationToken();
        String after = token != null ? decodeListToken(token) :
                request.startAfter();
        int maxKeys = request.maxKeys() == null ? 1000 : request.maxKeys();
        var options = new ListBlobsOptions()
                .setPrefix(request.prefix())
                .setStartFrom(after)
                .setMaxResultsPerPage(
                        Math.max(1, Math.min(maxKeys + 1, 5000)))
                .setDetails(new BlobListDetails()
                        .setRetrieveVersions(true)
                        .setRetrieveMetadata(true));
        var client = blobServiceClient.getBlobContainerClient(container);
        try {
            return latestPage(client.listBlobsByHierarchy(
                    request.delimiter(), options, /*timeout=*/ null)
                    .iterator(), after, maxKeys);
        } catch (BlobStorageException bse) {
            throw translate(bse, container, /*key=*/ null);
        }
    }

    /**
     * Maps Azure's version rows, in the order Azure lists them, onto one page
     * of a ListObjectsV2 response: each key once, by its latest version
     * ({@link #latestVersion}), unless that is a delete marker; each prefix
     * once; at most {@code maxKeys} of them, after {@code after}, which S3
     * excludes and Azure's startFrom includes.
     */
    ListObjectsV2Response latestPage(Iterator<BlobItem> rows,
            @Nullable String after, int maxKeys) {
        var contents = ImmutableList.<S3Object>builder();
        var prefixes = ImmutableList.<CommonPrefix>builder();
        PeekingIterator<BlobItem> it = Iterators.peekingIterator(rows);
        String last = null;
        boolean truncated = false;
        int count = 0;
        while (it.hasNext()) {
            BlobItem first = it.next();
            String name = first.getName();
            boolean prefix = Boolean.TRUE.equals(first.isPrefix());
            var versions = new ArrayList<BlobItem>();
            versions.add(first);
            while (!prefix && it.hasNext() &&
                    !Boolean.TRUE.equals(it.peek().isPrefix()) &&
                    it.peek().getName().equals(name)) {
                versions.add(it.next());
            }
            if (after != null && name.compareTo(after) <= 0) {
                continue;
            }
            BlobItem latest = prefix ? first : latestVersion(versions);
            if (!prefix && isDeleteMarker(latest.getMetadata())) {
                continue;
            }
            if (count == maxKeys) {
                truncated = true;
                break;
            }
            if (prefix) {
                prefixes.add(SdkResponses.commonPrefix(name));
            } else {
                var properties = latest.getProperties();
                contents.add(SdkResponses.objectEntry(name,
                        reportETag(properties.getETag()),
                        properties.getLastModified().toInstant(),
                        properties.getContentLength(),
                        fromAccessTier(properties.getAccessTier())));
            }
            ++count;
            last = name;
        }
        // S3 reports a listing that asks for no keys as complete.
        return SdkResponses.objectsPage(contents.build(), prefixes.build(),
                truncated && maxKeys > 0 ?
                        encodeListToken(requireNonNull(last)) : null);
    }

    /** The continuation token naming where a listing resumes: after name. */
    static String encodeListToken(String name) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(
                name.getBytes(StandardCharsets.UTF_8));
    }

    static String decodeListToken(String token) {
        try {
            return new String(Base64.getUrlDecoder().decode(token),
                    StandardCharsets.UTF_8);
        } catch (IllegalArgumentException iae) {
            throw S3Exceptions.invalidArgument(
                    "The continuation token provided is incorrect");
        }
    }

    private static boolean isDeleteMarker(
            @Nullable Map<String, String> metadata) {
        return metadata != null &&
                "true".equals(metadata.get(DELETE_MARKER_KEY));
    }

    /**
     * Whether a version is one written while its container was Suspended.
     * Only the newest of these is the null version; see {@link #nullVersion}.
     */
    static boolean isNullVersionTagged(
            @Nullable Map<String, String> metadata) {
        return metadata != null &&
                "true".equals(metadata.get(NULL_VERSION_KEY));
    }

    /**
     * The version id S3 knows a version of a versioned store by: "null" for
     * the base blob written before the account was versioned, which carries
     * no id, and for a version written while Suspended, whose Azure id the
     * caller never sees; otherwise Azure's own id.
     */
    static String reportedVersionId(@Nullable String versionId,
            @Nullable Map<String, String> metadata) {
        return versionId == null || isNullVersionTagged(metadata) ?
                NULL_VERSION_ID : versionId;
    }

    /**
     * A caller's user metadata less the entries the store keeps for itself.
     * An object written with {@code x-amz-meta-s3proxy_delete_marker: true}
     * would otherwise read as a delete marker -- 404 to GET, hidden from
     * listings -- one claiming {@code s3proxy_null_version} would stand in
     * for the null version, and one naming a multipart target would redirect
     * an upload.  Metadata names are case insensitive, so any spelling of
     * these is dropped, as S3 has no such names to keep.  Reads drop them
     * too, so that the store's own entries never reach a caller, nor ride
     * along on a copy.
     */
    static Map<String, String> withoutReservedMetadata(
            Map<String, String> metadata) {
        if (metadata.keySet().stream().noneMatch(
                AzureBlobStore::isReservedMetadataKey)) {
            return metadata;
        }
        var kept = new LinkedHashMap<String, String>(metadata);
        kept.keySet().removeIf(AzureBlobStore::isReservedMetadataKey);
        return kept;
    }

    /**
     * The metadata a version of a versioned store reports: what the caller
     * wrote, without the entries {@link #withoutReservedMetadata} keeps out.
     * An unversioned store reports what Azure holds, as it always has.
     */
    private @Nullable Map<String, String> reportedMetadata(
            @Nullable Map<String, String> metadata) {
        if (!versioning || metadata == null) {
            return metadata;
        }
        return withoutReservedMetadata(metadata);
    }

    /**
     * The metadata a write lands with: the caller's, tagged as the null
     * version when it is written while its container is Suspended.
     */
    static Map<String, String> withNullVersionTag(
            Map<String, String> metadata, boolean suspended) {
        if (!suspended) {
            return metadata;
        }
        var tagged = new LinkedHashMap<String, String>(metadata);
        tagged.put(NULL_VERSION_KEY, "true");
        return tagged;
    }

    /**
     * The version id a write reports.  One landing as the null version
     * reports none, as the transient store does: there is no version to
     * point the caller at, only the one the next suspended write replaces.
     * It stays addressable as "null".
     */
    private static @Nullable String writtenVersionId(
            @Nullable String versionId, @Nullable NullVersionWrite pending) {
        return pending != null ? null : versionId;
    }

    private static boolean isReservedMetadataKey(String key) {
        return key.equalsIgnoreCase(DELETE_MARKER_KEY) ||
                key.equalsIgnoreCase(NULL_VERSION_KEY) ||
                key.equalsIgnoreCase(TARGET_BLOB_NAME_METADATA);
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

    /**
     * Reads the version a request names, or the current one.  On a versioned
     * store a key whose current version was deleted by id has none until
     * another write, where S3 makes the newest remaining version current;
     * that version is read instead, as the google-cloud-storage store does,
     * and a delete marker there answers as one.
     */
    @Override
    public ResponseInputStream<GetObjectResponse> getBlob(
            GetObjectRequest request) {
        try {
            return readBlob(request);
        } catch (NoSuchKeyException nske) {
            String newest = promotedVersion(nske, request.bucket(),
                    request.key(), request.versionId());
            return readBlob(request.toBuilder().versionId(newest).build());
        }
    }

    private ResponseInputStream<GetObjectResponse> readBlob(
            GetObjectRequest request) {
        String container = request.bucket();
        String key = request.key();
        var client = blobServiceClient.getBlobContainerClient(container)
                .getBlobClient(key);
        if (request.versionId() != null) {
            // Read the named version rather than the current one; every
            // getProperties/openInputStream below then addresses that version.
            client = versionClient(client, container, key,
                    request.versionId());
            // openInputStream defers its first service call, so a malformed or
            // unknown versionId would otherwise fail mid-stream in the frontend
            // as a 500.  Probe the version's properties up front to surface it
            // as the 400/404 S3 answers instead.
            BlobProperties named;
            try {
                named = client.getProperties();
            } catch (BlobStorageException bse) {
                // An absent blob or version answers 404 through translate,
                // matching how the openInputStream read below reports one --
                // getBlob no longer returns null for an absent object.
                throw translate(bse, container, key, request.versionId());
            }
            if (versioning && isDeleteMarker(named.getMetadata())) {
                throw deleteMarkerNamed(request.versionId());
            }
        }
        // Azure rejects the literal If-None-Match: * with 400
        // UnsatisfiableCondition rather than treating it as "matches any
        // existing blob", so emulate the S3 semantics here: an existing blob
        // fails the precondition (412, which the frontend maps to 304 for
        // GET/HEAD) and a missing blob falls through to 404.
        if ("*".equals(request.ifNoneMatch())) {
            BlobProperties current;
            try {
                current = client.getProperties();
            } catch (BlobStorageException bse) {
                throw translate(bse, container, key, request.versionId());
            }
            if (versioning && isDeleteMarker(current.getMetadata())) {
                throw S3Exceptions.noSuchKeyDeleteMarker(container, key,
                        reportedVersionId(current.getVersionId(),
                                current.getMetadata()),
                        "current version is a delete marker");
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
                    throw translate(bse, container, key, request.versionId());
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
            throw translate(bse, container, key, request.versionId());
        }
        var properties = blobStream.getProperties();
        if (versioning && isDeleteMarker(properties.getMetadata())) {
            blobStream.close();
            if (request.versionId() != null) {
                throw deleteMarkerNamed(request.versionId());
            }
            throw S3Exceptions.noSuchKeyDeleteMarker(container, key,
                    reportedVersionId(properties.getVersionId(),
                            properties.getMetadata()),
                    "current version is a delete marker");
        }
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
                .metadata(reportedMetadata(properties.getMetadata()))
                .serverSideEncryption(
                        reportedSse(properties.isServerEncrypted()))
                .versionId(versioning ? reportedVersionId(
                        properties.getVersionId(), properties.getMetadata()) :
                        properties.getVersionId())
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

    @Override
    public boolean supportsVersioning() {
        return versioning;
    }

    /**
     * Reports the container's versioning: Enabled, or Suspended once a caller
     * has suspended it.  When {@link #versioning} is set the operator has
     * asserted the account has versioning turned on (ARM), and the data plane
     * offers no way to read the setting back, so a container nobody has
     * suspended answers Enabled -- never the empty status of a bucket that
     * was never versioned, since a store that reports {@link
     * #supportsVersioning} treats the account as versioned throughout.
     */
    @Override
    public GetBucketVersioningResponse getBucketVersioning(
            GetBucketVersioningRequest request) {
        return GetBucketVersioningResponse.builder()
                .status(versioningStatus(containerMetadata(request.bucket())))
                .build();
    }

    /**
     * Enables or suspends versioning on one container.  Azure versions every
     * write on the account whatever is asked, so neither changes what Azure
     * keeps; Suspended is recorded on the container ({@link
     * #VERSIONING_STATUS_KEY}) and changes what the store makes of the
     * versions it writes there: each write replaces the null version rather
     * than adding one (see {@link #replaceNullVersion}).
     *
     * <p>Azure replaces a container's metadata whole and conditions the
     * replacement on no ETag, so the entry is merged into what the container
     * already holds, and a write of the container's metadata by something
     * else between the read and the write here is lost.  S3Proxy writes no
     * other container metadata.
     */
    @Override
    public PutBucketVersioningResponse putBucketVersioning(
            PutBucketVersioningRequest request) {
        String container = request.bucket();
        var configuration = request.versioningConfiguration();
        var metadata = containerMetadata(container);
        if (configuration == null || configuration.status() == null) {
            return PutBucketVersioningResponse.builder().build();
        }
        var updated = withVersioningStatus(metadata, configuration.status());
        if (updated != null) {
            try {
                blobServiceClient.getBlobContainerClient(container)
                        .setMetadata(updated);
            } catch (BlobStorageException bse) {
                throw translate(bse, container, /*key=*/ null);
            }
        }
        return PutBucketVersioningResponse.builder().build();
    }

    /**
     * A container's metadata, which also refuses a versioning request for a
     * container that does not exist: a store that reports {@link
     * #supportsVersioning} is trusted by the frontend to answer NoSuchBucket
     * itself.
     */
    private Map<String, String> containerMetadata(String container) {
        try {
            var metadata = blobServiceClient.getBlobContainerClient(container)
                    .getProperties().getMetadata();
            return metadata == null ? Map.of() : metadata;
        } catch (BlobStorageException bse) {
            throw translate(bse, container, /*key=*/ null);
        }
    }

    /** The S3 versioning state a container's metadata records. */
    static BucketVersioningStatus versioningStatus(
            Map<String, String> containerMetadata) {
        for (var entry : containerMetadata.entrySet()) {
            if (entry.getKey().equalsIgnoreCase(VERSIONING_STATUS_KEY) &&
                    BucketVersioningStatus.SUSPENDED.toString()
                            .equalsIgnoreCase(entry.getValue())) {
                return BucketVersioningStatus.SUSPENDED;
            }
        }
        return BucketVersioningStatus.ENABLED;
    }

    /**
     * A container's metadata recording {@code status}, keeping every other
     * entry, or null when it already records it.  Enabled is recorded as the
     * entry's absence, so a container never suspended carries none.
     */
    static @Nullable Map<String, String> withVersioningStatus(
            Map<String, String> containerMetadata,
            BucketVersioningStatus status) {
        var updated = new LinkedHashMap<String, String>(containerMetadata);
        updated.keySet().removeIf(
                key -> key.equalsIgnoreCase(VERSIONING_STATUS_KEY));
        if (status == BucketVersioningStatus.SUSPENDED) {
            updated.put(VERSIONING_STATUS_KEY,
                    BucketVersioningStatus.SUSPENDED.toString());
        }
        return updated.equals(containerMetadata) ? null : updated;
    }

    /**
     * Whether a write to the container lands as the null version.  Asked of
     * the container on every write rather than cached, so that every proxy
     * instance in front of it agrees the moment one suspends it; that costs
     * one request per write on a versioned store.
     *
     * <p>A credential refused the container's properties -- a container
     * service SAS, or an account SAS without resource type c -- is refused
     * the write too, as AccessDenied naming what it lacks.  It cannot tell
     * whether someone else, with a broader credential, has suspended the
     * container, and writing as Enabled when it has would leave a version
     * S3 would have replaced, silently.
     */
    private boolean isSuspended(String container) {
        if (!versioning) {
            return false;
        }
        Map<String, String> metadata;
        try {
            metadata = blobServiceClient.getBlobContainerClient(container)
                    .getProperties().getMetadata();
        } catch (BlobStorageException bse) {
            if (bse.getStatusCode() == 403 || bse.getStatusCode() == 401) {
                throw S3Exceptions.accessDenied(("s3proxy.azureblob." +
                        "versioning is on, so a write reads the properties" +
                        " of container %s to learn whether versioning is" +
                        " Suspended, and Azure refused them (%s).  Grant" +
                        " Microsoft.Storage/storageAccounts/blobServices/" +
                        "containers/read, or use an account SAS with" +
                        " resource type c; a container service SAS cannot" +
                        " read container properties.").formatted(container,
                        bse.getErrorCode()), bse);
            }
            throw translate(bse, container, /*key=*/ null);
        }
        return versioningStatus(metadata == null ? Map.of() : metadata) ==
                BucketVersioningStatus.SUSPENDED;
    }

    /**
     * Lists a container's object versions.  Azure returns a row per version
     * when asked to retrieve them, each carrying its own version id and its
     * metadata, which map onto S3's Version entries -- or DeleteMarker
     * entries, for the empty blobs a versioned delete writes in their place.
     *
     * <p>Paging uses S3's own (key, version-id) markers rather than Azure's
     * continuation token: the listing restarts from the key marker, which
     * Azure's startFrom includes, and drops what the client has already
     * seen.  Azure lists a key's versions oldest first where S3 lists them
     * newest first, so a key is gathered whole before any of it is reported,
     * and a page that ends inside a key -- even one whose versions straddle
     * Azure pages -- resumes inside it.
     */
    @Override
    public ListObjectVersionsResponse listVersions(
            ListObjectVersionsRequest request) {
        String container = request.bucket();
        var client = blobServiceClient.getBlobContainerClient(container);
        int maxKeys = request.maxKeys() == null ? 1000 : request.maxKeys();
        var options = new ListBlobsOptions()
                .setPrefix(request.prefix())
                .setStartFrom(request.keyMarker())
                .setMaxResultsPerPage(
                        Math.max(1, Math.min(maxKeys + 1, 5000)))
                .setDetails(new BlobListDetails()
                        .setRetrieveVersions(true)
                        .setRetrieveMetadata(true));
        try {
            return versionsPage(client.listBlobsByHierarchy(
                    request.delimiter(), options, /*timeout=*/ null)
                    .iterator(),
                    request.keyMarker(), request.versionIdMarker(), maxKeys);
        } catch (BlobStorageException bse) {
            throw translate(bse, container, /*key=*/ null);
        }
    }

    /**
     * Maps Azure's version rows, in the order Azure lists them, onto one page
     * of a ListObjectVersions response: each key's versions newest first, at
     * most {@code maxKeys} entries, after the (key, version-id) marker.  The
     * marker's key is listed again by startFrom; its versions up to and
     * including the marker's are dropped, or all of them when the marker
     * names no version, as S3 does.  The latest version is the one
     * {@link #latestVersion} picks.  Rows tagged as delete markers are
     * reported as DeleteMarker entries.
     */
    ListObjectVersionsResponse versionsPage(Iterator<BlobItem> rows,
            @Nullable String keyMarker, @Nullable String versionIdMarker,
            int maxKeys) {
        var entries = new ArrayList<ObjectVersion>();
        var markers = new ArrayList<DeleteMarkerEntry>();
        var prefixes = ImmutableList.<CommonPrefix>builder();
        PeekingIterator<BlobItem> it = Iterators.peekingIterator(rows);
        String lastKey = null;
        String lastVersionId = null;
        boolean truncated = false;
        int count = 0;
        rows:
        while (it.hasNext()) {
            BlobItem first = it.next();
            String name = first.getName();
            if (Boolean.TRUE.equals(first.isPrefix())) {
                if (keyMarker != null && name.compareTo(keyMarker) <= 0) {
                    continue;
                }
                if (count == maxKeys) {
                    truncated = true;
                    break;
                }
                prefixes.add(SdkResponses.commonPrefix(name));
                ++count;
                lastKey = name;
                lastVersionId = null;
                continue;
            }
            var versions = new ArrayList<BlobItem>();
            versions.add(first);
            while (it.hasNext() && !Boolean.TRUE.equals(it.peek().isPrefix()) &&
                    it.peek().getName().equals(name)) {
                versions.add(it.next());
            }
            if (keyMarker != null && name.compareTo(keyMarker) < 0) {
                continue;
            }
            BlobItem latest = latestVersion(versions);
            BlobItem nullVersion = nullVersion(versions);
            String resumeBefore = null;
            if (name.equals(keyMarker) && versionIdMarker != null) {
                resumeBefore = !versionIdMarker.equals(NULL_VERSION_ID) ?
                        versionIdMarker : nullVersion != null ?
                        listingOrder(nullVersion) : NEWEST_ORDER;
            }
            for (var version : Lists.reverse(versions)) {
                if (version != nullVersion &&
                        isNullVersionTagged(version.getMetadata())) {
                    // A null version a later one replaced, which S3 no
                    // longer has; see replaceNullVersion.
                    continue;
                }
                String vid = version == nullVersion ? NULL_VERSION_ID :
                        requireNonNull(version.getVersionId());
                if (name.equals(keyMarker) && (resumeBefore == null ||
                        listingOrder(version).compareTo(resumeBefore) >= 0)) {
                    continue;
                }
                if (count == maxKeys) {
                    truncated = true;
                    break rows;
                }
                if (isDeleteMarker(version.getMetadata())) {
                    markers.add(DeleteMarkerEntry.builder()
                            .key(name)
                            .versionId(vid)
                            .isLatest(version == latest)
                            .lastModified(versionTime(version))
                            .build());
                } else {
                    entries.add(objectVersion(version, vid,
                            version == latest));
                }
                ++count;
                lastKey = name;
                lastVersionId = vid;
            }
        }

        var builder = ListObjectVersionsResponse.builder()
                .versions(entries)
                .deleteMarkers(markers)
                .commonPrefixes(prefixes.build())
                .isTruncated(truncated);
        if (truncated) {
            // A page with room for nothing resumes where it was asked to.
            builder.nextKeyMarker(lastKey != null ? lastKey : keyMarker)
                    .nextVersionIdMarker(lastKey != null ? lastVersionId :
                            versionIdMarker);
        }
        return builder.build();
    }

    /**
     * Where a version sits in S3's newest-first order of one key, for paging
     * by version-id marker: Azure version ids are UTC timestamps that sort
     * as strings.  The marker "null" no longer says where -- a null version
     * written while Suspended can be older than versions written after
     * versioning was enabled again -- so it is resolved to the version it
     * names before it is compared.
     */
    private static String listingOrder(BlobItem version) {
        return version.getVersionId() != null ? version.getVersionId() :
                NEWEST_ORDER;
    }

    /**
     * Which of a key's versions, in the order Azure lists them, is S3's null
     * version, or null when it has none: the base blob while it carries no
     * version id -- written before the account was versioned -- or else the
     * newest version written while its container was Suspended.  A suspended
     * write removes the null version it replaces only once it has landed, so
     * for a moment, or for good when that removal fails, a key can hold more
     * than one tagged version; only the newest stands for the null version.
     */
    static @Nullable BlobItem nullVersion(List<BlobItem> versions) {
        BlobItem tagged = null;
        for (var version : versions) {
            if (version.getVersionId() == null) {
                return version;
            }
            if (isNullVersionTagged(version.getMetadata()) &&
                    (tagged == null || version.getVersionId().compareTo(
                            tagged.getVersionId()) > 0)) {
                tagged = version;
            }
        }
        return tagged;
    }

    /**
     * The version of a key that S3 calls latest, from its rows in the order
     * Azure lists them (oldest first): the one Azure flags current or,
     * failing that, the one with no version id -- a blob written while the
     * account was unversioned, which Azure lists last and leaves unflagged
     * though a plain read serves it -- or, failing both, the newest: a key
     * whose current version was deleted by id has none flagged, and S3
     * promotes the newest remaining one, as reads of the key do here.
     */
    static BlobItem latestVersion(List<BlobItem> versions) {
        for (var version : versions) {
            if (Boolean.TRUE.equals(version.isCurrentVersion())) {
                return version;
            }
        }
        for (var version : versions) {
            if (version.getVersionId() == null) {
                return version;
            }
        }
        return versions.get(versions.size() - 1);
    }

    /**
     * When a version was written.  Azure's version id is that moment to a
     * tenth of a microsecond, where the Last-Modified it lists is whole
     * seconds; a PUT and the delete marker after it commonly share a second,
     * and the frontend, which interleaves versions and markers by this time,
     * would then put the older version first.  A version never changes once
     * written, so its id's time is its last modification.  The version
     * written while unversioned has no id and keeps its Last-Modified.
     */
    static @Nullable Instant versionTime(BlobItem version) {
        if (version.getVersionId() != null) {
            try {
                return Instant.parse(version.getVersionId());
            } catch (java.time.format.DateTimeParseException dtpe) {
                // Not a timestamp, as Azurite's ids may not be: fall back.
            }
        }
        var modified = version.getProperties().getLastModified();
        return modified == null ? null : modified.toInstant();
    }

    private ObjectVersion objectVersion(BlobItem blob, String versionId,
            boolean latest) {
        var properties = blob.getProperties();
        return ObjectVersion.builder()
                .key(blob.getName())
                .versionId(versionId)
                .isLatest(latest)
                .lastModified(versionTime(blob))
                .eTag(reportETag(properties.getETag()))
                .size(properties.getContentLength())
                .storageClass(fromAccessTier(
                        properties.getAccessTier()).toString())
                .build();
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

            NullVersionWrite pending = nullVersionWrite(container, client);
            var metadata = withNullVersionTag(
                    withoutReservedMetadata(request.metadata()),
                    pending != null);

            AccessTier tier = null;
            if (request.storageClass() != null &&
                    request.storageClass() != StorageClass.STANDARD) {
                tier = toAccessTier(request.storageClass());
            }

            BlobRequestConditions requestConditions = writeConditions(
                    client, request.ifMatch(), request.ifNoneMatch());

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
                if (pending != null) {
                    replaceNullVersion(client, uploaded.getVersionId(),
                            pending);
                }
                return SdkResponses.putResponse(reportETag(
                        uploaded.getETag()))
                        .toBuilder()
                        .serverSideEncryption(
                                reportedSse(uploaded.isServerEncrypted()))
                        .versionId(writtenVersionId(
                                uploaded.getVersionId(), pending))
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
            if (pending != null) {
                replaceNullVersion(client, properties.getVersionId(),
                        pending);
            }
            return SdkResponses.putResponse(reportETag(
                    properties.getETag()))
                    .toBuilder()
                    .serverSideEncryption(
                            reportedSse(properties.isServerEncrypted()))
                    .versionId(writtenVersionId(properties.getVersionId(),
                            pending))
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

    /**
     * Appends a SAS token to a source blob URL.  A version client's URL
     * already carries a {@code ?versionid=} query, so the token must join
     * with {@code &}; a bare {@code ?} would double it and Azure answers
     * CannotVerifyCopySource.
     */
    static String sasSourceUrl(String url, String token) {
        return url + (url.contains("?") ? "&" : "?") + token;
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
        String fromContainer = request.sourceBucket();
        String fromName = request.sourceKey();
        boolean replace =
                request.metadataDirective() == MetadataDirective.REPLACE;
        if (request.acl() == ObjectCannedACL.PUBLIC_READ) {
            // Matches setBlobAccess: Azure grants read at the container, so a
            // public copy is refused rather than silently made private.
            throw new UnsupportedOperationException("unsupported in Azure");
        }
        var fromClient = blobServiceClient
                .getBlobContainerClient(fromContainer)
                .getBlobClient(fromName);
        if (request.sourceVersionId() != null) {
            // Copy from the named source version: the version client's URL
            // carries the versionId query the service copies that version by.
            fromClient = versionClient(fromClient, fromContainer, fromName,
                    request.sourceVersionId());
        }
        CopySource source = copySource(fromClient, fromContainer, fromName,
                request.sourceVersionId());
        fromClient = source.client();
        var sourceUrl = signedSourceUrl(fromClient);
        var azureOptions = new BlobUploadFromUrlOptions(sourceUrl);
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
        // A versioned copy sets its metadata in the same request rather than
        // after it: setting metadata is a write of its own, which Azure
        // versions, so following the copy with one would leave the copy an
        // extra version carrying the wrong metadata and report the id of
        // that one rather than the copy's.
        NullVersionWrite pending = nullVersionWrite(
                request.destinationBucket(), client);
        Map<String, String> versionedMetadata = null;
        var context = Context.NONE;
        if (versioning) {
            var sourceProperties = requireNonNull(source.properties());
            versionedMetadata = copiedMetadata(sourceProperties.getMetadata(),
                    request.metadata(), replace, pending != null);
            headers = copiedHeaders(sourceProperties, headers);
            azureOptions.setCopySourceBlobProperties(false);
            context = new Context(
                    AddHeadersFromContextPolicy.AZURE_REQUEST_HTTP_HEADERS_KEY,
                    metadataHeaders(versionedMetadata));
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
                    azureOptions, /*timeout=*/ null, context);

            // TODO: cannot do this as part of uploadFromUrlWithResponse?
            if (replace && !versioning) {
                client.setMetadata(
                        withoutReservedMetadata(request.metadata()));
            }

            var copied = response.getValue();
            if (pending != null) {
                replaceNullVersion(client, copied.getVersionId(), pending);
            }
            return SdkResponses.copyResponse(reportETag(copied.getETag()),
                    copied.getLastModified() == null ? null :
                            copied.getLastModified().toInstant())
                    .toBuilder()
                    .serverSideEncryption(
                            reportedSse(copied.isServerEncrypted()))
                    .versionId(writtenVersionId(copied.getVersionId(),
                            pending))
                    .build();
        } catch (BlobStorageException bse) {
            if (bse.getStatusCode() != 501) {
                throw translate(bse, fromContainer, fromName,
                        request.sourceVersionId());
            }
            // Azurite does not implement Put Blob From URL (501
            // APINotImplemented); fall back to the classic asynchronous
            // Copy Blob API, which it does implement.  Request metadata
            // replaces the source metadata as with S3's REPLACE directive,
            // but content headers can only be set after the copy.
            // TODO: remove this fallback after upgrading to Azurite 3.38.0,
            // which implements Put Blob From URL (Azure/Azurite#2749).
            try {
                var copyOptions = new BlobBeginCopyOptions(sourceUrl)
                        .setPollInterval(Duration.ofMillis(10));
                if (versionedMetadata != null) {
                    // Copy Blob, like Put Blob From URL, copies the source's
                    // metadata when handed none.
                    copyOptions.setMetadata(versionedMetadata);
                } else if (replace) {
                    copyOptions.setMetadata(
                            withoutReservedMetadata(request.metadata()));
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
                if (pending != null) {
                    replaceNullVersion(client, properties.getVersionId(),
                            pending);
                }
                return SdkResponses.copyResponse(
                        reportETag(properties.getETag()),
                        properties.getLastModified() == null ? null :
                                properties.getLastModified().toInstant())
                        .toBuilder()
                        .serverSideEncryption(
                                reportedSse(properties.isServerEncrypted()))
                        .versionId(writtenVersionId(properties.getVersionId(),
                                pending))
                        .build();
            } catch (BlobStorageException bse2) {
                throw translate(bse2, fromContainer, fromName,
                        request.sourceVersionId());
            }
        }
    }

    @Override
    public DeleteObjectResponse removeBlob(DeleteObjectRequest request) {
        if (request.ifMatchSize() != null ||
                request.ifMatchLastModifiedTime() != null) {
            // Azure conditions a delete on the blob's ETag or on a time
            // range, neither of which expresses S3's size or its equality
            // on the exact time.
            throw new UnsupportedOperationException(
                    "conditional delete not supported");
        }
        // The literal "null" names the null version, which on an
        // unversioned namespace is the object itself; on a versioned one it
        // is a version like any other, and maybe not there.
        String versionId = request.versionId();
        boolean namesVersion = versionId != null &&
                (versioning || !versionId.equals(NULL_VERSION_ID));
        if (namesVersion && !versioning) {
            throw new UnsupportedOperationException(
                    "versioning not supported");
        }
        String ifMatch = backendCondition(request.ifMatch());
        if (namesVersion && ifMatch != null) {
            // S3 itself refuses If-Match on a delete naming a version, 501
            // NotImplemented whether or not the ETag matches, and honors it
            // only on a delete of the current object; refuse it the same
            // way rather than carry out a delete S3 would not.
            throw new UnsupportedOperationException(
                    "conditional delete of a version not supported");
        }
        var client = blobServiceClient.getBlobContainerClient(request.bucket())
                .getBlobClient(request.key());
        try {
            if (namesVersion && versionId.equals(NULL_VERSION_ID)) {
                deleteNullVersion(client);
            } else if (namesVersion) {
                // A versioned delete removes the one version named.
                deleteVersion(client, versionId);
            } else if (versioning) {
                // S3 lays a delete marker over the key, even one that holds
                // nothing, and keeps every version under it.  Azure keeps no
                // markers, so one is written: an empty blob tagged as one,
                // which Azure versions over the current blob like any write.
                // While Suspended the marker is the null version, and
                // replaces the one the key had, as any suspended write does.
                NullVersionWrite pending = nullVersionWrite(request.bucket(),
                        client);
                var options = new BlockBlobSimpleUploadOptions(
                        new ByteArrayInputStream(new byte[0]), 0)
                        .setMetadata(withNullVersionTag(
                                Map.of(DELETE_MARKER_KEY, "true"),
                                pending != null));
                if (ifMatch != null) {
                    options.setRequestConditions(
                            new BlobRequestConditions().setIfMatch(ifMatch));
                }
                var marker = client.getBlockBlobClient().uploadWithResponse(
                        options, /*timeout=*/ null, Context.NONE).getValue();
                if (pending != null) {
                    replaceNullVersion(client, marker.getVersionId(), pending);
                }
                return DeleteObjectResponse.builder()
                        .deleteMarker(true)
                        .versionId(pending != null ? NULL_VERSION_ID :
                                marker.getVersionId())
                        .build();
            } else if (ifMatch == null) {
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
            throw translate(bse, request.bucket(), request.key(), versionId);
        }
        var builder = DeleteObjectResponse.builder();
        if (namesVersion) {
            builder.versionId(versionId);
        }
        return builder.build();
    }

    /**
     * The version a read of a key's current version falls to when the key
     * has none: the newest remaining one, which S3 makes current once the
     * current version is deleted by id.  Rethrows {@code nske} when the read
     * named a version, the store is unversioned, the key's current version
     * is a delete marker, or nothing remains; a marker as the newest version
     * answers as the delete marker it is.
     */
    private String promotedVersion(NoSuchKeyException nske, String container,
            String key, @Nullable String versionId) {
        if (!versioning || versionId != null || nske.awsErrorDetails()
                .sdkHttpResponse().firstMatchingHeader("x-amz-delete-marker")
                .isPresent()) {
            throw nske;
        }
        BlobItem newest = newestVersion(blobServiceClient
                .getBlobContainerClient(container).getBlobClient(key));
        if (newest == null) {
            throw nske;
        }
        if (isDeleteMarker(newest.getMetadata())) {
            throw S3Exceptions.noSuchKeyDeleteMarker(container, key,
                    reportedVersionId(newest.getVersionId(),
                            newest.getMetadata()),
                    "current version is a delete marker");
        }
        return newest.getVersionId();
    }

    /**
     * The newest version of a blob, delete markers included, or null.
     *
     * <p>Finding it lists the container's versions, which a credential
     * allowed to read and write blobs may still be refused -- an account SAS
     * without resource type c, say.  That refusal answers 403 AccessDenied
     * naming the permission, as S3 answers a missing key to a caller that
     * may not list the bucket, rather than the 500 an untranslated Azure
     * error becomes, or a NoSuchKey that would deny a version which may be
     * there.
     */
    private static @Nullable BlobItem newestVersion(BlobClientBase base) {
        BlobItem newest = null;
        try {
            for (BlobItem blob : versions(base)) {
                if (blob.getVersionId() != null && (newest == null ||
                        blob.getVersionId().compareTo(
                                newest.getVersionId()) > 0)) {
                    newest = blob;
                }
            }
        } catch (BlobStorageException bse) {
            String container = base.getContainerName();
            if (bse.getStatusCode() == 403 || bse.getStatusCode() == 401) {
                throw S3Exceptions.accessDenied(("s3proxy.azureblob." +
                        "versioning is on, so a read, copy or If-None-Match" +
                        " write of key %s, which has no current version," +
                        " lists its versions in container %s to find the" +
                        " newest remaining one, and Azure refused the" +
                        " listing (%s).  Grant Microsoft.Storage/" +
                        "storageAccounts/blobServices/containers/blobs/read" +
                        " (Storage Blob Data Reader or above), or use a SAS" +
                        " with permission l and, for an account SAS," +
                        " resource type c.").formatted(base.getBlobName(),
                        container, bse.getErrorCode()), bse);
            }
            throw translate(bse, container, base.getBlobName());
        }
        return newest;
    }

    /**
     * S3's answer to a read naming a delete marker's version: 405, since a
     * marker stands for no object, saying which version is the marker.
     */
    private static S3Exception deleteMarkerNamed(String versionId) {
        return S3Exceptions.fromStatusCode(405, /*eTag=*/ null,
                Map.of("x-amz-delete-marker", "true",
                        "x-amz-version-id", versionId),
                /*cause=*/ null);
    }

    /**
     * The condition a write's If-None-Match: * stands for on a versioned
     * store.  A key whose current version is a delete marker holds no
     * object, so the write must succeed -- replacing that marker, under its
     * ETag -- and a key whose current version was deleted by id still holds
     * the newest remaining one, so the write must fail.
     */
    private @Nullable BlobRequestConditions writeConditions(
            BlobClientBase base,
            @Nullable String ifMatch, @Nullable String ifNoneMatch) {
        if (ifMatch == null && ifNoneMatch == null) {
            return null;
        }
        var conditions = new BlobRequestConditions()
                .setIfMatch(backendCondition(ifMatch))
                .setIfNoneMatch(backendCondition(ifNoneMatch));
        if (!versioning || ifMatch != null || !"*".equals(ifNoneMatch)) {
            return conditions;
        }
        try {
            var current = base.getProperties();
            if (isDeleteMarker(current.getMetadata())) {
                return new BlobRequestConditions().setIfMatch(
                        current.getETag());
            }
        } catch (BlobStorageException bse) {
            if (!BlobErrorCode.BLOB_NOT_FOUND.equals(bse.getErrorCode())) {
                throw bse;
            }
            BlobItem newest = newestVersion(base);
            if (newest != null && !isDeleteMarker(newest.getMetadata())) {
                throw S3Exceptions.fromStatusCode(412);
            }
        }
        return conditions;
    }

    /**
     * The blob a copy reads on a versioned store.  A source whose current
     * version is a delete marker holds no object, and one naming a marker
     * outright is refused as S3 refuses it; a source whose current version
     * was deleted by id is read from its newest remaining version.  An
     * unversioned store copies what it is given.
     */
    private CopySource copySource(BlobClient source, String container,
            String key, @Nullable String versionId) {
        if (!versioning) {
            return new CopySource(source, /*properties=*/ null);
        }
        BlobProperties properties;
        try {
            properties = source.getProperties();
        } catch (BlobStorageException bse) {
            if (versionId != null ||
                    !BlobErrorCode.BLOB_NOT_FOUND.equals(bse.getErrorCode())) {
                throw translate(bse, container, key, versionId);
            }
            String newest = promotedVersion(
                    S3Exceptions.noSuchKey(container, key, bse.getMessage()),
                    container, key, /*versionId=*/ null);
            var promoted = source.getVersionClient(newest);
            try {
                return new CopySource(promoted, promoted.getProperties());
            } catch (BlobStorageException raced) {
                throw translate(raced, container, key, newest);
            }
        }
        if (isDeleteMarker(properties.getMetadata())) {
            if (versionId != null) {
                throw S3Exceptions.invalidRequest("The source of a copy " +
                        "request may not specifically refer to a delete " +
                        "marker by version id.");
            }
            throw S3Exceptions.noSuchKeyDeleteMarker(container, key,
                    reportedVersionId(properties.getVersionId(),
                            properties.getMetadata()),
                    "current version is a delete marker");
        }
        return new CopySource(source, properties);
    }

    /**
     * The blob a copy reads, and on a versioned store its properties, which
     * the copy lands with: see {@link #copiedHeaders}.
     */
    private record CopySource(BlobClient client,
            @Nullable BlobProperties properties) { }

    /**
     * The metadata a copy on a versioned store lands with: the request's
     * under REPLACE, else the source's, less the store's own entries either
     * way -- a copy of a null version made while Enabled is no null version
     * itself -- and tagged as the null version when the destination is
     * Suspended.
     */
    static Map<String, String> copiedMetadata(
            @Nullable Map<String, String> source,
            Map<String, String> requested, boolean replace,
            boolean suspended) {
        Map<String, String> metadata = replace ? requested :
                source == null ? Map.of() : source;
        return withNullVersionTag(withoutReservedMetadata(metadata),
                suspended);
    }

    /**
     * The content headers a copy on a versioned store lands with: the
     * source's, each overridden by the one REPLACE names, as Put Blob From
     * URL merges them when it copies the source's properties itself.  A
     * versioned copy declines that, because it would copy the source's
     * metadata along with them whenever the copy names none -- the null
     * version's tag among it.
     */
    private static BlobHttpHeaders copiedHeaders(BlobProperties source,
            BlobHttpHeaders requested) {
        return new BlobHttpHeaders()
                .setCacheControl(requested.getCacheControl() != null ?
                        requested.getCacheControl() :
                        source.getCacheControl())
                .setContentDisposition(
                        requested.getContentDisposition() != null ?
                        requested.getContentDisposition() :
                        source.getContentDisposition())
                .setContentEncoding(requested.getContentEncoding() != null ?
                        requested.getContentEncoding() :
                        source.getContentEncoding())
                .setContentLanguage(requested.getContentLanguage() != null ?
                        requested.getContentLanguage() :
                        source.getContentLanguage())
                .setContentType(requested.getContentType() != null ?
                        requested.getContentType() : source.getContentType())
                .setContentMd5(source.getContentMd5());
    }

    /**
     * Metadata as the x-ms-meta-* request headers that carry it, for a call
     * whose options cannot: Put Blob From URL takes metadata, and the SDK's
     * options for it do not.  The client's pipeline adds headers handed to
     * it through the call's context ({@link AddHeadersFromContextPolicy})
     * before the request is signed.
     */
    static HttpHeaders metadataHeaders(Map<String, String> metadata) {
        var headers = new HttpHeaders();
        for (var entry : metadata.entrySet()) {
            headers.set(HttpHeaderName.fromString(
                    "x-ms-meta-" + entry.getKey()), entry.getValue());
        }
        return headers;
    }

    /**
     * The client addressing one version of a blob.  "null" names S3's null
     * version: on an unversioned store the object itself, and on a versioned
     * one the version {@link #nullVersion} picks -- the base blob while it
     * carries no version id, a blob written while the account was
     * unversioned, or else the newest version written while the container
     * was Suspended, which is the current one when it was the last write and
     * is otherwise found by listing the key's versions.  A key without one
     * answers NoSuchVersion, as S3 does, rather than handing Azure a version
     * id it rejects as malformed.
     */
    private BlobClient versionClient(BlobClient base, String container,
            String key, String versionId) {
        if (!versionId.equals(NULL_VERSION_ID)) {
            return base.getVersionClient(versionId);
        }
        if (!versioning) {
            return base;
        }
        try {
            BlobProperties properties = base.getProperties();
            if (properties.getVersionId() == null) {
                return base;
            }
            if (isNullVersionTagged(properties.getMetadata())) {
                return base.getVersionClient(properties.getVersionId());
            }
        } catch (BlobStorageException bse) {
            if (!BlobErrorCode.BLOB_NOT_FOUND.equals(bse.getErrorCode())) {
                throw translate(bse, container, key);
            }
        }
        BlobItem nullVersion;
        try {
            nullVersion = nullVersion(versions(base));
        } catch (BlobStorageException bse) {
            throw translate(bse, container, key);
        }
        if (nullVersion == null || nullVersion.getVersionId() == null) {
            throw S3Exceptions.noSuchVersion(container, key, versionId,
                    "no null version");
        }
        return base.getVersionClient(nullVersion.getVersionId());
    }

    /**
     * Every version of one blob, delete markers included, with its metadata,
     * in the order Azure lists them: oldest first, then the base blob when
     * it carries no version id.
     */
    private static List<BlobItem> versions(BlobClientBase base) {
        var options = new ListBlobsOptions()
                .setPrefix(base.getBlobName())
                .setDetails(new BlobListDetails()
                        .setRetrieveVersions(true)
                        .setRetrieveMetadata(true));
        var versions = new ArrayList<BlobItem>();
        for (BlobItem blob : base.getContainerClient().listBlobs(options,
                /*timeout=*/ null)) {
            if (blob.getName().equals(base.getBlobName())) {
                versions.add(blob);
            }
        }
        return versions;
    }

    /**
     * Removes S3's null version: the base blob while it carries no version
     * id, or else every version written while the container was Suspended
     * -- the newest of which is the null version, and any older one a null
     * version a suspended write replaced but did not get to remove.  A key
     * with no null version is left as it is and the delete still succeeds,
     * as S3 answers it.  The base blob is deleted under the ETag it was
     * checked by, so a write landing after the check is not removed in its
     * place.
     *
     * <p>Deleting the base blob of a versioned account does not discard it:
     * Azure keeps its content as a non-current version under an id of its
     * own minting, where S3 removes the null version for good.  That version
     * is found by the ETag the null version had and removed as well.  A
     * tagged null version that is current is removed as {@link
     * #deleteVersion} removes any current version, which leaves the newest
     * remaining one to be promoted.
     */
    private static void deleteNullVersion(BlobClient base) {
        BlobProperties properties = null;
        try {
            properties = base.getProperties();
        } catch (BlobStorageException bse) {
            if (!isAbsent(bse)) {
                throw bse;
            }
            if (BlobErrorCode.CONTAINER_NOT_FOUND.equals(bse.getErrorCode())) {
                return;
            }
        }
        if (properties == null || properties.getVersionId() != null) {
            for (BlobItem version : versions(base)) {
                if (version.getVersionId() != null &&
                        isNullVersionTagged(version.getMetadata())) {
                    try {
                        deleteVersion(base, version.getVersionId());
                    } catch (BlobStorageException bse) {
                        if (!isAbsent(bse)) {
                            throw bse;
                        }
                    }
                }
            }
            return;
        }
        String eTag = properties.getETag();
        try {
            base.deleteWithResponse(
                    /*deleteBlobSnapshotOptions=*/ null,
                    new BlobRequestConditions().setIfMatch(eTag),
                    /*timeout=*/ null, Context.NONE);
        } catch (BlobStorageException raced) {
            if (!BlobErrorCode.CONDITION_NOT_MET.equals(
                    raced.getErrorCode()) && !isAbsent(raced)) {
                throw raced;
            }
            return;
        }
        deleteVersionsWithETag(base, eTag, /*except=*/ null);
    }

    /**
     * Removes the versions Azure minted for a base blob it versioned when
     * the base blob was deleted or overwritten -- found by the ETag the base
     * blob had, which Azure keeps on the version -- other than {@code
     * except}.
     */
    private static void deleteVersionsWithETag(BlobClientBase base,
            String eTag, @Nullable String except) {
        for (BlobItem blob : versions(base)) {
            if (blob.getVersionId() != null &&
                    !blob.getVersionId().equals(except) &&
                    eTag.equals(blob.getProperties().getETag())) {
                base.getVersionClient(blob.getVersionId()).delete();
            }
        }
    }

    /**
     * What a write about to land while its container is Suspended knows of
     * the null version it replaces, for {@link #replaceNullVersion}: the
     * ETag of the base blob when that is the null version.  Written before
     * the account was versioned, it has no id to be found by once the write
     * makes Azure version it.
     */
    record NullVersionWrite(@Nullable String legacyETag) { }

    /**
     * Null unless the write about to land on {@code base} lands as S3's null
     * version, its container being Suspended.  Costs the container's
     * properties on every write to a versioned store, and the blob's on a
     * suspended one.
     */
    private @Nullable NullVersionWrite nullVersionWrite(String container,
            BlobClientBase base) {
        if (!isSuspended(container)) {
            return null;
        }
        try {
            BlobProperties properties = base.getProperties();
            return new NullVersionWrite(properties.getVersionId() == null ?
                    properties.getETag() : null);
        } catch (BlobStorageException bse) {
            if (!isAbsent(bse)) {
                throw translate(bse, container, base.getBlobName());
            }
            return new NullVersionWrite(/*legacyETag=*/ null);
        }
    }

    /**
     * Permanently removes the null version a suspended write replaced, once
     * the write has landed as version {@code written}: S3 keeps one null
     * version per key, where Azure has kept the one before as a version of
     * its own.
     *
     * <p>The write goes first so that a failure between the two leaves an
     * extra version rather than none: the write's own version is the newer,
     * so it is the one {@link #nullVersion} reports, and the older is hidden
     * from listings and removed by the next suspended write or by a delete
     * of the null version.  Only null versions older than {@code written}
     * are removed, so of two suspended writes racing, the later survives
     * whichever finishes first.
     *
     * <p>A failure to remove one is logged rather than failing a write that
     * has already happened: the client would retry it, adding a version of
     * its own.  A credential refused the removal -- one without
     * deleteBlobVersion, which Storage Blob Data Contributor lacks -- will be
     * refused it on every suspended overwrite, each leaving a hidden version
     * behind, so that is logged at ERROR naming the permission, at most once
     * per container per {@link #CLEANUP_REFUSAL_LOG_INTERVAL}; any other
     * failure is presumed passing and logged at WARN.
     */
    private void replaceNullVersion(BlobClientBase base,
            @Nullable String written, NullVersionWrite pending) {
        if (written == null) {
            // Azure minted no version, so the account is not versioned
            // after all, and the write replaced the base blob outright.
            return;
        }
        try {
            for (String versionId : replacedNullVersions(versions(base),
                    written, pending.legacyETag())) {
                try {
                    base.getVersionClient(versionId).delete();
                } catch (BlobStorageException bse) {
                    if (!isAbsent(bse)) {
                        throw bse;
                    }
                }
            }
        } catch (BlobStorageException bse) {
            String container = base.getContainerName();
            if (!isPermissionRefusal(bse)) {
                logger.warn("could not remove the null version that {}" +
                        " replaced in {}", base.getBlobName(), container,
                        bse);
            } else if (reportCleanupRefusal(container, Instant.now())) {
                logger.error("Azure refused ({}) to remove the null version" +
                        " that {} replaced in Suspended container {}, so" +
                        " hidden versions will accumulate there until it" +
                        " is granted Microsoft.Storage/storageAccounts/" +
                        "blobServices/containers/blobs/deleteBlobVersion/" +
                        "action (Storage Blob Data Owner or a custom role;" +
                        " SAS permission x).  Logged at most once per {}" +
                        " minutes per container.", bse.getErrorCode(),
                        base.getBlobName(), container,
                        CLEANUP_REFUSAL_LOG_INTERVAL.toMinutes(), bse);
            }
        }
    }

    /** Whether Azure refused the request for want of a permission. */
    static boolean isPermissionRefusal(BlobStorageException bse) {
        return bse.getStatusCode() == 403 || bse.getStatusCode() == 401 ||
                OPERATION_NOT_ALLOWED_ON_AUTOMATIC_SNAPSHOT.equals(
                        bse.getErrorCode());
    }

    /**
     * Whether to log, at {@code now}, that the credential cannot remove the
     * null versions suspended writes to {@code container} replace: true at
     * most once per {@link #CLEANUP_REFUSAL_LOG_INTERVAL} per container, so
     * a busy one does not log on every write.
     */
    boolean reportCleanupRefusal(String container, Instant now) {
        Instant last = cleanupRefusalsLogged.get(container);
        if (last == null) {
            return cleanupRefusalsLogged.putIfAbsent(container, now) == null;
        }
        return !now.isBefore(last.plus(CLEANUP_REFUSAL_LOG_INTERVAL)) &&
                cleanupRefusalsLogged.replace(container, last, now);
    }

    /**
     * The versions a suspended write that landed as {@code written} replaced,
     * from the key's versions as Azure lists them: those written while
     * Suspended before it, and the one Azure minted for the base blob that
     * was the null version, found by its ETag.
     */
    static List<String> replacedNullVersions(List<BlobItem> versions,
            String written, @Nullable String legacyETag) {
        var replaced = new ArrayList<String>();
        for (BlobItem version : versions) {
            String versionId = version.getVersionId();
            if (versionId == null || versionId.equals(written)) {
                continue;
            }
            if ((isNullVersionTagged(version.getMetadata()) &&
                    versionId.compareTo(written) < 0) ||
                    (legacyETag != null && legacyETag.equals(
                            version.getProperties().getETag()))) {
                replaced.add(versionId);
            }
        }
        return replaced;
    }

    /**
     * Permanently removes one version.  Azure refuses to delete the current
     * ("root") version by id -- OperationNotAllowedOnRootBlob -- so when that
     * is the version named, delete the base blob first, which demotes it to a
     * non-current version, then remove it by id.  That leaves the key with
     * no current version; reads and listings then take the newest remaining
     * one as current, which is S3's promotion (see {@link #getBlob}).
     *
     * <p>The base blob is deleted only while it still is the version named:
     * a write landing between the refusal and that delete would otherwise
     * have its own fresh version demoted, leaving the key with no current
     * version.  The condition is the named version's ETag, which the base
     * blob carries for as long as that version is current; when the
     * condition fails, or the base blob is already gone, something else has
     * demoted the version and it can simply be removed.
     */
    private static void deleteVersion(BlobClient base, String versionId) {
        var version = base.getVersionClient(versionId);
        try {
            version.delete();
        } catch (BlobStorageException bse) {
            if (!OPERATION_NOT_ALLOWED_ON_ROOT_BLOB.equals(
                    bse.getErrorCode())) {
                throw bse;
            }
            String eTag = version.getProperties().getETag();
            try {
                base.deleteWithResponse(
                        /*deleteBlobSnapshotOptions=*/ null,
                        new BlobRequestConditions().setIfMatch(eTag),
                        /*timeout=*/ null, Context.NONE);
            } catch (BlobStorageException raced) {
                if (!BlobErrorCode.CONDITION_NOT_MET.equals(
                        raced.getErrorCode()) && !isAbsent(raced)) {
                    throw raced;
                }
            }
            version.delete();
        }
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
        // A batch names blobs by URL alone and cannot carry a per-object
        // versionId, nor write the delete marker a versioned delete leaves,
        // so a versioned store takes the per-object path, which routes each
        // through removeBlob and reports the markers it writes.
        if (versioning) {
            return BlobStore.super.removeBlobs(request);
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

    /** As {@link #getBlob}, for the version's properties alone. */
    @Override
    public HeadObjectResponse blobMetadata(HeadObjectRequest request) {
        try {
            return readMetadata(request);
        } catch (NoSuchKeyException nske) {
            String newest = promotedVersion(nske, request.bucket(),
                    request.key(), request.versionId());
            return readMetadata(request.toBuilder().versionId(newest).build());
        }
    }

    private HeadObjectResponse readMetadata(HeadObjectRequest request) {
        String container = request.bucket();
        var client = blobServiceClient.getBlobContainerClient(container)
                .getBlobClient(request.key());
        if (request.versionId() != null) {
            client = versionClient(client, container, request.key(),
                    request.versionId());
        }
        BlobProperties properties;
        try {
            properties = client.getProperties();
        } catch (BlobStorageException bse) {
            throw translate(bse, container, request.key(),
                    request.versionId());
        }
        if (versioning && isDeleteMarker(properties.getMetadata())) {
            if (request.versionId() != null) {
                throw deleteMarkerNamed(request.versionId());
            }
            throw S3Exceptions.noSuchKeyDeleteMarker(container, request.key(),
                    reportedVersionId(properties.getVersionId(),
                            properties.getMetadata()),
                    "current version is a delete marker");
        }
        @SuppressWarnings("deprecation")
        HeadObjectResponse head = HeadObjectResponse.builder()
                .metadata(reportedMetadata(properties.getMetadata()))
                .serverSideEncryption(
                        reportedSse(properties.isServerEncrypted()))
                .versionId(versioning ? reportedVersionId(
                        properties.getVersionId(), properties.getMetadata()) :
                        properties.getVersionId())
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

        var userMetadata = withoutReservedMetadata(request.metadata());
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
        // userMetadata holds no spelling of the store's own names, so the
        // target entry added here is the only one.
        var stubMetadata = new java.util.LinkedHashMap<String, String>();
        stubMetadata.putAll(userMetadata);
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

        NullVersionWrite pending = nullVersionWrite(mpu.containerName(),
                client);
        userMetadata = withNullVersionTag(userMetadata, pending != null);

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
        var conditions = writeConditions(client, request.ifMatch(),
                request.ifNoneMatch());
        if (conditions != null) {
            options.setRequestConditions(conditions);
        }

        try {
            var response = client.commitBlockListWithResponse(
                    options, /*timeout=*/ null, /*context=*/ null);

            stubBlobClient.delete();

            var committed = response.getValue();
            if (pending != null) {
                replaceNullVersion(client, committed.getVersionId(), pending);
            }
            String finalETag = reportETag(committed.getETag());
            return SdkResponses.completeResponse(finalETag)
                    .toBuilder()
                    .serverSideEncryption(
                            reportedSse(committed.isServerEncrypted()))
                    .versionId(writtenVersionId(committed.getVersionId(),
                            pending))
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
        String sourceVersionId = request.sourceVersionId();
        if (sourceVersionId != null && !versioning) {
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
        var fromClient = blobServiceClient
                .getBlobContainerClient(request.sourceBucket())
                .getBlobClient(request.sourceKey());
        if (sourceVersionId != null) {
            // As in copyBlob, the version client's URL carries the versionId
            // query the service copies that version by.
            fromClient = versionClient(fromClient, request.sourceBucket(),
                    request.sourceKey(), sourceVersionId);
        }
        fromClient = copySource(fromClient, request.sourceBucket(),
                request.sourceKey(), sourceVersionId).client();

        var options = new BlockBlobStageBlockFromUrlOptions(blockId,
                signedSourceUrl(fromClient))
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
            throw translate(bse, request.sourceBucket(), request.sourceKey(),
                    sourceVersionId);
        }
        return SdkResponses.copiedPart(eTag, /*lastModified=*/ null,
                sourceVersionId);
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
        return translate(bse, container, key, /*versionId=*/ null);
    }

    /**
     * As {@link #translate(BlobStorageException, String, String)} for a
     * request naming a version.  Azure answers a version the blob does not
     * have 404 BlobNotFound, the same as for a blob that is not there, where
     * S3 says NoSuchVersion; a container that is not there is still
     * NoSuchBucket.
     */
    static RuntimeException translate(BlobStorageException bse,
            String container, @Nullable String key,
            @Nullable String versionId) {
        var code = bse.getErrorCode();
        if (versionId != null && !versionId.equals(NULL_VERSION_ID) &&
                BlobErrorCode.BLOB_NOT_FOUND.equals(code)) {
            return S3Exceptions.noSuchVersion(container, key, versionId,
                    bse.getMessage());
        }
        if (code == null) {
            // Azure names no x-ms-error-code for a malformed query parameter
            // -- a versionId that is no version id, say -- on any method, not
            // only a HEAD; fall back to the HTTP status so a client error
            // stays a client error rather than becoming the 500 a raw
            // exception would.
            int status = bse.getStatusCode();
            if (status == 403 || status == 401) {
                return S3Exceptions.fromStatusCode(403, bse);
            }
            if (status == 400 && versionId != null) {
                // S3 answers a versionId it cannot parse with InvalidArgument;
                // a bare 400 would become BadDigest, which says to retry.
                return S3Exceptions.invalidArgument(
                        "Invalid version id specified");
            }
            if (status == 400) {
                return S3Exceptions.fromStatusCode(400, bse);
            }
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
        } else if (code.equals(BlobErrorCode.INVALID_QUERY_PARAMETER_VALUE)) {
            // A query parameter Azure rejects by name.  S3 answers such a
            // request 400 rather than the 500 an unmapped Azure error would
            // otherwise become.
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

    /** How the store authenticates to Azure. */
    private enum Auth {
        /** A shared access signature in the session token. */
        SAS,
        /** The account name and key in the identity and credential. */
        KEY,
        /** A Microsoft Entra access token in the session token. */
        BEARER,
        /** Whatever DefaultAzureCredential finds. */
        DEFAULT;

        /** The mode that the parts of {@code cred} present imply. */
        static Auth infer(Credentials cred) {
            if (!Strings.isNullOrEmpty(cred.sessionToken())) {
                return SAS;
            } else if (!cred.identity().isEmpty() &&
                    !cred.credential().isEmpty()) {
                return KEY;
            } else {
                return DEFAULT;
            }
        }

        /** The mode {@code auth} names, checked against {@code cred}. */
        static Auth parse(String auth, Credentials cred) {
            var mode = switch (auth) {
            case "sas" -> SAS;
            case "key" -> KEY;
            case "bearer" -> BEARER;
            case "default" -> DEFAULT;
            default -> throw new IllegalArgumentException("Invalid auth: " +
                    auth + ".  Supported values: sas, key, bearer, default");
            };
            boolean satisfied = switch (mode) {
            case SAS, BEARER -> !Strings.isNullOrEmpty(cred.sessionToken());
            case KEY -> !cred.identity().isEmpty() &&
                    !cred.credential().isEmpty();
            case DEFAULT -> true;
            };
            if (!satisfied) {
                throw new IllegalArgumentException("auth " + auth +
                        " needs " + (mode == KEY ?
                        "an identity and a credential" : "a session token"));
            }
            return mode;
        }
    }

    /**
     * Bearer tokens read from the credential supplier.  Nothing in a
     * Credentials names how long the token it carries lasts, so each one is
     * handed over already lapsed and the supplier is asked again for the
     * next request rather than a withdrawn token being presented twice.
     */
    private static final class SuppliedTokenCredential
            implements TokenCredential {
        private final Supplier<Credentials> creds;

        SuppliedTokenCredential(Supplier<Credentials> creds) {
            this.creds = creds;
        }

        @Override
        public Mono<AccessToken> getToken(TokenRequestContext request) {
            return Mono.fromSupplier(() -> {
                String sessionToken = creds.get().sessionToken();
                if (Strings.isNullOrEmpty(sessionToken)) {
                    throw new IllegalStateException(
                            "Credential supplier named no session token");
                }
                return new AccessToken(sessionToken, OffsetDateTime.now());
            });
        }
    }

    /**
     * Re-reads the shared access signature from the credential supplier
     * before each request, so a signature that expires gives way to its
     * successor without the client being rebuilt.  It runs per call rather
     * than per retry because Azure signs between the two, and this client
     * retries nothing of its own in any case.
     */
    private static final class SasRefreshPolicy
            extends HttpPipelineSyncPolicy {
        private final Supplier<Credentials> creds;
        private final AzureSasCredential credential;

        SasRefreshPolicy(Supplier<Credentials> creds,
                AzureSasCredential credential) {
            this.creds = creds;
            this.credential = credential;
        }

        @Override
        public HttpPipelinePosition getPipelinePosition() {
            return HttpPipelinePosition.PER_CALL;
        }

        @Override
        protected void beforeSendingRequest(HttpPipelineCallContext context) {
            String sessionToken = creds.get().sessionToken();
            if (!Strings.isNullOrEmpty(sessionToken)) {
                credential.update(sasToken(sessionToken));
            }
        }
    }
}
