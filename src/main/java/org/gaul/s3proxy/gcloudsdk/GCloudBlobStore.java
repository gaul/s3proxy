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

package org.gaul.s3proxy.gcloudsdk;

import static java.util.Objects.requireNonNull;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.SequenceInputStream;
import java.net.URI;
import java.nio.channels.Channels;
import java.nio.charset.StandardCharsets;
import java.security.DigestInputStream;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.google.api.gax.paging.Page;
import com.google.auth.oauth2.AccessToken;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.auth.oauth2.ServiceAccountCredentials;
import com.google.cloud.NoCredentials;
import com.google.cloud.ReadChannel;
import com.google.cloud.ServiceOptions;
import com.google.cloud.http.HttpTransportOptions;
import com.google.cloud.storage.Acl;
import com.google.cloud.storage.Blob;
import com.google.cloud.storage.BlobId;
import com.google.cloud.storage.BlobInfo;
import com.google.cloud.storage.BlobWriteSessionConfigs;
import com.google.cloud.storage.Bucket;
import com.google.cloud.storage.BucketInfo;
import com.google.cloud.storage.CopyWriter;
import com.google.cloud.storage.Storage;
import com.google.cloud.storage.Storage.BlobField;
import com.google.cloud.storage.Storage.BlobGetOption;
import com.google.cloud.storage.Storage.BlobListOption;
import com.google.cloud.storage.Storage.BlobSourceOption;
import com.google.cloud.storage.Storage.BlobTargetOption;
import com.google.cloud.storage.Storage.BlobWriteOption;
import com.google.cloud.storage.Storage.BucketField;
import com.google.cloud.storage.Storage.BucketGetOption;
import com.google.cloud.storage.Storage.BucketListOption;
import com.google.cloud.storage.Storage.ComposeRequest;
import com.google.cloud.storage.Storage.CopyRequest;
import com.google.cloud.storage.StorageBatchResult;
import com.google.cloud.storage.StorageException;
import com.google.cloud.storage.StorageOptions;
import com.google.common.base.Strings;
import com.google.common.base.Supplier;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.collect.AbstractIterator;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Iterables;
import com.google.common.collect.Iterators;
import com.google.common.collect.Lists;
import com.google.common.collect.Streams;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.UncheckedExecutionException;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.Credentials;
import org.gaul.s3proxy.blobstore.MD5;
import org.gaul.s3proxy.blobstore.S3Exceptions;
import org.gaul.s3proxy.blobstore.SdkRequests;
import org.gaul.s3proxy.blobstore.SdkResponses;
import org.gaul.s3proxy.blobstore.UploadListings;
import org.gaul.s3proxy.blobstore.UploadNames;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.jspecify.annotations.Nullable;

import software.amazon.awssdk.core.ResponseInputStream;
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
import software.amazon.awssdk.services.s3.model.GetObjectAclRequest;
import software.amazon.awssdk.services.s3.model.GetObjectAclResponse;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.HeadBucketRequest;
import software.amazon.awssdk.services.s3.model.HeadBucketResponse;
import software.amazon.awssdk.services.s3.model.HeadObjectRequest;
import software.amazon.awssdk.services.s3.model.HeadObjectResponse;
import software.amazon.awssdk.services.s3.model.ListBucketsRequest;
import software.amazon.awssdk.services.s3.model.ListBucketsResponse;
import software.amazon.awssdk.services.s3.model.ListMultipartUploadsRequest;
import software.amazon.awssdk.services.s3.model.ListMultipartUploadsResponse;
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
import software.amazon.awssdk.services.s3.model.StorageClass;
import software.amazon.awssdk.services.s3.model.UploadPartCopyRequest;
import software.amazon.awssdk.services.s3.model.UploadPartCopyResponse;
import software.amazon.awssdk.services.s3.model.UploadPartRequest;
import software.amazon.awssdk.services.s3.model.UploadPartResponse;

public final class GCloudBlobStore implements BlobStore {
    /**
     * Where the store keeps its multipart bookkeeping, reserved from
     * client keys and hidden from listings.  Within it, an upload's stub is
     * named by its key and upload ID under {@link #UPLOADS_PREFIX}, so that
     * GCS lists the uploads in S3's order and ListMultipartUploads reads one
     * page of them; its parts lie apart under {@link #PARTS_PREFIX}.  A
     * stub whose key is too long for that name is kept under
     * {@link #LONG_UPLOADS_PREFIX} by its upload ID alone.  Uploads begun
     * before this layout lie directly under the prefix and are no longer
     * found; they stay hidden, and deleting the bucket removes them.
     */
    private static final String STUB_BLOB_PREFIX = ".s3proxy/stubs/";
    /** The first name that sorts after everything under the prefix. */
    private static final String STUB_BLOB_PREFIX_END = ".s3proxy/stubs0";
    private static final String UPLOADS_PREFIX = STUB_BLOB_PREFIX + "u/";
    private static final String LONG_UPLOADS_PREFIX = STUB_BLOB_PREFIX + "l/";
    private static final String PARTS_PREFIX = STUB_BLOB_PREFIX + "p/";
    /** GCS's longest object name, in bytes of UTF-8. */
    private static final int MAX_NAME_BYTES = 1024;
    private static final String TARGET_BLOB_NAME_KEY =
            "s3proxy_target_blob_name";
    private static final String BLOB_ACCESS_KEY = "s3proxy_blob_access";
    // GCS has no delete markers: a versioned delete archives the live
    // generation and a later read is a plain 404.  S3's marker is emulated
    // as a zero-byte generation wearing this metadata, hidden from
    // unversioned listings and reads.
    private static final String DELETE_MARKER_KEY = "s3proxy_delete_marker";
    // S3's version an object holds where versioning never applied.  GCS
    // assigns real generations from the first write, so only an unversioned
    // container resolves it, as the live object.
    private static final String NULL_VERSION_ID = "null";
    // GCS deprecated md5Match in favor of crc32cMatch but the client
    // supplies a Content-MD5 to validate, not a CRC32C.
    @SuppressWarnings("deprecation")
    private static final BlobWriteOption MD5_MATCH =
            BlobWriteOption.md5Match();
    // GCS compose supports up to 32 source objects
    private static final int MAX_COMPOSE_PARTS = 32;
    /** How many deletes GCS accepts in one batch request. */
    private static final int MAX_BATCH_DELETES = 100;
    /** How many entries GCS answers one listing request with at most. */
    private static final int MAX_LIST_PAGE_SIZE = 1000;
    // The chunk an upload buffers, which the SDK defaults to 15 MiB and
    // allocates twice: once as the ByteBuffer it reads the payload into and
    // again as the write channel's own array.
    private static final int MAX_UPLOAD_CHUNK_SIZE = 15 * 1024 * 1024;
    // The unit GCS accepts a resumable chunk in, and the SDK's rounding unit.
    private static final int UPLOAD_CHUNK_UNIT = 256 * 1024;
    // The suffix S3 gives an ETag of an object assembled from parts, which
    // S3 SDKs take as a value they must not verify against the payload.
    private static final String OPAQUE_ETAG_SUFFIX = "-1";

    private final Storage storage;
    private final boolean atomicBucketAcl;
    /**
     * Report an object's MD5 as its ETag, as S3 does, rather than the token
     * GCS mints.  See {@link #reportETag(BlobInfo)}.
     */
    private final boolean md5ETags;
    /**
     * Whether a container versions objects, which decides if writes report
     * version ids and deletes leave markers.  S3 asks this on every
     * operation while GCS answers only through bucket metadata, so the
     * answer is cached briefly; putBucketVersioning through this store
     * updates it immediately, and a change made behind its back is seen
     * within the expiry.
     */
    private final Cache<String, Boolean> versionedContainers =
            CacheBuilder.newBuilder()
                    .expireAfterWrite(java.time.Duration.ofSeconds(5))
                    .maximumSize(1000)
                    .build();
    /**
     * Whether a container has uniform bucket-level access, which decides if
     * a write can name its object's ACL.  Asked on every write and answered
     * only through bucket metadata, so cached as briefly as versioning is.
     */
    private final Cache<String, Boolean> uniformAccessContainers =
            CacheBuilder.newBuilder()
                    .expireAfterWrite(java.time.Duration.ofSeconds(5))
                    .maximumSize(1000)
                    .build();

    public GCloudBlobStore(
            Supplier<Credentials> creds,
            String endpointUrl) {
        this(creds, endpointUrl, /*eTagMode=*/ "md5");
    }

    public GCloudBlobStore(
            Supplier<Credentials> creds,
            String endpointUrl,
            String eTagMode) {
        this.md5ETags = switch (eTagMode) {
        case "md5" -> true;
        case "native" -> false;
        default -> throw new IllegalArgumentException(
                "Invalid ETag mode: " + eTagMode + ".  Supported modes:" +
                " md5, native");
        };
        var cred = creds.get();
        var storageBuilder = StorageOptions.newBuilder();
        // Fail rather than hanging forever on a stale connection.
        storageBuilder.setTransportOptions(HttpTransportOptions.newBuilder()
                .setConnectTimeout(60 * 1000)
                .setReadTimeout(60 * 1000)
                .build());
        // Disable SDK retries so failures surface to the S3 client on the
        // first request, which retries the whole operation instead.  Mirrors
        // the no-retry AwsS3SdkBlobStore and AzureBlobStore clients.
        storageBuilder.setRetrySettings(ServiceOptions.getNoRetrySettings());
        // A write session takes its chunk from the client and cannot size
        // it to the object being written; see upload.
        storageBuilder.setBlobWriteSessionConfig(BlobWriteSessionConfigs
                .getDefault().withChunkSize(MAX_UPLOAD_CHUNK_SIZE));
        if (!cred.identity().isEmpty()) {
            storageBuilder.setProjectId(cred.identity());
        }
        var endpoint = endpointUrl;
        boolean customEndpoint = endpoint != null && !endpoint.isEmpty() &&
                !endpoint.equals("https://storage.googleapis.com");
        // Google names its regional, locational and Private Service Connect
        // endpoints under googleapis.com, so a custom endpoint elsewhere, or
        // one reached over plain HTTP, is assumed to be an emulator.
        boolean emulator = false;
        if (customEndpoint) {
            URI endpointUri = URI.create(endpoint);
            String host = endpointUri.getHost();
            emulator = !"https".equals(endpointUri.getScheme()) ||
                    host == null || !host.endsWith(".googleapis.com");
        }
        String sessionToken = cred.sessionToken();
        if (!Strings.isNullOrEmpty(sessionToken)) {
            storageBuilder.setCredentials(new SuppliedTokenCredentials(creds));
        } else if (!cred.credential().isEmpty()) {
            try {
                // A service account key mints its own access tokens and
                // renews them itself, so the supplier is read no further
                // than here.
                var credentials = ServiceAccountCredentials.fromStream(
                        new ByteArrayInputStream(
                                cred.credential().getBytes(
                                        StandardCharsets.UTF_8)));
                storageBuilder.setCredentials(credentials);
            } catch (IOException ioe) {
                // Fall back to application default credentials
                try {
                    storageBuilder.setCredentials(
                            GoogleCredentials.getApplicationDefault());
                } catch (IOException ioe2) {
                    throw new RuntimeException(
                            "Failed to initialize GCS credentials", ioe2);
                }
            }
        } else if (emulator) {
            // No credentials were provided and the endpoint is not Google's.
            // So we assume this is an emulator that takes no credentials.
            storageBuilder.setCredentials(NoCredentials.getInstance());
        }
        // If no credentials are provided AND the endpoint is Google's then
        // we will rely on the SDK's mechanisms, which also support workload
        // identity.
        // The SDK looks up application default credentials: the file
        // GOOGLE_APPLICATION_CREDENTIALS names, gcloud's own, or the metadata
        // server, which is how GKE Workload Identity serves them.  Finding
        // none, it sends requests unauthenticated, as for a public bucket.


        if (customEndpoint) {
            storageBuilder.setHost(endpoint);
        }
        // Only Google's own service is known to apply a predefined ACL named
        // on buckets.insert; fake-gcs-server accepts the parameter and drops
        // it, leaving a private bucket.  An emulator therefore gets the ACL
        // set in a second request.  Keyed on the endpoint rather than on it
        // being local because an emulator is often reached by container
        // hostname rather than at localhost.
        // TODO: create every bucket atomically after
        // https://github.com/fsouza/fake-gcs-server/pull/2309 is released
        atomicBucketAcl = !emulator;
        storage = storageBuilder.build().getService();
    }

    // Lets tests see which credentials the client settled on.
    StorageOptions options() {
        return storage.getOptions();
    }

    /**
     * The ETag to report for an object, and to evaluate a client's
     * conditional request against.  GCS mints a base64 token that S3 SDKs
     * decode as hex and reject -- the AWS SDK for .NET throws a
     * FormatException from AWSSDKUtils.HexStringToBytes on every GetObject.
     * In md5 mode an object written in one request reports its MD5 in hex,
     * as S3 does, so a client can still verify what it downloaded.  A
     * composed object, which GCS gives no MD5, reports its token hex-encoded
     * under the multipart suffix instead, the one shape clients do not
     * verify.  Writes still pin to the generation, so a condition evaluated
     * against this value stays atomic.
     */
    String reportETag(BlobInfo blob) {
        return reportETag(md5ETags, blob.getEtag(), blob.getMd5ToHexString());
    }

    static String reportETag(boolean md5ETags, String eTag,
            @Nullable String md5Hex) {
        if (!md5ETags) {
            return eTag;
        }
        if (md5Hex != null) {
            return md5Hex;
        }
        try {
            return HexFormat.of().formatHex(Base64.getDecoder().decode(eTag)) +
                    OPAQUE_ETAG_SUFFIX;
        } catch (IllegalArgumentException iae) {
            // An emulator may mint a token that is not base64.
            return eTag + OPAQUE_ETAG_SUFFIX;
        }
    }

    // Releases the SDK client's transport channels and background threads when
    // the BlobStore is closed.
    @Override
    public void close() {
        try {
            storage.close();
        } catch (Exception e) {
            // Best effort: releasing the client on shutdown must not fail the
            // caller.
        }
    }

    // GCS names its bucket type as S3 does, and this file imports the GCS
    // one; the qualified element type keeps that import serving the rest.
    private static List<software.amazon.awssdk.services.s3.model.Bucket>
            toBuckets(Iterable<Bucket> gcsBuckets) {
        var buckets = ImmutableList
                .<software.amazon.awssdk.services.s3.model.Bucket>builder();
        for (Bucket bucket : gcsBuckets) {
            buckets.add(SdkResponses.bucket(bucket.getName(),
                    toInstant(bucket.getCreateTimeOffsetDateTime())));
        }
        return buckets.build();
    }

    @Override
    public ListBucketsResponse list() {
        return ListBucketsResponse.builder()
                .buckets(toBuckets(storage.list().iterateAll()))
                .build();
    }

    @Override
    public ListBucketsResponse list(ListBucketsRequest request) {
        var gcsOptions = new ArrayList<BucketListOption>();
        String prefix = request.prefix();
        if (prefix != null) {
            gcsOptions.add(BucketListOption.prefix(prefix));
        }
        if (request.maxBuckets() != null) {
            gcsOptions.add(BucketListOption.pageSize(request.maxBuckets()));
        }
        // GCS pages with a token of its own, opaque and round-tripped by the
        // frontend, so a page resumes where the last one stopped instead of
        // rescanning every bucket from the first as the default does.
        if (request.continuationToken() != null) {
            gcsOptions.add(BucketListOption.pageToken(
                    request.continuationToken()));
        }

        Page<Bucket> page = storage.list(
                gcsOptions.toArray(new BucketListOption[0]));
        return ListBucketsResponse.builder()
                .buckets(toBuckets(page.getValues()))
                // An exhausted listing can end on an empty cursor rather
                // than none -- the SDK's own hasNextPage reads the two
                // alike -- where a client reads any token as more to come.
                .continuationToken(
                        Strings.emptyToNull(page.getNextPageToken()))
                .prefix(prefix)
                .build();
    }

    @Override
    public ListObjectsV2Response list(ListObjectsV2Request request) {
        String container = request.bucket();
        String marker0 = request.continuationToken() != null ?
                request.continuationToken() : request.startAfter();
        var gcsOptions = new java.util.ArrayList<BlobListOption>();
        if (request.prefix() != null) {
            gcsOptions.add(BlobListOption.prefix(request.prefix()));
        }
        String marker = marker0;
        if (marker != null) {
            // Begin the server-side scan at the marker rather than paging from
            // the start of the bucket, which would make listing a bucket of N
            // objects cost O(N^2).  GCS startOffset is inclusive while the S3
            // marker is exclusive, so the loop below still skips the single
            // entry equal to the marker; results are otherwise identical.
            gcsOptions.add(BlobListOption.startOffset(marker));
        }
        if (request.delimiter() != null) {
            gcsOptions.add(BlobListOption.delimiter(request.delimiter()));
        }

        var contents = ImmutableList.<S3Object>builder();
        var prefixes = ImmutableList.<CommonPrefix>builder();
        Integer maxResults = request.maxKeys();
        int count = 0;
        boolean hasMore = false;
        String lastName = null;
        // The first page is as long as the answer can need: the keys asked
        // for, the entry after them that tells there is more, and the marker,
        // which startOffset includes.  The entries the loop passes over take
        // their places in a page all the same, and nothing tells how many
        // more of them follow, so the pages after the first are as long as
        // GCS makes them: at the length the client asks for, max-keys=1 cost
        // a request to GCS for every delete marker in a row.
        int pageSize = MAX_LIST_PAGE_SIZE;
        if (maxResults != null && maxResults < MAX_LIST_PAGE_SIZE) {
            pageSize = Math.min(maxResults + (marker == null ? 1 : 2),
                    MAX_LIST_PAGE_SIZE);
        }
        String pageToken = null;
        do {
            var pageOptions = new ArrayList<>(gcsOptions);
            pageOptions.add(BlobListOption.pageSize(pageSize));
            if (pageToken != null) {
                pageOptions.add(BlobListOption.pageToken(pageToken));
            }
            Page<Blob> page;
            try {
                page = storage.list(container,
                        pageOptions.toArray(new BlobListOption[0]));
            } catch (StorageException se) {
                throw translate(se, container, null);
            }
            // GCS names the common prefixes of a page after its objects, and
            // the listing can end within a page, so put the page in the order
            // of the names first: the marker handed out has to be the last
            // name before everything still to come.
            var blobs = Lists.newArrayList(page.getValues());
            blobs.sort(Comparator.comparing(Blob::getName));
            for (Blob blob : blobs) {
                // Skip blobs at or before the marker (S3 marker is
                // exclusive)
                if (marker != null && blob.getName().compareTo(marker) <= 0) {
                    continue;
                }
                if (isMultipartInternal(blob)) {
                    continue;
                }
                // A key whose current version is a delete marker holds
                // nothing an unversioned listing shows.
                if (!blob.isDirectory() && isDeleteMarker(blob)) {
                    continue;
                }
                if (maxResults != null && count >= maxResults) {
                    hasMore = true;
                    break;
                }
                if (blob.isDirectory()) {
                    prefixes.add(SdkResponses.commonPrefix(blob.getName()));
                } else {
                    contents.add(SdkResponses.objectEntry(blob.getName(),
                            reportETag(blob),
                            toInstant(blob.getUpdateTimeOffsetDateTime()),
                            blob.getSize(),
                            fromGcsStorageClass(blob.getStorageClass())));
                }
                lastName = blob.getName();
                count++;
            }
            // An exhausted listing can end on an empty cursor rather than
            // none, which the SDK's own hasNextPage reads alike.
            pageToken = Strings.emptyToNull(page.getNextPageToken());
            pageSize = MAX_LIST_PAGE_SIZE;
        } while (!hasMore && pageToken != null);

        // Synthesize a next marker if we truncated results
        String nextMarker = hasMore ? lastName : null;
        return SdkResponses.objectsPage(contents.build(), prefixes.build(),
                nextMarker);
    }

    /**
     * Whether a listed entry is this store's record of a multipart upload:
     * a stub, a part, or the common prefix a delimiter folds them into.
     * They are objects to GCS and no objects of the bucket's, and a listing
     * showed them: an upload in progress appeared as keys under
     * ".s3proxy/", which a client emptying the bucket would delete.  Only a
     * common prefix is that group: a client's object named ".s3proxy", or
     * ".", holds no stub and is listed like any other.
     */
    private static boolean isMultipartInternal(Blob blob) {
        String name = blob.getName();
        return name.startsWith(STUB_BLOB_PREFIX) || (blob.isDirectory() &&
                !name.isEmpty() && STUB_BLOB_PREFIX.startsWith(name));
    }

    @Override
    public HeadBucketResponse headBucket(HeadBucketRequest request) {
        try {
            if (storage.get(request.bucket(),
                    BucketGetOption.fields(BucketField.NAME)) == null) {
                throw S3Exceptions.noSuchBucket(request.bucket(), "");
            }
        } catch (StorageException se) {
            throw translate(se, request.bucket(), /*key=*/ null);
        }
        return HeadBucketResponse.builder().build();
    }

    @Override
    public CreateBucketResponse createContainer(CreateBucketRequest request) {
        String container = request.bucket();
        boolean publicRead = request.acl() == BucketCannedACL.PUBLIC_READ;
        boolean publicReadWrite =
                request.acl() == BucketCannedACL.PUBLIC_READ_WRITE;
        try {
            var bucketInfo = BucketInfo.newBuilder(container).build();
            if ((publicRead || publicReadWrite) && atomicBucketAcl) {
                storage.create(bucketInfo, Storage.BucketTargetOption
                        .predefinedAcl(publicReadWrite ?
                                Storage.PredefinedAcl.PUBLIC_READ_WRITE :
                                Storage.PredefinedAcl.PUBLIC_READ));
            } else {
                storage.create(bucketInfo);
                if (publicRead || publicReadWrite) {
                    storage.createAcl(container,
                            Acl.of(Acl.User.ofAllUsers(), publicReadWrite ?
                                    Acl.Role.WRITER : Acl.Role.READER));
                }
            }
            return CreateBucketResponse.builder().build();
        } catch (StorageException se) {
            if (se.getCode() == 409) {
                throw ownsBucket(container) ?
                        S3Exceptions.bucketAlreadyOwnedByYou(container) :
                        S3Exceptions.bucketAlreadyExists(container);
            }
            throw se;
        }
    }

    /**
     * Whether the bucket is one of the project's own.  Bucket names are one
     * namespace for all of Google Cloud Storage, and a create is refused
     * with the same 409 whether the name is the project's or another's,
     * which S3 tells apart: a client goes on to use a bucket it is told it
     * owns.  Listing the project's buckets names only its own.
     */
    private boolean ownsBucket(String container) {
        try {
            for (Bucket bucket : storage.list(
                    BucketListOption.prefix(container),
                    BucketListOption.fields(BucketField.NAME)).iterateAll()) {
                if (bucket.getName().equals(container)) {
                    return true;
                }
            }
        } catch (StorageException se) {
            // An account that may not list the project's buckets cannot
            // tell, and must not be told it owns one that may be another's.
            if (se.getCode() != 403) {
                throw se;
            }
        }
        return false;
    }

    /**
     * Deletes the container and everything it holds, archived generations
     * and delete markers included.  The interface default empties it with
     * plain deletes, which a versioning-enabled bucket answers by
     * archiving -- and, for the markers {@link #removeBlob} lays down, by
     * adding live objects -- so it fills the bucket it means to drain and
     * the bucket delete never happens.
     */
    @Override
    public void deleteContainer(String container) {
        try {
            deleteGenerations(storage.list(container,
                    BlobListOption.versions(true)));
            storage.delete(container);
        } catch (StorageException se) {
            if (se.getCode() == 404) {
                // The container is already gone; deleteContainer is
                // idempotent.
                return;
            }
            throw translate(se, container, /*key=*/ null);
        }
    }

    /**
     * Deletes each listed blob by the generation its blobId carries,
     * removing that version outright where a nameless delete would
     * archive it.  The deletes go in batches, as many as GCS takes in one,
     * since this is how an upload's parts are removed when it completes or
     * is aborted: one request apiece made a 10,000-part completion wait on
     * 10,000 sequential deletes.
     */
    private void deleteGenerations(Page<Blob> page) {
        deleteGenerations(page.iterateAll());
    }

    private void deleteGenerations(Iterable<Blob> blobs) {
        for (List<Blob> chunk : Iterables.partition(blobs,
                MAX_BATCH_DELETES)) {
            var batch = storage.batch();
            var results = new ArrayList<StorageBatchResult<Boolean>>(
                    chunk.size());
            for (Blob blob : chunk) {
                results.add(batch.delete(blob.getBlobId()));
            }
            batch.submit();
            for (StorageBatchResult<Boolean> result : results) {
                try {
                    // whether it was still there does not matter, only a
                    // failure to remove it
                    result.get();
                } catch (StorageException se) {
                    if (se.getCode() != 404) {
                        throw se;
                    }
                }
            }
        }
    }

    @Override
    public void deleteBucket(String container) {
        try {
            // What an upload in progress keeps here is no object -- a
            // listing does not show it -- and does not hold the bucket: S3
            // deletes a bucket whose only contents are unfinished uploads.
            // So look either side of that bookkeeping for a live object,
            // and if there is none take the bookkeeping away first, since
            // GCS deletes only a bucket that is empty.
            var before = storage.list(container, BlobListOption.pageSize(1),
                    BlobListOption.endOffset(STUB_BLOB_PREFIX));
            var after = storage.list(container, BlobListOption.pageSize(1),
                    BlobListOption.startOffset(STUB_BLOB_PREFIX_END));
            if (before.getValues().iterator().hasNext() ||
                    after.getValues().iterator().hasNext()) {
                throw S3Exceptions.bucketNotEmpty(container);
            }
            deleteGenerations(storage.list(container,
                    BlobListOption.prefix(STUB_BLOB_PREFIX),
                    BlobListOption.versions(true)));
            storage.delete(container);
        } catch (StorageException se) {
            if (se.getCode() == 409) {
                // Noncurrent generations keep a bucket alive even when no
                // live object answers the listing above.
                throw S3Exceptions.bucketNotEmpty(container);
            }
            if (se.getCode() != 404) {
                throw translate(se, container, /*key=*/ null);
            }
        }
    }

    @Override
    public boolean blobExists(String container, String key) {
        Blob blob = storage.get(BlobId.of(container, key),
                BlobGetOption.fields(BlobField.NAME, BlobField.METADATA));
        return blob != null && !isDeleteMarker(blob);
    }

    @Override
    public boolean supportsVersioning() {
        return true;
    }

    @Override
    public GetBucketVersioningResponse getBucketVersioning(
            GetBucketVersioningRequest request) {
        String container = request.bucket();
        Bucket bucket;
        try {
            bucket = storage.get(container,
                    BucketGetOption.fields(BucketField.VERSIONING));
        } catch (StorageException se) {
            throw translate(se, container, /*key=*/ null);
        }
        if (bucket == null) {
            throw S3Exceptions.noSuchBucket(container, "");
        }
        boolean enabled = Boolean.TRUE.equals(bucket.versioningEnabled());
        versionedContainers.put(container, enabled);
        // GCS versioning is on or off with no marking of ever having been
        // on, so off answers as never versioned rather than Suspended.
        return GetBucketVersioningResponse.builder()
                .status(enabled ? BucketVersioningStatus.ENABLED : null)
                .build();
    }

    @Override
    public PutBucketVersioningResponse putBucketVersioning(
            PutBucketVersioningRequest request) {
        String container = request.bucket();
        var configuration = request.versioningConfiguration();
        if (configuration == null ||
                configuration.status() != BucketVersioningStatus.ENABLED) {
            // Turning GCS versioning off keeps the noncurrent generations,
            // but S3's Suspended also replaces a "null" version on every
            // write and reports no version ids, which GCS cannot express.
            throw new UnsupportedOperationException(
                    "suspended versioning not supported");
        }
        try {
            storage.update(BucketInfo.newBuilder(container)
                    .setVersioningEnabled(true)
                    .build());
        } catch (StorageException se) {
            throw translate(se, container, /*key=*/ null);
        }
        versionedContainers.put(container, true);
        return PutBucketVersioningResponse.builder().build();
    }

    /** Whether writes to the container version rather than replace. */
    private boolean isVersioned(String container) {
        Boolean cached = versionedContainers.getIfPresent(container);
        if (cached != null) {
            return cached;
        }
        Bucket bucket;
        try {
            bucket = storage.get(container,
                    BucketGetOption.fields(BucketField.VERSIONING));
        } catch (StorageException se) {
            throw translate(se, container, /*key=*/ null);
        }
        boolean enabled = bucket != null &&
                Boolean.TRUE.equals(bucket.versioningEnabled());
        versionedContainers.put(container, enabled);
        return enabled;
    }

    /**
     * Whether the container has uniform bucket-level access.  Its objects
     * have no ACLs, so none is public or inherits anything, and GCS refuses
     * with 400 any request that names one.
     */
    private boolean hasUniformAccess(String container) {
        Boolean cached = uniformAccessContainers.getIfPresent(container);
        if (cached != null) {
            return cached;
        }
        Bucket bucket;
        try {
            bucket = storage.get(container,
                    BucketGetOption.fields(BucketField.IAMCONFIGURATION));
        } catch (StorageException se) {
            throw translate(se, container, /*key=*/ null);
        }
        var iam = bucket == null ? null : bucket.getIamConfiguration();
        boolean uniform = iam != null && Boolean.TRUE.equals(
                iam.isUniformBucketLevelAccessEnabled());
        uniformAccessContainers.put(container, uniform);
        return uniform;
    }

    /**
     * The ACL a write names for the object it creates, or null where it can
     * name none.  S3 creates an object private unless the request says
     * otherwise, and the frontend asks for that by naming no ACL.  GCS gives
     * an object written without one its bucket's default object ACL, which
     * S3 has no counterpart of and which may grant allUsers: everything
     * written to such a bucket would be public, x-amz-acl: private or not.
     * So a private write names projectPrivate, the default object ACL of a
     * new bucket: one that kept it gets the objects it always got, and one
     * that changed it no longer decides what S3's private means.
     */
    private Storage.@Nullable PredefinedAcl predefinedAcl(String container,
            boolean publicRead) {
        if (publicRead) {
            return Storage.PredefinedAcl.PUBLIC_READ;
        }
        return hasUniformAccess(container) ? null :
                Storage.PredefinedAcl.PROJECT_PRIVATE;
    }

    /**
     * The options that write the store's own objects -- a multipart upload's
     * stub and parts, a delete marker -- private, as predefinedAcl writes a
     * private object.  They hold the upload's metadata and content, and a
     * bucket's default object ACL would make them as public as it makes
     * anything else written without an ACL.
     */
    private BlobTargetOption[] bookkeepingTargetOptions(String container) {
        var acl = predefinedAcl(container, /*publicRead=*/ false);
        return acl == null ? new BlobTargetOption[0] :
                new BlobTargetOption[] {BlobTargetOption.predefinedAcl(acl)};
    }

    private static boolean isDeleteMarker(BlobInfo blob) {
        var metadata = blob.getMetadata();
        return metadata != null &&
                "true".equals(metadata.get(DELETE_MARKER_KEY));
    }

    /**
     * The generation a version id names.  S3 version ids on this store are
     * the decimal GCS generations, which are always positive.
     */
    private static long parseVersionId(String versionId) {
        try {
            long generation = Long.parseLong(versionId);
            if (generation > 0) {
                return generation;
            }
        } catch (NumberFormatException nfe) {
            // fall through
        }
        throw S3Exceptions.invalidArgument("Invalid version id specified");
    }

    /**
     * The version a read names: the live object when {@code versionId} is
     * null -- or the newest remaining generation when the live one was
     * deleted by id, which is S3's promotion -- and otherwise the
     * generation named.  Returns null when the key holds nothing to read.
     * Throws the way S3 answers a read whose current version is a delete
     * marker (404 naming the marker), one that names a marker outright
     * (405), and one that names a version that does not exist.
     */
    @Nullable
    private Blob resolveVersion(String container, String key,
            @Nullable String versionId) {
        if (versionId == null || (versionId.equals(NULL_VERSION_ID) &&
                !isVersioned(container))) {
            Blob live;
            try {
                live = storage.get(BlobId.of(container, key));
            } catch (StorageException se) {
                throw translate(se, container, key);
            }
            if (live != null) {
                if (isDeleteMarker(live)) {
                    throw S3Exceptions.noSuchKeyDeleteMarker(container, key,
                            Long.toString(live.getGeneration()),
                            "current version is a delete marker");
                }
                return live;
            }
            // The SDK collapses a missing bucket and a missing object both
            // to null; distinguish them so the frontend emits NoSuchBucket
            // vs NoSuchKey.
            if (storage.get(container) == null) {
                throw S3Exceptions.noSuchBucket(container, "");
            }
            if (versionId == null && isVersioned(container)) {
                Blob newest = newestGeneration(container, key);
                if (newest != null) {
                    if (isDeleteMarker(newest)) {
                        throw S3Exceptions.noSuchKeyDeleteMarker(container,
                                key, Long.toString(newest.getGeneration()),
                                "current version is a delete marker");
                    }
                    return newest;
                }
            }
            return null;
        }
        if (versionId.equals(NULL_VERSION_ID)) {
            throw S3Exceptions.noSuchVersion(container, key, versionId,
                    "no such version");
        }
        long generation = parseVersionId(versionId);
        Blob blob;
        try {
            blob = storage.get(BlobId.of(container, key, generation));
        } catch (StorageException se) {
            throw translate(se, container, key);
        }
        if (blob == null) {
            if (storage.get(container) == null) {
                throw S3Exceptions.noSuchBucket(container, "");
            }
            throw S3Exceptions.noSuchVersion(container, key, versionId,
                    "no such version");
        }
        if (isDeleteMarker(blob)) {
            // As on S3: a delete marker has no content to read, and saying
            // so is not the same as saying the key is gone.
            throw S3Exceptions.fromStatusCode(405, /*eTag=*/ null,
                    Map.of("x-amz-delete-marker", "true",
                            "x-amz-version-id", versionId),
                    /*cause=*/ null);
        }
        return blob;
    }

    /**
     * The newest generation of one key, archived generations included, or
     * null when the key holds none.  The scan is bounded to the key itself:
     * the offsets stop it at the shortest name after {@code key}, so
     * sibling keys sharing the prefix are never pulled.
     */
    @Nullable
    private Blob newestGeneration(String container, String key) {
        com.google.api.gax.paging.Page<Blob> page;
        try {
            page = storage.list(container,
                    BlobListOption.prefix(key),
                    BlobListOption.versions(true),
                    BlobListOption.startOffset(key),
                    BlobListOption.endOffset(key + '\0'));
        } catch (StorageException se) {
            throw translate(se, container, key);
        }
        Blob newest = null;
        for (Blob blob : page.iterateAll()) {
            if (!blob.getName().equals(key)) {
                continue;
            }
            if (newest == null ||
                    blob.getGeneration() > newest.getGeneration()) {
                newest = blob;
            }
        }
        return newest;
    }

    /**
     * The version id a read or write reports: the generation on a
     * versioned container or whenever the caller named a version, and
     * nothing otherwise -- S3 sends no x-amz-version-id header for a
     * container that has never been versioned.
     */
    @Nullable
    private String reportedVersionId(String container, BlobInfo blob,
            @Nullable String requestVersionId) {
        if (NULL_VERSION_ID.equals(requestVersionId)) {
            // The null version resolved on an unversioned container, whose
            // reads report no version id.
            return null;
        }
        if (requestVersionId != null || isVersioned(container)) {
            return Long.toString(blob.getGeneration());
        }
        return null;
    }

    @Override
    public ListObjectVersionsResponse listVersions(
            ListObjectVersionsRequest request) {
        String container = request.bucket();
        String delimiter = request.delimiter();
        String keyMarker = request.keyMarker();
        int maxKeys = request.maxKeys() == null ? 1000 : request.maxKeys();

        var gcsOptions = new ArrayList<BlobListOption>();
        gcsOptions.add(BlobListOption.versions(true));
        if (request.prefix() != null) {
            gcsOptions.add(BlobListOption.prefix(request.prefix()));
        }
        if (delimiter != null) {
            gcsOptions.add(BlobListOption.delimiter(delimiter));
        }
        if (keyMarker != null) {
            // Begin the server-side scan at the marker rather than at the
            // start of the bucket.  startOffset is inclusive, which the
            // slice below wants: resuming within a key needs that key's own
            // rows.
            gcsOptions.add(BlobListOption.startOffset(keyMarker));
        }

        Long parsedGeneration = null;
        if (keyMarker != null && request.versionIdMarker() != null) {
            try {
                parsedGeneration = Long.parseLong(request.versionIdMarker());
            } catch (NumberFormatException nfe) {
                // no generation of the key: resume at the next key
            }
        }
        Long markerGeneration = parsedGeneration;

        // Flatten every generation, and every common prefix, into S3's
        // order -- names ascending, a key's newest generation first -- and
        // slice one page out of it.  GCS lists by name, a page of its
        // listing the names after the page before, but says nothing about
        // the generations within one name, so a name is settled only once
        // GCS has listed a name after it.  The listing stops once the
        // settled entries past the marker fill the page and one more, which
        // tells that the page is truncated: reading every generation to the
        // end of the bucket made paging through V versions cost O(V^2).
        var rows = new ArrayList<VersionRow>();
        // The first GCS page is as long as a page of keys with a version
        // each needs, as list() asks; a key's other generations, and the
        // marker key's newer ones, take the pages after it.
        int pageSize = Math.min(maxKeys + (keyMarker == null ? 1 : 2),
                MAX_LIST_PAGE_SIZE);
        String pageToken = null;
        do {
            var pageOptions = new ArrayList<>(gcsOptions);
            pageOptions.add(BlobListOption.pageSize(pageSize));
            if (pageToken != null) {
                pageOptions.add(BlobListOption.pageToken(pageToken));
            }
            Page<Blob> page;
            try {
                page = storage.list(container,
                        pageOptions.toArray(new BlobListOption[0]));
            } catch (StorageException se) {
                throw translate(se, container, /*key=*/ null);
            }
            String frontier = null;
            for (Blob blob : page.getValues()) {
                String name = blob.getName();
                if (frontier == null || name.compareTo(frontier) > 0) {
                    frontier = name;
                }
                if (isMultipartInternal(blob)) {
                    continue;
                }
                if (blob.isDirectory()) {
                    rows.add(VersionRow.prefix(blob.getName()));
                    continue;
                }
                rows.add(new VersionRow(blob.getName(), blob.getGeneration(),
                        /*prefix=*/ false, isDeleteMarker(blob),
                        reportETag(blob),
                        toInstant(blob.getUpdateTimeOffsetDateTime()),
                        blob.getSize(),
                        fromGcsStorageClass(blob.getStorageClass())));
            }
            pageToken = Strings.emptyToNull(page.getNextPageToken());
            pageSize = MAX_LIST_PAGE_SIZE;
            if (pageToken != null && frontier != null) {
                String settledBefore = frontier;
                long settled = rows.stream()
                        .filter(row -> row.key().compareTo(settledBefore) < 0)
                        .filter(row -> row.after(keyMarker,
                                markerGeneration))
                        .count();
                if (settled > maxKeys) {
                    break;
                }
            }
        } while (pageToken != null);
        // A prefix shares its name with no key: a delimiter folds the keys
        // that would into it.
        rows.sort(Comparator.comparing(VersionRow::key)
                .thenComparing(Comparator
                        .comparingLong(VersionRow::generation).reversed()));

        // Resume at the first row past the marker in the order above, not
        // at the row after the marker's own: a caller that lists a page and
        // deletes what it listed, as emptying a versioned bucket does, comes
        // back with a marker naming a row no longer there, and looking for
        // that row found nothing and ended the listing with versions left.
        int start = rows.size();
        for (int i = 0; i < rows.size(); i++) {
            if (rows.get(i).after(keyMarker, markerGeneration)) {
                start = i;
                break;
            }
        }
        int end = Math.min(rows.size(), start + maxKeys);
        var pageRows = rows.subList(start, end);
        String nextKeyMarker = null;
        String nextVersionIdMarker = null;
        if (end < rows.size() && !pageRows.isEmpty()) {
            var last = pageRows.get(pageRows.size() - 1);
            nextKeyMarker = last.key();
            nextVersionIdMarker = last.prefix() ? null : last.versionId();
        }

        var versions = new ArrayList<ObjectVersion>();
        var markers = new ArrayList<DeleteMarkerEntry>();
        var commonPrefixes = new ArrayList<CommonPrefix>();
        for (int i = start; i < end; i++) {
            var row = rows.get(i);
            if (row.prefix()) {
                commonPrefixes.add(SdkResponses.commonPrefix(row.key()));
                continue;
            }
            // The newest generation of a key is its latest, marker or not;
            // the row before it in the flattened order belongs to another
            // name exactly then.  Every generation of a name the page
            // reaches was listed, the marker's own included, as startOffset
            // includes it.
            boolean latest = i == 0 ||
                    !rows.get(i - 1).key().equals(row.key());
            if (row.deleteMarker()) {
                markers.add(DeleteMarkerEntry.builder()
                        .key(row.key())
                        .versionId(row.versionId())
                        .isLatest(latest)
                        .lastModified(row.lastModified())
                        .build());
            } else {
                versions.add(ObjectVersion.builder()
                        .key(row.key())
                        .versionId(row.versionId())
                        .isLatest(latest)
                        .eTag(row.eTag())
                        .lastModified(row.lastModified())
                        .size(row.size())
                        .storageClass(requireNonNull(row.storageClass())
                                .toString())
                        .build());
            }
        }
        return ListObjectVersionsResponse.builder()
                .versions(versions)
                .deleteMarkers(markers)
                .commonPrefixes(commonPrefixes)
                .nextKeyMarker(nextKeyMarker)
                .nextVersionIdMarker(nextVersionIdMarker)
                .isTruncated(nextKeyMarker != null)
                .build();
    }

    /**
     * One row of the flattened versions listing: a generation of a key, or
     * a common prefix, which takes a place in the page as a key does.
     */
    private record VersionRow(String key, long generation, boolean prefix,
            boolean deleteMarker, @Nullable String eTag,
            @Nullable Instant lastModified, @Nullable Long size,
            @Nullable StorageClass storageClass) {
        static VersionRow prefix(String name) {
            return new VersionRow(name, /*generation=*/ 0, /*prefix=*/ true,
                    /*deleteMarker=*/ false, /*eTag=*/ null,
                    /*lastModified=*/ null, /*size=*/ null,
                    /*storageClass=*/ null);
        }

        String versionId() {
            return Long.toString(generation);
        }

        /**
         * Whether the row comes after the markers: a later name, or an
         * older generation of the marker's key.  A prefix named by the
         * marker was the last entry of the page before.
         */
        boolean after(@Nullable String keyMarker,
                @Nullable Long markerGeneration) {
            if (keyMarker == null) {
                return true;
            }
            int order = key.compareTo(keyMarker);
            return order > 0 || (order == 0 && !prefix &&
                    markerGeneration != null &&
                    generation < markerGeneration);
        }
    }

    @Override
    public ResponseInputStream<GetObjectResponse> getBlob(
            GetObjectRequest request) {
        String container = request.bucket();
        String key = request.key();
        Blob gcsBlob = resolveVersion(container, key, request.versionId());
        if (gcsBlob == null) {
            throw S3Exceptions.noSuchKey(container, key, "no such object");
        }
        // The blob carries its generation, which the reader below opens:
        // judged on that generation, the ACL is the one of the bytes served.
        if (SdkRequests.onlyIfPublicRead(request) &&
                blobAccess(container, key, gcsBlob) !=
                        ObjectCannedACL.PUBLIC_READ) {
            throw S3Exceptions.fromStatusCode(403);
        }

        // Enforce conditional-GET preconditions before streaming.  The
        // backends report every conditional-header failure as 412; the
        // frontend (S3ProxyHandlerJetty) remaps GET/HEAD If-None-Match and
        // If-Modified-Since misses to 304 Not Modified.
        String eTag = reportETag(gcsBlob);
        Instant lastModified = toInstant(gcsBlob.getUpdateTimeOffsetDateTime());
        enforceConditionalGet(request, eTag, lastModified);

        long blobSize = gcsBlob.getSize();
        Long rangeOffset = null;
        Long rangeEnd = null;
        var range = SdkRequests.parseRange(request.range());
        if (range != null && range.wholeOfEmpty(blobSize)) {
            range = null;
        }
        if (range != null) {
            if (range.first() == null) {
                // trailing range: last N bytes
                rangeOffset = Math.max(0,
                        blobSize - requireNonNull(range.last()));
                rangeEnd = blobSize - 1;
            } else if (range.last() == null) {
                rangeOffset = range.first();
            } else {
                rangeOffset = range.first();
                rangeEnd = range.last();
            }
            // A range starting at or past the end of the object is
            // unsatisfiable; S3 returns 416 InvalidRange.  Without this GCS
            // reads zero bytes and the declared Content-Length desyncs.
            if (rangeOffset >= blobSize) {
                throw S3Exceptions.fromStatusCode(416);
            }
            // Clamp an end that runs past the last byte (still satisfiable).
            if (rangeEnd != null && rangeEnd >= blobSize) {
                rangeEnd = blobSize - 1;
            }
        }

        InputStream is;
        long contentLength;
        try {
            if (rangeOffset != null) {
                ReadChannel reader = gcsBlob.reader();
                reader.seek(rangeOffset);
                if (rangeEnd != null) {
                    reader.limit(rangeEnd + 1);
                    contentLength = rangeEnd - rangeOffset + 1;
                } else {
                    contentLength = blobSize - rangeOffset;
                }
                is = Channels.newInputStream(reader);
            } else {
                ReadChannel reader = gcsBlob.reader();
                is = Channels.newInputStream(reader);
                contentLength = blobSize;
            }
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }

        var builder = GetObjectResponse.builder()
                .metadata(sanitizeUserMetadata(gcsBlob.getMetadata()))
                .cacheControl(gcsBlob.getCacheControl())
                .contentDisposition(gcsBlob.getContentDisposition())
                .contentEncoding(gcsBlob.getContentEncoding())
                .contentLanguage(gcsBlob.getContentLanguage())
                .contentLength(contentLength)
                .contentType(gcsBlob.getContentType())
                .eTag(reportETag(gcsBlob))
                .storageClass(
                        fromGcsStorageClass(gcsBlob.getStorageClass())
                                .toString())
                .versionId(reportedVersionId(container, gcsBlob,
                        request.versionId()))
                .lastModified(toInstant(
                        gcsBlob.getUpdateTimeOffsetDateTime()));
        if (rangeOffset != null) {
            long end = rangeEnd != null ? rangeEnd :
                    blobSize - 1;
            builder.contentRange(
                    "bytes " + rangeOffset + "-" + end + "/" + blobSize);
        }
        return SdkResponses.getResponse(builder.build(), is);
    }

    // Enforce S3 conditional-GET headers (If-Match / If-None-Match /
    // If-Modified-Since / If-Unmodified-Since).  GCS uses generation
    // preconditions rather than ETag/time matching, so evaluate them here
    // against the object's metadata.  Every failure is reported as 412;
    // S3ProxyHandlerJetty maps GET/HEAD If-None-Match and If-Modified-Since
    // misses to 304 Not Modified.
    private static void enforceConditionalGet(GetObjectRequest request,
            @Nullable String eTag, @Nullable Instant lastModified) {
        String ifMatch = request.ifMatch();
        String ifNoneMatch = request.ifNoneMatch();
        // The wildcard "*" matches any existing object rather than a literal
        // ETag.  The object exists here (getBlob already fetched it), so
        // If-Match: * always passes and If-None-Match: * always fails the
        // precondition (which the frontend remaps to 304 for GET/HEAD).
        if ("*".equals(ifMatch)) {
            ifMatch = null;
        }
        if ("*".equals(ifNoneMatch)) {
            throw preconditionFailed(eTag);
        }
        if (eTag != null) {
            String quoted = maybeQuoteETag(eTag);
            if (ifMatch != null && !maybeQuoteETag(ifMatch).equals(quoted)) {
                throw preconditionFailed(eTag);
            }
            if (ifNoneMatch != null &&
                    maybeQuoteETag(ifNoneMatch).equals(quoted)) {
                throw preconditionFailed(eTag);
            }
        }
        if (lastModified != null) {
            Instant modified = truncateToSecond(lastModified);
            Instant ifModifiedSince = request.ifModifiedSince();
            if (ifModifiedSince != null &&
                    modified.compareTo(ifModifiedSince) <= 0) {
                throw preconditionFailed(eTag);
            }
            // Only when If-Match is absent.  S3 answers a request carrying
            // both with 200 when the If-Match holds and the
            // If-Unmodified-Since does not, the stronger condition settling
            // it.  Asked of the request rather than the local, which the
            // wildcard above has already cleared.
            Instant ifUnmodifiedSince = request.ifUnmodifiedSince();
            if (ifUnmodifiedSince != null && request.ifMatch() == null &&
                    modified.compareTo(ifUnmodifiedSince) > 0) {
                throw preconditionFailed(eTag);
            }
        }
    }

    // HTTP dates (Last-Modified, If-Modified-Since, If-Unmodified-Since) have
    // one-second granularity, but GCS timestamps carry sub-second precision.
    // Truncate to whole seconds so a conditional header compares equal to the
    // Last-Modified value the client previously saw.
    private static Instant truncateToSecond(Instant instant) {
        return instant.truncatedTo(ChronoUnit.SECONDS);
    }

    private static String maybeQuoteETag(String eTag) {
        if (!eTag.startsWith("\"") && !eTag.endsWith("\"")) {
            eTag = "\"" + eTag + "\"";
        }
        return eTag;
    }

    /**
     * Chunks an upload to the payload it carries.  The SDK otherwise buffers
     * its 15 MiB default whatever the object weighs, so a one byte write costs
     * 30 MiB of allocation, and a server admitting many concurrent writes
     * holds that per write.  The chunk exceeds the payload rather than
     * matching it: the write channel flushes a chunk the moment it fills, so
     * an exact fit would send the payload and then a second request to
     * finalize it.  Uploads at or above the default keep it and so still cost
     * the requests they cost before.
     */
    private static int uploadChunkSize(@Nullable Long contentLength) {
        if (contentLength == null || contentLength >= MAX_UPLOAD_CHUNK_SIZE) {
            return MAX_UPLOAD_CHUNK_SIZE;
        }
        long units = contentLength / UPLOAD_CHUNK_UNIT + 1;
        return (int) Math.min(MAX_UPLOAD_CHUNK_SIZE,
                units * UPLOAD_CHUNK_UNIT);
    }

    /**
     * Writes a payload as an object, which comes to exist only once the
     * payload has been read to its end.  Closing the channel is what commits
     * a resumable upload, and Storage.createFrom closes its own whether or
     * not the payload could be read: a body the frontend refused while
     * streaming it -- for its digest, a chunk signature, or a client that
     * went away -- replaced the object with as much as had been read.  A
     * payload therefore streams through a write session, whose channel
     * commits nothing when left unclosed; GCS expires the session.  The
     * session's chunk is the client's whatever the object weighs, though,
     * so a small payload is instead read to its end first and only then
     * handed to createFrom, with the chunk sized to it.  Small means that
     * the copy made here and the two createFrom makes fit in one full chunk.
     */
    private BlobInfo upload(BlobInfo blobInfo, InputStream payload,
            @Nullable Long contentLength, BlobWriteOption... options)
            throws IOException {
        // A failure leaves without the SDK's account of the request (see
        // withoutRequest), however the SDK reports it: the request that
        // finalizes the upload throws a StorageException, an earlier chunk
        // an IOException wrapping one, and a write session's result an
        // unchecked execution exception around one.  The payload's own
        // failures, the frontend's refusals among them, pass as they came.
        try {
            return uploadOrThrow(blobInfo, payload, contentLength, options);
        } catch (StorageException se) {
            throw withoutRequest(se);
        } catch (IOException ioe) {
            if (ioe.getCause() instanceof StorageException se) {
                throw new IOException(withoutRequest(se));
            }
            throw ioe;
        } catch (UncheckedExecutionException uee) {
            if (uee.getCause() instanceof StorageException se) {
                throw withoutRequest(se);
            }
            throw uee;
        }
    }

    private BlobInfo uploadOrThrow(BlobInfo blobInfo, InputStream payload,
            @Nullable Long contentLength, BlobWriteOption... options)
            throws IOException {
        int chunkSize = uploadChunkSize(contentLength);
        if (chunkSize <= MAX_UPLOAD_CHUNK_SIZE / 3) {
            // The chunk exceeds the length declared, so only a payload that
            // goes on past that length fills it.
            byte[] head = payload.readNBytes(chunkSize);
            if (head.length < chunkSize) {
                return storage.createFrom(blobInfo,
                        new ByteArrayInputStream(head), chunkSize, options);
            }
            payload = new SequenceInputStream(
                    new ByteArrayInputStream(head), payload);
        } else {
            // A large payload is received up to a chunk before the session
            // is opened, whose buffers it would otherwise fill from nothing.
            payload = receiveFirstChunk(payload, chunkSize);
        }
        var session = storage.blobWriteSession(blobInfo, options);
        var channel = session.open();
        payload.transferTo(Channels.newOutputStream(channel));
        channel.close();
        return Futures.getUnchecked(session.getResult());
    }

    /**
     * Receives the first chunk of a payload before the SDK is handed it.
     * The chunk is sized by the Content-Length the client declares, not by
     * what it goes on to send, and Storage.createFrom allocates it twice in
     * full by the first byte it reads: a request that declared 16 MB, sent
     * one byte and stalled held 30 MiB for as long as it stayed, and a few
     * dozen of them held the heap.  Reading ahead grows with the bytes that
     * have arrived, so the SDK allocates its buffers only once there is a
     * chunk, or the whole of a shorter payload, to fill them with.
     */
    private static InputStream receiveFirstChunk(InputStream is,
            int chunkSize) throws IOException {
        byte[] head = is.readNBytes(chunkSize);
        if (head.length < chunkSize) {
            // The payload ended within the chunk: it is not read again,
            // since a stream that checks a digest at its end refuses a read
            // after it.
            return new ByteArrayInputStream(head);
        }
        var streams = new ArrayDeque<InputStream>(2);
        streams.add(new ByteArrayInputStream(head));
        streams.add(is);
        // Consumed, so that the chunk is let go of once the SDK has read it.
        // SequenceInputStream keeps the two streams it is constructed with
        // for as long as it lives, which would hold the chunk a third time,
        // beside the SDK's two buffers, until the upload ends.
        return new SequenceInputStream(Iterators.asEnumeration(
                Iterators.consumingIterator(streams.iterator())));
    }

    @Override
    public PutObjectResponse putBlob(PutObjectRequest request,
            InputStream payload) {
        String container = request.bucket();
        String name = request.key();
        checkNotReserved(name);
        var blobInfo = BlobInfo.newBuilder(BlobId.of(container, name));
        blobInfo.setContentType(request.contentType());
        blobInfo.setContentDisposition(request.contentDisposition());
        blobInfo.setContentEncoding(request.contentEncoding());
        blobInfo.setContentLanguage(request.contentLanguage());
        blobInfo.setCacheControl(request.cacheControl());
        var hash = request.contentMD5();
        if (hash != null) {
            blobInfo.setMd5(hash);
        }
        if (request.hasMetadata()) {
            blobInfo.setMetadata(request.metadata());
        }
        if (request.storageClass() != null &&
                request.storageClass() != StorageClass.STANDARD) {
            blobInfo.setStorageClass(
                    toGcsStorageClass(request.storageClass()));
        }

        var writeOptions = new java.util.ArrayList<BlobWriteOption>();
        if (hash != null) {
            // The Java SDK strips blobInfo's md5 from resumable upload
            // metadata unless md5Match is requested, so without this GCS
            // never validates the client-supplied Content-MD5.  md5Match
            // re-sends the md5 and requests server-side validation.
            writeOptions.add(MD5_MATCH);
        }
        String ifMatch = request.ifMatch();
        String ifNoneMatch = request.ifNoneMatch();
        if (ifMatch != null) {
            if (ifMatch.equals("*")) {
                // If-Match: * — overwrite only an existing object.  Pin
                // the write to its current generation so a concurrent
                // delete fails the precondition instead of recreating it.
                Blob existing = storage.get(BlobId.of(container, name));
                if (existing == null || isDeleteMarker(existing)) {
                    throw preconditionFailed(null);
                }
                writeOptions.add(BlobWriteOption.generationMatch(
                        existing.getGeneration()));
            } else {
                // If-Match: <etag> — gate the write on the matching
                // generation; mismatch or absence fails the precondition.
                writeOptions.add(BlobWriteOption.generationMatch(
                        getGeneration(container, name, ifMatch)));
            }
        }
        if (ifNoneMatch != null) {
            if (ifNoneMatch.equals("*")) {
                Blob existing = storage.get(BlobId.of(container, name));
                if (existing != null && isDeleteMarker(existing)) {
                    // A delete marker counts as no current object, so the
                    // write proceeds -- atomically, by requiring the marker
                    // to still be what it replaces.
                    writeOptions.add(BlobWriteOption.generationMatch(
                            existing.getGeneration()));
                } else {
                    writeOptions.add(BlobWriteOption.doesNotExist());
                }
            } else {
                // If-None-Match: <etag> — fail if an object with that ETag
                // currently exists.  GCS has no etag precondition, but
                // pinning generationNotMatch to the matching object's
                // generation makes the rejection atomic: if it is still
                // that version the write fails, and if it has since changed
                // or been deleted the write proceeds.
                Blob existing = storage.get(BlobId.of(container, name));
                if (existing != null && !isDeleteMarker(existing) &&
                        maybeQuoteETag(ifNoneMatch).equals(
                                maybeQuoteETag(reportETag(existing)))) {
                    writeOptions.add(BlobWriteOption.generationNotMatch(
                            existing.getGeneration()));
                }
            }
        }
        var acl = predefinedAcl(container,
                request.acl() == ObjectCannedACL.PUBLIC_READ);
        if (acl != null) {
            writeOptions.add(BlobWriteOption.predefinedAcl(acl));
        }

        try (var is = payload) {
            BlobInfo gcsBlob = upload(blobInfo.build(), is,
                    request.contentLength(),
                    writeOptions.toArray(new BlobWriteOption[0]));
            return SdkResponses.putResponse(reportETag(gcsBlob),
                    isVersioned(container) ?
                            Long.toString(gcsBlob.getGeneration()) : null);
        } catch (StorageException se) {
            // GCS has no dedicated error code for a checksum mismatch: it
            // reports the md5Match validation we requested as a generic 400
            // "invalid".  Only surface BadDigest when we actually asked GCS to
            // validate the checksum; other 400s are unrelated client errors.
            if (se.getCode() == 400 && hash != null) {
                throw S3Exceptions.fromStatusCode(400, se);
            }
            throw translate(se, container, null);
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }

    @Override
    public CopyObjectResponse copyBlob(CopyObjectRequest request) {
        checkNotReserved(request.destinationKey());
        String fromContainer = request.sourceBucket();
        String fromName = request.sourceKey();
        Blob sourceBlob = resolveVersion(fromContainer, fromName,
                request.sourceVersionId());
        if (sourceBlob == null) {
            throw S3Exceptions.noSuchKey(fromContainer, fromName,
                    "while copying");
        }
        // The copy reads the generation the resolution named rather than
        // whatever is live by the time it runs, which also lets it read a
        // noncurrent version -- restoring one is a copy of it onto its key.
        var source = sourceBlob.getBlobId();
        var targetId = BlobId.of(
                request.destinationBucket(), request.destinationKey());
        var targetBuilder = BlobInfo.newBuilder(targetId);

        boolean replace =
                request.metadataDirective() == MetadataDirective.REPLACE;
        if (replace) {
            if (request.cacheControl() != null) {
                targetBuilder.setCacheControl(request.cacheControl());
            }
            if (request.contentDisposition() != null) {
                targetBuilder.setContentDisposition(
                        request.contentDisposition());
            }
            if (request.contentEncoding() != null) {
                targetBuilder.setContentEncoding(request.contentEncoding());
            }
            if (request.contentLanguage() != null) {
                targetBuilder.setContentLanguage(request.contentLanguage());
            }
            if (request.contentType() != null) {
                targetBuilder.setContentType(request.contentType());
            }
            targetBuilder.setMetadata(request.metadata());
        }

        String ifMatch = request.copySourceIfMatch();
        String ifNoneMatch = request.copySourceIfNoneMatch();
        Instant ifModifiedSince = request.copySourceIfModifiedSince();
        Instant ifUnmodifiedSince = request.copySourceIfUnmodifiedSince();
        List<BlobSourceOption> sourceOptions = List.of();
        if (ifMatch != null || ifNoneMatch != null ||
                ifModifiedSince != null || ifUnmodifiedSince != null) {
            sourceOptions = checkCopySourceConditions(sourceBlob,
                    ifMatch, ifNoneMatch, ifModifiedSince, ifUnmodifiedSince);
        }

        var targetOptions = new java.util.ArrayList<BlobTargetOption>();
        var acl = predefinedAcl(request.destinationBucket(),
                request.acl() == ObjectCannedACL.PUBLIC_READ);
        if (acl != null) {
            targetOptions.add(BlobTargetOption.predefinedAcl(acl));
        }
        // If-Match and If-None-Match guard the destination, pinned to the
        // generation the check saw so the copy cannot replace another.
        targetOptions.addAll(destinationConditions(
                request.destinationBucket(), request.destinationKey(),
                request.ifMatch(), request.ifNoneMatch()));

        try {
            var copyBuilder = CopyRequest.newBuilder()
                    .setSource(source)
                    .setSourceOptions(sourceOptions);
            // A target given as a BlobInfo is sent as the new object's
            // whole description, and GCS then takes nothing from the
            // source -- a description of only a name leaves the copy with
            // no content type and no metadata.  Only a target given by its
            // ID has the source's carried over.
            if (replace) {
                copyBuilder.setTarget(targetBuilder.build(), targetOptions);
            } else {
                copyBuilder.setTarget(targetId, targetOptions);
            }
            var result = storage.copy(copyBuilder.build()).getResult();
            return SdkResponses.copyResponse(reportETag(result),
                    toInstant(result.getUpdateTimeOffsetDateTime()),
                    isVersioned(request.destinationBucket()) ?
                            Long.toString(result.getGeneration()) : null,
                    reportedVersionId(fromContainer, sourceBlob,
                            request.sourceVersionId()));
        } catch (StorageException se) {
            throw translate(se, fromContainer, fromName);
        }
    }

    /**
     * The conditions a copy or a multipart publish places on the key it is
     * about to write, enforced as on a plain put: the check resolves the
     * current object and the write pins its generation, so a concurrent
     * change fails the write rather than being clobbered.  If-Match: *
     * never arrives -- the frontend resolves existence and clears it -- so
     * only named ETags and If-None-Match do.
     */
    private List<BlobTargetOption> destinationConditions(String container,
            String key, @Nullable String ifMatch,
            @Nullable String ifNoneMatch) {
        var conditionOptions = new java.util.ArrayList<BlobTargetOption>();
        if (ifMatch == null && ifNoneMatch == null) {
            return conditionOptions;
        }
        Blob current = storage.get(BlobId.of(container, key));
        if (ifMatch != null) {
            if (current == null || isDeleteMarker(current)) {
                throw S3Exceptions.noSuchKey(container, key, "");
            }
            if (!maybeQuoteETag(ifMatch).equals(
                    maybeQuoteETag(reportETag(current)))) {
                throw preconditionFailed(reportETag(current));
            }
        }
        if (ifNoneMatch != null && current != null &&
                !isDeleteMarker(current) &&
                (ifNoneMatch.equals("*") ||
                        maybeQuoteETag(ifNoneMatch).equals(
                                maybeQuoteETag(reportETag(current))))) {
            throw preconditionFailed(reportETag(current));
        }
        // A live object -- a delete marker included, which counts as
        // absent but still holds the key's generation -- pins the write to
        // what the checks saw; nothing at all requires the key to still be
        // empty.
        conditionOptions.add(current != null ?
                BlobTargetOption.generationMatch(current.getGeneration()) :
                BlobTargetOption.doesNotExist());
        return conditionOptions;
    }

    /**
     * Emulates the x-amz-copy-source-if-* conditions against the source
     * object's current metadata since GCS has no native ETag or time
     * copy-source preconditions.  For If-Match the returned options pin the
     * copy to the verified generation so a concurrent change to the source
     * fails the copy rather than silently copying a different version.
     */
    private List<BlobSourceOption> checkCopySourceConditions(
            @Nullable Blob sourceBlob, @Nullable String ifMatch,
            @Nullable String ifNoneMatch, @Nullable Instant ifModifiedSince,
            @Nullable Instant ifUnmodifiedSince) {
        var sourceOptions = new java.util.ArrayList<BlobSourceOption>();
        if (sourceBlob == null) {
            return sourceOptions;
        }
        // An emulator may leave the ETag out, and then there is nothing to
        // hold the conditions against.
        String sourceETag = sourceBlob.getEtag() == null ? null :
                reportETag(sourceBlob);
        if (sourceETag != null) {
            String quoted = maybeQuoteETag(sourceETag);
            if (ifMatch != null &&
                    !maybeQuoteETag(ifMatch).equals(quoted)) {
                throw preconditionFailed(sourceETag);
            }
            if (ifNoneMatch != null &&
                    maybeQuoteETag(ifNoneMatch).equals(quoted)) {
                throw preconditionFailed(sourceETag);
            }
        }
        Instant lastModified = toInstant(
                sourceBlob.getUpdateTimeOffsetDateTime());
        if (lastModified != null) {
            Instant modified = truncateToSecond(lastModified);
            if (ifModifiedSince != null &&
                    modified.compareTo(ifModifiedSince) <= 0) {
                throw preconditionFailed(sourceETag);
            }
            // only when the if-match is absent, as on a read
            if (ifUnmodifiedSince != null && ifMatch == null &&
                    modified.compareTo(ifUnmodifiedSince) > 0) {
                throw preconditionFailed(sourceETag);
            }
        }
        if (ifMatch != null) {
            sourceOptions.add(BlobSourceOption.generationMatch(
                    sourceBlob.getGeneration()));
        }
        return sourceOptions;
    }

    /**
     * Deletes the live object of an unversioned bucket.  Deleting one that
     * is not there succeeds, as on S3 -- but not when the bucket is not
     * there either, which GCS reports the same way and S3 answers
     * NoSuchBucket for.
     */
    private void deleteLiveObject(String container, String key) {
        boolean deleted;
        try {
            deleted = storage.delete(BlobId.of(container, key));
        } catch (StorageException se) {
            if (se.getCode() != 404) {
                throw translate(se, container, key);
            }
            deleted = false;
        }
        if (!deleted && !containerExists(container)) {
            throw S3Exceptions.noSuchBucket(container, "");
        }
    }

    @Override
    public DeleteObjectResponse removeBlob(DeleteObjectRequest request) {
        if (request.ifMatch() != null || request.ifMatchSize() != null ||
                request.ifMatchLastModifiedTime() != null) {
            throw new UnsupportedOperationException(
                    "conditional delete not supported");
        }
        String container = request.bucket();
        String key = request.key();
        checkNotReserved(key);
        String versionId = request.versionId();
        if (versionId == null) {
            if (!isVersioned(container)) {
                deleteLiveObject(container, key);
                return DeleteObjectResponse.builder().build();
            }
            // Versioned: the generations stay and a marker goes on top of
            // them, archiving the live object the way any write does.  S3
            // leaves a marker even over a key that holds nothing.
            var markerInfo = BlobInfo.newBuilder(BlobId.of(container, key))
                    .setMetadata(Map.of(DELETE_MARKER_KEY, "true"))
                    .build();
            Blob marker;
            try {
                marker = storage.create(markerInfo, new byte[0],
                        bookkeepingTargetOptions(container));
            } catch (StorageException se) {
                throw translate(se, container, /*key=*/ null);
            }
            return DeleteObjectResponse.builder()
                    .versionId(Long.toString(marker.getGeneration()))
                    .deleteMarker(true)
                    .build();
        }
        if (versionId.equals(NULL_VERSION_ID)) {
            if (!isVersioned(container)) {
                // The null version names the live object on a container
                // that was never versioned.
                deleteLiveObject(container, key);
                return DeleteObjectResponse.builder().build();
            }
            // Nothing here is ever the null version, so it is already
            // gone, which S3 counts as deleted.
            return DeleteObjectResponse.builder()
                    .versionId(versionId)
                    .build();
        }
        // Deleting the one version named removes data, live or archived,
        // with no marker; removing the newest promotes whatever it hid.
        long generation = parseVersionId(versionId);
        Blob blob;
        try {
            blob = storage.get(BlobId.of(container, key, generation));
        } catch (StorageException se) {
            throw translate(se, container, key);
        }
        if (blob == null) {
            if (storage.get(container) == null) {
                throw S3Exceptions.noSuchBucket(container, "");
            }
            // A version that is not there is already deleted, which is
            // what the request asked for: S3 answers 204 and echoes the
            // version id, so that a delete can be retried.
            return DeleteObjectResponse.builder()
                    .versionId(versionId)
                    .build();
        }
        boolean deleteMarker = isDeleteMarker(blob);
        try {
            // The blobId carries the generation, so this removes exactly
            // the version read above; one deleted meanwhile counts as
            // deleted, the way S3 answers.
            storage.delete(blob.getBlobId());
        } catch (StorageException se) {
            if (se.getCode() != 404) {
                throw translate(se, container, key);
            }
        }
        return DeleteObjectResponse.builder()
                .versionId(versionId)
                .deleteMarker(deleteMarker ? true : null)
                .build();
    }

    /**
     * Deletes the objects a batch at a time, which GCS answers in one
     * request each -- where the interface default would spend a request per
     * object.
     *
     * <p>A batch that any object refused is asked again one object at a
     * time: the batch raises a GCS exception, while the single delete raises
     * the typed failure the frontend turns into that object's error code.
     * Refusals are rare, so the second pass is too.
     */
    @Override
    public DeleteObjectsResponse removeBlobs(DeleteObjectsRequest request) {
        var objects = request.delete() == null ? List.<ObjectIdentifier>of() :
                request.delete().objects();
        if (objects.isEmpty()) {
            return DeleteObjectsResponse.builder().build();
        }
        String container = request.bucket();
        if (isVersioned(container) ||
                objects.stream().anyMatch(o -> o.versionId() != null)) {
            // Versioned deletes each carry their own semantics -- a marker
            // to write and report, or one generation to remove outright --
            // which the batch cannot express.
            return BlobStore.super.removeBlobs(request);
        }
        if (objects.stream().anyMatch(
                o -> o.key().startsWith(STUB_BLOB_PREFIX))) {
            // The batch names its keys to GCS itself and would delete a
            // reserved one.  removeBlob refuses it with the typed failure
            // that becomes that object's error, and deletes the others.
            return BlobStore.super.removeBlobs(request);
        }
        var deleted = new ImmutableList.Builder<DeletedObject>();
        var errors = new ImmutableList.Builder<S3Error>();

        for (List<ObjectIdentifier> chunk :
                Lists.partition(objects, MAX_BATCH_DELETES)) {
            var batch = storage.batch();
            var results = new ArrayList<StorageBatchResult<Boolean>>(
                    chunk.size());
            for (ObjectIdentifier object : chunk) {
                results.add(batch.delete(
                        BlobId.of(container, object.key())));
            }
            batch.submit();

            boolean refused = false;
            for (StorageBatchResult<Boolean> result : results) {
                try {
                    // The Boolean reports whether the object was there, which
                    // an idempotent delete does not care about; only a
                    // failure to carry it out matters.
                    result.get();
                } catch (StorageException se) {
                    if (se.getCode() != 404) {
                        refused = true;
                        break;
                    }
                }
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

    @Override
    public HeadObjectResponse blobMetadata(HeadObjectRequest request) {
        String container = request.bucket();
        String key = request.key();
        Blob gcsBlob = resolveVersion(container, key, request.versionId());
        if (gcsBlob == null) {
            throw S3Exceptions.noSuchKey(container, key, "no such object");
        }
        // as getBlob does, on the generation whose metadata is reported
        if (SdkRequests.onlyIfPublicRead(request) &&
                blobAccess(container, key, gcsBlob) !=
                        ObjectCannedACL.PUBLIC_READ) {
            throw S3Exceptions.fromStatusCode(403);
        }
        return HeadObjectResponse.builder()
                .metadata(sanitizeUserMetadata(gcsBlob.getMetadata()))
                .eTag(reportETag(gcsBlob))
                .lastModified(toInstant(
                        gcsBlob.getUpdateTimeOffsetDateTime()))
                .storageClass(
                        fromGcsStorageClass(gcsBlob.getStorageClass())
                                .toString())
                .cacheControl(gcsBlob.getCacheControl())
                .contentDisposition(gcsBlob.getContentDisposition())
                .contentEncoding(gcsBlob.getContentEncoding())
                .contentLanguage(gcsBlob.getContentLanguage())
                .contentLength(gcsBlob.getSize())
                .contentType(gcsBlob.getContentType())
                .versionId(reportedVersionId(container, gcsBlob,
                        request.versionId()))
                .build();
    }


    @Override
    public BucketCannedACL getContainerAccess(String container) {
        var bucket = storage.get(container);
        if (bucket == null) {
            throw S3Exceptions.noSuchBucket(container, "");
        }
        if (preventsPublicAccess(bucket)) {
            return BucketCannedACL.PRIVATE;
        }
        try {
            var acls = bucket.listAcls();
            for (var acl : acls) {
                if (acl.getEntity().equals(Acl.User.ofAllUsers())) {
                    return Acl.Role.READER.equals(acl.getRole()) ?
                            BucketCannedACL.PUBLIC_READ :
                            BucketCannedACL.PUBLIC_READ_WRITE;
                }
            }
        } catch (StorageException se) {
            // The emulator returns ACL responses the SDK cannot deserialize
            // (StorageException with no HTTP status, code 0); tolerate those
            // but surface real failures rather than reporting PRIVATE.
            if (se.getCode() != 0) {
                throw translate(se, container, /*key=*/ null);
            }
        }
        return BucketCannedACL.PRIVATE;
    }

    /**
     * Whether the bucket overrides what its ACL and those of its objects
     * grant allUsers.  Public access prevention leaves the entries where
     * they are, to take effect again once it is lifted, and GCS refuses an
     * anonymous request whatever they say.  The requests of this store are
     * not anonymous, so the frontend must not take an entry alone to make
     * anything public.  A bucket that inherits the prevention from an
     * organization policy does not say so in its own metadata and is not
     * recognized here.
     */
    private static boolean preventsPublicAccess(Bucket bucket) {
        var configuration = bucket.getIamConfiguration();
        return configuration != null &&
                configuration.getPublicAccessPrevention() ==
                        BucketInfo.PublicAccessPrevention.ENFORCED;
    }

    /**
     * As above, for the bucket of an object whose ACL is about to be read.
     * A missing bucket prevents nothing: the ACL read reports it.
     */
    private boolean preventsPublicAccess(String container) {
        var bucket = storage.get(container,
                BucketGetOption.fields(BucketField.IAMCONFIGURATION));
        return bucket != null && preventsPublicAccess(bucket);
    }

    @Override
    public void setContainerAccess(String container,
            BucketCannedACL access) {
        try {
            if (access == BucketCannedACL.PUBLIC_READ_WRITE) {
                storage.createAcl(container,
                        Acl.of(Acl.User.ofAllUsers(), Acl.Role.WRITER));
            } else if (access == BucketCannedACL.PUBLIC_READ) {
                storage.createAcl(container,
                        Acl.of(Acl.User.ofAllUsers(), Acl.Role.READER));
            } else {
                storage.deleteAcl(container, Acl.User.ofAllUsers());
            }
        } catch (StorageException se) {
            // The emulator returns ACL responses the SDK cannot deserialize
            // (StorageException with no HTTP status, code 0); the ACL is
            // applied server-side, so tolerate those.  Surface real failures
            // (permission denied, uniform bucket-level access, missing bucket)
            // rather than reporting success for a change that did not apply.
            if (se.getCode() != 0) {
                throw translate(se, container, /*key=*/ null);
            }
        }
    }

    @Override
    public ObjectCannedACL getBlobAccess(String container, String key) {
        try {
            // Asked for every key rather than only for one whose ACL has
            // an entry for allUsers, so that how long a refusal takes does
            // not tell such a key from a private one.
            boolean prevented = preventsPublicAccess(container);
            var acls = storage.listAcls(BlobId.of(container, key));
            for (var acl : acls) {
                if (acl.getEntity().equals(Acl.User.ofAllUsers())) {
                    return prevented ? ObjectCannedACL.PRIVATE :
                            ObjectCannedACL.PUBLIC_READ;
                }
            }
        } catch (StorageException se) {
            // A missing bucket answers 404 as a missing object does.  Which
            // of them it was is not asked here: that is one more request,
            // made for a missing key alone, and an anonymous read refused
            // over it took that much longer than one of a private key.
            // Whoever refuses such a read learns of a missing bucket from
            // getContainerAccess, and getBlobAcl asks for its own caller.
            if (se.getCode() == 404) {
                throw S3Exceptions.noSuchKey(container, key, "");
            }
            // The emulator returns ACL responses the SDK cannot deserialize
            // (StorageException with no HTTP status, code 0); tolerate those
            // but surface real failures rather than reporting PRIVATE.
            if (se.getCode() != 0) {
                throw translate(se, container, key);
            }
        }
        return ObjectCannedACL.PRIVATE;
    }

    @Override
    public ObjectCannedACL getBlobAccess(String container, String key,
            @Nullable String versionId) {
        Blob blob = resolveVersion(container, key, versionId);
        if (blob == null) {
            throw S3Exceptions.noSuchKey(container, key, "");
        }
        return blobAccess(container, key, blob);
    }

    /** The access one generation of an object grants. */
    private ObjectCannedACL blobAccess(String container, String key,
            Blob blob) {
        try {
            // The blobId carries the generation, so the ACL read is the
            // version's own rather than the live object's.
            boolean prevented = preventsPublicAccess(container);
            var acls = storage.listAcls(blob.getBlobId());
            for (var acl : acls) {
                if (acl.getEntity().equals(Acl.User.ofAllUsers())) {
                    return prevented ? ObjectCannedACL.PRIVATE :
                            ObjectCannedACL.PUBLIC_READ;
                }
            }
        } catch (StorageException se) {
            if (se.getCode() == 404) {
                throw S3Exceptions.noSuchKey(container, key, "");
            }
            // The emulator returns ACL responses the SDK cannot deserialize
            // (StorageException with no HTTP status, code 0); tolerate those
            // but surface real failures rather than reporting PRIVATE.
            if (se.getCode() != 0) {
                throw translate(se, container, key);
            }
        }
        return ObjectCannedACL.PRIVATE;
    }

    /**
     * The ACL of an object, for a caller who has signed for it: told apart
     * here are the missing bucket and the missing object, which GCS reports
     * alike, so that the frontend emits NoSuchBucket vs NoSuchKey.
     */
    @Override
    public GetObjectAclResponse getBlobAcl(GetObjectAclRequest request) {
        try {
            return BlobStore.super.getBlobAcl(request);
        } catch (NoSuchKeyException e) {
            if (storage.get(request.bucket()) == null) {
                throw S3Exceptions.noSuchBucket(request.bucket(), "");
            }
            throw e;
        }
    }

    @Override
    public void setBlobAccess(String container, String key,
            ObjectCannedACL access) {
        checkNotReserved(key);
        try {
            if (access == ObjectCannedACL.PUBLIC_READ) {
                storage.createAcl(BlobId.of(container, key),
                        Acl.of(Acl.User.ofAllUsers(), Acl.Role.READER));
            } else {
                storage.deleteAcl(BlobId.of(container, key),
                        Acl.User.ofAllUsers());
            }
        } catch (StorageException se) {
            // The emulator returns ACL responses the SDK cannot deserialize
            // (StorageException with no HTTP status, code 0); the ACL is
            // applied server-side, so tolerate those.  Surface real failures
            // (permission denied, uniform bucket-level access, missing object)
            // rather than reporting success for a change that did not apply.
            if (se.getCode() != 0) {
                throw translate(se, container, key);
            }
        }
    }

    @Override
    public void setBlobAccess(String container, String key,
            ObjectCannedACL access, @Nullable String versionId) {
        checkNotReserved(key);
        Blob blob = resolveVersion(container, key, versionId);
        if (blob == null) {
            throw S3Exceptions.noSuchKey(container, key, "");
        }
        try {
            if (access == ObjectCannedACL.PUBLIC_READ) {
                storage.createAcl(blob.getBlobId(),
                        Acl.of(Acl.User.ofAllUsers(), Acl.Role.READER));
            } else {
                storage.deleteAcl(blob.getBlobId(), Acl.User.ofAllUsers());
            }
        } catch (StorageException se) {
            // As in the unversioned overload: tolerate the emulator's
            // undeserializable ACL responses, surface real failures.
            if (se.getCode() != 0) {
                throw translate(se, container, key);
            }
        }
    }

    @Override
    public MultipartUpload initiateMultipartUpload(
            CreateMultipartUploadRequest request) {
        // Completing this upload writes an object under the requested key,
        // which is the same write putBlob refuses.
        checkNotReserved(request.key());
        String container = request.bucket();
        if (!containerExists(container)) {
            throw S3Exceptions.noSuchBucket(container, "");
        }

        String uploadId = UploadNames.newUploadId(request.key());
        String targetBlobName = request.key();

        // Store stub blob with metadata for later use during complete
        var stubMetadata = new HashMap<String, String>();
        stubMetadata.put(TARGET_BLOB_NAME_KEY, targetBlobName);

        if (request.contentType() != null) {
            stubMetadata.put("s3proxy_content_type", request.contentType());
        }
        if (request.contentDisposition() != null) {
            stubMetadata.put("s3proxy_content_disposition",
                    request.contentDisposition());
        }
        if (request.contentEncoding() != null) {
            stubMetadata.put("s3proxy_content_encoding",
                    request.contentEncoding());
        }
        if (request.contentLanguage() != null) {
            stubMetadata.put("s3proxy_content_language",
                    request.contentLanguage());
        }
        if (request.cacheControl() != null) {
            stubMetadata.put("s3proxy_cache_control",
                    request.cacheControl());
        }

        for (var entry : request.metadata().entrySet()) {
            stubMetadata.put("s3proxy_user_" + entry.getKey(),
                    entry.getValue());
        }

        if (request.storageClass() != null &&
                request.storageClass() != StorageClass.STANDARD) {
            stubMetadata.put("s3proxy_storage_class",
                    request.storageClass().name());
        }

        // The access rides on the stub because it is only offered here.  This
        // backend does not require a stub as far as Quirks is concerned, so
        // the completion cannot be asked what the caller wanted.
        if (request.acl() == ObjectCannedACL.PUBLIC_READ) {
            stubMetadata.put(BLOB_ACCESS_KEY,
                    ObjectCannedACL.PUBLIC_READ.name());
        }

        var stubInfo = BlobInfo.newBuilder(
                BlobId.of(container, stubName(targetBlobName, uploadId)))
                .setMetadata(stubMetadata)
                .build();
        storage.create(stubInfo, new byte[0],
                bookkeepingTargetOptions(container));

        return new MultipartUpload(uploadId, request);
    }

    /** The name of an upload's stub, from its key and upload ID. */
    static String stubName(String key, String uploadId) {
        String name = UPLOADS_PREFIX + UploadNames.escapeKey(key) +
                UploadNames.SEPARATOR + uploadId;
        if (name.getBytes(StandardCharsets.UTF_8).length <= MAX_NAME_BYTES) {
            return name;
        }
        return LONG_UPLOADS_PREFIX + uploadId;
    }

    static String partName(String uploadId, int partNumber) {
        return PARTS_PREFIX + uploadId + "/part_%05d".formatted(partNumber);
    }

    /**
     * The stub of the upload the request names, by its key and upload ID
     * both, or null.  Another key's upload of the same ID has another stub,
     * so a part, completion, listing or abort naming the wrong key finds
     * none, as on S3; a long key's stub is named by its ID alone and keeps
     * the key in its metadata, which is compared instead.
     */
    private @Nullable Blob findStub(MultipartUpload mpu, boolean full) {
        if (!UploadNames.namesKey(mpu.id(), mpu.blobName())) {
            return null;
        }
        String name = stubName(mpu.blobName(), mpu.id());
        Blob stub = full ?
                storage.get(BlobId.of(mpu.containerName(), name)) :
                storage.get(BlobId.of(mpu.containerName(), name),
                        BlobGetOption.fields(BlobField.NAME,
                                BlobField.METADATA));
        if (stub == null || stub.getMetadata() == null ||
                !mpu.blobName().equals(
                        stub.getMetadata().get(TARGET_BLOB_NAME_KEY))) {
            return null;
        }
        return stub;
    }

    @Override
    public void abortMultipartUpload(MultipartUpload mpu) {
        // the stub of another key's upload is not this request's to remove
        if (findStub(mpu, /*full=*/ false) == null) {
            throw S3Exceptions.noSuchKey(mpu.containerName(), mpu.id(),
                    "Multipart upload not found: " + mpu.id());
        }
        removeUpload(mpu);
    }

    /**
     * Removes every generation of the upload's bookkeeping -- parts,
     * intermediate composes and the stub, the stub listed last.  On a
     * versioning-enabled container a plain delete would archive them
     * instead, and the hidden versions would outlive every upload and hold
     * the bucket undeletable on the real service.
     */
    private void removeUpload(MultipartUpload mpu) {
        String container = mpu.containerName();
        var parts = storage.list(container,
                BlobListOption.prefix(PARTS_PREFIX + mpu.id() + "/"),
                BlobListOption.versions(true)).iterateAll();
        var stub = storage.list(container,
                BlobListOption.prefix(stubName(mpu.blobName(), mpu.id())),
                BlobListOption.versions(true)).iterateAll();
        deleteGenerations(() -> java.util.stream.Stream.concat(
                Streams.stream(parts), Streams.stream(stub)).iterator());
    }

    @Override
    public CompleteMultipartUploadResponse completeMultipartUpload(MultipartUpload mpu,
            CompleteMultipartUploadRequest request) {
        List<CompletedPart> parts = request.multipartUpload() == null ?
                List.of() : request.multipartUpload().parts();
        String uploadId = mpu.id();

        // an upload of another key, which this request does not name, has
        // a stub of another name
        Blob stubBlob = findStub(mpu, /*full=*/ true);
        if (stubBlob == null) {
            throw S3Exceptions.noSuchUpload(uploadId);
        }
        var stubMetadata = requireNonNull(stubBlob.getMetadata());
        String targetBlobName = mpu.blobName();

        if (parts == null || parts.isEmpty()) {
            throw new IllegalArgumentException("Parts list cannot be empty");
        }

        int previousPartNumber = 0;
        for (var part : parts) {
            if (part.partNumber() <= previousPartNumber) {
                throw new IllegalArgumentException(
                        "Parts must be in strictly ascending order");
            }
            previousPartNumber = part.partNumber();
        }

        // Build target blob info from stub metadata
        var targetBuilder = BlobInfo.newBuilder(
                BlobId.of(mpu.containerName(), targetBlobName));
        if (stubMetadata.containsKey("s3proxy_content_type")) {
            targetBuilder.setContentType(
                    stubMetadata.get("s3proxy_content_type"));
        }
        if (stubMetadata.containsKey("s3proxy_content_disposition")) {
            targetBuilder.setContentDisposition(
                    stubMetadata.get("s3proxy_content_disposition"));
        }
        if (stubMetadata.containsKey("s3proxy_content_encoding")) {
            targetBuilder.setContentEncoding(
                    stubMetadata.get("s3proxy_content_encoding"));
        }
        if (stubMetadata.containsKey("s3proxy_content_language")) {
            targetBuilder.setContentLanguage(
                    stubMetadata.get("s3proxy_content_language"));
        }
        if (stubMetadata.containsKey("s3proxy_cache_control")) {
            targetBuilder.setCacheControl(
                    stubMetadata.get("s3proxy_cache_control"));
        }
        if (stubMetadata.containsKey("s3proxy_storage_class")) {
            targetBuilder.setStorageClass(toGcsStorageClass(
                    StorageClass.valueOf(stubMetadata.get(
                            "s3proxy_storage_class"))));
        }

        // Restore user metadata
        var userMetadata = new HashMap<String, String>();
        for (var entry : stubMetadata.entrySet()) {
            String value = entry.getValue();
            if (entry.getKey().startsWith("s3proxy_user_") &&
                    value != null) {
                userMetadata.put(
                        entry.getKey().substring("s3proxy_user_".length()),
                        value);
            }
        }
        if (!userMetadata.isEmpty()) {
            targetBuilder.setMetadata(userMetadata);
        }

        // The publish conditions, enforced as on a plain put.
        var conditionOptions = destinationConditions(mpu.containerName(),
                targetBlobName, request.ifMatch(), request.ifNoneMatch());

        // A single part is copied onto the target and can name the access on
        // that request, so no later one can fail and leave a private blob
        // where the caller asked for a public one.  Compose cannot; see below.
        boolean publicRead = ObjectCannedACL.PUBLIC_READ.name().equals(
                stubMetadata.get(BLOB_ACCESS_KEY));
        var acl = predefinedAcl(mpu.containerName(), publicRead);
        var targetOptions = new java.util.ArrayList<BlobTargetOption>();
        if (acl != null) {
            targetOptions.add(BlobTargetOption.predefinedAcl(acl));
        }
        targetOptions.addAll(conditionOptions);

        // If single part, just copy it to the target
        if (parts.size() == 1) {
            String partBlobName = partName(uploadId,
                    parts.get(0).partNumber());
            var source = BlobId.of(mpu.containerName(), partBlobName);
            var copyRequest = CopyRequest.newBuilder()
                    .setSource(source)
                    .setTarget(targetBuilder.build(), targetOptions)
                    .build();
            CopyWriter copyWriter;
            try {
                copyWriter = storage.copy(copyRequest);
            } catch (StorageException se) {
                throw translate(se, mpu.containerName(), targetBlobName);
            }
            var result = copyWriter.getResult();
            removeUpload(mpu);
            return SdkResponses.completeResponse(reportETag(result),
                    isVersioned(mpu.containerName()) ?
                            Long.toString(result.getGeneration()) : null);
        }

        // GCS compose supports up to 32 parts.
        // For more parts, compose recursively.
        var sourceBlobIds = new java.util.ArrayList<BlobId>();
        for (var part : parts) {
            String partBlobName = partName(uploadId, part.partNumber());
            sourceBlobIds.add(BlobId.of(mpu.containerName(), partBlobName));
        }

        Blob composed = composeRecursive(mpu.containerName(),
                targetBuilder.build(), sourceBlobIds, uploadId,
                conditionOptions);

        // objects.compose accepts destinationPredefinedAcl, but the SDK drops
        // it: HttpStorageRpc.compose forwards only the generation,
        // metageneration and userProject options.  Naming it here would do
        // nothing, so set the access in a second request -- cheaper than
        // composing to a temporary name and copying that onto the target
        // solely to carry the ACL.
        // TODO: name the ACL on the compose itself, as the single-part copy
        // above does, after
        // https://github.com/googleapis/google-cloud-java/pull/13975 is
        // released and google-cloud-storage is bumped past it
        // Asked of the upload's own access and not of targetOptions, which
        // hold the publish conditions too: a conditional completion of a
        // private upload would otherwise be made public here.
        if (publicRead) {
            storage.createAcl(composed.getBlobId(),
                    Acl.of(Acl.User.ofAllUsers(), Acl.Role.READER));
        } else if (acl != null) {
            // Composed without an ACL, the object has its bucket's default
            // one, which may grant allUsers where the upload is private.
            // The grant is removed as setBlobAccess removes it, which is no
            // error where there is none.  Until the compose can name the
            // ACL, such an object is public for as long as this takes; and
            // should the removal fail, the object is removed instead rather
            // than left public.  The parts are still there, so the caller
            // can complete again.
            try {
                storage.deleteAcl(composed.getBlobId(), Acl.User.ofAllUsers());
            } catch (RuntimeException re) {
                try {
                    storage.delete(composed.getBlobId());
                } catch (RuntimeException re2) {
                    re.addSuppressed(re2);
                }
                throw re;
            }
        }

        removeUpload(mpu);

        return SdkResponses.completeResponse(reportETag(composed),
                isVersioned(mpu.containerName()) ?
                        Long.toString(composed.getGeneration()) : null);
    }

    /**
     * Recursively compose blobs to handle more than 32 parts.
     * GCS compose supports max 32 sources, so for N > 32 parts we
     * compose in groups of 32, then compose those results.
     */
    private Blob composeRecursive(String container, BlobInfo target,
            List<BlobId> sources, String uploadId,
            List<BlobTargetOption> conditionOptions) {
        if (sources.size() <= MAX_COMPOSE_PARTS) {
            var composeBuilder = ComposeRequest.newBuilder();
            composeBuilder.setTarget(target);
            // The publish conditions ride only here, on the compose that
            // writes the target; the intermediates below are unconditional.
            composeBuilder.setTargetOptions(conditionOptions);
            for (var source : sources) {
                composeBuilder.addSource(source.getName());
            }
            try {
                return storage.compose(composeBuilder.build());
            } catch (StorageException se) {
                throw translate(se, container, target.getName());
            }
        }

        // Compose in groups of MAX_COMPOSE_PARTS
        var intermediateIds = new java.util.ArrayList<BlobId>();
        int groupIndex = 0;
        for (int i = 0; i < sources.size();
                i += MAX_COMPOSE_PARTS) {
            int end = Math.min(i + MAX_COMPOSE_PARTS, sources.size());
            var group = sources.subList(i, end);
            String intermediateName = PARTS_PREFIX + uploadId +
                    "/compose_" + groupIndex;
            var intermediateInfo = BlobInfo.newBuilder(
                    BlobId.of(container, intermediateName)).build();

            var composeBuilder = ComposeRequest.newBuilder();
            composeBuilder.setTarget(intermediateInfo);
            for (var source : group) {
                composeBuilder.addSource(source.getName());
            }
            Blob intermediate = storage.compose(composeBuilder.build());
            // Like the final compose, this one cannot name the ACL, and
            // the intermediate holds the upload's content.
            if (predefinedAcl(container, /*publicRead=*/ false) != null) {
                storage.deleteAcl(intermediate.getBlobId(),
                        Acl.User.ofAllUsers());
            }

            intermediateIds.add(BlobId.of(container, intermediateName));
            groupIndex++;
        }

        // Recursively compose intermediates
        return composeRecursive(container, target, intermediateIds,
                uploadId, conditionOptions);
    }

    @Override
    public UploadPartResponse uploadMultipartPart(MultipartUpload mpu,
            UploadPartRequest request, InputStream is) {
        int partNumber = request.partNumber();
        long contentLength = request.contentLength();
        var contentMD5 = SdkRequests.contentMD5(request);
        if (partNumber < 1 || partNumber > 10_000) {
            throw new IllegalArgumentException(
                    "Part number must be between 1 and 10,000, got: " +
                    partNumber);
        }

        String partBlobName = partName(openUploadId(mpu), partNumber);

        byte[] md5Hash;
        var digest = MD5.newDigest();
        try (var dis = new DigestInputStream(is, digest)) {
            var partInfo = BlobInfo.newBuilder(
                    BlobId.of(mpu.containerName(), partBlobName));
            // GCS judges the Content-MD5 itself and writes nothing when it
            // does not match, as in putBlob.  Comparing only after the part
            // was written refused it too late: the part's name is its
            // number, so the bad bytes had already replaced the part they
            // were a retry of, and deleting them took that part too.
            var partOptions = new ArrayList<BlobWriteOption>();
            var acl = predefinedAcl(mpu.containerName(),
                    /*publicRead=*/ false);
            if (acl != null) {
                partOptions.add(BlobWriteOption.predefinedAcl(acl));
            }
            if (contentMD5 != null) {
                partInfo.setMd5(Base64.getEncoder().encodeToString(
                        contentMD5.asBytes()));
                partOptions.add(MD5_MATCH);
            }
            upload(partInfo.build(), dis, contentLength,
                    partOptions.toArray(new BlobWriteOption[0]));

            md5Hash = digest.digest();
        } catch (StorageException se) {
            // As in putBlob: GCS reports the validation md5Match asked for
            // as a generic 400, which the frontend answers as BadDigest.
            if (se.getCode() == 400 && contentMD5 != null) {
                throw S3Exceptions.fromStatusCode(400, se);
            }
            throw translate(se, mpu.containerName(), mpu.blobName());
        } catch (IOException ioe) {
            throw new RuntimeException((
                    "Failed to upload part %d for blob '%s' in " +
                    "container '%s': %s").formatted(
                    partNumber, mpu.blobName(), mpu.containerName(),
                    ioe.getMessage()), ioe);
        }

        String eTag = HexFormat.of().formatHex(md5Hash);
        return SdkResponses.uploadedPart(eTag);
    }

    /**
     * The ID of an upload that is open, which is one whose stub exists.  A
     * part's name is built from the upload ID, so an ID that was never
     * issued, or whose upload has since been completed or aborted, must not
     * get as far as a write: the part would be kept where no completion
     * and no abort will ever find it.  An upload begun for another key than
     * the request names is no more open to it, as on S3.
     */
    private String openUploadId(MultipartUpload mpu) {
        if (findStub(mpu, /*full=*/ false) == null) {
            throw S3Exceptions.noSuchUpload(mpu.id());
        }
        return mpu.id();
    }

    @Override
    public boolean supportsCopyMultipartPart() {
        return true;
    }

    @Override
    public UploadPartCopyResponse copyMultipartPart(MultipartUpload mpu,
            UploadPartCopyRequest request) {
        int partNumber = request.partNumber();
        if (partNumber < 1 || partNumber > 10_000) {
            throw new IllegalArgumentException(
                    "Part number must be between 1 and 10,000, got: " +
                    partNumber);
        }

        String sourceContainer = request.sourceBucket();
        String sourceName = request.sourceKey();
        Blob sourceBlob = resolveVersion(sourceContainer, sourceName,
                request.sourceVersionId());
        if (sourceBlob == null) {
            throw S3Exceptions.noSuchKey(sourceContainer, sourceName, "");
        }
        // The generation rides on the blobId, so the copy reads the version
        // the resolution named.
        var source = sourceBlob.getBlobId();

        // GCS cannot copy a byte range server-side; a range covering the
        // whole object is equivalent to no range, anything else falls back
        // to streamed emulation in the caller.
        String copySourceRange = request.copySourceRange();
        if (copySourceRange != null && !isEntireObject(copySourceRange,
                sourceBlob.getSize())) {
            throw new UnsupportedOperationException(
                    "GCS does not support ranged server-side copies");
        }

        // A part's ETag is its MD5, and GCS keeps none for a composite
        // object -- which every object completed from a multipart upload
        // here is.  Copied server-side, such a part would have no ETag to
        // report or to complete the upload with, so it is streamed instead:
        // the caller's emulation uploads it as a part, and that has one.
        if (sourceBlob.getMd5() == null) {
            throw new UnsupportedOperationException(
                    "GCS keeps no MD5 for a composite source");
        }

        var sourceOptions = checkCopySourceConditions(sourceBlob,
                request.copySourceIfMatch(), request.copySourceIfNoneMatch(),
                request.copySourceIfModifiedSince(),
                request.copySourceIfUnmodifiedSince());

        String partBlobName = partName(openUploadId(mpu), partNumber);

        try {
            var copyRequest = CopyRequest.newBuilder()
                    .setSource(source)
                    .setSourceOptions(sourceOptions)
                    .setTarget(BlobInfo.newBuilder(BlobId.of(
                            mpu.containerName(), partBlobName)).build(),
                            List.of(bookkeepingTargetOptions(
                                    mpu.containerName())))
                    .build();
            var result = storage.copy(copyRequest).getResult();
            // Match uploadMultipartPart's hex MD5 part ETag;
            // listMultipartUpload reads the same value back from GCS.
            return SdkResponses.copiedPart(result.getMd5ToHexString(),
                    /*lastModified=*/ null,
                    reportedVersionId(sourceContainer, sourceBlob,
                            request.sourceVersionId()));
        } catch (StorageException se) {
            throw translate(se, sourceContainer, sourceName);
        }
    }

    /** Whether a strict bytes=first-last range spans the whole object. */
    private static boolean isEntireObject(String range, long size) {
        if (!range.startsWith("bytes=") || range.indexOf(',') != -1) {
            return false;
        }
        String[] parts = range.substring("bytes=".length()).split("-", 2);
        if (parts.length != 2 || parts[0].isEmpty() || parts[1].isEmpty()) {
            return false;
        }
        try {
            return Long.parseLong(parts[0]) == 0 &&
                    Long.parseLong(parts[1]) == size - 1;
        } catch (NumberFormatException nfe) {
            return false;
        }
    }

    @Override
    public List<Part> listMultipartUpload(MultipartUpload mpu) {
        String uploadId = mpu.id();
        // an upload begun for another key, or none at all
        if (!UploadNames.namesKey(uploadId, mpu.blobName())) {
            throw S3Exceptions.noSuchUpload(uploadId);
        }
        String prefix = PARTS_PREFIX + uploadId + "/part_";

        // A stub that is gone is left to the listing, which then finds no
        // parts: that is how the frontend knows to look for the finished
        // object, whose parts went before its stub.  Parts without the
        // stub this request names are another key's upload's, which are
        // not this request's to see.
        boolean open = findStub(mpu, /*full=*/ false) != null;

        var parts = ImmutableList.<Part>builder();
        var page = storage.list(mpu.containerName(),
                BlobListOption.prefix(prefix));
        for (Blob blob : page.iterateAll()) {
            String name = blob.getName();
            String partNumberStr = name.substring(
                    name.lastIndexOf('_') + 1);
            int partNumber;
            try {
                partNumber = Integer.parseInt(partNumberStr);
            } catch (NumberFormatException e) {
                continue;
            }
            // Report the part's hex MD5 as its ETag (matching
            // uploadMultipartPart) so CompleteMultipartUpload can validate the
            // client-supplied part ETags.
            if (!open) {
                throw S3Exceptions.noSuchUpload(uploadId);
            }
            parts.add(SdkResponses.part(partNumber, blob.getSize(),
                    blob.getMd5ToHexString(), null));
        }
        // the listing above is ordered by name, which puts part_10 ahead of
        // part_2
        return ImmutableList.sortedCopyOf(
                Comparator.comparingInt(Part::partNumber), parts.build());
    }

    @Override
    public List<software.amazon.awssdk.services.s3.model.MultipartUpload>
            listMultipartUploads(String container) {
        var uploads = new ArrayList<
                software.amazon.awssdk.services.s3.model.MultipartUpload>();
        for (Blob blob : storage.list(container,
                BlobListOption.prefix(UPLOADS_PREFIX)).iterateAll()) {
            var upload = keyedUpload(blob);
            if (upload != null) {
                uploads.add(upload);
            }
        }
        uploads.addAll(longUploads(container));
        return uploads;
    }

    /**
     * One page of uploads, read from GCS a page at a time.  The stubs sort
     * as S3 lists the uploads, so the listing starts where the markers
     * point and stops once it holds the page and the entry that tells
     * there is more; a slash delimiter is GCS's own, which folds a group
     * of keys into one entry however many uploads it holds.  The few stubs
     * of keys too long to be named by them are read whole and merged in.
     */
    @Override
    public ListMultipartUploadsResponse listMultipartUploads(
            ListMultipartUploadsRequest request) {
        String container = request.bucket();
        String prefix = Strings.nullToEmpty(request.prefix());
        String delimiter = Strings.emptyToNull(request.delimiter());
        String keyMarker = Strings.emptyToNull(request.keyMarker());
        var options = new ArrayList<BlobListOption>();
        options.add(BlobListOption.prefix(UPLOADS_PREFIX +
                UploadNames.escapeKey(prefix)));
        options.add(BlobListOption.pageSize(Math.min(
                UploadListings.maxUploads(request) + 2, MAX_LIST_PAGE_SIZE)));
        if ("/".equals(delimiter)) {
            options.add(BlobListOption.delimiter("/"));
        }
        String start = UploadNames.startName(prefix, delimiter, keyMarker,
                keyMarker == null ? null :
                        Strings.emptyToNull(request.uploadIdMarker()));
        if (start != null) {
            options.add(BlobListOption.startOffset(UPLOADS_PREFIX + start));
        }
        Iterable<software.amazon.awssdk.services.s3.model.MultipartUpload>
                ordered = () -> Streams.stream(inNameOrder(storage.list(
                        container, options.toArray(new BlobListOption[0]))))
                .map(GCloudBlobStore::listedUpload)
                .filter(java.util.Objects::nonNull)
                .iterator();
        try {
            return UploadListings.pageFromOrdered(ordered,
                    longUploads(container), request);
        } catch (StorageException se) {
            throw translate(se, container, /*key=*/ null);
        }
    }

    /**
     * An entry of a listing of the uploads area: an upload, or a group of
     * keys GCS folded, which the page reports as the common prefix an
     * upload of that name folds into.
     */
    private static software.amazon.awssdk.services.s3.model.@Nullable
            MultipartUpload listedUpload(Blob blob) {
        if (blob.isDirectory()) {
            return software.amazon.awssdk.services.s3.model.MultipartUpload
                    .builder()
                    .key(UploadNames.unescapeKey(blob.getName().substring(
                            UPLOADS_PREFIX.length())))
                    .uploadId("")
                    .build();
        }
        return keyedUpload(blob);
    }

    /**
     * A listing's entries in the order of their names, a page at a time.
     * GCS names a page's common prefixes after its objects, so each page is
     * sorted as it arrives; the pages themselves follow in order.
     */
    private static Iterable<Blob> inNameOrder(Page<Blob> first) {
        return () -> new AbstractIterator<Blob>() {
            // the page last read; the next is fetched once it is used
            private @Nullable Page<Blob> page;
            private java.util.Iterator<Blob> blobs =
                    java.util.Collections.emptyIterator();

            @Override
            protected @Nullable Blob computeNext() {
                while (!blobs.hasNext()) {
                    Page<Blob> current = page;
                    if (current == null) {
                        current = first;
                    } else if (current.hasNextPage()) {
                        current = current.getNextPage();
                    } else {
                        return endOfData();
                    }
                    page = current;
                    var values = Lists.newArrayList(current.getValues());
                    values.sort(Comparator.comparing(Blob::getName));
                    blobs = values.iterator();
                }
                return blobs.next();
            }
        };
    }

    /** The upload a stub named by its key records, or null for another. */
    private static software.amazon.awssdk.services.s3.model.@Nullable
            MultipartUpload keyedUpload(Blob blob) {
        String name = blob.getName();
        if (blob.isDirectory() || !name.startsWith(UPLOADS_PREFIX)) {
            return null;
        }
        // The stub is written when the upload is created and never again,
        // so its time is the upload's.
        return UploadNames.parseStubName(
                name.substring(UPLOADS_PREFIX.length()),
                toInstant(blob.getCreateTimeOffsetDateTime()));
    }

    /** The uploads of keys too long for a stub to be named by them. */
    private List<software.amazon.awssdk.services.s3.model.MultipartUpload>
            longUploads(String container) {
        var uploads = new ArrayList<
                software.amazon.awssdk.services.s3.model.MultipartUpload>();
        for (Blob blob : storage.list(container,
                BlobListOption.prefix(LONG_UPLOADS_PREFIX)).iterateAll()) {
            String uploadId = blob.getName().substring(
                    LONG_UPLOADS_PREFIX.length());
            String key = blob.getMetadata() == null ? null :
                    blob.getMetadata().get(TARGET_BLOB_NAME_KEY);
            if (key != null && UploadNames.isUploadId(uploadId)) {
                uploads.add(SdkResponses.upload(key, uploadId,
                        toInstant(blob.getCreateTimeOffsetDateTime())));
            }
        }
        return uploads;
    }

    @Override
    public long getMinimumMultipartPartSize() {
        // GCS minimum part is 5 MB except for last part
        return 5L * 1024 * 1024;
    }

    /**
     * Refuse a client key naming the store's multipart bookkeeping.  The
     * stub, the parts and the intermediate composes are objects of the
     * client's own bucket, and completeMultipartUpload publishes what the
     * stub's metadata says: the target key, the headers, the user metadata
     * and the ACL.  Upload IDs are the stubs' names and not secret, being
     * what ListMultipartUploads returns, so a client able to write one --
     * bucket WRITE is all that takes, which a public-read-write bucket
     * grants anyone -- decided what another client's upload published, a
     * private upload made public-read included, and one able to delete it
     * ended the upload.  The multipart methods reach these names through
     * {@code storage} directly and never through the methods that call
     * this.  Reads are not refused, as on the nio2 stores.
     */
    private static void checkNotReserved(String key) {
        if (key.startsWith(STUB_BLOB_PREFIX)) {
            throw S3Exceptions.invalidArgument("The key " + STUB_BLOB_PREFIX +
                    "... is reserved for multipart uploads.");
        }
    }

    /**
     * Get blob generation for conditional writes.  GCS uses generations
     * rather than ETags for conditional operations.
     */
    private long getGeneration(String container, String name,
            String eTag) {
        Blob blob = storage.get(BlobId.of(container, name));
        if (blob == null) {
            throw S3Exceptions.noSuchKey(container, name, "");
        }
        if (isDeleteMarker(blob)) {
            throw S3Exceptions.noSuchKeyDeleteMarker(container, name,
                    Long.toString(blob.getGeneration()),
                    "current version is a delete marker");
        }
        // If the ETag doesn't match, the precondition fails.
        if (!eTag.equals("*") && !maybeQuoteETag(eTag).equals(
                maybeQuoteETag(reportETag(blob)))) {
            throw preconditionFailed(reportETag(blob));
        }
        return blob.getGeneration();
    }

    // GCS permits null values in user metadata; filter them out since the
    // S3 model does not.
    private static Map<String, String> sanitizeUserMetadata(
            @Nullable Map<String, @Nullable String> metadata) {
        if (metadata == null) {
            return Map.of();
        }
        var result = new LinkedHashMap<String, String>();
        metadata.forEach((key, value) -> {
            if (value != null) {
                result.put(key, value);
            }
        });
        return result;
    }

    private static com.google.cloud.storage.StorageClass toGcsStorageClass(
            StorageClass storageClass) {
        return switch (storageClass) {
        case GLACIER, DEEP_ARCHIVE ->
            com.google.cloud.storage.StorageClass.ARCHIVE;
        case GLACIER_IR -> com.google.cloud.storage.StorageClass.COLDLINE;
        case STANDARD_IA, ONEZONE_IA ->
            com.google.cloud.storage.StorageClass.NEARLINE;
        default -> com.google.cloud.storage.StorageClass.STANDARD;
        };
    }

    private static java.time.@Nullable Instant toInstant(
            java.time.@Nullable OffsetDateTime dateTime) {
        return dateTime == null ? null : dateTime.toInstant();
    }

    private static StorageClass fromGcsStorageClass(
            com.google.cloud.storage.@Nullable StorageClass storageClass) {
        if (storageClass == null) {
            return StorageClass.STANDARD;
        } else if (storageClass.equals(
                com.google.cloud.storage.StorageClass.ARCHIVE)) {
            return StorageClass.DEEP_ARCHIVE;
        } else if (storageClass.equals(
                com.google.cloud.storage.StorageClass.COLDLINE)) {
            return StorageClass.GLACIER_IR;
        } else if (storageClass.equals(
                com.google.cloud.storage.StorageClass.NEARLINE)) {
            return StorageClass.STANDARD_IA;
        } else {
            return StorageClass.STANDARD;
        }
    }

    /**
     * Translate StorageException to an S3-shaped SDK exception, returning
     * the original StorageException unchanged if no translation applies.
     */
    private static RuntimeException translate(StorageException se,
            String container, @Nullable String key) {
        switch (se.getCode()) {
        case 404 -> {
            if (key != null) {
                return S3Exceptions.noSuchKey(container, key, "", se);
            } else {
                return S3Exceptions.noSuchBucket(container, "", se);
            }
        }
        case 412 -> {
            return S3Exceptions.fromStatusCode(412, se);
        }
        case 401, 403 -> {
            // Surface a permission failure as 403 AccessDenied rather than a
            // generic 500.
            return S3Exceptions.fromStatusCode(403, se);
        }
        // The rest reached the frontend as the raw exception, which it
        // answers 500 InternalError whatever GCS had said -- including for
        // a request GCS refused as invalid, and for the rate limit a
        // client is meant to back off from.
        case 400 -> {
            return S3Exceptions.invalidRequest(
                    Strings.nullToEmpty(se.getMessage()));
        }
        case 409 -> {
            return S3Exceptions.withCode(409, "OperationAborted",
                    "A conflicting conditional operation is currently in" +
                    " progress against this resource. Please try again.",
                    se);
        }
        case 429 -> {
            return S3Exceptions.withCode(503, "SlowDown",
                    "Please reduce your request rate.", se);
        }
        case 502, 503, 504 -> {
            return S3Exceptions.withCode(503, "ServiceUnavailable",
                    "Service is unable to handle request.", se);
        }
        default -> { }
        }
        return se;
    }

    /**
     * Rebuilds the SDK's failure of an upload from its status alone.  The
     * SDK's message, and again its cause's, quote the URI of the resumable
     * session, on which GCS accepts the object's bytes without any
     * credential for as long as the session is open -- and a refusal meant
     * to be retried, such as the 429 for writing one object twice within a
     * second or a 5xx, leaves it open.  An error {@link #translate} does not
     * map is logged by the servlet container, message and cause, so neither
     * may leave the store.  Callers read only the status.
     */
    private static StorageException withoutRequest(StorageException se) {
        String reason = se.getReason();
        Throwable cause = se.getCause();
        return new StorageException(se.getCode(),
                "Upload failed with status " + se.getCode() +
                (Strings.isNullOrEmpty(reason) ? "" : ", " + reason) +
                (cause == null ? "" : ": " + cause.getClass().getName()),
                reason, /*cause=*/ null);
    }

    // Build a 412 for a failed conditional-GET precondition, echoing the
    // object's ETag so the frontend can emit it on the 304 Not Modified
    // response (required by RFC 7232).
    private static S3Exception preconditionFailed(@Nullable String eTag) {
        return S3Exceptions.fromStatusCode(412,
                eTag == null ? null : maybeQuoteETag(eTag), Map.of(),
                /*cause=*/ null);
    }

    /**
     * OAuth 2.0 access tokens read from the credential supplier.  Nothing in
     * a Credentials names how long the token it carries lasts, so each one is
     * handed over already lapsed and the supplier is asked again for the next
     * request rather than a withdrawn token being presented twice.
     */
    private static final class SuppliedTokenCredentials
            extends GoogleCredentials {
        private final Supplier<Credentials> creds;

        SuppliedTokenCredentials(Supplier<Credentials> creds) {
            this.creds = creds;
        }

        @Override
        public AccessToken refreshAccessToken() {
            String sessionToken = creds.get().sessionToken();
            if (Strings.isNullOrEmpty(sessionToken)) {
                throw new IllegalStateException(
                        "Credential supplier named no session token");
            }
            return new AccessToken(sessionToken, new Date());
        }
    }
}
