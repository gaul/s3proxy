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
import java.nio.channels.Channels;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

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
import com.google.cloud.storage.Bucket;
import com.google.cloud.storage.BucketInfo;
import com.google.cloud.storage.Storage;
import com.google.cloud.storage.Storage.BlobField;
import com.google.cloud.storage.Storage.BlobGetOption;
import com.google.cloud.storage.Storage.BlobListOption;
import com.google.cloud.storage.Storage.BlobSourceOption;
import com.google.cloud.storage.Storage.BlobTargetOption;
import com.google.cloud.storage.Storage.BlobWriteOption;
import com.google.cloud.storage.Storage.BucketField;
import com.google.cloud.storage.Storage.BucketGetOption;
import com.google.cloud.storage.Storage.ComposeRequest;
import com.google.cloud.storage.Storage.CopyRequest;
import com.google.cloud.storage.StorageException;
import com.google.cloud.storage.StorageOptions;
import com.google.common.base.Supplier;
import com.google.common.collect.ImmutableList;
import com.google.common.hash.HashCode;
import com.google.common.hash.HashFunction;
import com.google.common.hash.Hashing;
import com.google.common.hash.HashingInputStream;
import com.google.common.io.BaseEncoding;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.Credentials;
import org.gaul.s3proxy.blobstore.S3Exceptions;
import org.gaul.s3proxy.blobstore.SdkRequests;
import org.gaul.s3proxy.blobstore.SdkResponses;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.jspecify.annotations.Nullable;

import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.services.s3.model.BucketCannedACL;
import software.amazon.awssdk.services.s3.model.CommonPrefix;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.CompletedPart;
import software.amazon.awssdk.services.s3.model.CopyObjectRequest;
import software.amazon.awssdk.services.s3.model.CopyObjectResponse;
import software.amazon.awssdk.services.s3.model.CreateBucketRequest;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.HeadObjectRequest;
import software.amazon.awssdk.services.s3.model.HeadObjectResponse;
import software.amazon.awssdk.services.s3.model.ListBucketsResponse;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Response;
import software.amazon.awssdk.services.s3.model.MetadataDirective;
import software.amazon.awssdk.services.s3.model.ObjectCannedACL;
import software.amazon.awssdk.services.s3.model.Part;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.services.s3.model.S3Object;
import software.amazon.awssdk.services.s3.model.StorageClass;
import software.amazon.awssdk.services.s3.model.UploadPartCopyRequest;
import software.amazon.awssdk.services.s3.model.UploadPartCopyResponse;
import software.amazon.awssdk.services.s3.model.UploadPartResponse;

public final class GCloudBlobStore implements BlobStore {
    private static final String STUB_BLOB_PREFIX = ".s3proxy/stubs/";
    private static final String TARGET_BLOB_NAME_KEY =
            "s3proxy_target_blob_name";
    private static final String BLOB_ACCESS_KEY = "s3proxy_blob_access";
    // S3 requires MD5 for ETag and Content-MD5 interoperability.
    @SuppressWarnings("deprecation")
    private static final HashFunction MD5 = Hashing.md5();
    // GCS deprecated md5Match in favor of crc32cMatch but the client
    // supplies a Content-MD5 to validate, not a CRC32C.
    @SuppressWarnings("deprecation")
    private static final BlobWriteOption MD5_MATCH =
            BlobWriteOption.md5Match();
    // GCS compose supports up to 32 source objects
    private static final int MAX_COMPOSE_PARTS = 32;

    private final Storage storage;
    private final boolean atomicBucketAcl;

    public GCloudBlobStore(
            Supplier<Credentials> creds,
            String endpointUrl) {
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
        if (cred.identity() != null && !cred.identity().isEmpty()) {
            storageBuilder.setProjectId(cred.identity());
        }
        if (cred.credential() != null && !cred.credential().isEmpty()) {
            try {
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
        } else {
            // No credentials provided — use NoCredentials for emulator
            storageBuilder.setCredentials(NoCredentials.getInstance());
        }
        var endpoint = endpointUrl;
        boolean customEndpoint = endpoint != null && !endpoint.isEmpty() &&
                !endpoint.equals("https://storage.googleapis.com");
        if (customEndpoint) {
            storageBuilder.setHost(endpoint);
        }
        // Only Google's own service is known to apply a predefined ACL named
        // on buckets.insert; fake-gcs-server accepts the parameter and drops
        // it, leaving a private bucket.  Anything but the real endpoint
        // therefore sets the ACL in a second request.  Keyed on the endpoint
        // rather than on it being local because an emulator is often reached
        // by container hostname rather than at localhost.
        // TODO: create every bucket atomically after
        // https://github.com/fsouza/fake-gcs-server/pull/2309 is released
        atomicBucketAcl = !customEndpoint;
        storage = storageBuilder.build().getService();
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

    @Override
    public ListBucketsResponse list() {
        var buckets = ImmutableList.<software.amazon.awssdk.services.s3.model.Bucket>builder();
        for (Bucket bucket : storage.list().iterateAll()) {
            buckets.add(SdkResponses.bucket(bucket.getName(),
                    toDate(bucket.getCreateTimeOffsetDateTime())));
        }
        return ListBucketsResponse.builder()
                .buckets(buckets.build())
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
        if (request.maxKeys() != null) {
            gcsOptions.add(BlobListOption.pageSize(
                    request.maxKeys()));
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

        com.google.api.gax.paging.Page<Blob> page;
        try {
            page = storage.list(container,
                    gcsOptions.toArray(new BlobListOption[0]));
        } catch (StorageException se) {
            throw translate(se, container, null);
        }

        var contents = ImmutableList.<S3Object>builder();
        var prefixes = ImmutableList.<CommonPrefix>builder();
        Integer maxResults = request.maxKeys();
        int count = 0;
        boolean hasMore = false;
        String lastName = null;
        for (Blob blob : page.iterateAll()) {
            // Skip blobs at or before the marker (S3 marker is exclusive)
            if (marker != null && blob.getName().compareTo(marker) <= 0) {
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
                        blob.getEtag(),
                        toDate(blob.getUpdateTimeOffsetDateTime()),
                        blob.getSize(),
                        fromGcsStorageClass(blob.getStorageClass())));
            }
            lastName = blob.getName();
            count++;
        }

        // Synthesize a next marker if we truncated results
        String nextMarker = hasMore ? lastName : null;
        return SdkResponses.objectsPage(contents.build(), prefixes.build(),
                nextMarker);
    }

    @Override
    public boolean containerExists(String container) {
        return storage.get(container,
                BucketGetOption.fields(BucketField.NAME)) != null;
    }

    @Override
    public boolean createContainer(CreateBucketRequest request) {
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
            return true;
        } catch (StorageException se) {
            if (se.getCode() == 409) {
                return false;
            }
            throw se;
        }
    }

    @Override
    public boolean deleteContainerIfEmpty(String container) {
        var page = storage.list(container,
                BlobListOption.pageSize(1));
        if (page.getValues().iterator().hasNext()) {
            return false;
        }
        try {
            storage.delete(container);
            return true;
        } catch (StorageException se) {
            if (se.getCode() == 404) {
                return true;
            }
            throw se;
        }
    }

    @Override
    public boolean blobExists(String container, String key) {
        return storage.get(BlobId.of(container, key),
                BlobGetOption.fields(BlobField.NAME)) != null;
    }

    @Override
    public @Nullable ResponseInputStream<GetObjectResponse> getBlob(
            GetObjectRequest request) {
        if (request.versionId() != null) {
            throw new UnsupportedOperationException(
                    "versioning not supported");
        }
        String container = request.bucket();
        String key = request.key();
        var gcsOptions = new java.util.ArrayList<BlobGetOption>();

        Blob gcsBlob;
        try {
            gcsBlob = storage.get(BlobId.of(container, key),
                    gcsOptions.toArray(new BlobGetOption[0]));
        } catch (StorageException se) {
            throw translate(se, container, key);
        }
        if (gcsBlob == null) {
            // The SDK collapses a missing bucket and a missing object both to
            // null; distinguish them so the frontend emits NoSuchBucket vs
            // NoSuchKey.
            if (storage.get(container) == null) {
                throw S3Exceptions.noSuchBucket(container, "");
            }
            return null;
        }

        // Enforce conditional-GET preconditions before streaming.  The
        // backends report every conditional-header failure as 412; the
        // frontend (S3ProxyHandlerJetty) remaps GET/HEAD If-None-Match and
        // If-Modified-Since misses to 304 Not Modified.
        String eTag = gcsBlob.getEtag();
        Date lastModified = toDate(gcsBlob.getUpdateTimeOffsetDateTime());
        enforceConditionalGet(request, eTag, lastModified);

        long blobSize = gcsBlob.getSize();
        Long rangeOffset = null;
        Long rangeEnd = null;
        var range = SdkRequests.parseRange(request.range());
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
                .eTag(gcsBlob.getEtag())
                .storageClass(
                        fromGcsStorageClass(gcsBlob.getStorageClass())
                                .toString())
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
            @Nullable String eTag, @Nullable Date lastModified) {
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
            Date modified = truncateToSecond(lastModified);
            Instant ifModifiedSince = request.ifModifiedSince();
            if (ifModifiedSince != null &&
                    modified.compareTo(Date.from(ifModifiedSince)) <= 0) {
                throw preconditionFailed(eTag);
            }
            Instant ifUnmodifiedSince = request.ifUnmodifiedSince();
            if (ifUnmodifiedSince != null &&
                    modified.compareTo(Date.from(ifUnmodifiedSince)) > 0) {
                throw preconditionFailed(eTag);
            }
        }
    }

    // HTTP dates (Last-Modified, If-Modified-Since, If-Unmodified-Since) have
    // one-second granularity, but GCS timestamps carry sub-second precision.
    // Truncate to whole seconds so a conditional header compares equal to the
    // Last-Modified value the client previously saw.
    private static Date truncateToSecond(Date date) {
        return new Date(Math.floorDiv(date.getTime(), 1000L) * 1000L);
    }

    @Nullable
    private static Date toDate(@Nullable Instant instant) {
        return instant == null ? null : Date.from(instant);
    }

    @Nullable
    private static Date toDate(
            java.time.@Nullable OffsetDateTime offsetDateTime) {
        if (offsetDateTime == null) {
            return null;
        }
        return new Date(offsetDateTime.toInstant().toEpochMilli());
    }

    private static String maybeQuoteETag(String eTag) {
        if (!eTag.startsWith("\"") && !eTag.endsWith("\"")) {
            eTag = "\"" + eTag + "\"";
        }
        return eTag;
    }

    @Override
    public PutObjectResponse putBlob(PutObjectRequest request,
            InputStream payload) {
        String container = request.bucket();
        String name = request.key();
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
                if (existing == null) {
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
                writeOptions.add(BlobWriteOption.doesNotExist());
            } else {
                // If-None-Match: <etag> — fail if an object with that ETag
                // currently exists.  GCS has no etag precondition, but
                // pinning generationNotMatch to the matching object's
                // generation makes the rejection atomic: if it is still
                // that version the write fails, and if it has since changed
                // or been deleted the write proceeds.
                Blob existing = storage.get(BlobId.of(container, name));
                if (existing != null && maybeQuoteETag(ifNoneMatch).equals(
                        maybeQuoteETag(existing.getEtag()))) {
                    writeOptions.add(BlobWriteOption.generationNotMatch(
                            existing.getGeneration()));
                }
            }
        }
        if (request.acl() == ObjectCannedACL.PUBLIC_READ) {
            writeOptions.add(BlobWriteOption.predefinedAcl(
                    Storage.PredefinedAcl.PUBLIC_READ));
        }

        try (var is = payload) {
            Blob gcsBlob = storage.createFrom(blobInfo.build(), is,
                    writeOptions.toArray(new BlobWriteOption[0]));
            return SdkResponses.putResponse(gcsBlob.getEtag());
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
        if (request.sourceVersionId() != null) {
            throw new UnsupportedOperationException(
                    "versioning not supported");
        }
        String fromContainer = request.sourceBucket();
        String fromName = request.sourceKey();
        var source = BlobId.of(fromContainer, fromName);
        var targetBuilder = BlobInfo.newBuilder(BlobId.of(
                request.destinationBucket(), request.destinationKey()));

        if (request.metadataDirective() == MetadataDirective.REPLACE) {
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
        Date ifModifiedSince = toDate(request.copySourceIfModifiedSince());
        Date ifUnmodifiedSince = toDate(request.copySourceIfUnmodifiedSince());
        List<BlobSourceOption> sourceOptions = List.of();
        if (ifMatch != null || ifNoneMatch != null ||
                ifModifiedSince != null || ifUnmodifiedSince != null) {
            sourceOptions = checkCopySourceConditions(storage.get(source),
                    ifMatch, ifNoneMatch, ifModifiedSince, ifUnmodifiedSince);
        }

        var targetOptions = new java.util.ArrayList<BlobTargetOption>();
        if (request.acl() == ObjectCannedACL.PUBLIC_READ) {
            targetOptions.add(BlobTargetOption.predefinedAcl(
                    Storage.PredefinedAcl.PUBLIC_READ));
        }

        try {
            var copyRequest = CopyRequest.newBuilder()
                    .setSource(source)
                    .setSourceOptions(sourceOptions)
                    .setTarget(targetBuilder.build(), targetOptions)
                    .build();
            var result = storage.copy(copyRequest);
            return SdkResponses.copyResponse(result.getResult().getEtag());
        } catch (StorageException se) {
            throw translate(se, fromContainer, fromName);
        }
    }

    /**
     * Emulates the x-amz-copy-source-if-* conditions against the source
     * object's current metadata since GCS has no native ETag or time
     * copy-source preconditions.  For If-Match the returned options pin the
     * copy to the verified generation so a concurrent change to the source
     * fails the copy rather than silently copying a different version.
     */
    private static List<BlobSourceOption> checkCopySourceConditions(
            @Nullable Blob sourceBlob, @Nullable String ifMatch,
            @Nullable String ifNoneMatch, @Nullable Date ifModifiedSince,
            @Nullable Date ifUnmodifiedSince) {
        var sourceOptions = new java.util.ArrayList<BlobSourceOption>();
        if (sourceBlob == null) {
            return sourceOptions;
        }
        String sourceETag = sourceBlob.getEtag();
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
        Date lastModified = toDate(
                sourceBlob.getUpdateTimeOffsetDateTime());
        if (lastModified != null) {
            Date modified = truncateToSecond(lastModified);
            if (ifModifiedSince != null &&
                    modified.compareTo(ifModifiedSince) <= 0) {
                throw preconditionFailed(sourceETag);
            }
            if (ifUnmodifiedSince != null &&
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

    @Override
    public void removeBlob(String container, String key) {
        try {
            storage.delete(BlobId.of(container, key));
        } catch (StorageException se) {
            if (se.getCode() != 404) {
                throw se;
            }
        }
    }

    @Override
    @Nullable
    public HeadObjectResponse blobMetadata(HeadObjectRequest request) {
        if (request.versionId() != null) {
            throw new UnsupportedOperationException(
                    "versioning not supported");
        }
        String container = request.bucket();
        Blob gcsBlob;
        try {
            gcsBlob = storage.get(BlobId.of(container, request.key()));
        } catch (StorageException se) {
            if (se.getCode() == 404) {
                return null;
            }
            throw translate(se, container, null);
        }
        if (gcsBlob == null) {
            return null;
        }
        return HeadObjectResponse.builder()
                .metadata(sanitizeUserMetadata(gcsBlob.getMetadata()))
                .eTag(gcsBlob.getEtag())
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
                .build();
    }


    @Override
    public BucketCannedACL getContainerAccess(String container) {
        var bucket = storage.get(container);
        if (bucket == null) {
            throw S3Exceptions.noSuchBucket(container, "");
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
            var acls = storage.listAcls(BlobId.of(container, key));
            for (var acl : acls) {
                if (acl.getEntity().equals(Acl.User.ofAllUsers())) {
                    return ObjectCannedACL.PUBLIC_READ;
                }
            }
        } catch (StorageException se) {
            // On 404, distinguish a missing bucket from a missing object so
            // the caller can emit NoSuchBucket vs NoSuchKey.
            if (se.getCode() == 404) {
                if (storage.get(container) == null) {
                    throw S3Exceptions.noSuchBucket(container, "");
                }
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
    public void setBlobAccess(String container, String key,
            ObjectCannedACL access) {
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
    public MultipartUpload initiateMultipartUpload(
            CreateMultipartUploadRequest request) {
        String container = request.bucket();
        if (!containerExists(container)) {
            throw S3Exceptions.noSuchBucket(container, "");
        }

        String uploadKey = STUB_BLOB_PREFIX + UUID.randomUUID().toString();
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
                BlobId.of(container, uploadKey))
                .setMetadata(stubMetadata)
                .build();
        storage.create(stubInfo, new byte[0]);

        return new MultipartUpload(uploadKey, request);
    }

    @Override
    public void abortMultipartUpload(MultipartUpload mpu) {
        String uploadKey = mpu.id();

        if (!uploadKey.startsWith(STUB_BLOB_PREFIX)) {
            throw S3Exceptions.noSuchKey(mpu.containerName(), uploadKey,
                    "Multipart upload not found: " + uploadKey);
        }

        String nonce = uploadKey.substring(STUB_BLOB_PREFIX.length());

        // Delete part blobs
        var page = storage.list(mpu.containerName(),
                BlobListOption.prefix(STUB_BLOB_PREFIX + nonce + "/"));
        for (Blob blob : page.iterateAll()) {
            storage.delete(blob.getBlobId());
        }

        // Delete stub
        if (!storage.delete(BlobId.of(mpu.containerName(), uploadKey))) {
            throw S3Exceptions.noSuchKey(mpu.containerName(), uploadKey,
                    "Multipart upload not found: " + uploadKey);
        }
    }

    @Override
    public CompleteMultipartUploadResponse completeMultipartUpload(MultipartUpload mpu,
            CompleteMultipartUploadRequest request) {
        List<CompletedPart> parts = request.multipartUpload() == null ?
                List.of() : request.multipartUpload().parts();
        String uploadKey = mpu.id();
        String nonce = uploadKey.substring(STUB_BLOB_PREFIX.length());

        Blob stubBlob = storage.get(
                BlobId.of(mpu.containerName(), uploadKey));
        if (stubBlob == null) {
            throw new IllegalArgumentException(
                    "Upload not found: uploadId=" + uploadKey);
        }

        var stubMetadata = stubBlob.getMetadata();
        if (stubMetadata == null) {
            throw new IllegalArgumentException(
                    "Stub blob missing target name: uploadId=" + uploadKey);
        }
        String targetBlobName = stubMetadata.get(TARGET_BLOB_NAME_KEY);
        if (targetBlobName == null) {
            throw new IllegalArgumentException(
                    "Stub blob missing target name: uploadId=" + uploadKey);
        }

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
            if (entry.getKey().startsWith("s3proxy_user_")) {
                userMetadata.put(
                        entry.getKey().substring("s3proxy_user_".length()),
                        entry.getValue());
            }
        }
        if (!userMetadata.isEmpty()) {
            targetBuilder.setMetadata(userMetadata);
        }

        // A single part is copied onto the target and can name the access on
        // that request, so no later one can fail and leave a private blob
        // where the caller asked for a public one.  Compose cannot; see below.
        var targetOptions = new java.util.ArrayList<BlobTargetOption>();
        if (ObjectCannedACL.PUBLIC_READ.name().equals(
                stubMetadata.get(BLOB_ACCESS_KEY))) {
            targetOptions.add(BlobTargetOption.predefinedAcl(
                    Storage.PredefinedAcl.PUBLIC_READ));
        }

        // If single part, just copy it to the target
        if (parts.size() == 1) {
            String partBlobName = makePartBlobName(nonce,
                    parts.get(0).partNumber());
            var source = BlobId.of(mpu.containerName(), partBlobName);
            var copyRequest = CopyRequest.newBuilder()
                    .setSource(source)
                    .setTarget(targetBuilder.build(), targetOptions)
                    .build();
            var result = storage.copy(copyRequest);
            // Clean up
            storage.delete(source);
            storage.delete(BlobId.of(mpu.containerName(), uploadKey));
            return SdkResponses.completeResponse(
                    result.getResult().getEtag());
        }

        // GCS compose supports up to 32 parts.
        // For more parts, compose recursively.
        var sourceBlobIds = new java.util.ArrayList<BlobId>();
        for (var part : parts) {
            String partBlobName = makePartBlobName(nonce, part.partNumber());
            sourceBlobIds.add(BlobId.of(mpu.containerName(), partBlobName));
        }

        String eTag = composeRecursive(mpu.containerName(),
                targetBuilder.build(), sourceBlobIds, nonce);

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
        if (!targetOptions.isEmpty()) {
            storage.createAcl(BlobId.of(mpu.containerName(), targetBlobName),
                    Acl.of(Acl.User.ofAllUsers(), Acl.Role.READER));
        }

        // Clean up part blobs and stub
        for (var blobId : sourceBlobIds) {
            storage.delete(blobId);
        }
        // Clean up any intermediate compose blobs
        var intermediatePage = storage.list(mpu.containerName(),
                BlobListOption.prefix(
                        STUB_BLOB_PREFIX + nonce + "/compose_"));
        for (Blob blob : intermediatePage.iterateAll()) {
            storage.delete(blob.getBlobId());
        }
        storage.delete(BlobId.of(mpu.containerName(), uploadKey));

        return SdkResponses.completeResponse(eTag);
    }

    /**
     * Recursively compose blobs to handle more than 32 parts.
     * GCS compose supports max 32 sources, so for N > 32 parts we
     * compose in groups of 32, then compose those results.
     */
    private String composeRecursive(String container, BlobInfo target,
            List<BlobId> sources, String nonce) {
        if (sources.size() <= MAX_COMPOSE_PARTS) {
            var composeBuilder = ComposeRequest.newBuilder();
            composeBuilder.setTarget(target);
            for (var source : sources) {
                composeBuilder.addSource(source.getName());
            }
            var result = storage.compose(composeBuilder.build());
            return result.getEtag();
        }

        // Compose in groups of MAX_COMPOSE_PARTS
        var intermediateIds = new java.util.ArrayList<BlobId>();
        int groupIndex = 0;
        for (int i = 0; i < sources.size();
                i += MAX_COMPOSE_PARTS) {
            int end = Math.min(i + MAX_COMPOSE_PARTS, sources.size());
            var group = sources.subList(i, end);
            String intermediateName = STUB_BLOB_PREFIX + nonce +
                    "/compose_" + groupIndex;
            var intermediateInfo = BlobInfo.newBuilder(
                    BlobId.of(container, intermediateName)).build();

            var composeBuilder = ComposeRequest.newBuilder();
            composeBuilder.setTarget(intermediateInfo);
            for (var source : group) {
                composeBuilder.addSource(source.getName());
            }
            storage.compose(composeBuilder.build());

            intermediateIds.add(BlobId.of(container, intermediateName));
            groupIndex++;
        }

        // Recursively compose intermediates
        return composeRecursive(container, target, intermediateIds,
                nonce);
    }

    @Override
    public UploadPartResponse uploadMultipartPart(MultipartUpload mpu,
            int partNumber, InputStream is, long contentLength,
            @Nullable HashCode contentMD5) {
        if (partNumber < 1 || partNumber > 10_000) {
            throw new IllegalArgumentException(
                    "Part number must be between 1 and 10,000, got: " +
                    partNumber);
        }

        String uploadKey = mpu.id();
        String nonce = uploadKey.substring(STUB_BLOB_PREFIX.length());
        String partBlobName = makePartBlobName(nonce, partNumber);

        byte[] md5Hash;
        try (var his = new HashingInputStream(MD5, is)) {
            var partInfo = BlobInfo.newBuilder(
                    BlobId.of(mpu.containerName(), partBlobName)).build();
            storage.createFrom(partInfo, his);

            md5Hash = his.hash().asBytes();

            if (contentMD5 != null) {
                if (!MessageDigest.isEqual(md5Hash,
                        contentMD5.asBytes())) {
                    // Clean up the uploaded part
                    storage.delete(BlobId.of(mpu.containerName(),
                            partBlobName));
                    throw new IllegalArgumentException(
                            "Content-MD5 mismatch");
                }
            }
        } catch (StorageException se) {
            throw translate(se, mpu.containerName(), mpu.blobName());
        } catch (IOException ioe) {
            throw new RuntimeException((
                    "Failed to upload part %d for blob '%s' in " +
                    "container '%s': %s").formatted(
                    partNumber, mpu.blobName(), mpu.containerName(),
                    ioe.getMessage()), ioe);
        }

        String eTag = BaseEncoding.base16().lowerCase().encode(md5Hash);
        return SdkResponses.uploadedPart(eTag);
    }

    @Override
    public boolean supportsCopyMultipartPart() {
        return true;
    }

    @Override
    public UploadPartCopyResponse copyMultipartPart(MultipartUpload mpu,
            UploadPartCopyRequest request) {
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

        String sourceContainer = request.sourceBucket();
        String sourceName = request.sourceKey();
        var source = BlobId.of(sourceContainer, sourceName);
        Blob sourceBlob;
        try {
            sourceBlob = storage.get(source);
        } catch (StorageException se) {
            throw translate(se, sourceContainer, sourceName);
        }
        if (sourceBlob == null) {
            throw S3Exceptions.noSuchKey(sourceContainer, sourceName, "");
        }

        // GCS cannot copy a byte range server-side; a range covering the
        // whole object is equivalent to no range, anything else falls back
        // to streamed emulation in the caller.
        String copySourceRange = request.copySourceRange();
        if (copySourceRange != null && !isEntireObject(copySourceRange,
                sourceBlob.getSize())) {
            throw new UnsupportedOperationException(
                    "GCS does not support ranged server-side copies");
        }

        var sourceOptions = checkCopySourceConditions(sourceBlob,
                request.copySourceIfMatch(), request.copySourceIfNoneMatch(),
                toDate(request.copySourceIfModifiedSince()),
                toDate(request.copySourceIfUnmodifiedSince()));

        String uploadKey = mpu.id();
        String nonce = uploadKey.substring(STUB_BLOB_PREFIX.length());
        String partBlobName = makePartBlobName(nonce, partNumber);

        try {
            var copyRequest = CopyRequest.newBuilder()
                    .setSource(source)
                    .setSourceOptions(sourceOptions)
                    .setTarget(BlobInfo.newBuilder(BlobId.of(
                            mpu.containerName(), partBlobName)).build())
                    .build();
            var result = storage.copy(copyRequest).getResult();
            // Match uploadMultipartPart's hex MD5 part ETag;
            // listMultipartUpload reads the same value back from GCS.
            return SdkResponses.copiedPart(result.getMd5ToHexString(),
                    /*lastModified=*/ null, /*copySourceVersionId=*/ null);
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
        String uploadKey = mpu.id();
        if (!uploadKey.startsWith(STUB_BLOB_PREFIX)) {
            throw S3Exceptions.noSuchKey(mpu.containerName(), uploadKey,
                    "Multipart upload not found: " + uploadKey);
        }

        String nonce = uploadKey.substring(STUB_BLOB_PREFIX.length());
        String prefix = STUB_BLOB_PREFIX + nonce + "/part_";

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
            parts.add(SdkResponses.part(partNumber, blob.getSize(),
                    blob.getMd5ToHexString(), null));
        }
        return parts.build();
    }

    @Override
    public List<software.amazon.awssdk.services.s3.model.MultipartUpload>
            listMultipartUploads(String container) {
        var builder = ImmutableList.<software.amazon.awssdk.services.s3
                .model.MultipartUpload>builder();
        var page = storage.list(container,
                BlobListOption.prefix(STUB_BLOB_PREFIX));
        for (Blob blob : page.iterateAll()) {
            String name = blob.getName();
            // Only look at stub blobs, not part blobs
            if (name.contains("/part_") || name.contains("/compose_")) {
                continue;
            }
            var metadata = blob.getMetadata();
            if (metadata == null ||
                    !metadata.containsKey(TARGET_BLOB_NAME_KEY)) {
                continue;
            }
            String targetBlobName = metadata.get(TARGET_BLOB_NAME_KEY);
            builder.add(SdkResponses.upload(targetBlobName, name));
        }
        return builder.build();
    }

    @Override
    public long getMinimumMultipartPartSize() {
        // GCS minimum part is 5 MB except for last part
        return 5L * 1024 * 1024;
    }

    private static String makePartBlobName(String nonce, int partNumber) {
        return STUB_BLOB_PREFIX + nonce +
                "/part_%05d".formatted(partNumber);
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
        // If the ETag doesn't match, the precondition fails.
        if (!eTag.equals("*") && !maybeQuoteETag(eTag).equals(
                maybeQuoteETag(blob.getEtag()))) {
            throw preconditionFailed(blob.getEtag());
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
        default -> { }
        }
        return se;
    }

    // Build a 412 for a failed conditional-GET precondition, echoing the
    // object's ETag so the frontend can emit it on the 304 Not Modified
    // response (required by RFC 7232).
    private static S3Exception preconditionFailed(@Nullable String eTag) {
        return S3Exceptions.fromStatusCode(412,
                eTag == null ? null : maybeQuoteETag(eTag), Map.of(),
                /*cause=*/ null);
    }
}
