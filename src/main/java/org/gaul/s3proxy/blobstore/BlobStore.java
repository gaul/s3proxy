/*
 * Copyright 2009-2025 The Apache Software Foundation
 * Copyright 2026 Andrew Gaul <andrew@gaul.org>
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

package org.gaul.s3proxy.blobstore;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import com.google.common.collect.ImmutableList;

import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.jspecify.annotations.Nullable;

import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.services.s3.model.Bucket;
import software.amazon.awssdk.services.s3.model.BucketCannedACL;
import software.amazon.awssdk.services.s3.model.BucketVersioningStatus;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.CopyObjectRequest;
import software.amazon.awssdk.services.s3.model.CopyObjectResponse;
import software.amazon.awssdk.services.s3.model.CreateBucketRequest;
import software.amazon.awssdk.services.s3.model.CreateBucketResponse;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.DeleteMarkerEntry;
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
import software.amazon.awssdk.services.s3.model.ListObjectVersionsRequest;
import software.amazon.awssdk.services.s3.model.ListObjectVersionsResponse;
import software.amazon.awssdk.services.s3.model.ListObjectsRequest;
import software.amazon.awssdk.services.s3.model.ListObjectsResponse;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Response;
import software.amazon.awssdk.services.s3.model.ObjectCannedACL;
import software.amazon.awssdk.services.s3.model.ObjectIdentifier;
import software.amazon.awssdk.services.s3.model.ObjectVersion;
import software.amazon.awssdk.services.s3.model.Part;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.awssdk.services.s3.model.S3Error;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.services.s3.model.S3Object;
import software.amazon.awssdk.services.s3.model.ServerSideEncryptionConfiguration;
import software.amazon.awssdk.services.s3.model.UploadPartCopyRequest;
import software.amazon.awssdk.services.s3.model.UploadPartCopyResponse;
import software.amazon.awssdk.services.s3.model.UploadPartRequest;
import software.amazon.awssdk.services.s3.model.UploadPartResponse;

/** Synchronous access to a BlobStore such as Amazon S3. */
public interface BlobStore extends AutoCloseable {
    /**
     * How many names {@link #removeBlobs} deletes at a time.  Ten matches the
     * sharded store's fan-out.  The point is to overlap the round trips, not
     * to saturate the backend: a wider pool would mostly add threads, and
     * every concurrent request brings a pool of its own.
     */
    int REMOVE_BLOBS_THREADS = 10;

    /** Releases backend resources such as SDK clients.  No-op by default. */
    @Override
    default void close() {
    }

    /** Lists every bucket in one response: the floor the request form
     * pages over. */
    ListBucketsResponse list();

    /**
     * Lists one page of buckets: the request's prefix filters names, its
     * continuationToken names the last bucket of the previous page, and
     * maxBuckets caps the page, null capping nothing -- with the next
     * token on the response only while more buckets remain.  The default
     * emulates over {@link #list()}, sorting by name since the stores
     * promise no order of their own and paginating an unstable one would
     * drop or repeat buckets between pages.  Wrappers inherit it, so
     * their renaming and filtering keep applying; a store whose service
     * pages natively overrides it.  The frontend validates the wire's
     * max-buckets range, so this trusts its request.
     */
    default ListBucketsResponse list(ListBucketsRequest request) {
        ListBucketsResponse all = list();
        var buckets = new ArrayList<>(all.buckets());
        buckets.sort(Comparator.comparing(Bucket::name));

        String prefix = request.prefix();
        String continuationToken = request.continuationToken();
        int maxBuckets = request.maxBuckets() == null ?
                Integer.MAX_VALUE : request.maxBuckets();

        var page = new ArrayList<Bucket>();
        String nextContinuationToken = null;
        for (Bucket bucket : buckets) {
            String name = bucket.name();
            if (prefix != null && !name.startsWith(prefix)) {
                continue;
            }
            if (continuationToken != null &&
                    name.compareTo(continuationToken) <= 0) {
                continue;
            }
            if (page.size() >= maxBuckets) {
                if (!page.isEmpty()) {
                    nextContinuationToken =
                            page.get(page.size() - 1).name();
                }
                break;
            }
            page.add(bucket);
        }
        return ListBucketsResponse.builder()
                .buckets(page)
                .owner(all.owner())
                .continuationToken(nextContinuationToken)
                .prefix(prefix)
                .build();
    }

    /**
     * Lists one page of a bucket.  The page's nextContinuationToken names
     * where the next page resumes, or is null when the listing is
     * complete; isTruncated says the same thing.  A store that emulates
     * listings issues last-key tokens and treats continuationToken and
     * startAfter alike; a native store passes both through.
     */
    ListObjectsV2Response list(ListObjectsV2Request request);

    /** Lists one full page of a bucket. */
    default ListObjectsV2Response list(String container) {
        return list(ListObjectsV2Request.builder()
                .bucket(container)
                .build());
    }

    /**
     * Lists one page with V1 marker semantics: the marker and NextMarker
     * are keys, not tokens.  The default bridges over the V2 listing --
     * marker rides as startAfter, which every store reads as a key --
     * and derives NextMarker as the page's last name.
     */
    default ListObjectsResponse listV1(ListObjectsRequest request) {
        var page = list(ListObjectsV2Request.builder()
                .bucket(request.bucket())
                .prefix(request.prefix())
                .delimiter(request.delimiter())
                .maxKeys(request.maxKeys())
                .startAfter(request.marker())
                .build());
        String nextMarker = null;
        if (Boolean.TRUE.equals(page.isTruncated())) {
            String lastKey = page.contents().isEmpty() ? null :
                    page.contents().get(page.contents().size() - 1).key();
            String lastPrefix = page.commonPrefixes().isEmpty() ? null :
                    page.commonPrefixes()
                            .get(page.commonPrefixes().size() - 1).prefix();
            nextMarker = lastPrefix == null ? lastKey :
                    lastKey == null || lastKey.compareTo(lastPrefix) < 0 ?
                    lastPrefix : lastKey;
        }
        return ListObjectsResponse.builder()
                .contents(page.contents())
                .commonPrefixes(page.commonPrefixes())
                .isTruncated(page.isTruncated())
                .nextMarker(nextMarker)
                .build();
    }

    /**
     * HeadBucket: reads the bucket's summary, or null when the bucket does
     * not exist.  The response's bucketRegion rides to the wire as
     * x-amz-bucket-region; only a backend whose service has regions
     * reports one.  A bucket that exists but is refused -- another
     * account's -- throws the store's refusal rather than reporting
     * absence.
     */
    @Nullable
    HeadBucketResponse headBucket(HeadBucketRequest request);

    /** Whether the bucket exists. */
    default boolean containerExists(String container) {
        return headBucket(HeadBucketRequest.builder()
                .bucket(container)
                .build()) != null;
    }

    /**
     * CreateBucket: creates the bucket, throwing the wire's
     * BucketAlreadyOwnedByYou when the caller already has it -- a store
     * with one namespace answers for all of it, since every bucket it
     * sees is the caller's own.
     */
    CreateBucketResponse createContainer(CreateBucketRequest request);

    /** Creates a bucket without further options. */
    default CreateBucketResponse createContainer(String container) {
        return createContainer(CreateBucketRequest.builder()
                .bucket(container)
                .build());
    }

    BucketCannedACL getContainerAccess(String container);

    void setContainerAccess(String container, BucketCannedACL access);

    /**
     * Removes the current objects a listing reports, page by page.  Not an
     * S3 operation -- S3 has no way to empty a bucket, and the frontend
     * never calls this -- but an embedder and test convenience with
     * DeleteObjects semantics per key: on a versioning-enabled container
     * every delete lays a marker over its key rather than removing data,
     * and whatever the listing hides -- noncurrent versions, multipart
     * bookkeeping -- stays.
     */
    default void clearContainer(ListObjectsV2Request request) {
        var request0 = request;
        while (true) {
            ListObjectsV2Response page = list(request0);
            for (S3Object object : page.contents()) {
                removeBlob(request.bucket(), object.key());
            }
            String token = page.nextContinuationToken();
            if (token == null) {
                return;
            }
            request0 = request.toBuilder().continuationToken(token).build();
        }
    }

    /**
     * Deletes the container and everything it holds: in-progress multipart
     * uploads aborted, every object removed -- by version id, on a
     * container that has ever versioned, since the versionless delete
     * would lay markers instead -- and the emptied container deleted.  Not
     * an S3 operation -- S3 refuses to delete a non-empty bucket, and the
     * frontend never calls this -- but an embedder and test convenience.
     * Deleting a container already gone succeeds quietly; a container the
     * store still refuses -- a concurrent writer, or bookkeeping its
     * listings hide -- throws BucketNotEmpty rather than leaving it
     * behind in silence.  Stores override this where the backend can do
     * better natively: one call that takes the contents with it, a
     * recursive remove, a purge by generation.
     */
    default void deleteContainer(String container) {
        try {
            for (var upload : listMultipartUploads(container)) {
                abortMultipartUpload(new MultipartUpload(upload.uploadId(),
                        CreateMultipartUploadRequest.builder()
                                .bucket(container)
                                .key(upload.key())
                                .build()));
            }
            if (supportsVersioning() &&
                    getContainerVersioning(container) != null) {
                removeAllVersions(container);
            } else {
                clearContainer(ListObjectsV2Request.builder()
                        .bucket(container)
                        .build());
            }
        } catch (S3Exception se) {
            if ("NoSuchBucket".equals(S3Exceptions.errorCode(se))) {
                // The container is already gone; deleteContainer is
                // idempotent.
                return;
            }
            throw se;
        }
        deleteBucket(container);
    }

    /**
     * Removes every version and delete marker by its id -- the delete
     * that removes data outright, where the versionless form would stack
     * one more marker per key forever.
     */
    private void removeAllVersions(String container) {
        var request = ListObjectVersionsRequest.builder()
                .bucket(container)
                .build();
        while (true) {
            ListObjectVersionsResponse page = listVersions(request);
            for (ObjectVersion version : page.versions()) {
                removeBlob(container, version.key(), version.versionId());
            }
            for (DeleteMarkerEntry marker : page.deleteMarkers()) {
                removeBlob(container, marker.key(), marker.versionId());
            }
            if (!Boolean.TRUE.equals(page.isTruncated())) {
                return;
            }
            request = request.toBuilder()
                    .keyMarker(page.nextKeyMarker())
                    .versionIdMarker(page.nextVersionIdMarker())
                    .build();
        }
    }

    /**
     * DeleteBucket: removes the bucket only when nothing remains in it --
     * no object, and on a versioning store no version, marker or upload
     * -- throwing BucketNotEmpty otherwise.  Deleting a bucket already
     * absent succeeds quietly; the frontend asks containerExists
     * separately to tell NoSuchBucket apart.
     */
    void deleteBucket(String container);

    /**
     * Whether the object exists, answering by {@link #blobMetadata}'s
     * rules -- so a delete marker over the key throws rather than
     * answering false, as reading the metadata would.  This is the floor,
     * one metadata round trip; a store with a lighter probe of its own
     * overrides it: a fields-limited read, the SDK's exists call, a bare
     * HEAD.
     */
    default boolean blobExists(String container, String name) {
        return blobMetadata(container, name) != null;
    }

    /**
     * Stores one object from {@code payload}, consuming and closing the
     * stream.  The request's contentLength is required; contentMD5 rides
     * base64-encoded as on the wire; ifMatch/ifNoneMatch carry any
     * conditional write.
     */
    PutObjectResponse putBlob(PutObjectRequest request, InputStream payload);

    /**
     * Copies one object onto another server-side.  Replacement metadata --
     * user metadata and the Content-* headers -- applies only when the
     * request's metadataDirective is REPLACE; otherwise the source's
     * metadata carries over.  A non-null sourceVersionId is only meaningful
     * on a store that {@link #supportsVersioning}.
     */
    CopyObjectResponse copyBlob(CopyObjectRequest request);

    /**
     * Reads the metadata of the version the request names, or of the
     * current version when its versionId is null.  Returns null when the
     * object does not exist; throws {@link
     * S3Exceptions#noSuchKeyDeleteMarker} carrying the marker's version
     * when the current "version" is a delete marker, and {@link
     * S3Exceptions#noSuchVersion} when the named version does not exist.
     * A non-null versionId is only meaningful on a store that {@link
     * #supportsVersioning}; the others throw
     * UnsupportedOperationException.
     */
    @Nullable
    HeadObjectResponse blobMetadata(HeadObjectRequest request);

    /** Reads the current object's metadata. */
    @Nullable
    default HeadObjectResponse blobMetadata(String container, String name) {
        return blobMetadata(HeadObjectRequest.builder()
                .bucket(container)
                .key(name)
                .build());
    }

    /**
     * Reads one object: the response riding on its payload stream, or null
     * when the object does not exist.  The caller consumes and closes the
     * stream.  The request's range rides verbatim as the Range header
     * form, e.g. bytes=0-9; a non-null versionId is only meaningful on a
     * store that {@link #supportsVersioning}.
     */
    @Nullable
    ResponseInputStream<GetObjectResponse> getBlob(GetObjectRequest request);

    /** Reads the current object in full. */
    @Nullable
    default ResponseInputStream<GetObjectResponse> getBlob(String container,
            String name) {
        return getBlob(GetObjectRequest.builder()
                .bucket(container)
                .key(name)
                .build());
    }

    /**
     * Deletes one object the way DeleteObject does.  A versionId names the
     * one version to remove outright -- only meaningful on a store that
     * {@link #supportsVersioning} -- while a versionless delete removes
     * the current object, or lays a delete marker over the key on a
     * versioning-enabled container.  The request's conditions -- ifMatch
     * and the size and last-modified-time forms -- must hold atomically,
     * which only the backing service can judge; a store refuses what it
     * cannot honor with UnsupportedOperationException, and the frontend
     * emulates conditions it can against the store's own metadata
     * instead.
     */
    DeleteObjectResponse removeBlob(DeleteObjectRequest request);

    /** Deletes the current object, or lays a marker over a versioned key. */
    default void removeBlob(String container, String name) {
        removeBlob(DeleteObjectRequest.builder()
                .bucket(container)
                .key(name)
                .build());
    }

    /**
     * Deletes the version named, or acts as an ordinary delete when
     * {@code versionId} is null.
     */
    default DeleteObjectResponse removeBlob(String container, String name,
            @Nullable String versionId) {
        return removeBlob(DeleteObjectRequest.builder()
                .bucket(container)
                .key(name)
                .versionId(versionId)
                .build());
    }

    /**
     * Whether this store supports object versioning.  Only a store that
     * reports true honors the read and copy requests' versionIds, the
     * versioned removeBlob overload, and the operations below; the default
     * implementations throw UnsupportedOperationException.
     */
    default boolean supportsVersioning() {
        return false;
    }

    /**
     * Reads the container's versioning state, or null when the container has
     * never been versioned.
     */
    @Nullable
    default BucketVersioningStatus getContainerVersioning(String container) {
        throw new UnsupportedOperationException("versioning not supported");
    }

    default void setContainerVersioning(String container,
            BucketVersioningStatus status) {
        throw new UnsupportedOperationException("versioning not supported");
    }

    /** Lists a container's object versions and delete markers. */
    default ListObjectVersionsResponse listVersions(
            ListObjectVersionsRequest request) {
        throw new UnsupportedOperationException("versioning not supported");
    }

    /**
     * Whether this store answers the bucket default-encryption
     * configuration, the ?encryption subresource.  Only a store that
     * reports true honors the operations below; the default
     * implementations throw UnsupportedOperationException, which the
     * frontend answers NotImplemented before consulting them.
     */
    default boolean supportsBucketEncryption() {
        return false;
    }

    /**
     * Reads the container's default encryption configuration.  A container
     * that was never given one answers the way S3 spells it -- a 404 whose
     * code is ServerSideEncryptionConfigurationNotFoundError -- rather
     * than returning null.
     */
    default ServerSideEncryptionConfiguration getContainerEncryption(
            String container) {
        throw new UnsupportedOperationException(
                "bucket encryption not supported");
    }

    default void setContainerEncryption(String container,
            ServerSideEncryptionConfiguration configuration) {
        throw new UnsupportedOperationException(
                "bucket encryption not supported");
    }

    /** Removes the configuration; removing an absence already succeeds. */
    default void deleteContainerEncryption(String container) {
        throw new UnsupportedOperationException(
                "bucket encryption not supported");
    }

    /**
     * Whether this store forwards the requests' server-side encryption
     * fields -- the x-amz-server-side-encryption header family on put,
     * copy and initiate-multipart -- to a backend that performs the
     * encryption and reports the outcome on its responses.  The frontend
     * refuses such requests to any other store up front, rather than
     * storing plaintext that asked to be encrypted.
     */
    default boolean supportsServerSideEncryption() {
        return false;
    }

    /**
     * Removes the objects named, reporting each one's outcome the way
     * DeleteObjects does: a Deleted entry naming any marker the delete wrote,
     * or an Error entry carrying the code the store refused it with.  A
     * MultiObjectDelete carries up to a thousand objects, so the round trip
     * -- the whole cost against a remote store -- would otherwise be paid a
     * thousand times over.
     *
     * <p>This is the floor for a store whose API deletes one object at a
     * time: it deletes {@value #REMOVE_BLOBS_THREADS} at a time and reports
     * each outcome.  A store with a bulk delete of its own should override
     * this with the one request, which is the whole point of the shape --
     * the results a caller needs are the results such an API already
     * returns.
     *
     * <p>Every object is attempted even after one fails, since this answers
     * for each of them separately.  A failure that is the request's rather
     * than an object's -- NotImplemented, which every other object would
     * meet the same way -- is thrown instead of being reported a thousand
     * times.
     */
    default DeleteObjectsResponse removeBlobs(DeleteObjectsRequest request) {
        String container = request.bucket();
        var objects = request.delete() == null ? List.<ObjectIdentifier>of() :
                request.delete().objects();
        if (objects.isEmpty()) {
            return DeleteObjectsResponse.builder().build();
        }

        var executor = Executors.newFixedThreadPool(
                Math.min(objects.size(), REMOVE_BLOBS_THREADS));
        var futuresBuilder = new ImmutableList.Builder<Future<DeletedObject>>();
        for (ObjectIdentifier object : objects) {
            futuresBuilder.add(executor.submit(
                    () -> removeOneBlob(container, object)));
        }
        // Nothing else is submitted, so the pool ends with these tasks.
        executor.shutdown();

        var deleted = new ImmutableList.Builder<DeletedObject>();
        var errors = new ImmutableList.Builder<S3Error>();
        // Collected only once every delete has finished: answering while some
        // are still in flight would describe a container the store is still
        // changing.
        AwsServiceException requestFailure = null;
        var futures = futuresBuilder.build();
        for (int i = 0; i < futures.size(); ++i) {
            ObjectIdentifier object = objects.get(i);
            try {
                deleted.add(futures.get(i).get());
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                throw new RuntimeException(ie);
            } catch (ExecutionException ee) {
                Throwable cause = ee.getCause();
                if (!(cause instanceof AwsServiceException ase)) {
                    if (cause instanceof RuntimeException re) {
                        throw re;
                    } else if (cause instanceof Error error) {
                        throw error;
                    }
                    throw new RuntimeException(cause);
                }
                if ("NotImplemented".equals(S3Exceptions.errorCode(ase))) {
                    if (requestFailure == null) {
                        requestFailure = ase;
                    }
                    continue;
                }
                errors.add(toError(object, ase));
            }
        }
        if (requestFailure != null) {
            throw requestFailure;
        }

        return DeleteObjectsResponse.builder()
                .deleted(deleted.build())
                .errors(errors.build())
                .build();
    }

    /** Deletes one object, reporting the marker a versioned delete wrote. */
    private DeletedObject removeOneBlob(String container,
            ObjectIdentifier object) {
        DeleteObjectResponse result = removeBlob(DeleteObjectRequest.builder()
                .bucket(container)
                .key(object.key())
                .versionId(object.versionId())
                .build());
        var builder = DeletedObject.builder()
                .key(object.key())
                .versionId(object.versionId());
        if (Boolean.TRUE.equals(result.deleteMarker())) {
            builder.deleteMarker(true)
                    .deleteMarkerVersionId(result.versionId());
        }
        return builder.build();
    }

    /**
     * Describes one object's refusal.  The code comes from the store, since
     * which one a service uses is not something to assume: LocalStack
     * refuses a version it does not have with InvalidArgument where S3 says
     * NoSuchVersion.
     */
    private static S3Error toError(ObjectIdentifier object,
            AwsServiceException exception) {
        String code = S3Exceptions.errorCode(exception);
        var details = exception.awsErrorDetails();
        return S3Error.builder()
                .key(object.key())
                .versionId(object.versionId())
                .code(code)
                .message(details == null ? null : details.errorMessage())
                .build();
    }

    ObjectCannedACL getBlobAccess(String container, String name);

    /**
     * Reads the access of the version named, or of the current version when
     * {@code versionId} is null.  Only meaningful on a store that {@link
     * #supportsVersioning}; the default implementation throws
     * UnsupportedOperationException, since answering for the current version
     * instead would report the wrong version's access.
     */
    default ObjectCannedACL getBlobAccess(String container, String name,
            @Nullable String versionId) {
        throw new UnsupportedOperationException("versioning not supported");
    }

    void setBlobAccess(String container, String name, ObjectCannedACL access);

    /**
     * Sets the access of the version named, or of the current version when
     * {@code versionId} is null.  Only meaningful on a store that {@link
     * #supportsVersioning}; the default implementation throws
     * UnsupportedOperationException, since changing the current version
     * instead would re-permission the wrong version.
     */
    default void setBlobAccess(String container, String name,
            ObjectCannedACL access, @Nullable String versionId) {
        throw new UnsupportedOperationException("versioning not supported");
    }

    MultipartUpload initiateMultipartUpload(
            CreateMultipartUploadRequest request);

    void abortMultipartUpload(MultipartUpload mpu);

    /**
     * Publishes a multipart upload's assembled object.  The request names
     * the upload, asserts its parts, and carries any completion
     * conditions; {@code mpu} carries the create-time request whose
     * metadata a store that assembles the object itself writes onto it.
     */
    CompleteMultipartUploadResponse completeMultipartUpload(
            MultipartUpload mpu, CompleteMultipartUploadRequest request);

    /**
     * Uploads a part of a multipart upload, consuming and closing
     * {@code is}.  The request carries the part number, the content
     * length and MD5, and the customer key when the upload was created
     * under one -- S3 requires every part to present the create-time key
     * again.  {@code mpu} carries the upload itself, and its names say
     * where the part lands; wrappers that rename do so through it, so the
     * request's own bucket and key are not consulted.
     */
    UploadPartResponse uploadMultipartPart(MultipartUpload mpu,
            UploadPartRequest request, InputStream is);

    /**
     * Whether {@link #copyMultipartPart} copies server-side on the backend.
     * Wrappers that transform payloads, e.g. encryption, must not report
     * true since a backend copy would bypass the transformation.
     */
    default boolean supportsCopyMultipartPart() {
        return false;
    }

    /**
     * Copies a source object range into a part of a multipart upload
     * server-side, without streaming the payload through the caller.
     * Throwing UnsupportedOperationException tells the caller to fall back
     * to streamed emulation, e.g. when the backend discovers at runtime
     * that the service does not implement the copy operation.  The
     * request's copySourceRange rides verbatim (bytes=first-last, or null
     * to copy the entire object) and the backend enforces its own
     * validation and the copy-source conditions; a non-null
     * sourceVersionId is only meaningful on a store that {@link
     * #supportsVersioning}.
     */
    default UploadPartCopyResponse copyMultipartPart(MultipartUpload mpu,
            UploadPartCopyRequest request) {
        throw new UnsupportedOperationException(
                "backend does not support server-side part copies");
    }

    List<Part> listMultipartUpload(MultipartUpload mpu);

    List<software.amazon.awssdk.services.s3.model.MultipartUpload>
            listMultipartUploads(String container);

    long getMinimumMultipartPartSize();
}
