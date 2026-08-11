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

package org.gaul.s3proxy.nio2blob;

import static java.util.Objects.requireNonNull;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryIteratorException;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.DirectoryStream;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.NotDirectoryException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserDefinedFileAttributeView;
import java.security.DigestInputStream;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSortedSet;
import com.google.common.hash.HashCode;
import com.google.common.hash.Hashing;
import com.google.common.io.ByteSource;
import com.google.common.io.ByteStreams;
import com.google.common.primitives.Longs;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.ContentMetadata;
import org.gaul.s3proxy.blobstore.CustomerKeys;
import org.gaul.s3proxy.blobstore.MD5;
import org.gaul.s3proxy.blobstore.S3Exceptions;
import org.gaul.s3proxy.blobstore.SdkRequests;
import org.gaul.s3proxy.blobstore.SdkResponses;
import org.gaul.s3proxy.blobstore.domain.Blob;
import org.gaul.s3proxy.blobstore.domain.Encryption;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
import software.amazon.awssdk.services.s3.model.CopyObjectResult;
import software.amazon.awssdk.services.s3.model.CreateBucketRequest;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.DeleteMarkerEntry;
import software.amazon.awssdk.services.s3.model.DeleteObjectResponse;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.HeadObjectRequest;
import software.amazon.awssdk.services.s3.model.HeadObjectResponse;
import software.amazon.awssdk.services.s3.model.ListBucketsResponse;
import software.amazon.awssdk.services.s3.model.ListObjectVersionsRequest;
import software.amazon.awssdk.services.s3.model.ListObjectVersionsResponse;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Response;
import software.amazon.awssdk.services.s3.model.MetadataDirective;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.s3.model.ObjectCannedACL;
import software.amazon.awssdk.services.s3.model.ObjectVersion;
import software.amazon.awssdk.services.s3.model.ObjectVersionStorageClass;
import software.amazon.awssdk.services.s3.model.Part;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.services.s3.model.S3Object;
import software.amazon.awssdk.services.s3.model.ServerSideEncryptionByDefault;
import software.amazon.awssdk.services.s3.model.ServerSideEncryptionConfiguration;
import software.amazon.awssdk.services.s3.model.ServerSideEncryptionRule;
import software.amazon.awssdk.services.s3.model.StorageClass;
import software.amazon.awssdk.services.s3.model.UploadPartRequest;
import software.amazon.awssdk.services.s3.model.UploadPartResponse;

public abstract class AbstractNio2BlobStore implements BlobStore {
    private static final Logger logger = LoggerFactory.getLogger(
            AbstractNio2BlobStore.class);
    private static final String XATTR_CACHE_CONTROL = "user.cache-control";
    private static final String XATTR_CONTENT_DISPOSITION =
            "user.content-disposition";
    private static final String XATTR_CONTENT_ENCODING =
            "user.content-encoding";
    private static final String XATTR_CONTENT_LANGUAGE =
            "user.content-language";
    private static final String XATTR_CONTENT_MD5 = "user.content-md5";
    private static final String XATTR_CONTENT_TYPE = "user.content-type";
    private static final String XATTR_EXPIRES = "user.expires";
    private static final String XATTR_STORAGE_TIER = "user.storage-tier";
    private static final String XATTR_USER_METADATA_PREFIX =
            "user.user-metadata.";
    private static final Set<String> NO_ATTRIBUTES = Set.of();
    // Reserved prefix for the store's own multipart bookkeeping: the stub
    // recording that an upload exists and the file behind each uploaded part.
    // These names are hidden from list(), which is why a client must not be
    // able to write one -- an object nobody can see is an object nobody can
    // delete, and these names decide what another client's in-flight upload
    // publishes. Reserved from client keys; see checkNotReserved.
    private static final String MULTIPART_PREFIX = ".mpus-";
    // Reserved in-container name that backs the object whose S3 key is exactly
    // "/". Path.resolve("/") yields the filesystem root, so this key cannot be
    // stored at its literal path; it previously had to be munged onto the
    // container directory itself, which let object operations (DELETE, PUT,
    // ACL) mutate bucket-level state. Redirecting it to a dedicated child keeps
    // it an ordinary directory-marker blob while isolating it from the
    // container inode. Hidden from listings and reserved from client keys.
    private static final String SLASH_BLOB_NAME = ".s3proxy-slash";
    // Reserved container-level directory holding every version of a key but
    // the current one, plus delete markers. The current version stays at its
    // natural path so that reads, listings and multipart assembly need to
    // know nothing about versioning. Hidden from list() and reserved from
    // client keys, like the multipart names above.
    private static final String VERSIONS_DIR = ".s3proxy-versions";
    private static final String XATTR_VERSION_ID = "user.version-id";
    private static final String XATTR_VERSION_KEY = "user.version-key";
    private static final String XATTR_DELETE_MARKER = "user.delete-marker";
    private static final String XATTR_VERSIONING = "user.versioning";
    // The container's default encryption, the ?encryption subresource:
    // what a write naming no encryption of its own comes to rest under,
    // the way S3 applies bucket default encryption.
    private static final String XATTR_BUCKET_ENCRYPTION_ALGORITHM =
            "user.bucket-encryption-algorithm";
    private static final String XATTR_BUCKET_ENCRYPTION_KMS_KEY_ID =
            "user.bucket-encryption-kms-key-id";
    private static final String XATTR_BUCKET_ENCRYPTION_BUCKET_KEY =
            "user.bucket-encryption-bucket-key-enabled";
    // The encryption an object rests under, written only by a store that
    // answers supportsServerSideEncryption().  An object encrypted the way
    // every unasked-for object is carries none of these: absent algorithm
    // reads back as the default, so the common case costs no attribute.
    private static final String XATTR_SSE_ALGORITHM = "user.sse-algorithm";
    private static final String XATTR_SSE_KMS_KEY_ID = "user.sse-kms-key-id";
    private static final String XATTR_SSE_KMS_CONTEXT = "user.sse-kms-context";
    private static final String XATTR_SSE_BUCKET_KEY =
            "user.sse-bucket-key-enabled";
    // A customer-key object keeps the key's MD5 and never the key: enough
    // to recognize the key when a later request presents it, and no more
    // than S3 itself echoes on responses.
    private static final String XATTR_SSE_C_ALGORITHM =
            "user.sse-c-algorithm";
    private static final String XATTR_SSE_C_KEY_MD5 = "user.sse-c-key-md5";
    /** The version id every write to an unversioned container carries. */
    private static final String NULL_VERSION_ID = "null";
    private static final int UUID_STRING_LENGTH =
            UUID.randomUUID().toString().length();
    private static final byte[] DIRECTORY_MD5 = MD5.hash(new byte[0]);

    /**
     * Orders the versions of one key.  A file name carries it rather than the
     * version id, because the id of every write to a suspended container is
     * "null" and orders nothing; and rather than the modification time,
     * because that is the version's own timestamp, which two writes in one
     * millisecond share.
     */
    private static final AtomicLong VERSION_SEQUENCE = new AtomicLong();
    /**
     * A strictly increasing timestamp.  The frontend interleaves versions and
     * delete markers by (key, lastModified desc), so two of them stamped in
     * the same millisecond would list in an arbitrary order.
     */
    private static final AtomicLong LAST_MILLIS = new AtomicLong();

    private final Path root;
    /**
     * Serializes the read-then-rename that moves a key's current version
     * aside and publishes its successor.  Two writers racing there both find
     * the same current version, and the second one's rename replaces the
     * first's -- losing a version the caller was told had been stored.
     * Within one process this closes it; across processes nothing here
     * could, which is why only the transient store offers versioning.
     */
    private final Object versionLock = new Object();

    protected AbstractNio2BlobStore(Path root) {
        this.root = root;
    }

    protected final Path getRoot() {
        return root;
    }

    @Override
    public final ListBucketsResponse list() {
        var set = ImmutableSortedSet.<Bucket>orderedBy(
                Comparator.comparing(Bucket::name));
        try (var stream = Files.newDirectoryStream(root)) {
            for (var path : stream) {
                BasicFileAttributes attr;
                try {
                    attr = Files.readAttributes(path,
                            BasicFileAttributes.class);
                } catch (IOException ioe) {
                    // A container deleted while being enumerated simply does
                    // not appear.
                    if (vanished(ioe, path)) {
                        continue;
                    }
                    throw ioe;
                }
                var creationTime =
                        Instant.ofEpochMilli(attr.creationTime().toMillis());
                set.add(SdkResponses.bucket(
                        path.getFileName().toString(), creationTime));
            }
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
        return ListBucketsResponse.builder()
                .buckets(set.build())
                .build();
    }

    @Override
    public final ListObjectsV2Response list(ListObjectsV2Request request) {
        return list(request, /*includeMultipart=*/ false);
    }

    /**
     * Lists, optionally including the multipart bookkeeping this store hides
     * from clients.  Only the store's own multipart methods ask for it: a
     * request naming the reserved prefix used to turn the filter off, which
     * made hidden mean hidden by default rather than hidden.
     */
    private ListObjectsV2Response list(ListObjectsV2Request request,
            boolean includeMultipart) {
        String container = request.bucket();
        String marker0 = request.continuationToken() != null ?
                request.continuationToken() : request.startAfter();
        var containerPath = requireContainerPath(container);

        var delimiter = request.delimiter();
        if ("".equals(delimiter)) {
            delimiter = null;
        } else if (delimiter != null && !delimiter.equals("/")) {
            throw new IllegalArgumentException("Delimiters other than / not supported");
        }

        var prefix = request.prefix();
        var dirPrefix = containerPath;
        if (prefix != null) {
            int idx = prefix.lastIndexOf('/');
            if (idx != -1) {
                dirPrefix = dirPrefix.resolve(prefix.substring(0, idx));
            }
        } else {
            prefix = "";
        }
        var pathPrefix = containerPath.resolve(prefix).normalize();
        checkValidPath(containerPath, pathPrefix);
        logger.debug("Listing blobs at: {}", pathPrefix);
        var set = ImmutableSortedSet.<ListEntry>naturalOrder();
        var filterMultipart = !includeMultipart;
        var pathPrefixString = root.resolve(pathPrefix).toAbsolutePath().toString();
        try {
            listHelper(set, containerPath, dirPrefix, pathPrefixString, delimiter,
                    filterMultipart);

            // A directory-marker object whose key equals the requested prefix
            // (e.g. prefix "dir-marker/") is the prefix directory itself, into
            // which listHelper descends and lists children -- so it never
            // emits the marker. Real S3 returns keys >= prefix that start with
            // the prefix, including this exact key, so add it here. It is a
            // BLOB (not a prefix) because its remainder after the prefix is
            // empty, placing it in <Contents> regardless of the delimiter.
            if (prefix.endsWith("/") && Files.isDirectory(pathPrefix)) {
                try {
                    var markerXattrs = safeGetXattrs(pathPrefix);
                    if (markerXattrs.attributes().contains(XATTR_CONTENT_MD5)) {
                        var attr = Files.readAttributes(pathPrefix,
                                BasicFileAttributes.class);
                        set.add(ListEntry.object(SdkResponses.objectEntry(
                                prefix, readETagXattr(markerXattrs),
                                Instant.ofEpochMilli(
                                        attr.lastModifiedTime().toMillis()),
                                0L, StorageClass.STANDARD)));
                    }
                } catch (IOException ioe) {
                    // The prefix directory was deleted mid-request: there is
                    // no marker left to report.
                    if (!vanished(ioe, pathPrefix)) {
                        throw ioe;
                    }
                }
            }

            var sorted = set.build();
            if (marker0 != null) {
                // The ordering is name-only, so a name-only stub lets
                // tailSet skip past the marker in O(log n).
                sorted = sorted.tailSet(
                        ListEntry.prefix(marker0),
                        /*inclusive=*/ false);
            }
            String marker = null;
            if (request.maxKeys() != null) {
                int maxResults = request.maxKeys().intValue();
                var sortedList = sorted.asList();
                if (sortedList.size() > maxResults) {
                    if (maxResults == 0) {
                        sorted = ImmutableSortedSet.of();
                    } else {
                        var last = sortedList.get(maxResults - 1);
                        sorted = sorted.headSet(last, /*inclusive=*/ true);
                        marker = last.name();
                    }
                }
            }
            var contents = ImmutableList.<S3Object>builder();
            var prefixes = ImmutableList.<CommonPrefix>builder();
            for (var entry : sorted) {
                if (entry.object() != null) {
                    contents.add(entry.object());
                } else {
                    prefixes.add(SdkResponses.commonPrefix(entry.name()));
                }
            }
            return SdkResponses.objectsPage(contents.build(),
                    prefixes.build(), marker);
        } catch (IOException ioe) {
            logger.error("unexpected exception", ioe);
            throw new RuntimeException(ioe);
        }
    }

    /**
     * One listing entry in lexicographic paging order: an object, or a
     * common prefix when {@code object} is null.  Prefixes interleave with
     * keys for paging exactly as S3 orders the combined document.
     */
    private record ListEntry(String name, @Nullable S3Object object)
            implements Comparable<ListEntry> {
        static ListEntry prefix(String name) {
            return new ListEntry(name, null);
        }

        static ListEntry object(S3Object object) {
            return new ListEntry(object.key(), object);
        }

        @Override
        public int compareTo(ListEntry other) {
            return name.compareTo(other.name);
        }
    }

    private void listHelper(ImmutableSortedSet.Builder<ListEntry> builder,
            Path containerPath, Path parent, String pathPrefixString,
            @Nullable String delimiter, boolean filterMultipart)
            throws IOException {
        logger.debug("recursing at: {} with prefix: {}", parent, pathPrefixString);
        if (!Files.isDirectory(parent)) {
            return;
        }
        try (var stream = openDirectoryStreamIfPresent(parent)) {
            if (stream == null) {
                // The directory was removed between the caller finding it
                // and this descent; nothing to list.
                return;
            }
            try {
                for (var path : stream) {
                    logger.debug("examining: {}", path);
                    if (filterMultipart && path.getFileName().toString()
                            .startsWith(MULTIPART_PREFIX)) {
                        continue;
                    }
                    // The reserved backing store for the "/" key is not
                    // itself a client-visible object; the key "/" is never
                    // enumerated.
                    if (path.getFileName().toString().equals(SLASH_BLOB_NAME)) {
                        continue;
                    }
                    // Non-current versions are objects of ListObjectVersions
                    // alone; ListObjects reports what is current.
                    if (path.getFileName().toString().equals(VERSIONS_DIR) &&
                            containerPath.equals(path.getParent())) {
                        continue;
                    }
                    if (!path.toAbsolutePath().toString().startsWith(
                            pathPrefixString)) {
                        // ignore
                        continue;
                    }
                    try {
                        listEntry(builder, containerPath, path,
                                pathPrefixString, delimiter, filterMultipart);
                    } catch (IOException ioe) {
                        // An object deleted while being enumerated simply
                        // does not appear.
                        if (vanished(ioe, path)) {
                            continue;
                        }
                        throw ioe;
                    }
                }
            } catch (DirectoryIteratorException die) {
                // The directory vanished mid-iteration: its remaining
                // entries went with it.
                var cause = requireNonNull(die.getCause());
                if (!vanished(cause, parent)) {
                    throw cause;
                }
            }
        }
    }

    private void listEntry(ImmutableSortedSet.Builder<ListEntry> builder,
            Path containerPath, Path path, String pathPrefixString,
            @Nullable String delimiter, boolean filterMultipart)
            throws IOException {
        var attr = Files.readAttributes(path, BasicFileAttributes.class);
        if (attr.isDirectory()) {
            if (!"/".equals(delimiter)) {
                listHelper(builder, containerPath, path, pathPrefixString,
                        delimiter, filterMultipart);
            }

            var dirXattrs = safeGetXattrs(path);
            var markerExists = dirXattrs.attributes()
                    .contains(XATTR_CONTENT_MD5);

            // Add a prefix if the directory blob exists or if the delimiter causes us not to recuse.
            if ("/".equals(delimiter) || markerExists) {
                var name = relativeName(containerPath, path);
                logger.debug("adding prefix: {}", name);
                // A directory-marker object (a key ending in "/") that
                // was explicitly stored carries the XATTR_CONTENT_MD5
                // xattr. Report its metadata so a non-delimited
                // ListObjects, which emits this entry as <Contents>,
                // includes Size/LastModified/ETag like any other
                // 0-byte object. Implicit prefixes (no marker object)
                // keep null metadata since they surface only as
                // <CommonPrefixes>.
                String eTag = null;
                Instant lastModified = null;
                Long size = null;
                if (markerExists) {
                    eTag = readETagXattr(dirXattrs);
                    lastModified = Instant.ofEpochMilli(
                            attr.lastModifiedTime().toMillis());
                    size = 0L;
                }

                // With a delimiter this entry is a common prefix; without
                // one only an explicitly stored directory marker surfaces,
                // as an ordinary zero-byte object in Contents.
                if ("/".equals(delimiter)) {
                    builder.add(ListEntry.prefix(name + "/"));
                } else {
                    builder.add(ListEntry.object(SdkResponses.objectEntry(
                            name + "/", eTag, lastModified, size,
                            StorageClass.STANDARD)));
                }
            }
        } else {
            var name = relativeName(containerPath, path);
            logger.debug("adding: {}", name);
            var lastModifiedTime =
                    Instant.ofEpochMilli(attr.lastModifiedTime().toMillis());

            var xattrs = safeGetXattrs(path);
            String eTag = readETagXattr(xattrs);
            StorageClass storageClass = StorageClass.STANDARD;
            if (xattrs.view() != null) {
                var tierString = readStringAttributeIfPresent(
                        xattrs.view(), xattrs.attributes(),
                        XATTR_STORAGE_TIER);
                if (tierString != null) {
                    storageClass = parseStorageClass(tierString);
                }
            }

            builder.add(ListEntry.object(SdkResponses.objectEntry(
                    name, eTag, lastModifiedTime, attr.size(),
                    storageClass)));
        }
    }

    @Override
    public final boolean containerExists(String container) {
        return Files.isDirectory(resolveContainer(container));
    }

    @Override
    public final boolean createContainer(CreateBucketRequest request) {
        String container = request.bucket();
        try {
            Files.createDirectories(getRoot());
            Files.createDirectory(resolveContainer(container));
        } catch (FileAlreadyExistsException faee) {
            return false;
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }

        BucketCannedACL acl = request.acl();
        setContainerAccess(container,
                acl == BucketCannedACL.PUBLIC_READ ||
                acl == BucketCannedACL.PUBLIC_READ_WRITE ?
                acl : BucketCannedACL.PRIVATE);

        return true;
    }

    @Override
    public final boolean blobExists(String container, String key) {
        return blobMetadata(container, key) != null;
    }

    @Override
    @Nullable
    public final ResponseInputStream<GetObjectResponse> getBlob(
            GetObjectRequest request) {
        Blob blob = getBlobInternal(request.bucket(), request.key(), request,
                /*openStream=*/ true);
        if (blob == null) {
            return null;
        }
        return SdkResponses.getResponse(
                SdkResponses.toGetResponse(blob.getMetadata(),
                        blob.getContentRange()),
                requireNonNull(blob.getPayload()));
    }

    @Nullable
    private Blob getBlobInternal(String container, String key,
            GetObjectRequest options, boolean openStream) {
        var containerPath = requireContainerPath(container);
        var path = resolveBlobPath(containerPath, key);
        String versionId = null;
        if (supportsVersioning() &&
                readContainerStatus(containerPath) != null) {
            var resolved = resolveVersion(container, containerPath, path, key,
                    options.versionId());
            if (resolved == null) {
                return null;
            }
            path = resolved.path();
            versionId = resolved.versionId();
        } else if (options.versionId() != null) {
            throw new UnsupportedOperationException(
                    "versioning not supported");
        }
        logger.debug("Getting blob at: {}", path);

        try {
            // Everything below the payload -- the ETag, the user metadata, the
            // Content-* headers, the storage class, Last-Modified -- is read
            // through the path, which resolves anew on each call.  putBlob
            // publishes by renaming a new file over the key, so a put landing
            // between two of these reads, or between them and the open that
            // follows, leaves the answer describing more than one version of
            // the object: an ETag naming bytes other than the ones sent, or
            // user metadata belonging to a write the payload does not.  The
            // payload's length is exempt, being taken from the descriptor that
            // serves it; nothing else can be.
            //
            // Reading it all through that one descriptor is what fstat(2) and
            // fgetxattr(2) are for, and NIO offers neither.  Attributes reach
            // only through a Path: Files.readAttributes and
            // Files.getFileAttributeView have no overload taking a
            // FileChannel, a SeekableByteChannel or a FileDescriptor, and
            // FileChannel exposes size() alone -- no modification time, no
            // user-defined attributes.  Nor is the descriptor itself reachable
            // to name through /proc/self/fd on Linux, since FileChannel does
            // not hand it out and FileDescriptor keeps its integer private.
            //
            // Closing this means keeping the metadata where the bytes are, so
            // that one read of one open file answers for both.  See #490.
            var attr = Files.readAttributes(path, BasicFileAttributes.class);
            var isDirectory = attr.isDirectory();
            var xattrs = safeGetXattrs(path);
            var view = xattrs.view();
            var attributes = xattrs.attributes();
            String cacheControl = null;
            String contentDisposition = null;
            String contentEncoding = null;
            String contentLanguage = null;
            String contentType = isDirectory ? "application/x-directory" : null;
            Instant expires = null;
            HashCode hashCode = null;
            String eTag = null;
            var storageClass = StorageClass.STANDARD;
            var userMetadata = ImmutableMap.<String, String>builder();
            var lastModifiedTime =
                    Instant.ofEpochMilli(attr.lastModifiedTime().toMillis());

            if (view != null) {
                cacheControl = readStringAttributeIfPresent(view, attributes, XATTR_CACHE_CONTROL);
                contentDisposition = readStringAttributeIfPresent(view, attributes, XATTR_CONTENT_DISPOSITION);
                contentEncoding = readStringAttributeIfPresent(view, attributes, XATTR_CONTENT_ENCODING);
                contentLanguage = readStringAttributeIfPresent(view, attributes, XATTR_CONTENT_LANGUAGE);
                if (!isDirectory) {
                    contentType = readStringAttributeIfPresent(view, attributes, XATTR_CONTENT_TYPE);
                }
            }
            if (contentType == null && !isDirectory) {
                // A file written around S3Proxy carries no type of ours, so
                // guess from its name and fall back to what S3 answers for an
                // object stored without one.
                contentType = Files.probeContentType(path);
                if (contentType == null) {
                    contentType = ContentMetadata.DEFAULT_CONTENT_TYPE;
                }
            }

            if (isDirectory) {
                if (!key.endsWith("/") ||
                        !attributes.contains(XATTR_CONTENT_MD5)) {
                    // Implicit directory, or caller asked for a non-slash
                    // variant that POSIX path normalization conflated with
                    // a directory-marker key.
                    return null;
                }
            } else if (view != null &&
                    attributes.contains(XATTR_CONTENT_MD5)) {
                var buf = ByteBuffer.allocate(view.size(XATTR_CONTENT_MD5));
                view.read(XATTR_CONTENT_MD5, buf);
                var etagBytes = buf.array();
                if (etagBytes.length == 16) {
                    // regular object
                    hashCode = HashCode.fromBytes(buf.array());
                    eTag = "\"" + hashCode + "\"";
                } else {
                    // multi-part object
                    eTag = new String(etagBytes, StandardCharsets.US_ASCII);
                }
            }
            if (view != null && attributes.contains(XATTR_EXPIRES)) {
                int xattrSize = view.size(XATTR_EXPIRES);
                if (xattrSize == Longs.BYTES) {
                    ByteBuffer buf = ByteBuffer.allocate(Longs.BYTES);
                    view.read(XATTR_EXPIRES, buf);
                    buf.flip();
                    expires = Instant.ofEpochMilli(buf.asLongBuffer().get());
                } else {
                    logger.warn("ignoring malformed {} xattr ({} bytes) on {}", XATTR_EXPIRES, xattrSize, path);
                }
            }
            if (view != null) {
                var tierString = readStringAttributeIfPresent(view, attributes, XATTR_STORAGE_TIER);
                if (tierString != null) {
                    storageClass = parseStorageClass(tierString);
                }
                for (String attribute : attributes) {
                    if (!attribute.startsWith(XATTR_USER_METADATA_PREFIX)) {
                        continue;
                    }
                    var value = requireNonNull(readStringAttributeIfPresent(view, attributes, attribute));
                    userMetadata.put(attribute.substring(XATTR_USER_METADATA_PREFIX.length()), value);
                }
            }

            // Evaluate conditional headers and range bounds before opening
            // the file so that failing preconditions do not leak the
            // InputStream.
            String ifMatch = options.ifMatch();
            String ifNoneMatch = options.ifNoneMatch();
            if (eTag != null) {
                eTag = maybeQuoteETag(eTag);
            }
            // The wildcard "*" matches any existing object rather than a
            // literal ETag.  The object exists here, so If-Match: * passes and
            // If-None-Match: * yields 304 Not Modified.
            if ("*".equals(ifMatch)) {
                ifMatch = null;
            }
            if ("*".equals(ifNoneMatch)) {
                throw conditionFailed(304, eTag);
            }
            if (eTag != null) {
                if (ifMatch != null) {
                    if (!eTag.equals(maybeQuoteETag(ifMatch))) {
                        throw conditionFailed(412, eTag);
                    }
                }
                if (ifNoneMatch != null) {
                    if (eTag.equals(maybeQuoteETag(ifNoneMatch))) {
                        throw conditionFailed(304, eTag);
                    }
                }
            }
            if (options.ifModifiedSince() != null) {
                var modifiedSince = options.ifModifiedSince();
                if (lastModifiedTime.compareTo(modifiedSince) <= 0) {
                    throw conditionFailed(304, eTag);
                }

            }
            if (options.ifUnmodifiedSince() != null) {
                var unmodifiedSince = options.ifUnmodifiedSince();
                if (lastModifiedTime.isAfter(unmodifiedSince)) {
                    throw conditionFailed(412, eTag);
                }
            }

            // Handle range and open stream.
            String contentRange = null;
            InputStream inputStream;
            long size;
            if (isDirectory || !openStream) {
                inputStream = ByteSource.empty().openStream();
                size = isDirectory ? 0 : attr.size();
            } else {
                // Length the response promises comes from the descriptor that
                // will serve it, not from the stat above.  putBlob publishes
                // by renaming a new file over the key, so the path can name a
                // different inode by the time it is opened, and a length taken
                // from the earlier stat describes a version other than the one
                // being sent: too long truncates the response, too short
                // overruns it.  A descriptor, once open, refers to one file for
                // as long as it is held, whatever the name goes on to mean.
                var channel = FileChannel.open(path, StandardOpenOption.READ);
                boolean giveAway = false;
                try {
                    size = channel.size();
                    long offset = 0;
                    long last = size;
                    var range = SdkRequests.parseRange(options.range());
                    boolean hasRange = range != null;
                    if (range != null) {
                        // HTTP uses a closed interval while Java array indexing uses a
                        // half-open interval.
                        if (range.first() == null) {
                            offset = last - requireNonNull(range.last());
                            if (offset < 0) {
                                offset = 0;
                            }
                        } else if (range.last() == null) {
                            offset = range.first();
                        } else {
                            offset = range.first();
                            last = range.last();
                        }

                        if (offset >= size || offset > last) {
                            throw S3Exceptions.fromStatusCode(416);
                        }
                        if (last + 1 > size) {
                            last = size - 1;
                        }
                        contentRange = "bytes " + offset + "-" + last + "/" + channel.size();
                        size = last - offset + 1;
                    }

                    if (hasRange) {
                        // Seek rather than read and discard: the stream
                        // Channels wraps a channel in skips the default way,
                        // by reading the prefix it means to throw away.
                        channel.position(offset);
                    }
                    inputStream = Channels.newInputStream(channel);
                    if (hasRange) {
                        inputStream = ByteStreams.limit(inputStream, size);
                    }
                    // The stream owns the channel from here; closing it closes
                    // the channel.
                    giveAway = true;
                } finally {
                    // A range this file cannot satisfy, or a seek that fails,
                    // leaves without a stream to carry the channel out.
                    if (!giveAway) {
                        try {
                            channel.close();
                        } catch (IOException ioe) {
                            logger.debug("failed to close {}", path, ioe);
                        }
                    }
                }
            }

            HashCode finalHashCode = hashCode;
            Blob.Builder builder = Blob.builder(key)
                    .userMetadata(userMetadata.build())
                    .payload(inputStream)
                    .cacheControl(cacheControl)
                    .contentDisposition(contentDisposition)
                    .contentEncoding(contentEncoding)
                    .contentLanguage(contentLanguage)
                    .contentLength(size)
                    // Content-MD5 covers the full object; omit it for
                    // ranged responses so it does not mismatch the partial
                    // body the client receives.
                    .contentMD5(contentRange == null ? hashCode : null)
                    .contentType(contentType)
                    .eTag(eTag)
                    .expires(expires)
                    .storageClass(storageClass)
                    .container(container)
                    .versionId(versionId)
                    .encryption(readEncryption(view, attributes))
                    .lastModified(lastModifiedTime);
            if (contentRange != null) {
                builder.contentRange(contentRange);
            }
            if (finalHashCode != null) {
                builder.eTag(HexFormat.of().formatHex(finalHashCode.asBytes()));
            }
            return builder.build();
        } catch (NoSuchFileException nsfe) {
            return null;
        } catch (IOException ioe) {
            if (Files.notExists(path)) {
                // SFTP sometimes reports the missing object as a generic
                // error rather than NoSuchFileException.
                return null;
            }
            throw new RuntimeException(ioe);
        }
    }

    @Override
    public final PutObjectResponse putBlob(PutObjectRequest request,
            InputStream payload) {
        checkNotReserved(request.key());
        var encryption = requestEncryption(request.bucket(),
                request.serverSideEncryptionAsString(), request.ssekmsKeyId(),
                request.ssekmsEncryptionContext(), request.bucketKeyEnabled(),
                request.sseCustomerAlgorithm(), request.sseCustomerKey(),
                request.sseCustomerKeyMD5());
        var result = putBlob(request.bucket(),
                toBlobBuilder(request).encryption(encryption).payload(payload)
                        .build(),
                SdkRequests.aclOrPrivate(request.acl()),
                request.ifNoneMatch(),
                /*parts=*/ null);
        return PutObjectResponse.builder()
                .eTag(result.eTag())
                .versionId(result.reportedVersionId())
                .serverSideEncryption(encryption == null ? null :
                        encryption.algorithm())
                .ssekmsKeyId(encryption == null ? null : encryption.kmsKeyId())
                .ssekmsEncryptionContext(encryption == null ? null :
                        encryption.kmsContext())
                .bucketKeyEnabled(encryption == null ? null :
                        encryption.bucketKeyEnabled())
                .sseCustomerAlgorithm(encryption == null ? null :
                        encryption.customerAlgorithm())
                .sseCustomerKeyMD5(encryption == null ? null :
                        encryption.customerKeyMD5())
                .build();
    }

    /**
     * Stores a blob, optionally assembling it from part files already in the
     * store rather than from the payload stream.  Naming the parts lets the
     * kernel join them: FileChannel.transferTo becomes copy_file_range, which
     * a copy-on-write filesystem serves by sharing extents rather than
     * copying bytes, and which a network filesystem can serve on the server.
     * Reading the payload instead would cost a full read and write of an
     * object that has already been written once as parts.
     */
    private PutResult putBlob(String container, Blob blob,
            ObjectCannedACL access, @Nullable String ifNoneMatch,
            @Nullable List<Path> parts) {
        var containerPath = requireContainerPath(container);
        var path = resolveBlobPath(containerPath, blob.getMetadata().name());
        // TODO: should we use a known suffix to filter these out during list?
        var tmpPath = containerPath.resolve(blob.getMetadata().name() + "-" + UUID.randomUUID());
        logger.debug("Creating blob at: {}", path);

        if (blob.getMetadata().name().endsWith("/")) {
            try {
                logger.debug("Creating directory blob: {}", path);
                Files.createDirectories(path);
            } catch (FileAlreadyExistsException faee) {
                logger.debug("Parent directories already exist: {}", path.getParent());
            } catch (IOException ioe) {
                throw new RuntimeException(ioe);
            }

            var view = getXattrView(path);
            if (view != null) {
                try {
                    writeCommonMetadataAttr(view, blob);
                    view.write(XATTR_CONTENT_MD5, ByteBuffer.wrap(DIRECTORY_MD5));
                } catch (IOException | UnsupportedOperationException ioe) {
                    logger.debug("xattrs not supported on {}", path);
                }
            }

            // A directory marker is the directory itself, which the versions
            // of the keys below it live in; it is not versioned.
            return new PutResult(HexFormat.of().formatHex(DIRECTORY_MD5),
                    /*versionId=*/ null);
        }

        // Create parent directories.
        try {
            Files.createDirectories(path.getParent());
        } catch (FileAlreadyExistsException faee) {
            logger.debug("Parent directories already exist: {}", path.getParent());
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }

        var metadata = blob.getMetadata().contentMetadata();
        try {
            // Null when the parts were joined by the kernel: nothing reads the
            // MD5 of an assembled multipart object, whose ETag is the digest
            // of the part digests that the caller already computed.
            HashCode actualHashCode = null;
            // Close the streams before doing xattr writes, setBlobAccess,
            // and Files.move: Windows refuses to atomically move a file
            // that still has an open OutputStream.
            if (parts != null) {
                concatenate(parts, tmpPath);
            } else {
                var digest = MD5.newDigest();
                try (var is = new DigestInputStream(
                        requireNonNull(blob.getPayload()), digest);
                     var os = Files.newOutputStream(tmpPath)) {
                    is.transferTo(os);
                }
                actualHashCode = HashCode.fromBytes(digest.digest());
                var expectedHashCode = metadata.contentMD5();
                if (expectedHashCode != null &&
                        !actualHashCode.equals(expectedHashCode)) {
                    throw returnResponseException(400);
                }
            }
            // What this reports back: the payload's MD5 for a regular put,
            // and for an assembled multipart the ETag the caller preset,
            // since no digest of the whole object was taken.
            String storedETag = actualHashCode != null ?
                    actualHashCode.toString() :
                    requireNonNull(blob.getMetadata().eTag());

            var view = getXattrView(tmpPath);
            if (view != null) {
                try {
                    // A multipart-completion blob carries the S3 multipart
                    // ETag ("<md5>-<n>"), which is not the MD5 of the assembled
                    // payload; persist it verbatim (as ASCII) so a later
                    // GET/HEAD reports the same ETag that
                    // completeMultipartUpload returned.  A regular put has no
                    // preset ETag, so store the computed MD5 as 16 raw bytes.
                    var providedETag = blob.getMetadata().eTag();
                    var eTag = providedETag != null ?
                            providedETag.getBytes(StandardCharsets.US_ASCII) :
                            requireNonNull(actualHashCode).asBytes();
                    view.write(XATTR_CONTENT_MD5, ByteBuffer.wrap(eTag));
                    writeStringAttributeIfPresent(view, XATTR_CACHE_CONTROL, metadata.cacheControl());
                    writeStringAttributeIfPresent(view, XATTR_CONTENT_DISPOSITION, metadata.contentDisposition());
                    writeStringAttributeIfPresent(view, XATTR_CONTENT_ENCODING, metadata.contentEncoding());
                    writeStringAttributeIfPresent(view, XATTR_CONTENT_LANGUAGE, metadata.contentLanguage());
                    writeStringAttributeIfPresent(view, XATTR_CONTENT_TYPE, metadata.contentType());
                    var expires = metadata.expires();
                    if (expires != null) {
                        ByteBuffer buf = ByteBuffer.allocate(Longs.BYTES).putLong(expires.toEpochMilli());
                        buf.flip();
                        view.write(XATTR_EXPIRES, buf);
                    }
                    writeStringAttributeIfPresent(view, XATTR_STORAGE_TIER, blob.getMetadata().storageClass().toString());
                    for (var entry : blob.getMetadata().userMetadata().entrySet()) {
                        writeStringAttributeIfPresent(view, XATTR_USER_METADATA_PREFIX + entry.getKey(), entry.getValue());
                    }
                    writeEncryptionAttr(view, blob);
                } catch (IOException | UnsupportedOperationException e) {
                    logger.debug("xattrs not supported on {}", tmpPath);
                }
            }

            setBlobAccessHelper(tmpPath, access);

            // The id this write carries, minted before publishing so that the
            // file is never briefly current without one.  A store that does
            // not version, or a container never enabled, mints nothing and
            // leaves every path below exactly as it was.  Nor is this store's
            // own multipart bookkeeping versioned: a re-uploaded part would
            // leave its predecessor archived behind a name no client can see
            // to delete, and completing the upload removes the parts outright
            // rather than through anything that understands versions.
            String versionId = null;
            if (supportsVersioning() &&
                    !blob.getMetadata().name().startsWith(MULTIPART_PREFIX)) {
                var status = readContainerStatus(containerPath);
                if (status != null) {
                    versionId = mintVersionId(status);
                    writeVersionAttributes(tmpPath, blob.getMetadata().name(),
                            versionId, /*deleteMarker=*/ false);
                    Files.setLastModifiedTime(tmpPath,
                            FileTime.from(mintTime()));
                }
            }

            if ("*".equals(ifNoneMatch)) {
                // Claiming a key: publish by linking rather than renaming, so
                // that two writers racing cannot both believe they created the
                // object.  This is why If-None-Match: * exists, so it must not
                // reduce to a check followed by an unconditional write.
                //
                // It has to be a link: ATOMIC_MOVE is rename(2) on a POSIX
                // filesystem, which replaces the target even without
                // REPLACE_EXISTING, whereas link(2) fails if it exists.  The
                // link shares the inode, so the xattrs and permissions
                // already written to tmpPath carry over.
                try {
                    Files.createLink(path, tmpPath);
                } catch (FileAlreadyExistsException faee) {
                    throw returnResponseException(412);
                } catch (UnsupportedOperationException uoe) {
                    // a filesystem without hard links leaves only a check
                    // followed by a write, which cannot be made atomic
                    if (Files.exists(path)) {
                        throw returnResponseException(412);
                    }
                    Files.move(tmpPath, path, StandardCopyOption.ATOMIC_MOVE);
                    return new PutResult(storedETag, versionId);
                }
                // Nothing was displaced: the condition held only because the
                // key had no current version to displace.
                return new PutResult(storedETag, versionId);
            }
            if (ifNoneMatch != null) {
                // A named ETag cannot be resolved by the move, and the
                // filesystem offers no compare-and-swap, so this remains a
                // read followed by a write.
                var current = currentMetadata(container,
                        blob.getMetadata().name());
                if (current != null && current.eTag() != null &&
                        maybeQuoteETag(ifNoneMatch).equals(
                                maybeQuoteETag(current.eTag()))) {
                    throw returnResponseException(412);
                }
            }

            if (versionId != null) {
                synchronized (versionLock) {
                    archiveCurrentVersion(containerPath, path,
                            blob.getMetadata().name(), versionId);
                    Files.move(tmpPath, path, StandardCopyOption.ATOMIC_MOVE,
                            StandardCopyOption.REPLACE_EXISTING);
                }
                return new PutResult(storedETag, versionId);
            }
            Files.move(tmpPath, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);

            return new PutResult(storedETag, versionId);
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        } finally {
            // No-op on the success path because Files.move has already
            // consumed tmpPath; on any earlier failure this removes the
            // partial file so it does not accumulate on disk.
            try {
                Files.deleteIfExists(tmpPath);
            } catch (IOException ioe) {
                logger.debug("unable to delete temp file {}", tmpPath, ioe);
            }
        }
    }

    /** What a write reports back: its ETag, and its version where kept. */
    private record PutResult(String eTag, @Nullable String versionId) {
        /**
         * The version a write announces.  A suspended container mints the
         * "null" id, which S3 keeps addressable but does not name in the
         * response -- there is no version to point a caller at.
         */
        @Nullable String reportedVersionId() {
            return NULL_VERSION_ID.equals(versionId) ? null : versionId;
        }
    }

    /**
     * The current object's metadata, or null where there is no current
     * object.  A key whose current version is a delete marker has none, and
     * a conditional write has to read that as absence: {@link #blobMetadata}
     * reports it as the 404 that a client's GET deserves instead.
     */
    @Nullable
    private HeadObjectResponse currentMetadata(String container, String key) {
        try {
            return blobMetadata(container, key);
        } catch (NoSuchKeyException nske) {
            return null;
        }
    }

    /** The request's metadata as this store's internal write carrier. */
    private static Blob.Builder toBlobBuilder(PutObjectRequest request) {
        var builder = Blob.builder(request.key())
                .cacheControl(request.cacheControl())
                .contentDisposition(request.contentDisposition())
                .contentEncoding(request.contentEncoding())
                .contentLanguage(request.contentLanguage())
                .contentType(request.contentType())
                .userMetadata(request.metadata());
        Long contentLength = request.contentLength();
        if (contentLength != null) {
            builder.contentLength(contentLength);
        }
        String contentMD5 = request.contentMD5();
        if (contentMD5 != null) {
            builder.contentMD5(HashCode.fromBytes(
                    Base64.getDecoder().decode(contentMD5)));
        }
        if (request.expires() != null) {
            builder.expires(request.expires());
        }
        if (request.storageClass() != null) {
            builder.storageClass(request.storageClass());
        }
        return builder;
    }

    @Override
    public final CopyObjectResponse copyBlob(CopyObjectRequest request) {
        if (request.sourceVersionId() != null && !supportsVersioning()) {
            throw new UnsupportedOperationException(
                    "versioning not supported");
        }
        String fromContainer = request.sourceBucket();
        String fromName = request.sourceKey();
        String toContainer = request.destinationBucket();
        String toName = request.destinationKey();
        checkNotReserved(toName);
        boolean replace =
                request.metadataDirective() == MetadataDirective.REPLACE;
        var blob = getBlobInternal(fromContainer, fromName,
                GetObjectRequest.builder()
                        .bucket(fromContainer)
                        .key(fromName)
                        .versionId(request.sourceVersionId())
                        .build(),
                /*openStream=*/ true);
        if (blob == null) {
            throw S3Exceptions.noSuchKey(fromContainer, fromName, "while copying");
        }
        // The version read, which the response reports even when the copy
        // named no version: restoring an old version is a copy of it onto
        // itself, and the caller checks this to see which one it got.
        String sourceVersionId = blob.getMetadata().versionId();

        // Evaluate preconditions inside the try-with-resources so that a
        // failing check still closes the file InputStream returned by
        // getBlob.
        try (var is = requireNonNull(blob.getPayload())) {
            // Reading the source is a read like any other: it answers only
            // to the key it rests under, presented in the copy-source
            // variants of the customer-key headers.
            var sourceEncryption = blob.getMetadata().encryption();
            CustomerKeys.enforce(sourceEncryption == null ? null :
                            sourceEncryption.customerKeyMD5(),
                    request.copySourceSSECustomerAlgorithm(),
                    request.copySourceSSECustomerKey(),
                    request.copySourceSSECustomerKeyMD5());
            var eTag = blob.getMetadata().eTag();
            String ifMatch = request.copySourceIfMatch();
            String ifNoneMatch = request.copySourceIfNoneMatch();
            if (eTag != null) {
                eTag = maybeQuoteETag(eTag);
                if (ifMatch != null && !maybeQuoteETag(ifMatch).equals(eTag)) {
                    throw returnResponseException(412);
                }
                if (ifNoneMatch != null && maybeQuoteETag(ifNoneMatch).equals(eTag)) {
                    throw returnResponseException(412);
                }
            }

            var lastModified = blob.getMetadata().lastModified();
            if (lastModified != null) {
                var ifModifiedSince = request.copySourceIfModifiedSince();
                var ifUnmodifiedSince = request.copySourceIfUnmodifiedSince();
                if (ifModifiedSince != null && lastModified.compareTo(ifModifiedSince) <= 0) {
                    throw returnResponseException(412);
                }
                if (ifUnmodifiedSince != null && lastModified.compareTo(ifUnmodifiedSince) > 0) {
                    throw returnResponseException(412);
                }
            }

            var metadata = blob.getMetadata().contentMetadata();
            var builder = Blob.builder(toName).payload(is);
            Long contentLength = metadata.contentLength();
            if (contentLength != null) {
                builder.contentLength(contentLength);
            }

            if (replace) {
                String cacheControl = request.cacheControl();
                if (cacheControl != null) {
                    builder.cacheControl(cacheControl);
                }
                String contentDisposition = request.contentDisposition();
                if (contentDisposition != null) {
                    builder.contentDisposition(contentDisposition);
                }
                String contentEncoding = request.contentEncoding();
                if (contentEncoding != null) {
                    builder.contentEncoding(contentEncoding);
                }
                String contentLanguage = request.contentLanguage();
                if (contentLanguage != null) {
                    builder.contentLanguage(contentLanguage);
                }
                String contentType = request.contentType();
                if (contentType != null) {
                    builder.contentType(contentType);
                }
            } else {
                builder.cacheControl(metadata.cacheControl())
                        .contentDisposition(metadata.contentDisposition())
                        .contentEncoding(metadata.contentEncoding())
                        .contentLanguage(metadata.contentLanguage())
                        .contentType(metadata.contentType());
            }

            if (replace) {
                builder.userMetadata(request.metadata());
            } else {
                builder.userMetadata(blob.getMetadata().userMetadata());
            }
            // The copy rests under what it asked for rather than under what
            // the source rested under, the way S3 encrypts a copy: the
            // destination is a new object, and only its own request says how.
            var encryption = requestEncryption(toContainer,
                    request.serverSideEncryptionAsString(),
                    request.ssekmsKeyId(), request.ssekmsEncryptionContext(),
                    request.bucketKeyEnabled(),
                    request.sseCustomerAlgorithm(),
                    request.sseCustomerKey(),
                    request.sseCustomerKeyMD5());
            var result = putBlob(toContainer,
                    builder.encryption(encryption).build(),
                    SdkRequests.aclOrPrivate(request.acl()),
                    /*ifNoneMatch=*/ null,
                    /*parts=*/ null);
            return CopyObjectResponse.builder()
                    .copyObjectResult(CopyObjectResult.builder()
                            .eTag(result.eTag())
                            .build())
                    .versionId(result.reportedVersionId())
                    .copySourceVersionId(NULL_VERSION_ID.equals(
                            sourceVersionId) ? null : sourceVersionId)
                    .serverSideEncryption(encryption == null ? null :
                            encryption.algorithm())
                    .ssekmsKeyId(encryption == null ? null :
                            encryption.kmsKeyId())
                    .ssekmsEncryptionContext(encryption == null ? null :
                            encryption.kmsContext())
                    .bucketKeyEnabled(encryption == null ? null :
                            encryption.bucketKeyEnabled())
                    .sseCustomerAlgorithm(encryption == null ? null :
                            encryption.customerAlgorithm())
                    .sseCustomerKeyMD5(encryption == null ? null :
                            encryption.customerKeyMD5())
                    .build();
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }

    @Override
    public final void removeBlob(String container, String key) {
        checkNotReserved(key);
        if (supportsVersioning()) {
            // A delete that names no version is still a delete marker on a
            // versioned container; the frontend reaches this overload for it
            // whenever it has no result to report, e.g. a conditional delete.
            removeBlob(container, key, /*versionId=*/ null);
            return;
        }
        removeBlobInternal(container, key);
    }

    @Override
    public final DeleteObjectResponse removeBlob(String container, String key,
            @Nullable String versionId) {
        checkNotReserved(key);
        if (!supportsVersioning()) {
            throw new UnsupportedOperationException(
                    "versioning not supported");
        }
        var containerPath = requireContainerPath(container);
        var status = readContainerStatus(containerPath);
        var path = resolveBlobPath(containerPath, key);

        if (versionId != null) {
            return removeVersion(container, containerPath, path, key,
                    versionId);
        }
        // A key whose storage is a directory -- a directory marker, or a
        // prefix other keys live under -- is not versioned, so a delete of
        // one is the ordinary delete, which knows to keep the directory for
        // the objects inside it.
        if (status == null || Files.isDirectory(path)) {
            removeBlobInternal(container, key);
            return DeleteObjectResponse.builder().build();
        }

        // Versioned: the data stays and a marker goes on top of it.
        var markerId = mintVersionId(status);
        try {
            synchronized (versionLock) {
                archiveCurrentVersion(containerPath, path, key, markerId);
                Files.deleteIfExists(path);
                removeEmptyParentDirectories(containerPath, path.getParent());
                var marker = newVersionPath(containerPath, key);
                Files.createDirectories(marker.getParent());
                Files.createFile(marker);
                writeVersionAttributes(marker, key, markerId,
                        /*deleteMarker=*/ true);
                Files.setLastModifiedTime(marker,
                        FileTime.from(mintTime()));
            }
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
        return DeleteObjectResponse.builder()
                .versionId(markerId)
                .deleteMarker(true)
                .build();
    }

    /**
     * Deletes the one version named, which unlike an ordinary delete removes
     * data.  Deleting the current version promotes whatever it was hiding.
     */
    private DeleteObjectResponse removeVersion(String container,
            Path containerPath, Path path, String key, String versionId) {
        try {
            synchronized (versionLock) {
                if (Files.exists(path) &&
                        currentVersionId(path).equals(versionId)) {
                    // Removing an object at its natural path is what the
                    // ordinary delete does, directory-marker keys included.
                    removeBlobInternal(container, key);
                    if (Files.notExists(path)) {
                        promoteNewestVersion(containerPath, path, key);
                    }
                    if (Files.notExists(path)) {
                        removeEmptyParentDirectories(containerPath,
                                path.getParent());
                    }
                    return DeleteObjectResponse.builder()
                            .versionId(versionId)
                            .build();
                }
                for (var version : archivedVersions(containerPath, key)) {
                    if (!version.versionId().equals(versionId)) {
                        continue;
                    }
                    Files.delete(version.path());
                    // The version removed may have been the one standing for
                    // the key -- a delete marker on top of older versions --
                    // in which case the next one down becomes current.
                    if (Files.notExists(path)) {
                        promoteNewestVersion(containerPath, path, key);
                    }
                    if (Files.notExists(path)) {
                        // The last of a key like "dir/blob" leaves "dir"
                        // behind, which nothing lists and which would keep
                        // the bucket from ever being deleted.
                        removeEmptyParentDirectories(containerPath,
                                path.getParent());
                    }
                    return DeleteObjectResponse.builder()
                            .versionId(versionId)
                            .deleteMarker(version.deleteMarker() ? true : null)
                            .build();
                }
            }
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
        throw S3Exceptions.noSuchVersion(container, key, versionId,
                "no such version");
    }

    /**
     * Deletes without the reserved-name check, for the multipart bookkeeping
     * this store both writes and cleans up.
     */
    private void removeBlobInternal(String container, String key) {
        var containerPath = resolveContainer(container);
        var path = resolveBlobPath(containerPath, key);
        if (!key.endsWith("/") && Files.isDirectory(path)) {
            // POSIX path normalization conflates "key" with "key/";
            // a non-slash key must not match a directory marker.
            return;
        }
        try {
            logger.debug("Deleting blob at: {}", path);
            Files.delete(path);
            removeEmptyParentDirectories(containerPath, path.getParent());
        } catch (NoSuchFileException nsfe) {
            return;
        } catch (DirectoryNotEmptyException dnee) {
            clearDirectoryMarker(path);
        } catch (IOException ioe) {
            if (key.endsWith("/") && Files.isDirectory(path)) {
                // An SFTP server reports the non-empty directory as a
                // generic failure (SSH_FX_DIR_NOT_EMPTY) that the provider
                // does not map to DirectoryNotEmptyException.
                clearDirectoryMarker(path);
                return;
            }
            throw new RuntimeException(ioe);
        }
    }

    /**
     * Handles deleting a directory-marker key ("dir/") whose directory still
     * holds objects: the directory must stay for those objects, so drop only
     * the marker attribute rather than failing with 500.  A later GET of the
     * marker then correctly reports it absent.
     */
    private void clearDirectoryMarker(Path path) {
        var view = getXattrView(path);
        if (view != null) {
            try {
                if (view.list().contains(XATTR_CONTENT_MD5)) {
                    view.delete(XATTR_CONTENT_MD5);
                }
            } catch (IOException | UnsupportedOperationException e) {
                logger.debug("could not clear directory marker on {}", path);
            }
        }
    }

    @Override
    @Nullable
    public final HeadObjectResponse blobMetadata(HeadObjectRequest request) {
        String container = request.bucket();
        String key = request.key();
        Blob blob = getBlobInternal(container, key,
                GetObjectRequest.builder().bucket(container).key(key)
                        .versionId(request.versionId()).build(),
                /*openStream=*/ false);
        if (blob == null) {
            return null;
        }
        var in = blob.getMetadata();
        var lowerCaseUserMetadata = new HashMap<String, String>();
        for (var entry : in.userMetadata().entrySet()) {
            lowerCaseUserMetadata.put(entry.getKey().toLowerCase(),
                    entry.getValue());
        }
        return SdkResponses.toHead(SdkResponses.toGetResponse(
                in.toBuilder().userMetadata(lowerCaseUserMetadata).build(),
                /*contentRange=*/ null));
    }

    @Override
    @Nullable
    public final BucketVersioningStatus getContainerVersioning(
            String container) {
        if (!supportsVersioning()) {
            throw new UnsupportedOperationException(
                    "versioning not supported");
        }
        return readContainerStatus(requireContainerPath(container));
    }

    @Override
    public final void setContainerVersioning(String container,
            BucketVersioningStatus status) {
        if (!supportsVersioning()) {
            throw new UnsupportedOperationException(
                    "versioning not supported");
        }
        var containerPath = requireContainerPath(container);
        var view = getXattrView(containerPath);
        if (view == null) {
            throw new UnsupportedOperationException(
                    "versioning needs user attributes");
        }
        try {
            writeStringAttributeIfPresent(view, XATTR_VERSIONING,
                    status.toString());
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }

    @Override
    public final ServerSideEncryptionConfiguration getContainerEncryption(
            String container) {
        if (!supportsBucketEncryption()) {
            throw new UnsupportedOperationException(
                    "bucket encryption not supported");
        }
        var encryption = readContainerEncryption(
                requireContainerPath(container));
        if (encryption == null) {
            throw S3Exceptions.serverSideEncryptionConfigurationNotFound(
                    container);
        }
        var byDefault = ServerSideEncryptionByDefault.builder()
                .sseAlgorithm(encryption.algorithm());
        if (encryption.kmsKeyId() != null) {
            byDefault.kmsMasterKeyID(encryption.kmsKeyId());
        }
        return ServerSideEncryptionConfiguration.builder()
                .rules(ServerSideEncryptionRule.builder()
                        .applyServerSideEncryptionByDefault(byDefault.build())
                        .bucketKeyEnabled(encryption.bucketKeyEnabled())
                        .build())
                .build();
    }

    @Override
    public final void setContainerEncryption(String container,
            ServerSideEncryptionConfiguration configuration) {
        if (!supportsBucketEncryption()) {
            throw new UnsupportedOperationException(
                    "bucket encryption not supported");
        }
        if (configuration.rules().size() != 1) {
            throw S3Exceptions.invalidArgument(
                    "Exactly one encryption rule is expected.");
        }
        var rule = configuration.rules().get(0);
        var byDefault = rule.applyServerSideEncryptionByDefault();
        String algorithm = byDefault == null ? null :
                byDefault.sseAlgorithmAsString();
        String kmsKeyId = byDefault == null ? null :
                byDefault.kmsMasterKeyID();
        // Judge the configuration as the write requests it will default
        // are judged: nothing may enter it that requestEncryption would
        // refuse, or unadorned writes would start failing after the fact.
        if (Encryption.KMS_ALGORITHM.equals(algorithm)) {
            if (kmsKeyId == null) {
                throw S3Exceptions.invalidArgument("Server side encryption" +
                        " with aws:kms requires a KMSMasterKeyID.");
            }
        } else {
            if (algorithm == null ||
                    !Encryption.DEFAULT_ALGORITHM.equals(algorithm)) {
                throw S3Exceptions.invalidArgument("The encryption" +
                        " algorithm specified is not valid.");
            }
            if (kmsKeyId != null) {
                throw S3Exceptions.invalidArgument("a KMSMasterKeyID is not" +
                        " applicable if the default sse algorithm is not" +
                        " aws:kms");
            }
        }
        var containerPath = requireContainerPath(container);
        var view = getXattrView(containerPath);
        if (view == null) {
            throw new UnsupportedOperationException(
                    "bucket encryption needs user attributes");
        }
        try {
            writeStringAttributeIfPresent(view,
                    XATTR_BUCKET_ENCRYPTION_ALGORITHM, algorithm);
            // Rewrite the optional fields outright: this configuration
            // replaces the last one, absences included.
            writeOrDeleteAttribute(view,
                    XATTR_BUCKET_ENCRYPTION_KMS_KEY_ID, kmsKeyId);
            writeOrDeleteAttribute(view,
                    XATTR_BUCKET_ENCRYPTION_BUCKET_KEY,
                    rule.bucketKeyEnabled() == null ? null :
                            rule.bucketKeyEnabled().toString());
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }

    @Override
    public final void deleteContainerEncryption(String container) {
        if (!supportsBucketEncryption()) {
            throw new UnsupportedOperationException(
                    "bucket encryption not supported");
        }
        var containerPath = requireContainerPath(container);
        var view = getXattrView(containerPath);
        if (view == null) {
            // Nothing could have been stored, so nothing needs removing.
            return;
        }
        try {
            writeOrDeleteAttribute(view,
                    XATTR_BUCKET_ENCRYPTION_ALGORITHM, null);
            writeOrDeleteAttribute(view,
                    XATTR_BUCKET_ENCRYPTION_KMS_KEY_ID, null);
            writeOrDeleteAttribute(view,
                    XATTR_BUCKET_ENCRYPTION_BUCKET_KEY, null);
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }

    /** The container's default encryption, or null when none was put. */
    @Nullable
    private Encryption readContainerEncryption(Path containerPath) {
        var xattrs = safeGetXattrs(containerPath);
        var view = xattrs.view();
        if (view == null) {
            return null;
        }
        try {
            var algorithm = readStringAttributeIfPresent(view,
                    xattrs.attributes(), XATTR_BUCKET_ENCRYPTION_ALGORITHM);
            if (algorithm == null) {
                return null;
            }
            var bucketKey = readStringAttributeIfPresent(view,
                    xattrs.attributes(), XATTR_BUCKET_ENCRYPTION_BUCKET_KEY);
            return new Encryption(algorithm,
                    readStringAttributeIfPresent(view, xattrs.attributes(),
                            XATTR_BUCKET_ENCRYPTION_KMS_KEY_ID),
                    /*kmsContext=*/ null,
                    bucketKey == null ? null : Boolean.valueOf(bucketKey),
                    /*customerAlgorithm=*/ null, /*customerKeyMD5=*/ null);
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }

    @Override
    public final ListObjectVersionsResponse listVersions(
            ListObjectVersionsRequest request) {
        if (!supportsVersioning()) {
            throw new UnsupportedOperationException(
                    "versioning not supported");
        }
        String container = request.bucket();
        var containerPath = requireContainerPath(container);
        String prefix = request.prefix() == null ? "" : request.prefix();
        String delimiter = request.delimiter();
        int maxKeys = request.maxKeys() == null ? 1000 : request.maxKeys();

        // Flatten every version of every key into S3's order -- keys
        // ascending, newest first -- and slice one page out of it.  The
        // current versions come from the ordinary listing, since that is
        // where they live; the rest come from the sidecar.
        var rows = new ArrayList<VersionRow>();
        var commonPrefixes = new LinkedHashSet<String>();
        for (var object : listAll(container, prefix)) {
            var path = resolveBlobPath(containerPath, object.key());
            if (collectCommonPrefix(object.key(), prefix, delimiter,
                    commonPrefixes)) {
                continue;
            }
            rows.add(new VersionRow(object.key(), currentVersionId(path),
                    /*latest=*/ true, /*deleteMarker=*/ false, object.eTag(),
                    object.lastModified(), object.size()));
        }
        // A key whose newest version is a delete marker has nothing current,
        // so the marker is what is latest.
        var latestArchived = new TreeMap<String, String>();
        for (var version : archivedVersions(containerPath, /*key=*/ null)) {
            if (!version.key().startsWith(prefix)) {
                continue;
            }
            latestArchived.putIfAbsent(version.key(), version.versionId());
        }
        for (var version : archivedVersions(containerPath, /*key=*/ null)) {
            String key = version.key();
            if (!key.startsWith(prefix)) {
                continue;
            }
            if (collectCommonPrefix(key, prefix, delimiter, commonPrefixes)) {
                continue;
            }
            boolean latest = Files.notExists(
                    resolveBlobPath(containerPath, key)) &&
                    version.versionId().equals(latestArchived.get(key));
            Long size = null;
            String eTag = null;
            if (!version.deleteMarker()) {
                var head = readVersionMetadata(container, key, version);
                if (head != null) {
                    size = head.contentLength();
                    eTag = head.eTag();
                }
            }
            rows.add(new VersionRow(key, version.versionId(), latest,
                    version.deleteMarker(), eTag, version.lastModified(),
                    size));
        }
        rows.sort(Comparator.comparing(VersionRow::key)
                .thenComparing(Comparator.comparing(
                        VersionRow::lastModified).reversed()));

        int start = 0;
        String keyMarker = request.keyMarker();
        if (keyMarker != null) {
            String versionIdMarker = request.versionIdMarker();
            for (int i = 0; i < rows.size(); i++) {
                var candidate = rows.get(i);
                if (versionIdMarker == null) {
                    if (candidate.key().compareTo(keyMarker) > 0) {
                        start = i;
                        break;
                    }
                } else if (candidate.key().equals(keyMarker) &&
                        candidate.versionId().equals(versionIdMarker)) {
                    start = i + 1;
                    break;
                }
                start = i + 1;
            }
        }
        int end = Math.min(rows.size(), start + maxKeys);
        var page = rows.subList(start, end);
        String nextKeyMarker = null;
        String nextVersionIdMarker = null;
        if (end < rows.size() && !page.isEmpty()) {
            var last = page.get(page.size() - 1);
            nextKeyMarker = last.key();
            nextVersionIdMarker = last.versionId();
        }

        var versions = new ArrayList<ObjectVersion>();
        var markers = new ArrayList<DeleteMarkerEntry>();
        for (var row : page) {
            if (row.deleteMarker()) {
                markers.add(DeleteMarkerEntry.builder()
                        .key(row.key())
                        .versionId(row.versionId())
                        .isLatest(row.latest())
                        .lastModified(row.lastModified())
                        .build());
            } else {
                versions.add(ObjectVersion.builder()
                        .key(row.key())
                        .versionId(row.versionId())
                        .isLatest(row.latest())
                        .eTag(row.eTag())
                        .lastModified(row.lastModified())
                        .size(row.size())
                        .storageClass(ObjectVersionStorageClass.STANDARD)
                        .build());
            }
        }
        return ListObjectVersionsResponse.builder()
                .versions(versions)
                .deleteMarkers(markers)
                .commonPrefixes(commonPrefixes.stream()
                        .map(value -> CommonPrefix.builder().prefix(value)
                                .build())
                        .toList())
                .nextKeyMarker(nextKeyMarker)
                .nextVersionIdMarker(nextVersionIdMarker)
                .isTruncated(nextKeyMarker != null)
                .build();
    }

    /** One row of the flattened versions listing. */
    private record VersionRow(String key, String versionId, boolean latest,
            boolean deleteMarker, @Nullable String eTag, Instant lastModified,
            @Nullable Long size) {
    }

    /**
     * Records the common prefix a key rolls up into, answering whether it
     * did -- in which case the key itself is not listed.
     */
    private static boolean collectCommonPrefix(String key, String prefix,
            @Nullable String delimiter, Set<String> commonPrefixes) {
        if (delimiter == null || delimiter.isEmpty()) {
            return false;
        }
        int index = key.indexOf(delimiter, prefix.length());
        if (index == -1) {
            return false;
        }
        commonPrefixes.add(key.substring(0, index + delimiter.length()));
        return true;
    }

    /** Every current object under a prefix, following the listing's pages. */
    private List<S3Object> listAll(String container, String prefix) {
        var objects = new ArrayList<S3Object>();
        var options = ListObjectsV2Request.builder()
                .bucket(container)
                .prefix(prefix.isEmpty() ? null : prefix)
                .build();
        while (true) {
            var page = list(options, /*includeMultipart=*/ false);
            objects.addAll(page.contents());
            var token = page.nextContinuationToken();
            if (token == null) {
                break;
            }
            options = options.toBuilder().continuationToken(token).build();
        }
        return objects;
    }

    /** The size and ETag a non-current version reports to a listing. */
    @Nullable
    private HeadObjectResponse readVersionMetadata(String container,
            String key, StoredVersion version) {
        var blob = getBlobInternal(container, key,
                GetObjectRequest.builder().bucket(container).key(key)
                        .versionId(version.versionId()).build(),
                /*openStream=*/ false);
        if (blob == null) {
            return null;
        }
        return SdkResponses.toHead(SdkResponses.toGetResponse(
                blob.getMetadata(), /*contentRange=*/ null));
    }

    @Override
    public final boolean deleteContainerIfEmpty(String container) {
        var containerPath = resolveContainer(container);
        try {
            // Versions and delete markers keep a bucket alive, as on S3 --
            // they are the directory's remaining entries.  The directory
            // itself, once emptied of them, is bookkeeping and not a reason
            // to refuse.
            try {
                Files.deleteIfExists(versionsDir(containerPath));
            } catch (DirectoryNotEmptyException dnee) {
                return false;
            }
            Files.deleteIfExists(containerPath);
        } catch (DirectoryNotEmptyException dnee) {
            return false;
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
        return true;
    }

    /**
     * Delete the container and everything under it, s3proxy's own bookkeeping
     * included.  The default implementation clears what list() reports and
     * then removes the directory, but list() hides the multipart parts and
     * stubs and the "/" key sentinel, so a container left holding only those
     * -- an upload that was never completed or aborted -- was never emptied,
     * and the directory silently survived because the caller cannot see the
     * deleteContainerIfEmpty that failed.
     */
    @Override
    public final void deleteContainer(String container) {
        var path = resolveContainer(container);
        if (!Files.isDirectory(path)) {
            return;
        }
        try {
            deleteRecursively(path);
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }

    /**
     * Deletes depth-first, so a directory is emptied before it is removed,
     * tolerating entries that vanish concurrently -- Files.walk fails its
     * whole traversal when a visited entry disappears before it is statted,
     * where skipping it is exactly what deletion wants.
     */
    private static void deleteRecursively(Path path) throws IOException {
        if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
            try (var stream = openDirectoryStreamIfPresent(path)) {
                if (stream != null) {
                    try {
                        for (var child : stream) {
                            deleteRecursively(child);
                        }
                    } catch (DirectoryIteratorException die) {
                        // The directory vanished mid-iteration: its
                        // remaining entries went with it.
                        var cause = requireNonNull(die.getCause());
                        if (!vanished(cause, path)) {
                            throw cause;
                        }
                    }
                }
            }
        }
        try {
            Files.deleteIfExists(path);
        } catch (IOException ioe) {
            if (!vanished(ioe, path)) {
                throw ioe;
            }
        }
    }

    @Override
    public final BucketCannedACL getContainerAccess(String container) {
        var path = requireContainerPath(container);
        Set<PosixFilePermission> permissions;
        try {
            permissions = Files.getPosixFilePermissions(path);
        } catch (UnsupportedOperationException uoe) {
            // Windows/SMB/other non-POSIX: default to PRIVATE
            return BucketCannedACL.PRIVATE;
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
        if (permissions.contains(PosixFilePermission.OTHERS_READ) &&
                permissions.contains(PosixFilePermission.OTHERS_WRITE)) {
            return BucketCannedACL.PUBLIC_READ_WRITE;
        }
        return permissions.contains(PosixFilePermission.OTHERS_READ) ?
                BucketCannedACL.PUBLIC_READ : BucketCannedACL.PRIVATE;
    }

    @Override
    public final void setContainerAccess(String container, BucketCannedACL access) {
        var path = requireContainerPath(container);
        Set<PosixFilePermission> permissions;
        try {
            permissions = new HashSet<>(Files.getPosixFilePermissions(path));
            if (access == BucketCannedACL.PUBLIC_READ_WRITE) {
                permissions.add(PosixFilePermission.OTHERS_READ);
                permissions.add(PosixFilePermission.OTHERS_WRITE);
            } else if (access == BucketCannedACL.PUBLIC_READ) {
                permissions.add(PosixFilePermission.OTHERS_READ);
                permissions.remove(PosixFilePermission.OTHERS_WRITE);
            } else {
                permissions.remove(PosixFilePermission.OTHERS_READ);
                permissions.remove(PosixFilePermission.OTHERS_WRITE);
            }
            Files.setPosixFilePermissions(path, permissions);
        } catch (UnsupportedOperationException uoe) {
            // Windows/SMB/other non-POSIX: ignore, cannot set permissions
            return;
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }

    @Override
    public final ObjectCannedACL getBlobAccess(String container, String key) {
        return getBlobAccess(container, key, /*versionId=*/ null);
    }

    @Override
    public final ObjectCannedACL getBlobAccess(String container, String key,
            @Nullable String versionId) {
        var containerPath = requireContainerPath(container);
        var path = aclPath(container, containerPath, key, versionId);

        Set<PosixFilePermission> permissions;
        try {
            permissions = Files.getPosixFilePermissions(path);
        } catch (UnsupportedOperationException uoe) {
            // Windows/SMB/other non-POSIX: default to PRIVATE
            return ObjectCannedACL.PRIVATE;
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
        return permissions.contains(PosixFilePermission.OTHERS_READ) ?
                ObjectCannedACL.PUBLIC_READ : ObjectCannedACL.PRIVATE;
    }

    @Override
    public final void setBlobAccess(String container, String key, ObjectCannedACL access) {
        setBlobAccess(container, key, access, /*versionId=*/ null);
    }

    @Override
    public final void setBlobAccess(String container, String key,
            ObjectCannedACL access, @Nullable String versionId) {
        checkNotReserved(key);
        var containerPath = requireContainerPath(container);
        setBlobAccessHelper(
                aclPath(container, containerPath, key, versionId), access);
    }

    /**
     * The file an ACL request applies to: the version named, or the current
     * one.  A key with no current object has no access to read or set, which
     * is a missing key as far as the caller is concerned -- and where the
     * current version is a delete marker, resolveVersion says so in the
     * terms S3 uses rather than letting it read as an ordinary absence.
     */
    private Path aclPath(String container, Path containerPath, String key,
            @Nullable String versionId) {
        var path = resolveBlobPath(containerPath, key);
        if (!supportsVersioning() ||
                readContainerStatus(containerPath) == null) {
            if (versionId != null) {
                throw new UnsupportedOperationException(
                        "versioning not supported");
            }
            if (!blobExists(container, key)) {
                throw S3Exceptions.noSuchKey(container, key, "");
            }
            return path;
        }
        var resolved = resolveVersion(container, containerPath, path, key,
                versionId);
        if (resolved == null) {
            throw S3Exceptions.noSuchKey(container, key, "");
        }
        return resolved.path();
    }

    /**
     * Name of the hidden blob storing one uploaded part's content.  Exposed
     * so S3ProxyHandler can read part content back, e.g. to compute the
     * composite checksum during CompleteMultipartUpload.
     */
    public static String multipartPartName(String uploadId, String blobName,
            int partNumber) {
        return MULTIPART_PREFIX + uploadId + "-" + blobName + "-" +
                partNumber;
    }

    @Override
    public final MultipartUpload initiateMultipartUpload(
            CreateMultipartUploadRequest request) {
        // Completing this upload writes an object under the requested key,
        // which is the same write putBlob refuses above.
        checkNotReserved(request.key());
        var uploadId = UUID.randomUUID().toString();
        // The carriers built for this upload's later requests name only the
        // bucket and key, so the encryption it was created under has to
        // outlive the create; the stub is where the upload keeps it.
        var encryption = requestEncryption(request.bucket(),
                request.serverSideEncryptionAsString(), request.ssekmsKeyId(),
                request.ssekmsEncryptionContext(), request.bucketKeyEnabled(),
                request.sseCustomerAlgorithm(), request.sseCustomerKey(),
                request.sseCustomerKeyMD5());
        // create a stub blob
        var blob = Blob.builder(MULTIPART_PREFIX + uploadId + "-" + request.key() + "-stub").payload(ByteSource.empty()).encryption(encryption).build();
        putBlob(request.bucket(), blob, ObjectCannedACL.PRIVATE,
                /*ifNoneMatch=*/ null, /*parts=*/ null);
        return new MultipartUpload(uploadId, request,
                encryption == null ? null :
                        CreateMultipartUploadResponse.builder()
                                .bucket(request.bucket())
                                .key(request.key())
                                .uploadId(uploadId)
                                .serverSideEncryption(encryption.algorithm())
                                .ssekmsKeyId(encryption.kmsKeyId())
                                .ssekmsEncryptionContext(
                                        encryption.kmsContext())
                                .bucketKeyEnabled(encryption.bucketKeyEnabled())
                                .sseCustomerAlgorithm(
                                        encryption.customerAlgorithm())
                                .sseCustomerKeyMD5(
                                        encryption.customerKeyMD5())
                                .build());
    }

    /** The encryption an upload was created under, kept on its stub. */
    @Nullable
    private Encryption uploadEncryption(MultipartUpload mpu) {
        if (!supportsServerSideEncryption()) {
            return null;
        }
        // The domain metadata rather than a HEAD response, which has no
        // field for the KMS context the upload may have named.
        String stubName = MULTIPART_PREFIX + mpu.id() + "-" +
                mpu.blobName() + "-stub";
        var stub = getBlobInternal(mpu.containerName(), stubName,
                GetObjectRequest.builder()
                        .bucket(mpu.containerName())
                        .key(stubName)
                        .build(),
                /*openStream=*/ false);
        return stub == null ? Encryption.forRequest(null, null, null, null) :
                stub.getMetadata().encryption();
    }

    @Override
    public final void abortMultipartUpload(MultipartUpload mpu) {
        var parts = listMultipartUpload(mpu);
        for (var part : parts) {
            removeBlobInternal(mpu.containerName(), multipartPartName(mpu.id(), mpu.blobName(), part.partNumber()));
        }
        removeBlobInternal(mpu.containerName(), MULTIPART_PREFIX + mpu.id() + "-" + mpu.blobName() + "-stub");
    }

    @Override
    public final CompleteMultipartUploadResponse completeMultipartUpload(
            MultipartUpload mpu, CompleteMultipartUploadRequest request) {
        List<CompletedPart> parts = request.multipartUpload() == null ?
                List.of() : request.multipartUpload().parts();
        var partNames = ImmutableList.<String>builder();
        long contentLength = 0;
        var md5Hasher = MD5.newDigest();

        for (var part : parts) {
            var partName = multipartPartName(mpu.id(), mpu.blobName(),
                    part.partNumber());
            var meta = blobMetadata(mpu.containerName(), partName);
            if (meta == null) {
                // S3 returns InvalidPart (400) when the manifest references
                // a part that was never uploaded.
                throw returnResponseException(400);
            }
            contentLength += requireNonNull(meta.contentLength());
            partNames.add(partName);
            if (meta.eTag() != null) {
                var eTag = meta.eTag();
                if (eTag.startsWith("\"") && eTag.endsWith("\"") &&
                       eTag.length() >= 2) {
                    eTag = eTag.substring(1, eTag.length() - 1);
                }
                md5Hasher.update(HexFormat.of().parseHex(eTag));
            }
        }
        var mpuETag = "\"" + HexFormat.of().formatHex(md5Hasher.digest()) +
                "-" + parts.size() + "\"";
        var blobBuilder = Blob.builder(mpu.blobName())
                .payload(new MultiBlobInputStream(this, mpu.containerName(),
                        partNames.build()))
                .contentLength(contentLength)
                .eTag(mpuETag);
        var mpuRequest = mpu.request();
        blobBuilder.userMetadata(mpuRequest.metadata());
        var cacheControl = mpuRequest.cacheControl();
        if (cacheControl != null) {
            blobBuilder.cacheControl(cacheControl);
        }
        var contentDisposition = mpuRequest.contentDisposition();
        if (contentDisposition != null) {
            blobBuilder.contentDisposition(contentDisposition);
        }
        var contentEncoding = mpuRequest.contentEncoding();
        if (contentEncoding != null) {
            blobBuilder.contentEncoding(contentEncoding);
        }
        var contentLanguage = mpuRequest.contentLanguage();
        if (contentLanguage != null) {
            blobBuilder.contentLanguage(contentLanguage);
        }
        // intentionally not copying MD5
        var contentType = mpuRequest.contentType();
        if (contentType != null) {
            blobBuilder.contentType(contentType);
        }
        var expires = mpuRequest.expires();
        if (expires != null) {
            blobBuilder.expires(expires);
        }
        var storageClass = mpuRequest.storageClass();
        if (storageClass != null) {
            blobBuilder.storageClass(storageClass);
        }
        // The assembled object rests under what the upload was created
        // under, which the stub has carried since; this request's carrier
        // names only the bucket and key.  The completion must present the
        // create-time customer key again, as every part did.
        var encryption = uploadEncryption(mpu);
        enforceUploadCustomerKey(encryption, request.sseCustomerAlgorithm(),
                request.sseCustomerKey(), request.sseCustomerKeyMD5());
        blobBuilder.encryption(encryption);

        // Publishing the assembled object is the write the condition applies
        // to, so hand it to putBlob rather than checking it beforehand.  A
        // refused completion throws from here, leaving the parts in place for
        // the client to retry or abort.  Only If-None-Match: the caller
        // resolves If-Match, which needs a compare-and-swap this store has
        // no way to perform.

        // Name the part files so the assembly is a kernel copy rather than a
        // read of every byte back through this process.  The payload built
        // above stays on the blob as the fallback for a store whose parts are
        // not files of its own.
        var containerPath = requireContainerPath(mpu.containerName());
        var partPaths = ImmutableList.<Path>builder();
        for (var part : parts) {
            partPaths.add(resolveBlobPath(containerPath, multipartPartName(
                    mpu.id(), mpu.blobName(), part.partNumber())));
        }
        var result = putBlob(mpu.containerName(), blobBuilder.build(),
                ObjectCannedACL.PRIVATE, request.ifNoneMatch(),
                partPaths.build());

        // Remove every uploaded part, not just the ones referenced by the
        // manifest, so parts excluded from the final object do not leak.
        for (var part : listMultipartUpload(mpu)) {
            removeBlobInternal(mpu.containerName(), multipartPartName(mpu.id(), mpu.blobName(), part.partNumber()));
        }
        removeBlobInternal(mpu.containerName(), MULTIPART_PREFIX + mpu.id() + "-" + mpu.blobName() + "-stub");

        setBlobAccess(mpu.containerName(), mpu.blobName(),
                SdkRequests.aclOrPrivate(mpuRequest.acl()));

        return CompleteMultipartUploadResponse.builder()
                .eTag(mpuETag)
                .versionId(result.reportedVersionId())
                .serverSideEncryption(encryption == null ? null :
                        encryption.algorithm())
                .ssekmsKeyId(encryption == null ? null : encryption.kmsKeyId())
                .bucketKeyEnabled(encryption == null ? null :
                        encryption.bucketKeyEnabled())
                .build();
    }

    @Override
    public final UploadPartResponse uploadMultipartPart(MultipartUpload mpu, UploadPartRequest request, InputStream is) {
        // Judge the part's key against the upload's before taking the
        // bytes, the way the create-time request was judged.
        var encryption = uploadEncryption(mpu);
        enforceUploadCustomerKey(encryption, request.sseCustomerAlgorithm(),
                request.sseCustomerKey(), request.sseCustomerKeyMD5());
        var partName = multipartPartName(mpu.id(), mpu.blobName(), request.partNumber());
        var blob = Blob.builder(partName)
                .payload(is)
                .contentLength(requireNonNull(request.contentLength()))
                .contentMD5(SdkRequests.contentMD5(request))
                .build();
        var partETag = putBlob(mpu.containerName(), blob,
                ObjectCannedACL.PRIVATE, /*ifNoneMatch=*/ null, /*parts=*/ null)
                .eTag();
        if (encryption == null) {
            return SdkResponses.uploadedPart(partETag);
        }
        return UploadPartResponse.builder()
                .eTag(partETag)
                .serverSideEncryption(encryption.algorithm())
                .ssekmsKeyId(encryption.kmsKeyId())
                .bucketKeyEnabled(encryption.bucketKeyEnabled())
                .sseCustomerAlgorithm(encryption.customerAlgorithm())
                .sseCustomerKeyMD5(encryption.customerKeyMD5())
                .build();
    }

    @Override
    public final List<Part> listMultipartUpload(MultipartUpload mpu) {
        var parts = ImmutableList.<Part>builder();
        var partPrefix = MULTIPART_PREFIX + mpu.id() + "-" + mpu.blobName() + "-";
        var options = ListObjectsV2Request.builder()
                .bucket(mpu.containerName())
                .prefix(partPrefix).build();
        while (true) {
            var pageSet = list(options, /*includeMultipart=*/ true);
            for (var sm : pageSet.contents()) {
                if (sm.key().endsWith("-stub")) {
                    continue;
                }
                int partNumber;
                try {
                    partNumber = Integer.parseInt(sm.key().substring(partPrefix.length()));
                } catch (NumberFormatException nfe) {
                    logger.warn("ignoring multipart entry with non-numeric suffix: {}", sm.key());
                    continue;
                }
                long partSize = requireNonNull(sm.size());
                parts.add(SdkResponses.part(partNumber, partSize,
                        sm.eTag(), sm.lastModified()));
            }
            if (pageSet.contents().isEmpty() ||
                    pageSet.nextContinuationToken() == null) {
                break;
            }
            options = options.toBuilder()
                    .continuationToken(pageSet.nextContinuationToken())
                    .build();
        }
        return parts.build();
    }

    @Override
    public final List<software.amazon.awssdk.services.s3.model.MultipartUpload>
            listMultipartUploads(String container) {
        var mpus = ImmutableList.<software.amazon.awssdk.services.s3
                .model.MultipartUpload>builder();
        var options = ListObjectsV2Request.builder()
                .bucket(container)
                .prefix(MULTIPART_PREFIX).build();
        while (true) {
            var pageSet = list(options, /*includeMultipart=*/ true);
            for (S3Object sm : pageSet.contents()) {
                if (!sm.key().endsWith("-stub")) {
                    continue;
                }
                // A name this store did not write -- one left in the
                // container by hand, or by a client back when the namespace
                // was writable -- must not decide whether the bucket's real
                // uploads can be listed at all, which is what letting the
                // arithmetic below run off the end of it did.
                if (sm.key().length() <=
                        MULTIPART_PREFIX.length() + UUID_STRING_LENGTH) {
                    logger.warn("ignoring multipart stub too short to name an" +
                            " upload: {}", sm.key());
                    continue;
                }
                var uploadId = sm.key().substring(MULTIPART_PREFIX.length(), MULTIPART_PREFIX.length() + UUID_STRING_LENGTH);
                var blobName = sm.key().substring(MULTIPART_PREFIX.length() + UUID_STRING_LENGTH + 1);
                int index = blobName.lastIndexOf('-');
                if (index < 0) {
                    logger.warn("ignoring multipart stub without a blob name:" +
                            " {}", sm.key());
                    continue;
                }
                blobName = blobName.substring(0, index);

                mpus.add(SdkResponses.upload(blobName, uploadId));
            }
            if (pageSet.contents().isEmpty() ||
                    pageSet.nextContinuationToken() == null) {
                break;
            }
            options = options.toBuilder()
                    .continuationToken(pageSet.nextContinuationToken())
                    .build();
        }

        return mpus.build();
    }

    @Override
    public final long getMinimumMultipartPartSize() {
        return 1;
    }

   /**
    * Read the String representation of a filesystem attribute, or return null
    * if not present.
    */
    @Nullable
    private static String readStringAttributeIfPresent(
            UserDefinedFileAttributeView view, Set<String> attr, String name)
            throws IOException {
        if (!attr.contains(name)) {
            return null;
        }
        ByteBuffer buf = ByteBuffer.allocate(view.size(name));
        view.read(name, buf);
        return new String(buf.array(), StandardCharsets.UTF_8);
    }

    /**
     * Reads the stored ETag for an object from its XATTR_CONTENT_MD5 xattr, or
     * null when the object carries no such xattr (e.g. an implicit directory).
     * A 16-byte value is the MD5 of a single-part object; anything else is a
     * multipart ETag stored verbatim.
     */
    @Nullable
    private static String readETagXattr(XattrState xattrs) throws IOException {
        var view = xattrs.view();
        if (view == null || !xattrs.attributes().contains(XATTR_CONTENT_MD5)) {
            return null;
        }
        var buf = ByteBuffer.allocate(view.size(XATTR_CONTENT_MD5));
        view.read(XATTR_CONTENT_MD5, buf);
        var etagBytes = buf.array();
        if (etagBytes.length == 16) {
            // regular object
            return HashCode.fromBytes(etagBytes).toString();
        }
        // multi-part object
        return new String(etagBytes, StandardCharsets.US_ASCII);
    }

    /**
     * Parses a storage-class name previously written to {@link
     * #XATTR_STORAGE_TIER}, tolerating values that are not valid {@link
     * StorageClass} constants -- such as the jclouds {@code Tier} names
     * {@code INFREQUENT} and {@code ARCHIVE} written by older S3Proxy
     * versions -- by falling back to {@link StorageClass#STANDARD}.
     */
    private static StorageClass parseStorageClass(String value) {
        try {
            return StorageClass.valueOf(value);
        } catch (IllegalArgumentException iae) {
            logger.debug("ignoring unrecognized {} value: {}",
                    XATTR_STORAGE_TIER, value);
            return StorageClass.STANDARD;
        }
    }

    /** Write the String representation of a filesystem attribute. */
    private static void writeStringAttributeIfPresent(
            UserDefinedFileAttributeView view, String name,
            @Nullable String value)
            throws IOException {
        if (value != null) {
            view.write(name, ByteBuffer.wrap(value.getBytes(StandardCharsets.UTF_8)));
        }
    }

    /**
     * Writes the attribute, or removes any existing one when the value is
     * null -- for fields where an absent value must not leave the old one
     * behind.
     */
    private static void writeOrDeleteAttribute(
            UserDefinedFileAttributeView view, String name,
            @Nullable String value) throws IOException {
        if (value != null) {
            writeStringAttributeIfPresent(view, name, value);
        } else if (view.list().contains(name)) {
            view.delete(name);
        }
    }

    private static final class MultiBlobInputStream extends InputStream {
        private final BlobStore blobStore;
        private final String container;
        private final Iterator<String> metas;
        @Nullable private InputStream current;

        MultiBlobInputStream(BlobStore blobStore, String container,
                List<String> metas) {
            this.blobStore = blobStore;
            this.container = container;
            this.metas = metas.iterator();
        }

        @Override
        public int read() throws IOException {
            while (true) {
                if (current == null) {
                    if (!metas.hasNext()) {
                        return -1;
                    }
                    current = openPartStream(metas.next());
                }
                int result = current.read();
                if (result == -1) {
                    current.close();
                    current = null;
                    continue;
                }
                return result & 0x000000FF;
            }
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            // Per InputStream's contract, return 0 for a zero-length read
            // regardless of whether EOF has been reached.
            if (len == 0) {
                return 0;
            }
            while (true) {
                if (current == null) {
                    if (!metas.hasNext()) {
                        return -1;
                    }
                    current = openPartStream(metas.next());
                }
                int result = current.read(b, off, len);
                if (result == -1) {
                    current.close();
                    current = null;
                    continue;
                }
                return result;
            }
        }

        private InputStream openPartStream(String name) throws IOException {
            var blob = blobStore.getBlob(container, name);
            if (blob == null) {
                throw new IOException("Part disappeared: " +
                        container + "/" + name);
            }
            return blob;
        }

        @Override
        public void close() throws IOException {
            if (current != null) {
                current.close();
                current = null;
            }
        }
    }

    private static S3Exception returnResponseException(int code) {
        return S3Exceptions.fromStatusCode(code);
    }

    // A failed conditional read: 304 or 412 carrying the ETag the response
    // must echo per RFC 7232.
    private static S3Exception conditionFailed(int code,
            @Nullable String eTag) {
        return S3Exceptions.fromStatusCode(code, eTag, Map.of(),
                /*cause=*/ null);
    }

    private static String maybeQuoteETag(String eTag) {
        if (!eTag.startsWith("\"") && !eTag.endsWith("\"")) {
            eTag = "\"" + eTag + "\"";
        }
        return eTag;
    }

    /**
     * AbstractNio2BlobStore implicitly creates directories when creating a key /a/b/c.
     * When removing /a/b/c, it must clean up /a and /a/b, unless a client explicitly created a subdirectory which has file attributes.
     */
    private static void removeEmptyParentDirectories(Path containerPath, @Nullable Path path) throws IOException {
        logger.debug("removing empty parents: {}", path);
        while (path != null && !path.equals(containerPath)) {
            if (safeGetXattrs(path).attributes().contains(XATTR_CONTENT_MD5)) {
                break;
            }
            try {
                logger.debug("deleting: {}", path);
                Files.deleteIfExists(path);
            } catch (DirectoryNotEmptyException dnee) {
                break;
            } catch (IOException ioe) {
                // Another delete's cleanup already removed this parent.
                if (!vanished(ioe, path)) {
                    throw ioe;
                }
            }
            path = path.getParent();
        }
    }

    /**
     * What a write request's encryption fields come to rest as, or null
     * where this store does not encrypt -- there the frontend has refused
     * anything naming them, so the request carries none to record.  A
     * request naming a customer key is vetted here, since this store is
     * the backend that judges it.  A request naming nothing at all rests
     * under the container's default configuration when one has been put,
     * the way S3 applies bucket default encryption.
     */
    @Nullable
    private Encryption requestEncryption(String container,
            @Nullable String algorithm,
            @Nullable String kmsKeyId, @Nullable String kmsContext,
            @Nullable Boolean bucketKeyEnabled,
            @Nullable String customerAlgorithm, @Nullable String customerKey,
            @Nullable String customerKeyMD5) {
        if (!supportsServerSideEncryption()) {
            return null;
        }
        if (supportsBucketEncryption() && algorithm == null &&
                kmsKeyId == null && kmsContext == null &&
                bucketKeyEnabled == null && customerAlgorithm == null &&
                customerKey == null && customerKeyMD5 == null) {
            var containerDefault = readContainerEncryption(
                    requireContainerPath(container));
            if (containerDefault != null) {
                return containerDefault;
            }
        }
        if (customerAlgorithm != null || customerKey != null ||
                customerKeyMD5 != null) {
            if (algorithm != null) {
                throw S3Exceptions.invalidArgument("Server side encryption" +
                        " specified with both SSE-C and SSE-S3 headers.");
            }
            return CustomerKeys.vet(customerAlgorithm, customerKey,
                    customerKeyMD5);
        }
        // Judge the SSE-S3/KMS fields against each other the way S3 does:
        // a KMS key makes sense only under aws:kms, and aws:kms names a
        // key or nothing at all.
        if (Encryption.KMS_ALGORITHM.equals(algorithm)) {
            if (kmsKeyId == null) {
                throw S3Exceptions.invalidArgument("Server side encryption" +
                        " with aws:kms requires" +
                        " x-amz-server-side-encryption-aws-kms-key-id.");
            }
        } else {
            if (algorithm != null &&
                    !Encryption.DEFAULT_ALGORITHM.equals(algorithm)) {
                throw S3Exceptions.invalidArgument("The encryption" +
                        " algorithm specified is not valid.");
            }
            if (kmsKeyId != null || kmsContext != null) {
                throw S3Exceptions.invalidArgument("A KMS key or context" +
                        " requires x-amz-server-side-encryption: aws:kms.");
            }
        }
        return Encryption.forRequest(algorithm, kmsKeyId, kmsContext,
                bucketKeyEnabled);
    }

    /**
     * Judges an upload's later requests -- each part, and the completion
     * -- against the key the upload was created under.  S3 requires the
     * create-time key presented again on every one and answers 400 to
     * anything else.
     */
    private static void enforceUploadCustomerKey(
            @Nullable Encryption uploadEncryption,
            @Nullable String customerAlgorithm, @Nullable String customerKey,
            @Nullable String customerKeyMD5) {
        String storedKeyMD5 = uploadEncryption == null ? null :
                uploadEncryption.customerKeyMD5();
        if (storedKeyMD5 == null) {
            if (customerAlgorithm != null || customerKey != null ||
                    customerKeyMD5 != null) {
                throw S3Exceptions.invalidRequest("The encryption" +
                        " parameters are not applicable to this upload.");
            }
            return;
        }
        if (customerAlgorithm == null && customerKey == null &&
                customerKeyMD5 == null) {
            throw S3Exceptions.invalidRequest("The multipart upload was" +
                    " created using a form of Server Side Encryption.  The" +
                    " correct parameters must be provided.");
        }
        var presented = CustomerKeys.vet(customerAlgorithm, customerKey,
                customerKeyMD5);
        if (!CustomerKeys.matches(storedKeyMD5,
                presented.customerKeyMD5())) {
            throw S3Exceptions.invalidArgument("The provided customer key" +
                    " does not match the key the multipart upload was" +
                    " created with.");
        }
    }

    /**
     * The encryption an object rests under, or null where the store does not
     * encrypt -- there the frontend has already refused every request naming
     * any of it, so reporting one would answer a question nobody asked.  An
     * object written without an algorithm attribute rests under the default,
     * the way S3 encrypts what nobody asked it to.
     */
    @Nullable
    private Encryption readEncryption(
            @Nullable UserDefinedFileAttributeView view,
            Set<String> attributes) throws IOException {
        if (!supportsServerSideEncryption()) {
            return null;
        }
        if (view == null) {
            return Encryption.forRequest(null, null, null, null);
        }
        var customerKeyMD5 = readStringAttributeIfPresent(view, attributes,
                XATTR_SSE_C_KEY_MD5);
        if (customerKeyMD5 != null) {
            var customerAlgorithm = readStringAttributeIfPresent(view,
                    attributes, XATTR_SSE_C_ALGORITHM);
            return Encryption.forCustomerKey(customerAlgorithm == null ?
                    Encryption.DEFAULT_ALGORITHM : customerAlgorithm,
                    customerKeyMD5);
        }
        var bucketKey = readStringAttributeIfPresent(view, attributes,
                XATTR_SSE_BUCKET_KEY);
        var algorithm = readStringAttributeIfPresent(view, attributes,
                XATTR_SSE_ALGORITHM);
        return new Encryption(
                algorithm == null ? Encryption.DEFAULT_ALGORITHM : algorithm,
                readStringAttributeIfPresent(view, attributes,
                        XATTR_SSE_KMS_KEY_ID),
                readStringAttributeIfPresent(view, attributes,
                        XATTR_SSE_KMS_CONTEXT),
                bucketKey == null ? null : Boolean.valueOf(bucketKey),
                /*customerAlgorithm=*/ null, /*customerKeyMD5=*/ null);
    }

    /**
     * Records an object's encryption, writing nothing for the default that
     * an absent algorithm already reads back as.
     */
    private static void writeEncryptionAttr(
            UserDefinedFileAttributeView view, Blob blob) throws IOException {
        var encryption = blob.getMetadata().encryption();
        if (encryption == null || encryption.isDefault()) {
            return;
        }
        writeStringAttributeIfPresent(view, XATTR_SSE_ALGORITHM,
                encryption.algorithm());
        writeStringAttributeIfPresent(view, XATTR_SSE_KMS_KEY_ID,
                encryption.kmsKeyId());
        writeStringAttributeIfPresent(view, XATTR_SSE_KMS_CONTEXT,
                encryption.kmsContext());
        writeStringAttributeIfPresent(view, XATTR_SSE_BUCKET_KEY,
                encryption.bucketKeyEnabled() == null ? null :
                        encryption.bucketKeyEnabled().toString());
        writeStringAttributeIfPresent(view, XATTR_SSE_C_ALGORITHM,
                encryption.customerAlgorithm());
        writeStringAttributeIfPresent(view, XATTR_SSE_C_KEY_MD5,
                encryption.customerKeyMD5());
    }

    // TODO: call in other places
    private static void writeCommonMetadataAttr(UserDefinedFileAttributeView view, Blob blob) throws IOException {
        var metadata = blob.getMetadata().contentMetadata();
        writeStringAttributeIfPresent(view, XATTR_CACHE_CONTROL, metadata.cacheControl());
        writeStringAttributeIfPresent(view, XATTR_CONTENT_DISPOSITION, metadata.contentDisposition());
        writeStringAttributeIfPresent(view, XATTR_CONTENT_ENCODING, metadata.contentEncoding());
        writeStringAttributeIfPresent(view, XATTR_CONTENT_LANGUAGE, metadata.contentLanguage());
        writeStringAttributeIfPresent(view, XATTR_CONTENT_TYPE, metadata.contentType());
        var expires = metadata.expires();
        if (expires != null) {
            var buf = ByteBuffer.allocate(Longs.BYTES).putLong(expires.toEpochMilli());
            buf.flip();
            view.write(XATTR_EXPIRES, buf);
        }
        writeStringAttributeIfPresent(view, XATTR_STORAGE_TIER, blob.getMetadata().storageClass().toString());
        for (var entry : blob.getMetadata().userMetadata().entrySet()) {
            writeStringAttributeIfPresent(view, XATTR_USER_METADATA_PREFIX + entry.getKey(), entry.getValue());
        }
        writeEncryptionAttr(view, blob);
    }

    private record XattrState(@Nullable UserDefinedFileAttributeView view,
            Set<String> attributes) {
        static final XattrState EMPTY = new XattrState(null, NO_ATTRIBUTES);
    }

    /**
     * Whether an I/O failure on path means it was concurrently removed.
     * SFTP sometimes reports a vanished entry as a generic error rather
     * than NoSuchFileException, so settle it with a second look.
     */
    private static boolean vanished(IOException ioe, Path path) {
        return ioe instanceof NoSuchFileException || Files.notExists(path);
    }

    /**
     * Opens a directory stream, or returns null when the directory was
     * concurrently removed or replaced by a file.
     */
    // Both callers take the returned stream into a try-with-resources, which
    // the check cannot see from the factory method that hands it over.
    @Nullable
    @SuppressWarnings("StreamResourceLeak")
    private static DirectoryStream<Path> openDirectoryStreamIfPresent(
            Path path) throws IOException {
        try {
            return Files.newDirectoryStream(path);
        } catch (NoSuchFileException | NotDirectoryException e) {
            return null;
        } catch (IOException ioe) {
            if (Files.notExists(path)) {
                return null;
            }
            throw ioe;
        }
    }

    /**
     * Safely read extended attributes for a path. Returns a view and attribute
     * set, or EMPTY if the filesystem does not support extended attributes
     * (e.g., Docker Desktop bind mounts via VirtioFS, some NFS/NAS mounts).
     */
    private static XattrState safeGetXattrs(Path path) {
        var view = getXattrView(path);
        if (view == null) {
            return XattrState.EMPTY;
        }
        try {
            return new XattrState(view, Set.copyOf(view.list()));
        } catch (IOException | UnsupportedOperationException e) {
            logger.debug("xattrs not supported on {}", path);
            return XattrState.EMPTY;
        }
    }

    private static String relativeName(Path containerPath, Path path) {
        var sep = path.getFileSystem().getSeparator();
        var name = containerPath.relativize(path).toString();
        return sep.equals("/") ? name : name.replace(sep, "/");
    }

    @Nullable
    private static UserDefinedFileAttributeView getXattrView(Path path) {
        try {
            return Files.getFileAttributeView(path,
                    UserDefinedFileAttributeView.class);
        } catch (UnsupportedOperationException uoe) {
            logger.debug("xattrs not supported on {}", path);
            return null;
        }
    }

    private static void checkValidPath(Path container, Path path) {
        if (!path.normalize().startsWith(container)) {
            throw new IllegalArgumentException("Path traversal attempt detected: " + container + " " + path);
        }
    }

    /**
     * Joins part files into one, asking the kernel to do the copying.
     * FileChannel.transferTo is copy_file_range on Linux, which btrfs and XFS
     * serve by sharing extents when the destination offset is block aligned --
     * every part but the last is, at the part sizes clients actually use -- and
     * which NFS and SMB can serve on the server rather than over the wire.
     * Where none of that holds the kernel still copies without the bytes
     * crossing into this process.
     */
    private static void concatenate(List<Path> parts, Path tmpPath)
            throws IOException {
        try (var dst = FileChannel.open(tmpPath, StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE)) {
            long position = 0;
            for (var part : parts) {
                try (var src = FileChannel.open(part, StandardOpenOption.READ)) {
                    long size = src.size();
                    long transferred = 0;
                    while (transferred < size) {
                        long count = src.transferTo(transferred,
                                size - transferred, dst);
                        if (count <= 0) {
                            // transferTo declines rather than fails on some
                            // filesystems; fall back for the remainder.
                            try (var is = Channels.newInputStream(
                                    src.position(transferred));
                                 var os = Channels.newOutputStream(dst)) {
                                is.transferTo(os);
                            }
                            transferred = size;
                            break;
                        }
                        transferred += count;
                    }
                    position += size;
                }
            }
            if (dst.size() != position) {
                throw new IOException("assembled " + dst.size() +
                        " bytes from parts totalling " + position);
            }
        }
    }

    /**
     * Resolve an S3 object key to its filesystem path within a container.
     *
     * <p>The key "/" is special: {@code containerPath.resolve("/")} yields the
     * absolute filesystem root, which {@link #checkValidPath} rejects. Real S3
     * treats "/" as a legitimate, distinct object, so it is redirected to a
     * reserved child ({@link #SLASH_BLOB_NAME}). Because "/" ends in a slash it
     * flows through the existing directory-marker code as an ordinary 0-byte
     * marker, but backed by its own inode -- so DELETE/PUT/ACL of "/" never
     * touch the container directory (which represents the bucket).
     *
     * <p>To keep that reserved namespace private, any other key that would
     * resolve to the slash blob or a descendant of it is rejected with 400.
     */
    private static Path resolveBlobPath(Path containerPath, String key) {
        var slashBlob = containerPath.resolve(SLASH_BLOB_NAME);
        Path path;
        if (key.equals("/")) {
            path = slashBlob;
        } else {
            path = containerPath.resolve(key).normalize();
            if (path.startsWith(slashBlob)) {
                throw returnResponseException(400);
            }
        }
        checkValidPath(containerPath, path);
        return path;
    }

    // Versioning.  The current version of a key is the ordinary file at its
    // natural path, carrying its version id in an xattr; every other version
    // and every delete marker is a file under VERSIONS_DIR named
    // "<hash of key>-<sequence>", carrying the key it belongs to in an xattr
    // of its own.  Keeping the current version where it always was is what
    // lets reads, listings, multipart assembly and the ACL paths stay
    // oblivious to versioning; the flat sidecar keeps a version file from
    // ever colliding with an object whose key happens to look like one.
    //
    // The invariant the rest of this relies on: when the natural path exists
    // it holds the newest version, and when it does not, either the key has
    // no versions at all or the newest one is a delete marker.

    @Nullable
    private BucketVersioningStatus readContainerStatus(Path containerPath) {
        var xattrs = safeGetXattrs(containerPath);
        var view = xattrs.view();
        if (view == null) {
            return null;
        }
        try {
            var value = readStringAttributeIfPresent(view, xattrs.attributes(),
                    XATTR_VERSIONING);
            return value == null ? null :
                    BucketVersioningStatus.fromValue(value);
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }

    /**
     * A fresh version id on an enabled container, or the "null" id every
     * write mints while versioning is off or suspended.
     */
    private static String mintVersionId(
            @Nullable BucketVersioningStatus status) {
        return status == BucketVersioningStatus.ENABLED ?
                "v%016d".formatted(VERSION_SEQUENCE.incrementAndGet()) :
                NULL_VERSION_ID;
    }

    private static Instant mintTime() {
        return Instant.ofEpochMilli(LAST_MILLIS.updateAndGet(
                last -> Math.max(last + 1, System.currentTimeMillis())));
    }

    private static Path versionsDir(Path containerPath) {
        return containerPath.resolve(VERSIONS_DIR);
    }

    /**
     * Groups a key's versions under one file-name prefix without letting the
     * key's own characters -- slashes above all -- shape the layout.
     */
    private static String keyHash(String key) {
        return Hashing.sha256().hashString(key, StandardCharsets.UTF_8)
                .toString().substring(0, 32);
    }

    /** One version of one key, held outside its natural path. */
    private record StoredVersion(Path path, String key, String versionId,
            boolean deleteMarker, Instant lastModified) {
    }

    /** Which file a read of a version resolves to, and the id it carries. */
    private record ResolvedVersion(Path path, String versionId) {
    }

    /**
     * The file a read names, or null when the key holds nothing to read.
     * Throws the way S3 answers a read whose current version is a delete
     * marker (404 naming the marker), one that names a delete marker
     * outright (405), and one that names a version that does not exist.
     */
    @Nullable
    private ResolvedVersion resolveVersion(String container,
            Path containerPath, Path path, String key,
            @Nullable String versionId) {
        if (versionId == null) {
            if (Files.exists(path)) {
                return new ResolvedVersion(path, currentVersionId(path));
            }
            var archived = archivedVersions(containerPath, key);
            if (!archived.isEmpty() && archived.get(0).deleteMarker()) {
                throw S3Exceptions.noSuchKeyDeleteMarker(container, key,
                        archived.get(0).versionId(),
                        "current version is a delete marker");
            }
            return null;
        }
        if (Files.exists(path) && currentVersionId(path).equals(versionId)) {
            return new ResolvedVersion(path, versionId);
        }
        for (var version : archivedVersions(containerPath, key)) {
            if (version.versionId().equals(versionId)) {
                if (version.deleteMarker()) {
                    // As on S3: a delete marker has no content to read, and
                    // saying so is not the same as saying the key is gone.
                    throw S3Exceptions.fromStatusCode(405, /*eTag=*/ null,
                            Map.of("x-amz-delete-marker", "true",
                                    "x-amz-version-id", version.versionId()),
                            /*cause=*/ null);
                }
                return new ResolvedVersion(version.path(), versionId);
            }
        }
        throw S3Exceptions.noSuchVersion(container, key, versionId,
                "no such version");
    }

    @Nullable
    private static String readVersionId(Path path) {
        var xattrs = safeGetXattrs(path);
        var view = xattrs.view();
        if (view == null) {
            return null;
        }
        try {
            return readStringAttributeIfPresent(view, xattrs.attributes(),
                    XATTR_VERSION_ID);
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }

    /** The version id of the object at its natural path. */
    private static String currentVersionId(Path path) {
        var versionId = readVersionId(path);
        return versionId == null ? NULL_VERSION_ID : versionId;
    }

    /**
     * The versions of {@code key} kept outside its natural path, newest
     * first.  A null key reads every key's, for listVersions.
     */
    private List<StoredVersion> archivedVersions(Path containerPath,
            @Nullable String key) {
        var dir = versionsDir(containerPath);
        var prefix = key == null ? null : keyHash(key) + "-";
        var versions = new ArrayList<StoredVersion>();
        try (var stream = openDirectoryStreamIfPresent(dir)) {
            if (stream == null) {
                return versions;
            }
            for (var path : stream) {
                var name = path.getFileName().toString();
                if (prefix != null && !name.startsWith(prefix)) {
                    continue;
                }
                var xattrs = safeGetXattrs(path);
                var view = xattrs.view();
                if (view == null) {
                    continue;
                }
                var versionKey = readStringAttributeIfPresent(view,
                        xattrs.attributes(), XATTR_VERSION_KEY);
                var versionId = readStringAttributeIfPresent(view,
                        xattrs.attributes(), XATTR_VERSION_ID);
                if (versionKey == null || versionId == null ||
                        (key != null && !versionKey.equals(key))) {
                    // Not one of ours, or one whose key the hash only
                    // appeared to match.
                    continue;
                }
                var attr = Files.readAttributes(path,
                        BasicFileAttributes.class);
                versions.add(new StoredVersion(path, versionKey, versionId,
                        xattrs.attributes().contains(XATTR_DELETE_MARKER),
                        Instant.ofEpochMilli(
                                attr.lastModifiedTime().toMillis())));
            }
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
        // The sequence in the name orders them; it is monotonic where the
        // version id and the timestamp are not.
        versions.sort(Comparator.comparing(
                (StoredVersion version) ->
                        version.path().getFileName().toString()).reversed());
        return versions;
    }

    /** Where the next version of {@code key} goes. */
    private static Path newVersionPath(Path containerPath, String key) {
        return versionsDir(containerPath).resolve("%s-%016d".formatted(
                keyHash(key), VERSION_SEQUENCE.incrementAndGet()));
    }

    private static void writeVersionAttributes(Path path, String key,
            String versionId, boolean deleteMarker) throws IOException {
        var view = getXattrView(path);
        if (view == null) {
            throw new IOException("versioning needs user attributes: " + path);
        }
        writeStringAttributeIfPresent(view, XATTR_VERSION_KEY, key);
        writeStringAttributeIfPresent(view, XATTR_VERSION_ID, versionId);
        if (deleteMarker) {
            writeStringAttributeIfPresent(view, XATTR_DELETE_MARKER, "true");
        }
    }

    /**
     * Makes room for a new version of {@code key}: the current version, if
     * any, becomes non-current.  A write minting the "null" id instead
     * replaces whatever null version the key has, since S3 keeps only one.
     */
    private void archiveCurrentVersion(Path containerPath, Path path,
            String key, String newVersionId) throws IOException {
        boolean mintingNull = NULL_VERSION_ID.equals(newVersionId);
        if (mintingNull) {
            for (var version : archivedVersions(containerPath, key)) {
                if (NULL_VERSION_ID.equals(version.versionId())) {
                    Files.deleteIfExists(version.path());
                }
            }
        }
        if (!Files.exists(path)) {
            return;
        }
        if (Files.isDirectory(path)) {
            // A directory-marker key's "file" is the directory the keys
            // below it live in, and moving it aside would take them with it.
            // Such a key is not versioned at all, which is also why putBlob
            // gives one no version id.
            return;
        }
        // Read before the move, which is what makes the file unreadable
        // under its old name.
        var currentId = currentVersionId(path);
        if (mintingNull && NULL_VERSION_ID.equals(currentId)) {
            // The write that follows replaces it where it lies.
            return;
        }
        var archived = newVersionPath(containerPath, key);
        Files.createDirectories(archived.getParent());
        Files.move(path, archived, StandardCopyOption.ATOMIC_MOVE);
        // A version written before its container was enabled carries no id
        // or key of its own, and could not be found again without them.
        writeVersionAttributes(archived, key, currentId,
                /*deleteMarker=*/ false);
    }

    /**
     * Restores the invariant after the current version is deleted: the
     * newest remaining version moves back to the natural path, unless it is
     * a delete marker, which is current precisely by that path's absence.
     */
    private void promoteNewestVersion(Path containerPath, Path path,
            String key) throws IOException {
        var versions = archivedVersions(containerPath, key);
        if (versions.isEmpty()) {
            return;
        }
        var newest = versions.get(0);
        if (newest.deleteMarker()) {
            return;
        }
        Files.createDirectories(path.getParent());
        Files.move(newest.path(), path, StandardCopyOption.ATOMIC_MOVE);
    }

    /**
     * Refuse a client key naming the store's private multipart bookkeeping.
     * Writing one lets a client replace a part of an upload it does not own,
     * or leave behind an object that list() hides from the bucket's owner.
     * The store reaches those names through its own internal overloads,
     * which do not call this; nothing arriving as an S3 key gets past it.
     *
     * <p>Reads are deliberately not refused: CompleteMultipartUpload hashes
     * each part by reading it back through {@link #getBlob}, and there is no
     * separate way in to say so.  Reading a part exposes no more than
     * ListParts already does to the same caller.
     */
    private static void checkNotReserved(String key) {
        if (key.startsWith(MULTIPART_PREFIX)) {
            throw S3Exceptions.invalidArgument("The key " + MULTIPART_PREFIX +
                    "... is reserved for multipart uploads.");
        }
        if (key.equals(VERSIONS_DIR) || key.startsWith(VERSIONS_DIR + "/")) {
            throw S3Exceptions.invalidArgument("The key " + VERSIONS_DIR +
                    " is reserved for object versions.");
        }
    }

    /** Resolves a container name relative to root and rejects names that
     *  normalize to a path outside root (e.g. "..", "../foo", "/abs"). */
    private Path resolveContainer(String container) {
        var path = root.resolve(container);
        checkValidPath(root, path);
        return path;
    }

    /** Resolves a container name and throws NoSuchBucket if the resolved
     *  path is not an existing directory. */
    private Path requireContainerPath(String container) {
        var path = resolveContainer(container);
        if (!Files.isDirectory(path)) {
            throw S3Exceptions.noSuchBucket(container, "");
        }
        return path;
    }

    private static void setBlobAccessHelper(Path path, ObjectCannedACL access) {
        try {
            var permissions = new HashSet<>(Files.getPosixFilePermissions(path));
            if (access == ObjectCannedACL.PRIVATE) {
                permissions.remove(PosixFilePermission.OTHERS_READ);
            } else if (access == ObjectCannedACL.PUBLIC_READ) {
                permissions.add(PosixFilePermission.OTHERS_READ);
            }
            Files.setPosixFilePermissions(path, permissions);
        } catch (UnsupportedOperationException uoe) {
            // Windows/SMB/other non-POSIX: ignore, cannot set permissions
            return;
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }
}
