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
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserDefinedFileAttributeView;
import java.util.Base64;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSortedSet;
import com.google.common.hash.HashCode;
import com.google.common.hash.HashFunction;
import com.google.common.hash.Hashing;
import com.google.common.hash.HashingInputStream;
import com.google.common.io.BaseEncoding;
import com.google.common.io.ByteSource;
import com.google.common.io.ByteStreams;
import com.google.common.primitives.Longs;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.ContentMetadata;
import org.gaul.s3proxy.blobstore.S3Exceptions;
import org.gaul.s3proxy.blobstore.SdkRequests;
import org.gaul.s3proxy.blobstore.SdkResponses;
import org.gaul.s3proxy.blobstore.domain.Blob;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.services.s3.model.Bucket;
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
    private static final String MULTIPART_PREFIX = ".mpus-";
    // Reserved in-container name that backs the object whose S3 key is exactly
    // "/". Path.resolve("/") yields the filesystem root, so this key cannot be
    // stored at its literal path; it previously had to be munged onto the
    // container directory itself, which let object operations (DELETE, PUT,
    // ACL) mutate bucket-level state. Redirecting it to a dedicated child keeps
    // it an ordinary directory-marker blob while isolating it from the
    // container inode. Hidden from listings and reserved from client keys.
    private static final String SLASH_BLOB_NAME = ".s3proxy-slash";
    private static final int UUID_STRING_LENGTH =
            UUID.randomUUID().toString().length();
    @SuppressWarnings("deprecation")
    private static final HashFunction md5 = Hashing.md5();
    private static final byte[] DIRECTORY_MD5 =
            md5.hashBytes(new byte[0]).asBytes();

    private final Path root;

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
                var creationTime = new Date(attr.creationTime().toMillis());
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
        var filterMultipart = !prefix.startsWith(MULTIPART_PREFIX);
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
                                new Date(attr.lastModifiedTime().toMillis()),
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
                Date lastModified = null;
                Long size = null;
                if (markerExists) {
                    eTag = readETagXattr(dirXattrs);
                    lastModified = new Date(
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
            var lastModifiedTime = new Date(attr.lastModifiedTime().toMillis());

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
        if (request.versionId() != null) {
            throw new UnsupportedOperationException(
                    "versioning not supported");
        }
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
            Date expires = null;
            HashCode hashCode = null;
            String eTag = null;
            var storageClass = StorageClass.STANDARD;
            var userMetadata = ImmutableMap.<String, String>builder();
            var lastModifiedTime = new Date(attr.lastModifiedTime().toMillis());

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
                    expires = new Date(buf.asLongBuffer().get());
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
                Date modifiedSince = Date.from(options.ifModifiedSince());
                if (lastModifiedTime.compareTo(modifiedSince) <= 0) {
                    throw conditionFailed(304, eTag);
                }

            }
            if (options.ifUnmodifiedSince() != null) {
                Date unmodifiedSince = Date.from(options.ifUnmodifiedSince());
                if (lastModifiedTime.after(unmodifiedSince)) {
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
                    .lastModified(lastModifiedTime);
            if (contentRange != null) {
                builder.contentRange(contentRange);
            }
            if (finalHashCode != null) {
                builder.eTag(BaseEncoding.base16().lowerCase().encode(finalHashCode.asBytes()));
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
        return SdkResponses.putResponse(putBlob(request.bucket(),
                toBlobBuilder(request).payload(payload).build(),
                SdkRequests.aclOrPrivate(request.acl()),
                request.ifNoneMatch(),
                /*parts=*/ null));
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
    private String putBlob(String container, Blob blob, ObjectCannedACL access,
            @Nullable String ifNoneMatch, @Nullable List<Path> parts) {
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

            return BaseEncoding.base16().lowerCase().encode(DIRECTORY_MD5);
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
                try (var is = new HashingInputStream(md5,
                        requireNonNull(blob.getPayload()));
                     var os = Files.newOutputStream(tmpPath)) {
                    is.transferTo(os);
                    actualHashCode = is.hash();
                }
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
                        ByteBuffer buf = ByteBuffer.allocate(Longs.BYTES).putLong(expires.getTime());
                        buf.flip();
                        view.write(XATTR_EXPIRES, buf);
                    }
                    writeStringAttributeIfPresent(view, XATTR_STORAGE_TIER, blob.getMetadata().storageClass().toString());
                    for (var entry : blob.getMetadata().userMetadata().entrySet()) {
                        writeStringAttributeIfPresent(view, XATTR_USER_METADATA_PREFIX + entry.getKey(), entry.getValue());
                    }
                } catch (IOException | UnsupportedOperationException e) {
                    logger.debug("xattrs not supported on {}", tmpPath);
                }
            }

            setBlobAccessHelper(tmpPath, access);

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
                    return storedETag;
                }
                return storedETag;
            }
            if (ifNoneMatch != null) {
                // A named ETag cannot be resolved by the move, and the
                // filesystem offers no compare-and-swap, so this remains a
                // read followed by a write.
                var current = blobMetadata(container,
                        blob.getMetadata().name());
                if (current != null && current.eTag() != null &&
                        maybeQuoteETag(ifNoneMatch).equals(
                                maybeQuoteETag(current.eTag()))) {
                    throw returnResponseException(412);
                }
            }

            Files.move(tmpPath, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);

            return storedETag;
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
            builder.expires(Date.from(request.expires()));
        }
        if (request.storageClass() != null) {
            builder.storageClass(request.storageClass());
        }
        return builder;
    }

    @Override
    public final CopyObjectResponse copyBlob(CopyObjectRequest request) {
        if (request.sourceVersionId() != null) {
            throw new UnsupportedOperationException(
                    "versioning not supported");
        }
        String fromContainer = request.sourceBucket();
        String fromName = request.sourceKey();
        String toContainer = request.destinationBucket();
        String toName = request.destinationKey();
        boolean replace =
                request.metadataDirective() == MetadataDirective.REPLACE;
        var blob = getBlobInternal(fromContainer, fromName,
                GetObjectRequest.builder()
                        .bucket(fromContainer)
                        .key(fromName)
                        .build(),
                /*openStream=*/ true);
        if (blob == null) {
            throw S3Exceptions.noSuchKey(fromContainer, fromName, "while copying");
        }

        // Evaluate preconditions inside the try-with-resources so that a
        // failing check still closes the file InputStream returned by
        // getBlob.
        try (var is = requireNonNull(blob.getPayload())) {
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
                if (ifModifiedSince != null && lastModified.compareTo(Date.from(ifModifiedSince)) <= 0) {
                    throw returnResponseException(412);
                }
                if (ifUnmodifiedSince != null && lastModified.compareTo(Date.from(ifUnmodifiedSince)) > 0) {
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
            return SdkResponses.copyResponse(putBlob(toContainer,
                    builder.build(),
                    SdkRequests.aclOrPrivate(request.acl()),
                    /*ifNoneMatch=*/ null,
                    /*parts=*/ null));
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }

    @Override
    public final void removeBlob(String container, String key) {
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
        if (request.versionId() != null) {
            throw new UnsupportedOperationException(
                    "versioning not supported");
        }
        String container = request.bucket();
        String key = request.key();
        Blob blob = getBlobInternal(container, key,
                GetObjectRequest.builder().bucket(container).key(key).build(),
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
    public final boolean deleteContainerIfEmpty(String container) {
        try {
            Files.deleteIfExists(resolveContainer(container));
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
        var containerPath = requireContainerPath(container);
        if (!blobExists(container, key)) {
            throw S3Exceptions.noSuchKey(container, key, "");
        }
        var path = resolveBlobPath(containerPath, key);

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
        var containerPath = requireContainerPath(container);
        if (!blobExists(container, key)) {
            throw S3Exceptions.noSuchKey(container, key, "");
        }
        var path = resolveBlobPath(containerPath, key);

        setBlobAccessHelper(path, access);
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
        var uploadId = UUID.randomUUID().toString();
        // create a stub blob
        var blob = Blob.builder(MULTIPART_PREFIX + uploadId + "-" + request.key() + "-stub").payload(ByteSource.empty()).build();
        putBlob(request.bucket(), blob, ObjectCannedACL.PRIVATE,
                /*ifNoneMatch=*/ null, /*parts=*/ null);
        return new MultipartUpload(uploadId, request);
    }

    @Override
    public final void abortMultipartUpload(MultipartUpload mpu) {
        var parts = listMultipartUpload(mpu);
        for (var part : parts) {
            removeBlob(mpu.containerName(), multipartPartName(mpu.id(), mpu.blobName(), part.partNumber()));
        }
        removeBlob(mpu.containerName(), MULTIPART_PREFIX + mpu.id() + "-" + mpu.blobName() + "-stub");
    }

    @Override
    public final CompleteMultipartUploadResponse completeMultipartUpload(
            MultipartUpload mpu, CompleteMultipartUploadRequest request) {
        List<CompletedPart> parts = request.multipartUpload() == null ?
                List.of() : request.multipartUpload().parts();
        var partNames = ImmutableList.<String>builder();
        long contentLength = 0;
        var md5Hasher = md5.newHasher();

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
                md5Hasher.putBytes(BaseEncoding.base16().lowerCase().decode(eTag));
            }
        }
        var mpuETag = "\"" + md5Hasher.hash() + "-" + parts.size() + "\"";
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
            blobBuilder.expires(Date.from(expires));
        }
        var storageClass = mpuRequest.storageClass();
        if (storageClass != null) {
            blobBuilder.storageClass(storageClass);
        }

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
        putBlob(mpu.containerName(), blobBuilder.build(),
                ObjectCannedACL.PRIVATE, request.ifNoneMatch(),
                partPaths.build());

        // Remove every uploaded part, not just the ones referenced by the
        // manifest, so parts excluded from the final object do not leak.
        for (var part : listMultipartUpload(mpu)) {
            removeBlob(mpu.containerName(), multipartPartName(mpu.id(), mpu.blobName(), part.partNumber()));
        }
        removeBlob(mpu.containerName(), MULTIPART_PREFIX + mpu.id() + "-" + mpu.blobName() + "-stub");

        setBlobAccess(mpu.containerName(), mpu.blobName(),
                SdkRequests.aclOrPrivate(mpuRequest.acl()));

        return SdkResponses.completeResponse(mpuETag);
    }

    @Override
    public final UploadPartResponse uploadMultipartPart(MultipartUpload mpu, int partNumber, InputStream is, long contentLength, @Nullable HashCode contentMD5) {
        var partName = multipartPartName(mpu.id(), mpu.blobName(), partNumber);
        var blob = Blob.builder(partName)
                .payload(is)
                .contentLength(contentLength)
                .contentMD5(contentMD5)
                .build();
        var partETag = putBlob(mpu.containerName(), blob,
                ObjectCannedACL.PRIVATE, /*ifNoneMatch=*/ null, /*parts=*/ null);
        var metadata = requireNonNull(
                blobMetadata(mpu.containerName(), partName));
        return SdkResponses.uploadedPart(partETag);
    }

    @Override
    public final List<Part> listMultipartUpload(MultipartUpload mpu) {
        var parts = ImmutableList.<Part>builder();
        var partPrefix = MULTIPART_PREFIX + mpu.id() + "-" + mpu.blobName() + "-";
        var options = ListObjectsV2Request.builder()
                .bucket(mpu.containerName())
                .prefix(partPrefix).build();
        while (true) {
            var pageSet = list(options);
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
                        sm.eTag(), Date.from(sm.lastModified())));
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
            var pageSet = list(options);
            for (S3Object sm : pageSet.contents()) {
                if (!sm.key().endsWith("-stub")) {
                    continue;
                }
                var uploadId = sm.key().substring(MULTIPART_PREFIX.length(), MULTIPART_PREFIX.length() + UUID_STRING_LENGTH);
                var blobName = sm.key().substring(MULTIPART_PREFIX.length() + UUID_STRING_LENGTH + 1);
                int index = blobName.lastIndexOf('-');
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
            var buf = ByteBuffer.allocate(Longs.BYTES).putLong(expires.getTime());
            buf.flip();
            view.write(XATTR_EXPIRES, buf);
        }
        writeStringAttributeIfPresent(view, XATTR_STORAGE_TIER, blob.getMetadata().storageClass().toString());
        for (var entry : blob.getMetadata().userMetadata().entrySet()) {
            writeStringAttributeIfPresent(view, XATTR_USER_METADATA_PREFIX + entry.getKey(), entry.getValue());
        }
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
