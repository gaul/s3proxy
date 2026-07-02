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

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserDefinedFileAttributeView;
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
import com.google.common.net.HttpHeaders;
import com.google.common.primitives.Longs;

import org.gaul.s3proxy.blobstore.BaseBlobStore;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.ContainerNotFoundException;
import org.gaul.s3proxy.blobstore.ContentMetadata;
import org.gaul.s3proxy.blobstore.HttpResponse;
import org.gaul.s3proxy.blobstore.HttpResponseException;
import org.gaul.s3proxy.blobstore.KeyNotFoundException;
import org.gaul.s3proxy.blobstore.Payload;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class AbstractNio2BlobStore extends BaseBlobStore {
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
    public final PageSet<? extends StorageMetadata> list() {
        var set = ImmutableSortedSet.<StorageMetadata>naturalOrder();
        try (var stream = Files.newDirectoryStream(root)) {
            for (var path : stream) {
                var attr = Files.readAttributes(path,
                        BasicFileAttributes.class);
                var lastModifiedTime = new Date(
                        attr.lastModifiedTime().toMillis());
                var creationTime = new Date(attr.creationTime().toMillis());
                set.add(new ContainerMetadata(
                        path.getFileName().toString(),
                        Map.of(), /*eTag=*/ null, creationTime,
                        lastModifiedTime, /*size=*/ null, StorageClass.STANDARD));
            }
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
        return new PageSet<StorageMetadata>(set.build(), null);
    }

    @Override
    public final PageSet<? extends StorageMetadata> list(String container,
            ListContainerOptions options) {
        var containerPath = requireContainerPath(container);

        var delimiter = options.delimiter();
        if ("".equals(delimiter)) {
            delimiter = null;
        } else if (delimiter != null && !delimiter.equals("/")) {
            throw new IllegalArgumentException("Delimiters other than / not supported");
        }

        var prefix = options.prefix();
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
        var set = ImmutableSortedSet.<StorageMetadata>naturalOrder();
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
                var markerXattrs = safeGetXattrs(pathPrefix);
                if (markerXattrs.attributes().contains(XATTR_CONTENT_MD5)) {
                    var attr = Files.readAttributes(pathPrefix,
                            BasicFileAttributes.class);
                    set.add(new BlobMetadata(StorageType.BLOB,
                            prefix, Map.of(),
                            readETagXattr(markerXattrs), /*creationDate=*/ null,
                            new Date(attr.lastModifiedTime().toMillis()),
                            StorageClass.STANDARD, /*container=*/ null,
                            ContentMetadata.builder()
                                    .contentLength(0L).build()));
                }
            }

            var sorted = set.build();
            if (options.marker() != null) {
                // StorageMetadata's natural ordering is name-only (nulls
                // last), so a name-only stub lets tailSet skip past the
                // marker in O(log n).
                sorted = sorted.tailSet(markerStub(options.marker()),
                        /*inclusive=*/ false);
            }
            String marker = null;
            if (options.maxResults() != null) {
                int maxResults = options.maxResults().intValue();
                var sortedList = sorted.asList();
                if (sortedList.size() > maxResults) {
                    if (maxResults == 0) {
                        sorted = ImmutableSortedSet.of();
                    } else {
                        var last = sortedList.get(maxResults - 1);
                        sorted = sorted.headSet(last, /*inclusive=*/ true);
                        marker = last.getName();
                    }
                }
            }
            return new PageSet<StorageMetadata>(sorted, marker);
        } catch (IOException ioe) {
            logger.error("unexpected exception", ioe);
            throw new RuntimeException(ioe);
        }
    }

    private void listHelper(ImmutableSortedSet.Builder<StorageMetadata> builder,
            Path containerPath, Path parent, String pathPrefixString,
            String delimiter, boolean filterMultipart)
            throws IOException {
        logger.debug("recursing at: {} with prefix: {}", parent, pathPrefixString);
        if (!Files.isDirectory(parent)) {  // TODO: TOCTOU
            return;
        }
        try (var stream = Files.newDirectoryStream(parent)) {
            for (var path : stream) {
                logger.debug("examining: {}", path);
                if (filterMultipart && path.getFileName().toString()
                        .startsWith(MULTIPART_PREFIX)) {
                    continue;
                }
                if (!path.toAbsolutePath().toString().startsWith(pathPrefixString)) {
                    // ignore
                    continue;
                }
                var attr = Files.readAttributes(path, BasicFileAttributes.class);
                if (attr.isDirectory()) {
                    if (!"/".equals(delimiter)) {
                        listHelper(builder, containerPath, path, pathPrefixString, delimiter,
                                filterMultipart);
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

                        builder.add(new BlobMetadata(
                                StorageType.RELATIVE_PATH,
                                name + "/", Map.of(), eTag,
                                /*creationDate=*/ null,
                                lastModified,
                                StorageClass.STANDARD, /*container=*/ null,
                                ContentMetadata.builder()
                                        .contentLength(size).build()));
                    }
                } else {
                    var name = relativeName(containerPath, path);
                    logger.debug("adding: {}", name);
                    var lastModifiedTime = new Date(attr.lastModifiedTime().toMillis());
                    var creationTime = new Date(attr.creationTime().toMillis());

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

                    builder.add(new BlobMetadata(StorageType.BLOB,
                            name, Map.of(),
                            eTag, creationTime, lastModifiedTime,
                            storageClass,
                            /*container=*/ null,
                            ContentMetadata.builder()
                                    .contentLength(attr.size())
                                    .build()));
                }
            }
        } catch (NoSuchFileException nsfe) {
            // ignore
        }
    }

    @Override
    public final boolean containerExists(String container) {
        return Files.isDirectory(resolveContainer(container));
    }

    @Override
    public final boolean createContainer(String container) {
        return createContainer(container, CreateContainerOptions.NONE);
    }

    @Override
    public final boolean createContainer(String container,
            CreateContainerOptions options) {
        try {
            Files.createDirectories(getRoot());
            Files.createDirectory(resolveContainer(container));
        } catch (FileAlreadyExistsException faee) {
            return false;
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }

        setContainerAccess(container, options.publicRead() ? ContainerAccess.PUBLIC_READ : ContainerAccess.PRIVATE);

        return true;
    }

    @Override
    public final boolean blobExists(String container, String key) {
        return blobMetadata(container, key) != null;
    }

    @Override
    public final Blob getBlob(String container, String key, GetOptions options) {
        return getBlobInternal(container, key, options, /*openStream=*/ true);
    }

    private Blob getBlobInternal(String container, String key,
            GetOptions options, boolean openStream) {
        var containerPath = requireContainerPath(container);
        var path = containerPath.resolve(key).normalize();
        checkValidPath(containerPath, path);
        logger.debug("Getting blob at: {}", path);

        try {
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
            var creationTime = new Date(attr.creationTime().toMillis());

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
                contentType = Files.probeContentType(path);
                if (contentType == null) {
                    contentType = "application/octet-stream";
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
            } else if (attributes.contains(XATTR_CONTENT_MD5)) {
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
            if (attributes.contains(XATTR_EXPIRES)) {
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
                    var value = readStringAttributeIfPresent(view, attributes, attribute);
                    userMetadata.put(attribute.substring(XATTR_USER_METADATA_PREFIX.length()), value);
                }
            }

            // Evaluate conditional headers and range bounds before opening
            // the file so that failing preconditions do not leak the
            // InputStream.
            if (eTag != null) {
                eTag = maybeQuoteETag(eTag);
                if (options.ifMatch() != null) {
                    if (!eTag.equals(maybeQuoteETag(options.ifMatch()))) {
                        HttpResponse response = HttpResponse.builder().statusCode(412).addHeader(HttpHeaders.ETAG, eTag).build();
                        throw new HttpResponseException(response);
                    }
                }
                if (options.ifNoneMatch() != null) {
                    if (eTag.equals(maybeQuoteETag(options.ifNoneMatch()))) {
                        HttpResponse response = HttpResponse.builder().statusCode(304).addHeader(HttpHeaders.ETAG, eTag).build();
                        throw new HttpResponseException(response);
                    }
                }
            }
            if (options.ifModifiedSince() != null) {
                Date modifiedSince = options.ifModifiedSince();
                if (lastModifiedTime.compareTo(modifiedSince) <= 0) {
                    @SuppressWarnings("rawtypes")
                    HttpResponse.Builder response = HttpResponse.builder().statusCode(304);
                    if (eTag != null) {
                        response.addHeader(HttpHeaders.ETAG, eTag);
                    }
                    throw new HttpResponseException("%1$s is before %2$s".formatted(lastModifiedTime, modifiedSince), response.build());
                }

            }
            if (options.ifUnmodifiedSince() != null) {
                Date unmodifiedSince = options.ifUnmodifiedSince();
                if (lastModifiedTime.after(unmodifiedSince)) {
                    @SuppressWarnings("rawtypes")
                    HttpResponse.Builder response = HttpResponse.builder().statusCode(412);
                    if (eTag != null) {
                        response.addHeader(HttpHeaders.ETAG, eTag);
                    }
                    throw new HttpResponseException("%1$s is after %2$s".formatted(lastModifiedTime, unmodifiedSince), response.build());
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
                size = attr.size();
                long offset = 0;
                long last = size;
                boolean hasRange = !options.ranges().isEmpty();
                if (hasRange) {
                    var range = options.ranges().get(0);
                    if (!range.contains("-")) {
                        throw new HttpResponseException("illegal range: " + range, HttpResponse.builder().statusCode(416).build());
                    }
                    // HTTP uses a closed interval while Java array indexing uses a
                    // half-open interval.
                    try {
                        if (range.startsWith("-")) {
                            offset = last - Long.parseLong(range.substring(1));
                            if (offset < 0) {
                                offset = 0;
                            }
                        } else if (range.endsWith("-")) {
                            offset = Long.parseLong(range.substring(0, range.length() - 1));
                        } else {
                            String[] firstLast = range.split("\\-", 2);
                            offset = Long.parseLong(firstLast[0]);
                            last = Long.parseLong(firstLast[1]);
                        }
                    } catch (NumberFormatException nfe) {
                        throw new HttpResponseException("illegal range: " + range, HttpResponse.builder().statusCode(416).build());
                    }

                    if (offset >= size || offset > last) {
                        throw new HttpResponseException("illegal range: " + range, HttpResponse.builder().statusCode(416).build());
                    }
                    if (last + 1 > size) {
                        last = size - 1;
                    }
                    contentRange = "bytes " + offset + "-" + last + "/" + attr.size();
                    size = last - offset + 1;
                }

                inputStream = Files.newInputStream(path);
                if (hasRange) {
                    try {
                        inputStream.skipNBytes(offset);
                    } catch (IOException ioe) {
                        try {
                            inputStream.close();
                        } catch (IOException ce) {
                            ioe.addSuppressed(ce);
                        }
                        throw ioe;
                    }
                    inputStream = ByteStreams.limit(inputStream, size);
                }
            }

            HashCode finalHashCode = hashCode;
            Blob.Builder builder = Blob.builder(key)
                    .type(isDirectory ? StorageType.FOLDER : StorageType.BLOB)
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
                    .creationDate(creationTime)
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
            throw new RuntimeException(ioe);
        }
    }

    @Override
    public final String putBlob(String container, Blob blob) {
        return putBlob(container, blob, PutOptions.NONE);
    }

    @Override
    public final String putBlob(String container, Blob blob, PutOptions options) {
        var containerPath = requireContainerPath(container);
        var path = containerPath.resolve(blob.getMetadata().getName()).normalize();
        checkValidPath(containerPath, path);
        // TODO: should we use a known suffix to filter these out during list?
        var tmpPath = containerPath.resolve(blob.getMetadata().getName() + "-" + UUID.randomUUID());
        logger.debug("Creating blob at: {}", path);

        if (blob.getMetadata().getName().endsWith("/")) {
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

        var metadata = blob.getMetadata().getContentMetadata();
        try {
            HashCode actualHashCode;
            // Close the streams before doing xattr writes, setBlobAccess,
            // and Files.move: Windows refuses to atomically move a file
            // that still has an open OutputStream.
            try (var is = new HashingInputStream(md5, blob.getPayload().openStream());
                 var os = Files.newOutputStream(tmpPath)) {
                is.transferTo(os);
                actualHashCode = is.hash();
            }
            var expectedHashCode = metadata.contentMD5();
            if (expectedHashCode != null && !actualHashCode.equals(expectedHashCode)) {
                throw returnResponseException(400);
            }

            var view = getXattrView(tmpPath);
            if (view != null) {
                try {
                    var eTag = actualHashCode.asBytes();
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
                    writeStringAttributeIfPresent(view, XATTR_STORAGE_TIER, blob.getMetadata().getStorageClass().toString());
                    for (var entry : blob.getMetadata().getUserMetadata().entrySet()) {
                        writeStringAttributeIfPresent(view, XATTR_USER_METADATA_PREFIX + entry.getKey(), entry.getValue());
                    }
                } catch (IOException | UnsupportedOperationException e) {
                    logger.debug("xattrs not supported on {}", tmpPath);
                }
            }

            setBlobAccessHelper(tmpPath, options.blobAccess());

            Files.move(tmpPath, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);

            return actualHashCode.toString();
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

    @Override
    public final String copyBlob(String fromContainer, String fromName,
            String toContainer, String toName, CopyOptions options) {
        var blob = getBlob(fromContainer, fromName);
        if (blob == null) {
            throw new KeyNotFoundException(fromContainer, fromName, "while copying");
        }

        // Evaluate preconditions inside the try-with-resources so that a
        // failing check still closes the file InputStream returned by
        // getBlob.
        try (var is = blob.getPayload().openStream()) {
            var eTag = blob.getMetadata().getETag();
            if (eTag != null) {
                eTag = maybeQuoteETag(eTag);
                if (options.ifMatch() != null && !maybeQuoteETag(options.ifMatch()).equals(eTag)) {
                    throw returnResponseException(412);
                }
                if (options.ifNoneMatch() != null && maybeQuoteETag(options.ifNoneMatch()).equals(eTag)) {
                    throw returnResponseException(412);
                }
            }

            var lastModified = blob.getMetadata().getLastModified();
            if (lastModified != null) {
                if (options.ifModifiedSince() != null && lastModified.compareTo(options.ifModifiedSince()) <= 0) {
                    throw returnResponseException(412);
                }
                if (options.ifUnmodifiedSince() != null && lastModified.compareTo(options.ifUnmodifiedSince()) > 0) {
                    throw returnResponseException(412);
                }
            }

            var metadata = blob.getMetadata().getContentMetadata();
            var builder = Blob.builder(toName).payload(is);
            Long contentLength = metadata.contentLength();
            if (contentLength != null) {
                builder.contentLength(contentLength);
            }

            var contentMetadata = options.contentMetadata();
            if (contentMetadata != null) {
                String cacheControl = contentMetadata.cacheControl();
                if (cacheControl != null) {
                    builder.cacheControl(cacheControl);
                }
                String contentDisposition = contentMetadata.contentDisposition();
                if (contentDisposition != null) {
                    builder.contentDisposition(contentDisposition);
                }
                String contentEncoding = contentMetadata.contentEncoding();
                if (contentEncoding != null) {
                    builder.contentEncoding(contentEncoding);
                }
                String contentLanguage = contentMetadata.contentLanguage();
                if (contentLanguage != null) {
                    builder.contentLanguage(contentLanguage);
                }
                String contentType = contentMetadata.contentType();
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

            var userMetadata = options.userMetadata();
            if (userMetadata != null) {
                builder.userMetadata(userMetadata);
            } else {
                builder.userMetadata(blob.getMetadata().getUserMetadata());
            }
            return putBlob(toContainer, builder.build());
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }

    @Override
    public final void removeBlob(String container, String key) {
        try {
            var containerPath = resolveContainer(container);
            var path = containerPath.resolve(key).normalize();
            checkValidPath(containerPath, path);
            if (!key.endsWith("/") && Files.isDirectory(path)) {
                // POSIX path normalization conflates "key" with "key/";
                // a non-slash key must not match a directory marker.
                return;
            }
            logger.debug("Deleting blob at: {}", path);
            Files.delete(path);
            removeEmptyParentDirectories(containerPath, path.getParent());
        } catch (NoSuchFileException nsfe) {
            return;
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }

    @Override
    public final BlobMetadata blobMetadata(String container, String key) {
        Blob blob = getBlobInternal(container, key, GetOptions.NONE,
                /*openStream=*/ false);
        if (blob == null) {
            return null;
        }
        var in = blob.getMetadata();
        var lowerCaseUserMetadata = new HashMap<String, String>();
        for (var entry : in.getUserMetadata().entrySet()) {
            lowerCaseUserMetadata.put(entry.getKey().toLowerCase(),
                    entry.getValue());
        }
        return in.toBuilder().userMetadata(lowerCaseUserMetadata).build();
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

    @Override
    public final ContainerAccess getContainerAccess(String container) {
        var path = requireContainerPath(container);
        Set<PosixFilePermission> permissions;
        try {
            permissions = Files.getPosixFilePermissions(path);
        } catch (UnsupportedOperationException uoe) {
            // Windows/SMB/other non-POSIX: default to PRIVATE
            return ContainerAccess.PRIVATE;
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
        return permissions.contains(PosixFilePermission.OTHERS_READ) ?
                ContainerAccess.PUBLIC_READ : ContainerAccess.PRIVATE;
    }

    @Override
    public final void setContainerAccess(String container, ContainerAccess access) {
        var path = requireContainerPath(container);
        Set<PosixFilePermission> permissions;
        try {
            permissions = new HashSet<>(Files.getPosixFilePermissions(path));
            if (access == ContainerAccess.PRIVATE) {
                permissions.remove(PosixFilePermission.OTHERS_READ);
            } else if (access == ContainerAccess.PUBLIC_READ) {
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

    @Override
    public final BlobAccess getBlobAccess(String container, String key) {
        var containerPath = requireContainerPath(container);
        if (!blobExists(container, key)) {
            throw new KeyNotFoundException(container, key, "");
        }
        var path = containerPath.resolve(key).normalize();
        checkValidPath(containerPath, path);

        Set<PosixFilePermission> permissions;
        try {
            permissions = Files.getPosixFilePermissions(path);
        } catch (UnsupportedOperationException uoe) {
            // Windows/SMB/other non-POSIX: default to PRIVATE
            return BlobAccess.PRIVATE;
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
        return permissions.contains(PosixFilePermission.OTHERS_READ) ?
                BlobAccess.PUBLIC_READ : BlobAccess.PRIVATE;
    }

    @Override
    public final void setBlobAccess(String container, String key, BlobAccess access) {
        var containerPath = requireContainerPath(container);
        if (!blobExists(container, key)) {
            throw new KeyNotFoundException(container, key, "");
        }
        var path = containerPath.resolve(key).normalize();
        checkValidPath(containerPath, path);

        setBlobAccessHelper(path, access);
    }

    @Override
    public final MultipartUpload initiateMultipartUpload(String container,
            BlobMetadata blobMetadata, PutOptions options) {
        var uploadId = UUID.randomUUID().toString();
        // create a stub blob
        var blob = Blob.builder(MULTIPART_PREFIX + uploadId + "-" + blobMetadata.getName() + "-stub").payload(ByteSource.empty()).build();
        putBlob(container, blob);
        return new MultipartUpload(container, blobMetadata.getName(), uploadId,
                blobMetadata, options);
    }

    @Override
    public final void abortMultipartUpload(MultipartUpload mpu) {
        var parts = listMultipartUpload(mpu);
        for (var part : parts) {
            removeBlob(mpu.containerName(), MULTIPART_PREFIX + mpu.id() + "-" + mpu.blobName() + "-" + part.partNumber());
        }
        removeBlob(mpu.containerName(), MULTIPART_PREFIX + mpu.id() + "-" + mpu.blobName() + "-stub");
    }

    @Override
    public final String completeMultipartUpload(MultipartUpload mpu, List<MultipartPart> parts) {
        var metas = ImmutableList.<BlobMetadata>builder();
        long contentLength = 0;
        var md5Hasher = md5.newHasher();

        for (var part : parts) {
            var meta = blobMetadata(mpu.containerName(), MULTIPART_PREFIX + mpu.id() + "-" + mpu.blobName() + "-" + part.partNumber());
            if (meta == null) {
                // S3 returns InvalidPart (400) when the manifest references
                // a part that was never uploaded.
                throw returnResponseException(400);
            }
            contentLength += meta.getContentMetadata().contentLength();
            metas.add(meta);
            if (meta.getETag() != null) {
                var eTag = meta.getETag();
                if (eTag.startsWith("\"") && eTag.endsWith("\"") &&
                       eTag.length() >= 2) {
                    eTag = eTag.substring(1, eTag.length() - 1);
                }
                md5Hasher.putBytes(BaseEncoding.base16().lowerCase().decode(eTag));
            }
        }
        var mpuETag = "\"" + md5Hasher.hash() + "-" + parts.size() + "\"";
        var blobBuilder = Blob.builder(mpu.blobName())
                .payload(new MultiBlobInputStream(this, metas.build()))
                .contentLength(contentLength)
                .eTag(mpuETag);
        var mpuBlobMetadata = mpu.blobMetadata();
        if (mpuBlobMetadata != null) {
            blobBuilder.userMetadata(mpuBlobMetadata.getUserMetadata());
            var contentMetadata = mpuBlobMetadata.getContentMetadata();
            var cacheControl = contentMetadata.cacheControl();
            if (cacheControl != null) {
                blobBuilder.cacheControl(cacheControl);
            }
            var contentDisposition = contentMetadata.contentDisposition();
            if (contentDisposition != null) {
                blobBuilder.contentDisposition(contentDisposition);
            }
            var contentEncoding = contentMetadata.contentEncoding();
            if (contentEncoding != null) {
                blobBuilder.contentEncoding(contentEncoding);
            }
            var contentLanguage = contentMetadata.contentLanguage();
            if (contentLanguage != null) {
                blobBuilder.contentLanguage(contentLanguage);
            }
            // intentionally not copying MD5
            var contentType = contentMetadata.contentType();
            if (contentType != null) {
                blobBuilder.contentType(contentType);
            }
            var expires = contentMetadata.expires();
            if (expires != null) {
                blobBuilder.expires(expires);
            }
            var storageClass = mpuBlobMetadata.getStorageClass();
            if (storageClass != null) {
                blobBuilder.storageClass(storageClass);
            }
        }

        putBlob(mpu.containerName(), blobBuilder.build());

        // Remove every uploaded part, not just the ones referenced by the
        // manifest, so parts excluded from the final object do not leak.
        for (var part : listMultipartUpload(mpu)) {
            removeBlob(mpu.containerName(), MULTIPART_PREFIX + mpu.id() + "-" + mpu.blobName() + "-" + part.partNumber());
        }
        removeBlob(mpu.containerName(), MULTIPART_PREFIX + mpu.id() + "-" + mpu.blobName() + "-stub");

        var mpuPutOptions = mpu.putOptions();
        if (mpuPutOptions != null) {
            setBlobAccess(mpu.containerName(), mpu.blobName(), mpuPutOptions.blobAccess());
        }

        return mpuETag;
    }

    @Override
    public final MultipartPart uploadMultipartPart(MultipartUpload mpu, int partNumber, Payload payload) {
        var partName = MULTIPART_PREFIX + mpu.id() + "-" + mpu.blobName() + "-" + partNumber;
        var blob = Blob.builder(partName)
                .payload(payload)
                .build();
        var partETag = putBlob(mpu.containerName(), blob);
        var metadata = blobMetadata(mpu.containerName(), partName);  // TODO: racy, how to get this from payload?
        var partSize = metadata.getContentMetadata().contentLength();
        return new MultipartPart(partNumber, partSize, partETag, metadata.getLastModified());
    }

    @Override
    public final List<MultipartPart> listMultipartUpload(MultipartUpload mpu) {
        var parts = ImmutableList.<MultipartPart>builder();
        var partPrefix = MULTIPART_PREFIX + mpu.id() + "-" + mpu.blobName() + "-";
        var options = ListContainerOptions.builder()
                .prefix(partPrefix).recursive().build();
        while (true) {
            var pageSet = list(mpu.containerName(), options);
            for (var sm : pageSet) {
                if (sm.getName().endsWith("-stub")) {
                    continue;
                }
                int partNumber;
                try {
                    partNumber = Integer.parseInt(sm.getName().substring(partPrefix.length()));
                } catch (NumberFormatException nfe) {
                    logger.warn("ignoring multipart entry with non-numeric suffix: {}", sm.getName());
                    continue;
                }
                long partSize = sm.getSize();
                parts.add(new MultipartPart(partNumber, partSize, sm.getETag(), sm.getLastModified()));
            }
            if (pageSet.isEmpty() || pageSet.getNextMarker() == null) {
                break;
            }
            options = options.toBuilder()
                    .afterMarker(pageSet.getNextMarker()).build();
        }
        return parts.build();
    }

    @Override
    public final List<MultipartUpload> listMultipartUploads(String container) {
        var mpus = ImmutableList.<MultipartUpload>builder();
        var options = ListContainerOptions.builder()
                .prefix(MULTIPART_PREFIX).recursive().build();
        while (true) {
            var pageSet = list(container, options);
            for (StorageMetadata sm : pageSet) {
                if (!sm.getName().endsWith("-stub")) {
                    continue;
                }
                var uploadId = sm.getName().substring(MULTIPART_PREFIX.length(), MULTIPART_PREFIX.length() + UUID_STRING_LENGTH);
                var blobName = sm.getName().substring(MULTIPART_PREFIX.length() + UUID_STRING_LENGTH + 1);
                int index = blobName.lastIndexOf('-');
                blobName = blobName.substring(0, index);

                mpus.add(new MultipartUpload(container, blobName, uploadId, null, null));
            }
            if (pageSet.isEmpty() || pageSet.getNextMarker() == null) {
                break;
            }
            options = options.toBuilder()
                    .afterMarker(pageSet.getNextMarker()).build();
        }

        return mpus.build();
    }

    @Override
    public final long getMinimumMultipartPartSize() {
        return 1;
    }

    @Override
    public final long getMaximumMultipartPartSize() {
        return 100 * 1024 * 1024;
    }

   /**
    * Read the String representation of a filesystem attribute, or return null
    * if not present.
    */
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
            UserDefinedFileAttributeView view, String name, String value)
            throws IOException {
        if (value != null) {
            view.write(name, ByteBuffer.wrap(value.getBytes(StandardCharsets.UTF_8)));
        }
    }

    private static final class MultiBlobInputStream extends InputStream {
        private final BlobStore blobStore;
        private final Iterator<BlobMetadata> metas;
        private InputStream current;

        MultiBlobInputStream(BlobStore blobStore, List<BlobMetadata> metas) {
            this.blobStore = blobStore;
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

        private InputStream openPartStream(BlobMetadata meta) throws IOException {
            Blob blob = blobStore.getBlob(meta.getContainer(), meta.getName());
            if (blob == null) {
                throw new IOException("Part disappeared: " +
                        meta.getContainer() + "/" + meta.getName());
            }
            return blob.getPayload().openStream();
        }

        @Override
        public void close() throws IOException {
            if (current != null) {
                current.close();
                current = null;
            }
        }
    }

    private static HttpResponseException returnResponseException(int code) {
        return new HttpResponseException(
                HttpResponse.builder().statusCode(code).build());
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
    private static void removeEmptyParentDirectories(Path containerPath, Path path) throws IOException {
        logger.debug("removing empty parents: {}", path);
        while (path != null && !path.equals(containerPath)) {
            if (safeGetXattrs(path).attributes().contains(XATTR_CONTENT_MD5)) {
                break;
            }
            try {
                logger.debug("deleting: {}", path);
                Files.delete(path);
            } catch (DirectoryNotEmptyException dnee) {
                break;
            }
            path = path.getParent();
        }
    }

    // TODO: call in other places
    private static void writeCommonMetadataAttr(UserDefinedFileAttributeView view, Blob blob) throws IOException {
        var metadata = blob.getMetadata().getContentMetadata();
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
        writeStringAttributeIfPresent(view, XATTR_STORAGE_TIER, blob.getMetadata().getStorageClass().toString());
        for (var entry : blob.getMetadata().getUserMetadata().entrySet()) {
            writeStringAttributeIfPresent(view, XATTR_USER_METADATA_PREFIX + entry.getKey(), entry.getValue());
        }
    }

    private record XattrState(UserDefinedFileAttributeView view, Set<String> attributes) {
        static final XattrState EMPTY = new XattrState(null, NO_ATTRIBUTES);
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

    /** Resolves a container name relative to root and rejects names that
     *  normalize to a path outside root (e.g. "..", "../foo", "/abs"). */
    private Path resolveContainer(String container) {
        var path = root.resolve(container);
        checkValidPath(root, path);
        return path;
    }

    /** Resolves a container name and throws ContainerNotFoundException if
     *  the resolved path is not an existing directory. */
    private Path requireContainerPath(String container) {
        var path = resolveContainer(container);
        if (!Files.isDirectory(path)) {
            throw new ContainerNotFoundException(container, "");
        }
        return path;
    }

    /** Minimal StorageMetadata used as a name-only key for SortedSet
     *  range queries; relies on StorageMetadata's natural ordering being
     *  by name. */
    private static StorageMetadata markerStub(String name) {
        return new BlobMetadata(StorageType.BLOB, name, Map.of(),
                /*eTag=*/ null, /*creationDate=*/ null, /*lastModified=*/ null,
                StorageClass.STANDARD,
                /*container=*/ null,
                ContentMetadata.builder().build());
    }

    private static void setBlobAccessHelper(Path path, BlobAccess access) {
        try {
            var permissions = new HashSet<>(Files.getPosixFilePermissions(path));
            if (access == BlobAccess.PRIVATE) {
                permissions.remove(PosixFilePermission.OTHERS_READ);
            } else if (access == BlobAccess.PUBLIC_READ) {
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
