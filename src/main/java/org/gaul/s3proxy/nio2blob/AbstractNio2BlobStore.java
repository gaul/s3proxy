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

package org.gaul.s3proxy.nio2blob;

import static java.util.Objects.requireNonNull;

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
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import com.google.common.base.Supplier;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSortedSet;
import com.google.common.hash.HashCode;
import com.google.common.hash.Hashing;
import com.google.common.hash.HashingInputStream;
import com.google.common.io.BaseEncoding;
import com.google.common.io.ByteSource;
import com.google.common.io.ByteStreams;
import com.google.common.net.HttpHeaders;
import com.google.common.primitives.Longs;

import jakarta.inject.Singleton;
import jakarta.ws.rs.core.Response.Status;

import org.jclouds.blobstore.BlobStore;
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
import org.jclouds.blobstore.domain.internal.PageSetImpl;
import org.jclouds.blobstore.domain.internal.StorageMetadataImpl;
import org.jclouds.blobstore.internal.BaseBlobStore;
import org.jclouds.blobstore.options.CopyOptions;
import org.jclouds.blobstore.options.CreateContainerOptions;
import org.jclouds.blobstore.options.GetOptions;
import org.jclouds.blobstore.options.ListContainerOptions;
import org.jclouds.blobstore.options.PutOptions;
import org.jclouds.blobstore.util.BlobStoreUtils;
import org.jclouds.blobstore.util.BlobUtils;
import org.jclouds.collect.Memoized;
import org.jclouds.domain.Credentials;
import org.jclouds.domain.Location;
import org.jclouds.http.HttpCommand;
import org.jclouds.http.HttpRequest;
import org.jclouds.http.HttpResponse;
import org.jclouds.http.HttpResponseException;
import org.jclouds.io.Payload;
import org.jclouds.io.PayloadSlicer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Singleton
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
    private static final String MULTIPART_PREFIX = ".mpus-";
    private static final byte[] DIRECTORY_MD5 =
            Hashing.md5().hashBytes(new byte[0]).asBytes();

    private final Supplier<Set<? extends Location>> locations;
    private final Path root;

    protected AbstractNio2BlobStore(BlobStoreContext context, BlobUtils blobUtils,
            Supplier<Location> defaultLocation,
            @Memoized Supplier<Set<? extends Location>> locations,
            PayloadSlicer slicer,
            @org.jclouds.location.Provider Supplier<Credentials> creds,
            Path root) {
        super(context, blobUtils, defaultLocation, locations, slicer);
        this.locations = requireNonNull(locations, "locations");
        this.root = root;
    }

    protected final Path getRoot() {
        return root;
    }

    @Override
    public final Set<? extends Location> listAssignableLocations() {
        return locations.get();
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
                set.add(new StorageMetadataImpl(StorageType.CONTAINER,
                        /*id=*/ null, path.getFileName().toString(),
                        /*location=*/ null, /*uri=*/ null,
                        /*eTag=*/ null, creationTime, lastModifiedTime,
                        Map.of(), /*size=*/ null, Tier.STANDARD));
            }
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
        return new PageSetImpl<StorageMetadata>(set.build(), null);
    }

    @Override
    public final PageSet<? extends StorageMetadata> list(String container,
            ListContainerOptions options) {
        if (!containerExists(container)) {
            throw new ContainerNotFoundException(container, "");
        }

        var delimiter = options.getDelimiter();
        if ("".equals(delimiter)) {
            delimiter = null;
        } else if (delimiter != null && !delimiter.equals("/")) {
            throw new IllegalArgumentException("Delimiters other than / not supported");
        }

        var prefix = options.getPrefix();
        var dirPrefix = root.resolve(container);
        if (prefix != null) {
            int idx = prefix.lastIndexOf('/');
            if (idx != -1) {
                dirPrefix = dirPrefix.resolve(prefix.substring(0, idx));
            }
        } else {
            prefix = "";
        }
        var containerPath = root.resolve(container);
        var pathPrefix = containerPath.resolve(prefix).normalize();
        checkValidPath(containerPath, pathPrefix);
        logger.debug("Listing blobs at: {}", pathPrefix);
        var set = ImmutableSortedSet.<StorageMetadata>naturalOrder();
        try {
            listHelper(set, container, dirPrefix, pathPrefix, delimiter);
            var sorted = set.build();
            if (options.getMarker() != null) {
                var found = false;
                for (var blob : sorted) {
                    if (blob.getName().compareTo(options.getMarker()) > 0) {
                        sorted = sorted.tailSet(blob);
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    sorted = ImmutableSortedSet.of();
                }
            }
            String marker = null;
            if (options.getMaxResults() != null) {
                // TODO: efficiency?
                var temp = ImmutableSortedSet.copyOf(sorted.stream().limit(options.getMaxResults().intValue()).collect(Collectors.toSet()));
                if (!temp.isEmpty()) {
                    var next = sorted.higher(temp.last());
                    if (next != null) {
                        marker = temp.last().getName();
                    }
                }
                sorted = temp;
            }
            return new PageSetImpl<StorageMetadata>(sorted, marker);
        } catch (IOException ioe) {
            logger.error("unexpected exception", ioe);
            throw new RuntimeException(ioe);
        }
    }

    private void listHelper(ImmutableSortedSet.Builder<StorageMetadata> builder,
            String container, Path parent, Path prefix, String delimiter)
            throws IOException {
        logger.debug("recursing at: {} with prefix: {}", parent, prefix);
        if (!Files.isDirectory(parent)) {  // TODO: TOCTOU
            return;
        }
        try (var stream = Files.newDirectoryStream(parent)) {
            for (var path : stream) {
                logger.debug("examining: {}", path);
                if (!path.toAbsolutePath().toString().startsWith(root.resolve(prefix).toAbsolutePath().toString())) {
                    // ignore
                } else if (Files.isDirectory(path)) {
                    if (!"/".equals(delimiter)) {
                        listHelper(builder, container, path, prefix, delimiter);
                    }

                    // Add a prefix if the directory blob exists or if the delimiter causes us not to recuse.
                    var view = Files.getFileAttributeView(path, UserDefinedFileAttributeView.class);
                    if ((view != null && Set.copyOf(view.list()).contains(XATTR_CONTENT_MD5)) || "/".equals(delimiter)) {
                        var name = path.toString().substring((root.resolve(container) + "/").length());
                        if (path.getFileSystem().getSeparator().equals("\\")) {
                            name = name.replace('\\', '/');
                        }
                        logger.debug("adding prefix: {}", name);
                        builder.add(new StorageMetadataImpl(
                                StorageType.RELATIVE_PATH,
                                /*id=*/ null, name + "/",
                                /*location=*/ null, /*uri=*/ null,
                                /*eTag=*/ null, /*creationTime=*/ null,
                                /*lastModifiedTime=*/ null,
                                Map.of(), /*size=*/ null, Tier.STANDARD));
                    }
                } else {
                    var name = path.toString().substring((root.resolve(container) + "/").length());
                    if (path.getFileSystem().getSeparator().equals("\\")) {
                        name = name.replace('\\', '/');
                    }
                    logger.debug("adding: {}", name);
                    var attr = Files.readAttributes(path, BasicFileAttributes.class);
                    var lastModifiedTime = new Date(attr.lastModifiedTime().toMillis());
                    var creationTime = new Date(attr.creationTime().toMillis());

                    String eTag;
                    HashCode hashCode;
                    var view = Files.getFileAttributeView(path, UserDefinedFileAttributeView.class);
                    var attributes = Set.copyOf(view.list());
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

                    var tierString = readStringAttributeIfPresent(view, attributes, XATTR_STORAGE_TIER);
                    Tier tier = tierString != null ? Tier.valueOf(tierString) : Tier.STANDARD;

                    builder.add(new StorageMetadataImpl(StorageType.BLOB,
                            /*id=*/ null, name,
                            /*location=*/ null, /*uri=*/ null,
                            eTag, creationTime, lastModifiedTime,
                            Map.of(), attr.size(), tier));
                }
            }
        } catch (NoSuchFileException nsfe) {
            // ignore
        }
    }

    @Override
    public final boolean containerExists(String container) {
        return Files.exists(root.resolve(container));
    }

    @Override
    public final boolean createContainerInLocation(Location location,
            String container) {
        return createContainerInLocation(location, container,
                new CreateContainerOptions());
    }

    @Override
    public final boolean createContainerInLocation(Location location,
            String container, CreateContainerOptions options) {
        try {
            Files.createDirectory(root.resolve(container));
        } catch (FileAlreadyExistsException faee) {
            return false;
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }

        setContainerAccess(container, options.isPublicRead() ? ContainerAccess.PUBLIC_READ : ContainerAccess.PRIVATE);

        return true;
    }

    @Override
    public final void deleteContainer(String container) {
        try {
            Files.deleteIfExists(root.resolve(container));
        } catch (DirectoryNotEmptyException dnee) {
            // TODO: what to do?
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }

    @Override
    public final boolean blobExists(String container, String key) {
        return blobMetadata(container, key) != null;
    }

    @Override
    public final Blob getBlob(String container, String key, GetOptions options) {
        if (!containerExists(container)) {
            throw new ContainerNotFoundException(container, "");
        }

        var containerPath = root.resolve(container);
        var path = containerPath.resolve(key);
        checkValidPath(containerPath, path);
        logger.debug("Getting blob at: {}", path);

        try {
            var isDirectory = Files.isDirectory(path);
            var attr = Files.readAttributes(path, BasicFileAttributes.class);
            var view = Files.getFileAttributeView(path, UserDefinedFileAttributeView.class);
            var attributes = Set.copyOf(view.list());
            var cacheControl = readStringAttributeIfPresent(view, attributes, XATTR_CACHE_CONTROL);
            var contentDisposition = readStringAttributeIfPresent(view, attributes, XATTR_CONTENT_DISPOSITION);
            var contentEncoding = readStringAttributeIfPresent(view, attributes, XATTR_CONTENT_ENCODING);
            var contentLanguage = readStringAttributeIfPresent(view, attributes, XATTR_CONTENT_LANGUAGE);
            var contentType = isDirectory ? "application/x-directory" :
                    readStringAttributeIfPresent(view, attributes, XATTR_CONTENT_TYPE);
            Date expires = null;
            HashCode hashCode = null;
            String eTag = null;
            var tier = Tier.STANDARD;
            var userMetadata = ImmutableMap.<String, String>builder();
            var lastModifiedTime = new Date(attr.lastModifiedTime().toMillis());
            var creationTime = new Date(attr.creationTime().toMillis());

            if (isDirectory) {
                if (!attributes.contains(XATTR_CONTENT_MD5)) {
                    // Lacks directory marker -- implicit directory.
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
                ByteBuffer buf = ByteBuffer.allocate(view.size(XATTR_EXPIRES));
                view.read(XATTR_EXPIRES, buf);
                buf.flip();
                expires = new Date(buf.asLongBuffer().get());
            }
            var tierString = readStringAttributeIfPresent(view, attributes, XATTR_STORAGE_TIER);
            if (tierString != null) {
                tier = Tier.valueOf(tierString);
            }
            for (String attribute : attributes) {
                if (!attribute.startsWith(XATTR_USER_METADATA_PREFIX)) {
                    continue;
                }
                var value = readStringAttributeIfPresent(view, attributes, attribute);
                userMetadata.put(attribute.substring(XATTR_USER_METADATA_PREFIX.length()), value);
            }

            // Handle range.
            String contentRange = null;
            InputStream inputStream;
            long size;
            if (isDirectory) {
                inputStream = ByteSource.empty().openStream();
                size = 0;
            } else {
                inputStream = Files.newInputStream(path);  // TODO: leaky on exception
                size = attr.size();
                if (options.getRanges().size() > 0) {
                    var range = options.getRanges().get(0);
                    // HTTP uses a closed interval while Java array indexing uses a
                    // half-open interval.
                    long offset = 0;
                    long last = size;
                    if (range.startsWith("-")) {
                        offset = last - Long.parseLong(range.substring(1));
                        if (offset < 0) {
                            offset = 0;
                        }
                    } else if (range.endsWith("-")) {
                        offset = Long.parseLong(range.substring(0, range.length() - 1));
                    } else if (range.contains("-")) {
                        String[] firstLast = range.split("\\-", 2);
                        offset = Long.parseLong(firstLast[0]);
                        last = Long.parseLong(firstLast[1]);
                    } else {
                        throw new HttpResponseException("illegal range: " + range, null, HttpResponse.builder().statusCode(416).build());
                    }

                    if (offset >= size) {
                        throw new HttpResponseException("illegal range: " + range, null, HttpResponse.builder().statusCode(416).build());
                    }
                    if (last + 1 > size) {
                        last = size - 1;
                    }
                    ByteStreams.skipFully(inputStream, offset);
                    size = last - offset + 1;
                    inputStream = ByteStreams.limit(inputStream, size);
                    contentRange = "bytes " + offset + "-" + last + "/" + attr.size();
                }
            }

            if (eTag != null) {
                eTag = maybeQuoteETag(eTag);
                if (options.getIfMatch() != null) {
                    if (!eTag.equals(maybeQuoteETag(options.getIfMatch()))) {
                        HttpResponse response = HttpResponse.builder().statusCode(Status.PRECONDITION_FAILED.getStatusCode()).addHeader(HttpHeaders.ETAG, eTag).build();
                        throw new HttpResponseException(new HttpCommand(HttpRequest.builder().method("GET").endpoint("http://stub").build()), response);
                    }
                }
                if (options.getIfNoneMatch() != null) {
                    if (eTag.equals(maybeQuoteETag(options.getIfNoneMatch()))) {
                        HttpResponse response = HttpResponse.builder().statusCode(Status.NOT_MODIFIED.getStatusCode()).addHeader(HttpHeaders.ETAG, eTag).build();
                        throw new HttpResponseException(new HttpCommand(HttpRequest.builder().method("GET").endpoint("http://stub").build()), response);
                    }
                }
            }
            if (options.getIfModifiedSince() != null) {
                Date modifiedSince = options.getIfModifiedSince();
                if (lastModifiedTime.before(modifiedSince)) {
                    HttpResponse.Builder response = HttpResponse.builder().statusCode(Status.NOT_MODIFIED.getStatusCode());
                    if (eTag != null) {
                        response.addHeader(HttpHeaders.ETAG, eTag);
                    }
                    throw new HttpResponseException(String.format("%1$s is before %2$s", lastModifiedTime, modifiedSince), null, response.build());
                }

            }
            if (options.getIfUnmodifiedSince() != null) {
                Date unmodifiedSince = options.getIfUnmodifiedSince();
                if (lastModifiedTime.after(unmodifiedSince)) {
                    HttpResponse.Builder response = HttpResponse.builder().statusCode(Status.PRECONDITION_FAILED.getStatusCode());
                    if (eTag != null) {
                        response.addHeader(HttpHeaders.ETAG, eTag);
                    }
                    throw new HttpResponseException(String.format("%1$s is after %2$s", lastModifiedTime, unmodifiedSince), null, response.build());
                }
            }

            Blob blob = new BlobBuilderImpl()
                    .type(isDirectory ? StorageType.FOLDER : StorageType.BLOB)
                    .name(key)
                    .userMetadata(userMetadata.build())
                    .payload(inputStream)
                    .cacheControl(cacheControl)
                    .contentDisposition(contentDisposition)
                    .contentEncoding(contentEncoding)
                    .contentLanguage(contentLanguage)
                    .contentLength(size)
                    .contentMD5(hashCode)
                    .contentType(contentType)
                    .eTag(eTag)
                    .expires(expires)
                    .tier(tier)
                    .build();
            blob.getMetadata().setContainer(container);
            blob.getMetadata().setCreationDate(creationTime);
            blob.getMetadata().setLastModified(lastModifiedTime);
            blob.getMetadata().setSize(size);
            if (contentRange != null) {
                blob.getAllHeaders().put(HttpHeaders.CONTENT_RANGE, contentRange);
            }
            if (hashCode != null) {
                blob.getMetadata().setETag(BaseEncoding.base16().lowerCase().encode(hashCode.asBytes()));
            }
            return blob;
        } catch (NoSuchFileException nsfe) {
            return null;
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }

    @Override
    public final String putBlob(String container, Blob blob) {
        return putBlob(container, blob, new PutOptions());
    }

    @Override
    public final String putBlob(String container, Blob blob, PutOptions options) {
        if (!containerExists(container)) {
            throw new ContainerNotFoundException(container, "");
        }

        var containerPath = root.resolve(container);
        var path = containerPath.resolve(blob.getMetadata().getName());
        checkValidPath(containerPath, path);
        // TODO: should we use a known suffix to filter these out during list?
        var tmpPath = root.resolve(container).resolve(blob.getMetadata().getName() + "-" + UUID.randomUUID());
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

            var view = Files.getFileAttributeView(path, UserDefinedFileAttributeView.class);
            try {
                writeCommonMetadataAttr(view, blob);
                view.write(XATTR_CONTENT_MD5, ByteBuffer.wrap(DIRECTORY_MD5));
            } catch (IOException ioe) {
                throw new RuntimeException(ioe);
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
        try (var is = new HashingInputStream(Hashing.md5(), blob.getPayload().openStream());
             var os = Files.newOutputStream(tmpPath)) {
            var count = is.transferTo(os);
            var actualHashCode = is.hash();
            var expectedHashCode = metadata.getContentMD5AsHashCode();
            if (expectedHashCode != null && !actualHashCode.equals(expectedHashCode)) {
                Files.delete(tmpPath);
                throw returnResponseException(400);
            }

            var view = Files.getFileAttributeView(tmpPath, UserDefinedFileAttributeView.class);
            if (view != null) {
                try {
                    var eTag = actualHashCode.asBytes();
                    view.write(XATTR_CONTENT_MD5, ByteBuffer.wrap(eTag));
                    writeStringAttributeIfPresent(view, XATTR_CACHE_CONTROL, metadata.getCacheControl());
                    writeStringAttributeIfPresent(view, XATTR_CONTENT_DISPOSITION, metadata.getContentDisposition());
                    writeStringAttributeIfPresent(view, XATTR_CONTENT_ENCODING, metadata.getContentEncoding());
                    writeStringAttributeIfPresent(view, XATTR_CONTENT_LANGUAGE, metadata.getContentLanguage());
                    writeStringAttributeIfPresent(view, XATTR_CONTENT_TYPE, metadata.getContentType());
                    var expires = metadata.getExpires();
                    if (expires != null) {
                        ByteBuffer buf = ByteBuffer.allocate(Longs.BYTES).putLong(expires.getTime());
                        buf.flip();
                        view.write(XATTR_EXPIRES, buf);
                    }
                    writeStringAttributeIfPresent(view, XATTR_STORAGE_TIER, blob.getMetadata().getTier().toString());
                    for (var entry : blob.getMetadata().getUserMetadata().entrySet()) {
                        writeStringAttributeIfPresent(view, XATTR_USER_METADATA_PREFIX + entry.getKey(), entry.getValue());
                    }
                } catch (IOException e) {
                    // TODO:
                    //logger.debug("xattrs not supported on %s", path);
                }
            }

            Files.move(tmpPath, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);

            setBlobAccess(container, blob.getMetadata().getName(), options.getBlobAccess());

            return "\"" + actualHashCode + "\"";
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }

    @Override
    public final String copyBlob(String fromContainer, String fromName,
            String toContainer, String toName, CopyOptions options) {
        var blob = getBlob(fromContainer, fromName);
        if (blob == null) {
            throw new KeyNotFoundException(fromContainer, fromName, "while copying");
        }

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
            if (options.ifUnmodifiedSince() != null && lastModified.compareTo(options.ifUnmodifiedSince()) >= 0) {
                throw returnResponseException(412);
            }
        }

        try (var is = blob.getPayload().openStream()) {
            var metadata = blob.getMetadata().getContentMetadata();
            var builder = blobBuilder(toName).payload(is);
            Long contentLength = metadata.getContentLength();
            if (contentLength != null) {
                builder.contentLength(contentLength);
            }

            var contentMetadata = options.contentMetadata();
            if (contentMetadata != null) {
                String cacheControl = contentMetadata.getCacheControl();
                if (cacheControl != null) {
                    builder.cacheControl(cacheControl);
                }
                String contentDisposition = contentMetadata.getContentDisposition();
                if (contentDisposition != null) {
                    builder.contentDisposition(contentDisposition);
                }
                String contentEncoding = contentMetadata.getContentEncoding();
                if (contentEncoding != null) {
                    builder.contentEncoding(contentEncoding);
                }
                String contentLanguage = contentMetadata.getContentLanguage();
                if (contentLanguage != null) {
                    builder.contentLanguage(contentLanguage);
                }
                String contentType = contentMetadata.getContentType();
                if (contentType != null) {
                    builder.contentType(contentType);
                }
            } else {
                builder.cacheControl(metadata.getCacheControl())
                        .contentDisposition(metadata.getContentDisposition())
                        .contentEncoding(metadata.getContentEncoding())
                        .contentLanguage(metadata.getContentLanguage())
                        .contentType(metadata.getContentType());
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
            var containerPath = root.resolve(container);
            var path = containerPath.resolve(key).normalize();
            checkValidPath(containerPath, path);
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
        Blob blob = getBlob(container, key);
        if (blob == null) {
            return null;
        }

        try {
            blob.getPayload().openStream().close();
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
        return blob != null ? (BlobMetadata) BlobStoreUtils.copy(blob.getMetadata()) : null;
    }

    @Override
    protected final boolean deleteAndVerifyContainerGone(String container) {
        deleteContainer(container);
        return !containerExists(container);
    }

    @Override
    public final ContainerAccess getContainerAccess(String container) {
        if (!containerExists(container)) {
            throw new ContainerNotFoundException(container, "");
        }

        var path = root.resolve(container);
        Set<PosixFilePermission> permissions;
        try {
            permissions = Files.getPosixFilePermissions(path);
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
        return permissions.contains(PosixFilePermission.OTHERS_READ) ?
                ContainerAccess.PUBLIC_READ : ContainerAccess.PRIVATE;
    }

    @Override
    public final void setContainerAccess(String container, ContainerAccess access) {
        if (!containerExists(container)) {
            throw new ContainerNotFoundException(container, "");
        }

        var path = root.resolve(container);
        Set<PosixFilePermission> permissions;
        try {
            permissions = new HashSet<>(Files.getPosixFilePermissions(path));
            if (access == ContainerAccess.PRIVATE) {
                permissions.remove(PosixFilePermission.OTHERS_READ);
            } else if (access == ContainerAccess.PUBLIC_READ) {
                permissions.add(PosixFilePermission.OTHERS_READ);
            }
            Files.setPosixFilePermissions(path, permissions);
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }

    @Override
    public final BlobAccess getBlobAccess(String container, String key) {
        if (!containerExists(container)) {
            throw new ContainerNotFoundException(container, "");
        }
        if (!blobExists(container, key)) {
            throw new KeyNotFoundException(container, key, "");
        }

        var containerPath = root.resolve(container);
        var path = containerPath.resolve(key).normalize();
        checkValidPath(containerPath, path);

        Set<PosixFilePermission> permissions;
        try {
            permissions = Files.getPosixFilePermissions(path);
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
        return permissions.contains(PosixFilePermission.OTHERS_READ) ?
                BlobAccess.PUBLIC_READ : BlobAccess.PRIVATE;
    }

    @Override
    public final void setBlobAccess(String container, String key, BlobAccess access) {
        if (!containerExists(container)) {
            throw new ContainerNotFoundException(container, "");
        }
        if (!blobExists(container, key)) {
            throw new KeyNotFoundException(container, key, "");
        }

        var containerPath = root.resolve(container);
        var path = containerPath.resolve(key).normalize();
        checkValidPath(containerPath, path);

        Set<PosixFilePermission> permissions;
        try {
            permissions = new HashSet<>(Files.getPosixFilePermissions(path));
            if (access == BlobAccess.PRIVATE) {
                permissions.remove(PosixFilePermission.OTHERS_READ);
            } else if (access == BlobAccess.PUBLIC_READ) {
                permissions.add(PosixFilePermission.OTHERS_READ);
            }
            Files.setPosixFilePermissions(path, permissions);
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }

    @Override
    public final MultipartUpload initiateMultipartUpload(String container,
            BlobMetadata blobMetadata, PutOptions options) {
        var uploadId = UUID.randomUUID().toString();
        // create a stub blob
        var blob = blobBuilder(MULTIPART_PREFIX + uploadId + "-" + blobMetadata.getName() + "-stub").payload(ByteSource.empty()).build();
        putBlob(container, blob);
        return MultipartUpload.create(container, blobMetadata.getName(), uploadId,
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
        var md5Hasher = Hashing.md5().newHasher();

        for (var part : parts) {
            var meta = blobMetadata(mpu.containerName(), MULTIPART_PREFIX + mpu.id() + "-" + mpu.blobName() + "-" + part.partNumber());
            contentLength += meta.getContentMetadata().getContentLength();
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
        var blobBuilder = blobBuilder(mpu.blobName())
                .userMetadata(mpu.blobMetadata().getUserMetadata())
                .payload(new MultiBlobInputStream(this, metas.build()))
                .contentLength(contentLength)
                .eTag(mpuETag);
        var cacheControl = mpu.blobMetadata().getContentMetadata().getCacheControl();
        if (cacheControl != null) {
            blobBuilder.cacheControl(cacheControl);
        }
        var contentDisposition = mpu.blobMetadata().getContentMetadata().getContentDisposition();
        if (contentDisposition != null) {
            blobBuilder.contentDisposition(contentDisposition);
        }
        var contentEncoding = mpu.blobMetadata().getContentMetadata().getContentEncoding();
        if (contentEncoding != null) {
            blobBuilder.contentEncoding(contentEncoding);
        }
        var contentLanguage = mpu.blobMetadata().getContentMetadata().getContentLanguage();
        if (contentLanguage != null) {
            blobBuilder.contentLanguage(contentLanguage);
        }
        // intentionally not copying MD5
        var contentType = mpu.blobMetadata().getContentMetadata().getContentType();
        if (contentType != null) {
            blobBuilder.contentType(contentType);
        }
        var expires = mpu.blobMetadata().getContentMetadata().getExpires();
        if (expires != null) {
            blobBuilder.expires(expires);
        }
        var tier = mpu.blobMetadata().getTier();
        if (tier != null) {
            blobBuilder.tier(tier);
        }

        putBlob(mpu.containerName(), blobBuilder.build());

        for (var part : parts) {
            removeBlob(mpu.containerName(), MULTIPART_PREFIX + mpu.id() + "-" + mpu.blobName() + "-" + part.partNumber());
        }
        removeBlob(mpu.containerName(), MULTIPART_PREFIX + mpu.id() + "-" + mpu.blobName() + "-stub");

        setBlobAccess(mpu.containerName(), mpu.blobName(), mpu.putOptions().getBlobAccess());

        return mpuETag;
    }

    @Override
    public final MultipartPart uploadMultipartPart(MultipartUpload mpu, int partNumber, Payload payload) {
        var partName = MULTIPART_PREFIX + mpu.id() + "-" + mpu.blobName() + "-" + partNumber;
        var blob = blobBuilder(partName)
                .payload(payload)
                .build();
        var partETag = putBlob(mpu.containerName(), blob);
        var metadata = blobMetadata(mpu.containerName(), partName);  // TODO: racy, how to get this from payload?
        var partSize = metadata.getContentMetadata().getContentLength();
        return MultipartPart.create(partNumber, partSize, partETag, metadata.getLastModified());
    }

    @Override
    public final List<MultipartPart> listMultipartUpload(MultipartUpload mpu) {
        var parts = ImmutableList.<MultipartPart>builder();
        var options =
                new ListContainerOptions().prefix(MULTIPART_PREFIX + mpu.id() + "-" + mpu.blobName() + "-").recursive();
        while (true) {
            var pageSet = list(mpu.containerName(), options);
            for (var sm : pageSet) {
                if (sm.getName().endsWith("-stub")) {
                    continue;
                }
                int partNumber = Integer.parseInt(sm.getName().substring((MULTIPART_PREFIX + mpu.id() + "-" + mpu.blobName() + "-").length()));
                long partSize = sm.getSize();
                parts.add(MultipartPart.create(partNumber, partSize, sm.getETag(), sm.getLastModified()));
            }
            if (pageSet.isEmpty() || pageSet.getNextMarker() == null) {
                break;
            }
            options.afterMarker(pageSet.getNextMarker());
        }
        return parts.build();
    }

    @Override
    public final List<MultipartUpload> listMultipartUploads(String container) {
        var mpus = ImmutableList.<MultipartUpload>builder();
        var options = new ListContainerOptions().prefix(MULTIPART_PREFIX).recursive();
        int uuidLength = UUID.randomUUID().toString().length();
        while (true) {
            var pageSet = list(container, options);
            for (StorageMetadata sm : pageSet) {
                if (!sm.getName().endsWith("-stub")) {
                    continue;
                }
                var uploadId = sm.getName().substring(MULTIPART_PREFIX.length(), MULTIPART_PREFIX.length() + uuidLength);
                var blobName = sm.getName().substring(MULTIPART_PREFIX.length() + uuidLength + 1);
                int index = blobName.lastIndexOf('-');
                blobName = blobName.substring(0, index);

                mpus.add(MultipartUpload.create(container, blobName, uploadId, null, null));
            }
            if (pageSet.isEmpty() || pageSet.getNextMarker() == null) {
                break;
            }
            options.afterMarker(pageSet.getNextMarker());
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

    @Override
    public final int getMaximumNumberOfParts() {
        return 50 * 1000;
    }

    @Override
    public final InputStream streamBlob(String container, String name) {
        throw new UnsupportedOperationException("not yet implemented");
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
                    BlobMetadata meta = metas.next();
                    current = blobStore.getBlob(meta.getContainer(), meta.getName()).getPayload().openStream();
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
            while (true) {
                if (current == null) {
                    if (!metas.hasNext()) {
                        return -1;
                    }
                    BlobMetadata meta = metas.next();
                    current = blobStore.getBlob(meta.getContainer(), meta.getName()).getPayload().openStream();
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

        @Override
        public void close() throws IOException {
            if (current != null) {
                current.close();
                current = null;
            }
        }
    }

    private static HttpResponseException returnResponseException(int code) {
        var response = HttpResponse.builder().statusCode(code).build();
        return new HttpResponseException(new HttpCommand(HttpRequest.builder()
                .method("GET")
                .endpoint("http://stub")
                .build()), response);
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
        while (true) {
            var parent = path.getParent();
            if (parent == null || path.equals(containerPath)) {
                break;
            }
            var view = Files.getFileAttributeView(path, UserDefinedFileAttributeView.class);
            if (view != null && Set.copyOf(view.list()).contains(XATTR_CONTENT_MD5)) {
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
        writeStringAttributeIfPresent(view, XATTR_CACHE_CONTROL, metadata.getCacheControl());
        writeStringAttributeIfPresent(view, XATTR_CONTENT_DISPOSITION, metadata.getContentDisposition());
        writeStringAttributeIfPresent(view, XATTR_CONTENT_ENCODING, metadata.getContentEncoding());
        writeStringAttributeIfPresent(view, XATTR_CONTENT_LANGUAGE, metadata.getContentLanguage());
        writeStringAttributeIfPresent(view, XATTR_CONTENT_TYPE, metadata.getContentType());
        var expires = metadata.getExpires();
        if (expires != null) {
            var buf = ByteBuffer.allocate(Longs.BYTES).putLong(expires.getTime());
            buf.flip();
            view.write(XATTR_EXPIRES, buf);
        }
        writeStringAttributeIfPresent(view, XATTR_STORAGE_TIER, blob.getMetadata().getTier().toString());
        for (var entry : blob.getMetadata().getUserMetadata().entrySet()) {
            writeStringAttributeIfPresent(view, XATTR_USER_METADATA_PREFIX + entry.getKey(), entry.getValue());
        }
    }

    private static void checkValidPath(Path container, Path path) {
        if (!path.normalize().startsWith(container)) {
            throw new IllegalArgumentException("Invalid key name: path traversal attempt detected: " + path);
        }
    }
}
