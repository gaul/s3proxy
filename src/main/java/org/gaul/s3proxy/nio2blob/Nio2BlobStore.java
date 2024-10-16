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

package org.gaul.s3proxy.nio2blob;

import static java.util.Objects.requireNonNull;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.FileSystem;
import java.nio.file.NoSuchFileException;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.UserDefinedFileAttributeView;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.common.base.Supplier;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.hash.HashCode;
import com.google.common.hash.Hashing;
import com.google.common.hash.HashingInputStream;
import com.google.common.jimfs.Configuration;
import com.google.common.jimfs.Jimfs;
import com.google.common.primitives.Longs;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

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
import org.jclouds.blobstore.util.BlobStoreUtils;
import org.jclouds.collect.Memoized;
import org.jclouds.domain.Credentials;
import org.jclouds.domain.Location;
import org.jclouds.io.ContentMetadataBuilder;
import org.jclouds.io.Payload;
import org.jclouds.io.PayloadSlicer;

@Singleton
public final class Nio2BlobStore extends BaseBlobStore {
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

    private final Supplier<Set<? extends Location>> locations;
    private final FileSystem fs;

    @Inject
    Nio2BlobStore(BlobStoreContext context, BlobUtils blobUtils,
            Supplier<Location> defaultLocation,
            @Memoized Supplier<Set<? extends Location>> locations,
            PayloadSlicer slicer,
            @org.jclouds.location.Provider Supplier<Credentials> creds) {
        super(context, blobUtils, defaultLocation, locations, slicer);
        this.locations = requireNonNull(locations, "locations");
        this.fs = Jimfs.newFileSystem(Configuration.unix().toBuilder()
                .setAttributeViews("basic", "user")
                .build());
    }

    @Override
    public Set<? extends Location> listAssignableLocations() {
        return locations.get();
    }

    @Override
    public PageSet<? extends StorageMetadata> list() {
        var set = ImmutableSet.<StorageMetadata>builder();
        try (var stream = Files.newDirectoryStream(fs.getPath("/"))) {
            for (var path : stream) {
                var attr = Files.readAttributes(path, BasicFileAttributes.class);
                var lastModifiedTime = new Date(attr.lastModifiedTime().toMillis());
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
    public PageSet<? extends StorageMetadata> list(String container,
            ListContainerOptions options) {
        var set = ImmutableSet.<StorageMetadata>builder();
        try (var stream = Files.newDirectoryStream(fs.getPath("/" + container))) {
            for (var path : stream) {
                var attr = Files.readAttributes(path, BasicFileAttributes.class);
                var lastModifiedTime = new Date(attr.lastModifiedTime().toMillis());
                var creationTime = new Date(attr.creationTime().toMillis());
                set.add(new StorageMetadataImpl(StorageType.CONTAINER,
                        /*id=*/ null, path.getFileName().toString(),
                        /*location=*/ null, /*uri=*/ null,
                        /*eTag=*/ null, creationTime, lastModifiedTime,
                        Map.of(), attr.size(), Tier.STANDARD));
            }
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
        return new PageSetImpl<StorageMetadata>(set.build(), null);
    }

    @Override
    public boolean containerExists(String container) {
        return Files.exists(fs.getPath("/" + container));
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
        try {
            Files.createDirectory(fs.getPath("/" + container));
        } catch (FileAlreadyExistsException faee) {
            return false;
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
        return true;
    }

    @Override
    public void deleteContainer(String container) {
        try {
            Files.deleteIfExists(fs.getPath("/" + container));
        } catch (DirectoryNotEmptyException dnee) {
            // TODO: what to do?
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }

    @Override
    public boolean blobExists(String container, String key) {
        throw new UnsupportedOperationException("not yet implemented");
    }

    // TODO: range requests
    @Override
    public Blob getBlob(String container, String key, GetOptions options) {
        var path = fs.getPath("/" + container + "/" + key);
        try {
            var attr = Files.readAttributes(path, BasicFileAttributes.class);
            var view = Files.getFileAttributeView(path, UserDefinedFileAttributeView.class);
            var attributes = Set.copyOf(view.list());
            var cacheControl = readStringAttributeIfPresent(view, attributes, XATTR_CACHE_CONTROL);
            var contentDisposition = readStringAttributeIfPresent(view, attributes, XATTR_CONTENT_DISPOSITION);
            var contentEncoding = readStringAttributeIfPresent(view, attributes, XATTR_CONTENT_ENCODING);
            var contentLanguage = readStringAttributeIfPresent(view, attributes, XATTR_CONTENT_LANGUAGE);
            var contentType = readStringAttributeIfPresent(view, attributes, XATTR_CONTENT_TYPE);
            Date expires = null;
            HashCode hashCode = null;
            String eTag = null;
            var tier = Tier.STANDARD;
            var userMetadata = ImmutableMap.<String, String>builder();
            //var lastModifiedTime = new Date(attr.lastModifiedTime().toMillis());
            //var creationTime = new Date(attr.creationTime().toMillis());

            if (attributes.contains(XATTR_CONTENT_MD5)) {
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
            String tierString = readStringAttributeIfPresent(view, attributes, XATTR_STORAGE_TIER);
            if (tierString != null) {
                tier = Tier.valueOf(tierString);
            }
            for (String attribute : attributes) {
                if (!attribute.startsWith(XATTR_USER_METADATA_PREFIX)) {
                    continue;
                }
                String value = readStringAttributeIfPresent(view, attributes, attribute);
                userMetadata.put(attribute.substring(XATTR_USER_METADATA_PREFIX.length()), value);
            }
            return new BlobBuilderImpl()
                    .name(key)
                    .userMetadata(userMetadata.build())
                    .payload(Files.newInputStream(path))
                    .cacheControl(cacheControl)
                    .contentDisposition(contentDisposition)
                    .contentEncoding(contentEncoding)
                    .contentLanguage(contentLanguage)
                    .contentLength(attr.size())
                    .contentMD5(hashCode)
                    .contentType(contentType)
                    .eTag(eTag)
                    .expires(expires)
                    .build();
        } catch (NoSuchFileException nsfe) {
            return null;
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }

    @Override
    public String putBlob(String container, Blob blob) {
        return putBlob(container, blob, new PutOptions());
    }

    @Override
    public String putBlob(String container, Blob blob, PutOptions options) {
        var path = fs.getPath("/" + container + "/" + blob.getMetadata().getName());
        var metadata = blob.getMetadata().getContentMetadata();
        try (var is = new HashingInputStream(Hashing.md5(), blob.getPayload().openStream());
             var os = Files.newOutputStream(path)) {
            var count = is.transferTo(os);
            var hashCode = is.hash();

            var view = Files.getFileAttributeView(path, UserDefinedFileAttributeView.class);
            if (view != null) {
                try {
                    var eTag = hashCode.asBytes();
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

            // TODO: atomic replace

            return "\"" + hashCode + "\"";
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
        try {
            Files.delete(fs.getPath("/" + container + "/" + key));
        } catch (NoSuchFileException nsfe) {
            return;
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }

    @Override
    public BlobMetadata blobMetadata(String container, String key) {
        Blob blob = getBlob(container, key);
        try {
            blob.getPayload().openStream().close();
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
        return blob != null ? (BlobMetadata) BlobStoreUtils.copy(blob.getMetadata()) : null;
    }

    @Override
    protected boolean deleteAndVerifyContainerGone(String container) {
        deleteContainer(container);
        return !containerExists(container);
    }

    @Override
    public ContainerAccess getContainerAccess(String container) {
        throw new UnsupportedOperationException("not yet implemented");
    }

    @Override
    public void setContainerAccess(String container, ContainerAccess access) {
        throw new UnsupportedOperationException("not yet implemented");
    }

    @Override
    public BlobAccess getBlobAccess(String container, String key) {
        //return BlobAccess.PRIVATE;
        throw new UnsupportedOperationException("not yet implemented");
    }

    @Override
    public void setBlobAccess(String container, String key, BlobAccess access) {
        throw new UnsupportedOperationException("unsupported in Azure");
    }

    @Override
    public MultipartUpload initiateMultipartUpload(String container,
            BlobMetadata blobMetadata, PutOptions options) {
        throw new UnsupportedOperationException("unsupported in Azure");
    }

    @Override
    public void abortMultipartUpload(MultipartUpload mpu) {
        throw new UnsupportedOperationException("not yet implemented");
    }

    @Override
    public String completeMultipartUpload(MultipartUpload mpu,
            List<MultipartPart> parts) {
        throw new UnsupportedOperationException("not yet implemented");
    }

    @Override
    public MultipartPart uploadMultipartPart(MultipartUpload mpu,
            int partNumber, Payload payload) {
        throw new UnsupportedOperationException("not yet implemented");
    }

    @Override
    public List<MultipartPart> listMultipartUpload(MultipartUpload mpu) {
        throw new UnsupportedOperationException("not yet implemented");
    }

    @Override
    public List<MultipartUpload> listMultipartUploads(String container) {
        throw new UnsupportedOperationException("not yet implemented");
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
}
