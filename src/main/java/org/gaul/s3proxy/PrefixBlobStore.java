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

package org.gaul.s3proxy;

import static com.google.common.base.Preconditions.checkArgument;
import static java.util.Objects.requireNonNull;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;

import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.domain.Blob;
import org.jclouds.blobstore.domain.BlobAccess;
import org.jclouds.blobstore.domain.BlobMetadata;
import org.jclouds.blobstore.domain.MultipartPart;
import org.jclouds.blobstore.domain.MultipartUpload;
import org.jclouds.blobstore.domain.PageSet;
import org.jclouds.blobstore.domain.StorageMetadata;
import org.jclouds.blobstore.domain.internal.MutableBlobMetadataImpl;
import org.jclouds.blobstore.domain.internal.MutableStorageMetadataImpl;
import org.jclouds.blobstore.domain.internal.PageSetImpl;
import org.jclouds.blobstore.options.CopyOptions;
import org.jclouds.blobstore.options.GetOptions;
import org.jclouds.blobstore.options.ListContainerOptions;
import org.jclouds.blobstore.options.PutOptions;
import org.jclouds.blobstore.util.ForwardingBlobStore;
import org.jclouds.io.Payload;

/**
 * Middleware that scopes a virtual bucket to a fixed backend prefix.
 */
public final class PrefixBlobStore extends ForwardingBlobStore {
    private final Map<String, String> prefixes;

    private PrefixBlobStore(BlobStore delegate, Map<String, String> prefixes) {
        super(delegate);
        this.prefixes = ImmutableMap.copyOf(requireNonNull(prefixes));
    }

    static BlobStore newPrefixBlobStore(BlobStore delegate,
            Map<String, String> prefixes) {
        return new PrefixBlobStore(delegate, prefixes);
    }

    public static Map<String, String> parsePrefixes(Properties properties) {
        Map<String, String> prefixMap = new HashMap<>();
        for (String key : properties.stringPropertyNames()) {
            if (!key.startsWith(S3ProxyConstants.PROPERTY_PREFIX_BLOBSTORE + ".")) {
                continue;
            }
            String bucket = key.substring(
                    S3ProxyConstants.PROPERTY_PREFIX_BLOBSTORE.length() + 1);
            String prefix = properties.getProperty(key);
            checkArgument(!Strings.isNullOrEmpty(bucket),
                    "Prefix property %s must specify a bucket", key);
            checkArgument(!Strings.isNullOrEmpty(prefix),
                    "Prefix for bucket %s must not be empty", bucket);
            checkArgument(prefixMap.put(bucket, prefix) == null,
                    "Multiple prefixes configured for bucket %s", bucket);
        }
        return ImmutableMap.copyOf(prefixMap);
    }

    private boolean hasPrefix(String container) {
        return this.prefixes.containsKey(container);
    }

    private String getPrefix(String container) {
        return this.prefixes.get(container);
    }

    private String addPrefix(String container, String name) {
        if (!hasPrefix(container) || Strings.isNullOrEmpty(name)) {
            return name;
        }
        String prefix = getPrefix(container);
        if (name.startsWith(prefix)) {
            return name;
        }
        if (prefix.endsWith("/") && name.startsWith("/")) {
            return prefix + name.substring(1);
        }
        return prefix + name;
    }

    private String trimPrefix(String container, String name) {
        if (!hasPrefix(container) || Strings.isNullOrEmpty(name)) {
            return name;
        }
        String prefix = getPrefix(container);
        if (name.startsWith(prefix)) {
            return name.substring(prefix.length());
        }
        return name;
    }

    private BlobMetadata trimBlobMetadata(String container,
            BlobMetadata metadata) {
        if (metadata == null || !hasPrefix(container)) {
            return metadata;
        }
        var mutable = new MutableBlobMetadataImpl(metadata);
        mutable.setName(trimPrefix(container, metadata.getName()));
        return mutable;
    }

    private Blob trimBlob(String container, Blob blob) {
        if (blob == null || !hasPrefix(container)) {
            return blob;
        }
        blob.getMetadata().setName(
                trimPrefix(container, blob.getMetadata().getName()));
        return blob;
    }

    private MultipartUpload toDelegateMultipartUpload(MultipartUpload upload) {
        if (upload == null || !hasPrefix(upload.containerName())) {
            return upload;
        }
        var metadata = upload.blobMetadata() == null ? null :
                new MutableBlobMetadataImpl(upload.blobMetadata());
        if (metadata != null) {
            metadata.setName(
                    addPrefix(upload.containerName(), metadata.getName()));
        }
        return MultipartUpload.create(upload.containerName(),
                addPrefix(upload.containerName(), upload.blobName()),
                upload.id(), metadata, upload.putOptions());
    }

    private MultipartUpload toClientMultipartUpload(MultipartUpload upload) {
        if (upload == null || !hasPrefix(upload.containerName())) {
            return upload;
        }
        var metadata = upload.blobMetadata() == null ? null :
                new MutableBlobMetadataImpl(upload.blobMetadata());
        if (metadata != null) {
            metadata.setName(
                    trimPrefix(upload.containerName(), metadata.getName()));
        }
        return MultipartUpload.create(upload.containerName(),
                trimPrefix(upload.containerName(), upload.blobName()),
                upload.id(), metadata, upload.putOptions());
    }

    private ListContainerOptions applyPrefix(String container,
            ListContainerOptions options) {
        if (!hasPrefix(container)) {
            return options;
        }
        ListContainerOptions effective = options == null ?
                new ListContainerOptions() : options.clone();
        String basePrefix = getPrefix(container);
        String requestedPrefix = effective.getPrefix();
        String requestedMarker = effective.getMarker();
        String requestedDir = effective.getDir();

        if (Strings.isNullOrEmpty(requestedPrefix)) {
            effective.prefix(basePrefix);
        } else {
            effective.prefix(addPrefix(container, requestedPrefix));
        }

        if (!Strings.isNullOrEmpty(requestedMarker)) {
            effective.afterMarker(addPrefix(container, requestedMarker));
        }

        if (!Strings.isNullOrEmpty(requestedDir)) {
            effective.inDirectory(addPrefix(container, requestedDir));
        }

        return effective;
    }

    private PageSet<? extends StorageMetadata> trimListing(String container,
            PageSet<? extends StorageMetadata> listing) {
        if (!hasPrefix(container)) {
            return listing;
        }
        var builder = ImmutableList.<StorageMetadata>builder();
        for (StorageMetadata metadata : listing) {
            if (metadata instanceof BlobMetadata blobMetadata) {
                var mutable = new MutableBlobMetadataImpl(blobMetadata);
                mutable.setName(trimPrefix(container, blobMetadata.getName()));
                builder.add(mutable);
            } else {
                var mutable = new MutableStorageMetadataImpl(metadata);
                mutable.setName(trimPrefix(container, metadata.getName()));
                builder.add(mutable);
            }
        }
        String nextMarker = listing.getNextMarker();
        if (nextMarker != null) {
            nextMarker = trimPrefix(container, nextMarker);
        }
        return new PageSetImpl<>(builder.build(), nextMarker);
    }

    @Override
    public boolean directoryExists(String container, String directory) {
        return super.directoryExists(container,
                addPrefix(container, directory));
    }

    @Override
    public void createDirectory(String container, String directory) {
        super.createDirectory(container, addPrefix(container, directory));
    }

    @Override
    public void deleteDirectory(String container, String directory) {
        super.deleteDirectory(container, addPrefix(container, directory));
    }

    @Override
    public boolean blobExists(String container, String name) {
        return super.blobExists(container, addPrefix(container, name));
    }

    @Override
    public BlobMetadata blobMetadata(String container, String name) {
        return trimBlobMetadata(container,
                super.blobMetadata(container, addPrefix(container, name)));
    }

    @Override
    public Blob getBlob(String containerName, String blobName) {
        return trimBlob(containerName,
                super.getBlob(containerName, addPrefix(containerName,
                        blobName)));
    }

    @Override
    public Blob getBlob(String containerName, String blobName,
                        GetOptions getOptions) {
        return trimBlob(containerName,
                super.getBlob(containerName, addPrefix(containerName,
                        blobName), getOptions));
    }

    @Override
    public String putBlob(String containerName, Blob blob) {
        String originalName = blob.getMetadata().getName();
        blob.getMetadata().setName(addPrefix(containerName, originalName));
        try {
            return super.putBlob(containerName, blob);
        } finally {
            blob.getMetadata().setName(originalName);
        }
    }

    @Override
    public String putBlob(String containerName, Blob blob,
                          PutOptions options) {
        String originalName = blob.getMetadata().getName();
        blob.getMetadata().setName(addPrefix(containerName, originalName));
        try {
            return super.putBlob(containerName, blob, options);
        } finally {
            blob.getMetadata().setName(originalName);
        }
    }

    @Override
    public void removeBlob(String container, String name) {
        super.removeBlob(container, addPrefix(container, name));
    }

    @Override
    public void removeBlobs(String container, Iterable<String> names) {
        if (!hasPrefix(container)) {
            super.removeBlobs(container, names);
            return;
        }
        var builder = ImmutableList.<String>builder();
        for (String name : names) {
            builder.add(addPrefix(container, name));
        }
        super.removeBlobs(container, builder.build());
    }

    @Override
    public BlobAccess getBlobAccess(String container, String name) {
        return super.getBlobAccess(container, addPrefix(container, name));
    }

    @Override
    public void setBlobAccess(String container, String name,
            BlobAccess access) {
        super.setBlobAccess(container, addPrefix(container, name), access);
    }

    @Override
    public String copyBlob(String fromContainer, String fromName,
            String toContainer, String toName, CopyOptions options) {
        return super.copyBlob(fromContainer, addPrefix(fromContainer, fromName),
                toContainer, addPrefix(toContainer, toName), options);
    }

    @Override
    public PageSet<? extends StorageMetadata> list(String container) {
        if (!hasPrefix(container)) {
            return super.list(container);
        }
        return list(container, new ListContainerOptions());
    }

    @Override
    public PageSet<? extends StorageMetadata> list(String container,
            ListContainerOptions options) {
        if (!hasPrefix(container)) {
            return super.list(container, options);
        }
        var effective = applyPrefix(container, options);
        return trimListing(container, super.list(container, effective));
    }

    @Override
    public void clearContainer(String container) {
        if (!hasPrefix(container)) {
            super.clearContainer(container);
            return;
        }
        var options = new ListContainerOptions()
                .prefix(getPrefix(container))
                .recursive();
        super.clearContainer(container, options);
    }

    @Override
    public void clearContainer(String container, ListContainerOptions options) {
        if (!hasPrefix(container)) {
            super.clearContainer(container, options);
            return;
        }
        super.clearContainer(container, applyPrefix(container, options));
    }

    @Override
    public MultipartUpload initiateMultipartUpload(String container,
            BlobMetadata blobMetadata, PutOptions options) {
        var mutable = new MutableBlobMetadataImpl(blobMetadata);
        mutable.setName(addPrefix(container, blobMetadata.getName()));
        MultipartUpload upload = super.initiateMultipartUpload(container,
                mutable, options);
        return toClientMultipartUpload(upload);
    }

    @Override
    public void abortMultipartUpload(MultipartUpload mpu) {
        super.abortMultipartUpload(toDelegateMultipartUpload(mpu));
    }

    @Override
    public String completeMultipartUpload(MultipartUpload mpu,
            List<MultipartPart> parts) {
        return super.completeMultipartUpload(
                toDelegateMultipartUpload(mpu), parts);
    }

    @Override
    public MultipartPart uploadMultipartPart(MultipartUpload mpu,
            int partNumber, Payload payload) {
        return super.uploadMultipartPart(
                toDelegateMultipartUpload(mpu), partNumber, payload);
    }

    @Override
    public List<MultipartPart> listMultipartUpload(MultipartUpload mpu) {
        return super.listMultipartUpload(toDelegateMultipartUpload(mpu));
    }

    @Override
    public List<MultipartUpload> listMultipartUploads(String container) {
        List<MultipartUpload> uploads =
                super.listMultipartUploads(container);
        if (!hasPrefix(container)) {
            return uploads;
        }
        var builder = ImmutableList.<MultipartUpload>builder();
        for (MultipartUpload upload : uploads) {
            builder.add(toClientMultipartUpload(upload));
        }
        return builder.build();
    }
}

