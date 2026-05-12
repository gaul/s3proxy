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

package org.gaul.s3proxy;

import static com.google.common.base.Preconditions.checkArgument;
import static java.util.Objects.requireNonNull;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.ForwardingBlobStore;
import org.gaul.s3proxy.blobstore.Payload;
import org.gaul.s3proxy.blobstore.domain.Blob;
import org.gaul.s3proxy.blobstore.domain.BlobAccess;
import org.gaul.s3proxy.blobstore.domain.BlobMetadata;
import org.gaul.s3proxy.blobstore.domain.ContainerMetadata;
import org.gaul.s3proxy.blobstore.domain.MultipartPart;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.gaul.s3proxy.blobstore.domain.PageSet;
import org.gaul.s3proxy.blobstore.domain.StorageMetadata;
import org.gaul.s3proxy.blobstore.options.CopyOptions;
import org.gaul.s3proxy.blobstore.options.GetOptions;
import org.gaul.s3proxy.blobstore.options.ListContainerOptions;
import org.gaul.s3proxy.blobstore.options.PutOptions;

/**
 * Middleware that scopes a virtual bucket to a fixed backend prefix.
 */
public final class PrefixBlobStore extends ForwardingBlobStore {
    private final Map<String, String> prefixes;

    private PrefixBlobStore(BlobStore delegate, Map<String, String> prefixes) {
        super(delegate);
        this.prefixes = Map.copyOf(requireNonNull(prefixes));
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
        return Map.copyOf(prefixMap);
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
        return metadata.toBuilder()
                .name(trimPrefix(container, metadata.getName()))
                .build();
    }

    private Blob trimBlob(String container, Blob blob) {
        if (blob == null || !hasPrefix(container)) {
            return blob;
        }
        return blob.toBuilder().name(
                trimPrefix(container, blob.getMetadata().getName())).build();
    }

    private MultipartUpload toDelegateMultipartUpload(MultipartUpload upload) {
        if (upload == null || !hasPrefix(upload.containerName())) {
            return upload;
        }
        var metadata = upload.blobMetadata() == null ? null :
                upload.blobMetadata().toBuilder()
                        .name(addPrefix(upload.containerName(),
                                upload.blobMetadata().getName()))
                        .build();
        return new MultipartUpload(upload.containerName(),
                addPrefix(upload.containerName(), upload.blobName()),
                upload.id(), metadata, upload.putOptions());
    }

    private MultipartUpload toClientMultipartUpload(MultipartUpload upload) {
        if (upload == null || !hasPrefix(upload.containerName())) {
            return upload;
        }
        var metadata = upload.blobMetadata() == null ? null :
                upload.blobMetadata().toBuilder()
                        .name(trimPrefix(upload.containerName(),
                                upload.blobMetadata().getName()))
                        .build();
        return new MultipartUpload(upload.containerName(),
                trimPrefix(upload.containerName(), upload.blobName()),
                upload.id(), metadata, upload.putOptions());
    }

    private ListContainerOptions applyPrefix(String container,
            ListContainerOptions options) {
        if (!hasPrefix(container)) {
            return options;
        }
        var builder = options == null ?
                ListContainerOptions.builder() : options.toBuilder();
        String basePrefix = getPrefix(container);
        String requestedPrefix = options == null ? null : options.prefix();
        String requestedMarker = options == null ? null : options.marker();

        if (Strings.isNullOrEmpty(requestedPrefix)) {
            builder.prefix(basePrefix);
        } else {
            builder.prefix(addPrefix(container, requestedPrefix));
        }

        if (!Strings.isNullOrEmpty(requestedMarker)) {
            builder.afterMarker(addPrefix(container, requestedMarker));
        }

        return builder.build();
    }

    private PageSet<? extends StorageMetadata> trimListing(String container,
            PageSet<? extends StorageMetadata> listing) {
        if (!hasPrefix(container)) {
            return listing;
        }
        var builder = ImmutableList.<StorageMetadata>builder();
        for (StorageMetadata metadata : listing) {
            if (metadata instanceof BlobMetadata blobMetadata) {
                builder.add(blobMetadata.toBuilder()
                        .name(trimPrefix(container, blobMetadata.getName()))
                        .build());
            } else if (metadata instanceof ContainerMetadata cm) {
                builder.add(cm.toBuilder()
                        .name(trimPrefix(container, cm.getName()))
                        .build());
            }
        }
        String nextMarker = listing.getNextMarker();
        if (nextMarker != null) {
            nextMarker = trimPrefix(container, nextMarker);
        }
        return new PageSet<>(builder.build(), nextMarker);
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
        return super.putBlob(containerName, blob.toBuilder()
                .name(addPrefix(containerName, blob.getMetadata().getName()))
                .build());
    }

    @Override
    public String putBlob(String containerName, Blob blob,
                          PutOptions options) {
        return super.putBlob(containerName, blob.toBuilder()
                .name(addPrefix(containerName, blob.getMetadata().getName()))
                .build(), options);
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
        return list(container, ListContainerOptions.NONE);
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
        var options = ListContainerOptions.builder()
                .prefix(getPrefix(container))
                .recursive()
                .build();
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
        BlobMetadata renamed = blobMetadata.toBuilder()
                .name(addPrefix(container, blobMetadata.getName()))
                .build();
        MultipartUpload upload = super.initiateMultipartUpload(container,
                renamed, options);
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
