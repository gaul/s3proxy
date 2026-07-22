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

import java.io.InputStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import com.google.common.collect.BiMap;
import com.google.common.collect.ImmutableBiMap;
import com.google.common.collect.ImmutableList;
import com.google.common.hash.HashCode;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.ForwardingBlobStore;
import org.gaul.s3proxy.blobstore.domain.Blob;
import org.gaul.s3proxy.blobstore.domain.BlobAccess;
import org.gaul.s3proxy.blobstore.domain.BlobMetadata;
import org.gaul.s3proxy.blobstore.domain.ContainerAccess;
import org.gaul.s3proxy.blobstore.domain.ContainerMetadata;
import org.gaul.s3proxy.blobstore.domain.MultipartPart;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.gaul.s3proxy.blobstore.domain.PageSet;
import org.gaul.s3proxy.blobstore.domain.StorageMetadata;
import org.gaul.s3proxy.blobstore.options.CopyOptions;
import org.gaul.s3proxy.blobstore.options.CreateContainerOptions;
import org.gaul.s3proxy.blobstore.options.GetOptions;
import org.gaul.s3proxy.blobstore.options.ListContainerOptions;
import org.gaul.s3proxy.blobstore.options.PutOptions;
import org.jspecify.annotations.Nullable;

/**
 * This class implements a middleware to alias buckets to a different name.
 * The aliases are configured as:
 *   s3proxy.alias-blobstore.&lt;alias name&gt; = &lt;backend bucket&gt;
 *
 * The aliases appear in bucket listings if the configured
 * backend buckets are present. Requests for all other buckets are unaffected.
 */
public final class AliasBlobStore extends ForwardingBlobStore {
    private final BiMap<String, String> aliases;

    private AliasBlobStore(BlobStore delegate,
                           BiMap<String, String> aliases) {
        super(delegate);
        this.aliases = requireNonNull(aliases);
    }

    static BlobStore newAliasBlobStore(BlobStore delegate,
                                       BiMap<String, String> aliases) {
        return new AliasBlobStore(delegate, aliases);
    }

    private MultipartUpload getDelegateMpu(MultipartUpload mpu) {
        return new MultipartUpload(
                getContainer(mpu.containerName()),
                mpu.blobName(),
                mpu.id(),
                mpu.blobMetadata(),
                mpu.putOptions());
    }

    private MultipartUpload getClientMpu(MultipartUpload mpu) {
        return new MultipartUpload(
                aliases.inverse().getOrDefault(
                        mpu.containerName(), mpu.containerName()),
                mpu.blobName(),
                mpu.id(),
                mpu.blobMetadata(),
                mpu.putOptions());
    }

    public static ImmutableBiMap<String, String> parseAliases(
            Properties properties) {
        Map<String, String> backendBuckets = new HashMap<>();
        for (String key : properties.stringPropertyNames()) {
            if (key.startsWith(S3ProxyConstants.PROPERTY_ALIAS_BLOBSTORE)) {
                String virtualBucket = key.substring(
                        S3ProxyConstants.PROPERTY_ALIAS_BLOBSTORE.length() + 1);
                String backendBucket = properties.getProperty(key);
                checkArgument(
                        !backendBuckets.containsKey(backendBucket),
                        "Backend bucket %s is aliased twice",
                        backendBucket);
                backendBuckets.put(backendBucket, virtualBucket);
            }
        }
        return ImmutableBiMap.copyOf(backendBuckets).inverse();
    }

    private String getContainer(String container) {
        return this.aliases.getOrDefault(container, container);
    }

    @Override
    public boolean createContainer(String container,
            CreateContainerOptions options) {
        return delegate().createContainer(getContainer(container), options);
    }

    @Override
    public boolean containerExists(String container) {
        return delegate().containerExists(getContainer(container));
    }

    @Override
    public ContainerAccess getContainerAccess(String container) {
        return delegate().getContainerAccess(getContainer(container));
    }

    @Override
    public void setContainerAccess(String container,
                                   ContainerAccess containerAccess) {
        delegate().setContainerAccess(getContainer(container), containerAccess);
    }

    @Override
    public PageSet<? extends StorageMetadata> list() {
        PageSet<? extends StorageMetadata> upstream = this.delegate().list();
        var results = new ImmutableList.Builder<StorageMetadata>();
        for (StorageMetadata sm : upstream) {
            if (aliases.containsValue(sm.name())) {
                results.add(new ContainerMetadata(
                        aliases.inverse().get(sm.name()),
                        sm.creationDate()));
            } else {
                results.add(sm);
            }
        }
        return new PageSet<>(results.build(), upstream.nextMarker());
    }

    @Override
    public PageSet<? extends StorageMetadata> list(
            String container, ListContainerOptions options) {
        return delegate().list(getContainer(container), options);
    }

    @Override
    public void clearContainer(String container, ListContainerOptions options) {
        delegate().clearContainer(getContainer(container), options);
    }

    @Override
    public void deleteContainer(String container) {
        delegate().deleteContainer(getContainer(container));
    }

    @Override
    public boolean deleteContainerIfEmpty(String container) {
        return delegate().deleteContainerIfEmpty(getContainer(container));
    }

    @Override
    public boolean blobExists(String container, String name) {
        return delegate().blobExists(getContainer(container), name);
    }

    @Override
    public BlobMetadata blobMetadata(String container, String name) {
        return delegate().blobMetadata(getContainer(container), name);
    }

    @Override
    public BlobAccess getBlobAccess(String container, String name) {
        return delegate().getBlobAccess(getContainer(container), name);
    }

    @Override
    public void setBlobAccess(String container, String name,
                              BlobAccess access) {
        delegate().setBlobAccess(getContainer(container), name, access);
    }

    @Override
    public Blob getBlob(String containerName, String blobName,
                        GetOptions getOptions) {
        return delegate().getBlob(getContainer(containerName), blobName,
                getOptions);
    }

    @Override
    public String putBlob(final String containerName, Blob blob,
                          final PutOptions options) {
        return delegate().putBlob(getContainer(containerName), blob,
                options);
    }

    @Override
    public void removeBlob(final String containerName, final String blobName) {
        delegate().removeBlob(getContainer(containerName), blobName);
    }

    @Override
    public void removeBlobs(final String containerName,
                            final Iterable<String> blobNames) {
        delegate().removeBlobs(getContainer(containerName), blobNames);
    }

    @Override
    public String copyBlob(final String fromContainer, final String fromName,
                           final String toContainer, final String toName,
                           final CopyOptions options) {
        return delegate().copyBlob(getContainer(fromContainer), fromName,
                getContainer(toContainer), toName, options);
    }

    @Override
    public MultipartUpload initiateMultipartUpload(
            String container, BlobMetadata blobMetadata, PutOptions options) {
        MultipartUpload mpu = delegate().initiateMultipartUpload(
                getContainer(container), blobMetadata, options);
        return new MultipartUpload(container, blobMetadata.name(),
                mpu.id(), mpu.blobMetadata(), mpu.putOptions());
    }

    @Override
    public void abortMultipartUpload(MultipartUpload mpu) {
        delegate().abortMultipartUpload(getDelegateMpu(mpu));
    }

    @Override
    public String completeMultipartUpload(final MultipartUpload mpu,
                                          final List<MultipartPart> parts) {
        return delegate().completeMultipartUpload(getDelegateMpu(mpu), parts);
    }

    @Override
    public MultipartPart uploadMultipartPart(MultipartUpload mpu,
            int partNumber, InputStream is, long contentLength,
            @Nullable HashCode contentMD5) {
        return delegate().uploadMultipartPart(getDelegateMpu(mpu), partNumber,
                is, contentLength, contentMD5);
    }

    @Override
    public List<MultipartPart> listMultipartUpload(MultipartUpload mpu) {
        return delegate().listMultipartUpload(getDelegateMpu(mpu));
    }

    @Override
    public List<MultipartUpload> listMultipartUploads(String container) {
        List<MultipartUpload> uploads =
                delegate().listMultipartUploads(getContainer(container));
        var builder = new ImmutableList.Builder<MultipartUpload>();
        for (MultipartUpload mpu : uploads) {
            builder.add(getClientMpu(mpu));
        }
        return builder.build();
    }
}
