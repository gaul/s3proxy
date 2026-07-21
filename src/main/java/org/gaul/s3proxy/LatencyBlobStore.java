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
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.google.common.collect.ImmutableMap;
import com.google.common.hash.HashCode;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.ContentMetadata;
import org.gaul.s3proxy.blobstore.ForwardingBlobStore;
import org.gaul.s3proxy.blobstore.domain.Blob;
import org.gaul.s3proxy.blobstore.domain.BlobAccess;
import org.gaul.s3proxy.blobstore.domain.BlobMetadata;
import org.gaul.s3proxy.blobstore.domain.ContainerAccess;
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

public final class LatencyBlobStore extends ForwardingBlobStore {
    private static final Pattern PROPERTIES_LATENCY_RE = Pattern.compile(
            "^" + S3ProxyConstants.PROPERTY_LATENCY + "\\.(?<op>.*)\\.latency$");
    private static final Pattern PROPERTIES_SPEED_RE = Pattern.compile(
            "^" + S3ProxyConstants.PROPERTY_LATENCY + "\\.(?<op>.*)\\.speed$");
    private static final String OP_ALL = "*";
    private static final String OP_CONTAINER_EXISTS = "container-exists";
    private static final String OP_CREATE_CONTAINER = "create-container";
    private static final String OP_CONTAINER_ACCESS = "container-access";
    private static final String OP_LIST = "list";
    private static final String OP_CLEAR_CONTAINER = "clear-container";
    private static final String OP_DELETE_CONTAINER = "delete-container";
    private static final String OP_BLOB_EXISTS = "blob-exists";
    private static final String OP_PUT_BLOB = "put";
    private static final String OP_COPY_BLOB = "copy";
    private static final String OP_BLOB_METADATA = "metadata";
    private static final String OP_GET_BLOB = "get";
    private static final String OP_REMOVE_BLOB = "remove";
    private static final String OP_BLOB_ACCESS = "blob-access";
    private static final String OP_MULTIPART_MESSAGE = "multipart-message";
    private static final String OP_UPLOAD_PART = "upload-part";
    private static final String OP_LIST_MULTIPART = "list-multipart";
    private static final String OP_MULTIPART_PARAM = "multipart-param";
    private final Map<String, Long> latencies;
    private final Map<String, Long> speeds;

    private LatencyBlobStore(BlobStore blobStore, Map<String, Long> latencies, Map<String, Long> speeds) {
        super(blobStore);
        this.latencies = requireNonNull(latencies);
        for (String op : latencies.keySet()) {
            checkArgument(latencies.get(op) >= 0, "Latency must be non negative for %s", op);
        }
        this.speeds = requireNonNull(speeds);
        for (String op : speeds.keySet()) {
            checkArgument(speeds.get(op) > 0, "Speed must be positive for %s", op);
        }
    }

    public static Map<String, Long> parseLatencies(Properties properties) {
        var latencies = new ImmutableMap.Builder<String, Long>();
        for (String key : properties.stringPropertyNames()) {
            Matcher matcher = PROPERTIES_LATENCY_RE.matcher(key);
            if (!matcher.matches()) {
                continue;
            }
            String op = matcher.group("op");
            long latency = Long.parseLong(properties.getProperty(key));
            checkArgument(latency >= 0, "Latency must be non negative for %s", op);
            latencies.put(op, latency);
        }
        return latencies.build();
    }

    public static Map<String, Long> parseSpeeds(Properties properties) {
        var speeds = new ImmutableMap.Builder<String, Long>();
        for (String key : properties.stringPropertyNames()) {
            Matcher matcher = PROPERTIES_SPEED_RE.matcher(key);
            if (!matcher.matches()) {
                continue;
            }
            String op = matcher.group("op");
            long speed = Long.parseLong(properties.getProperty(key));
            checkArgument(speed > 0, "Speed must be positive for %s", op);
            speeds.put(op, speed);
        }
        return speeds.build();
    }

    static BlobStore newLatencyBlobStore(BlobStore delegate, Map<String, Long> latencies, Map<String, Long> speeds) {
        return new LatencyBlobStore(delegate, latencies, speeds);
    }

    @Override
    public PageSet<? extends StorageMetadata> list() {
        simulateLatency(OP_LIST);
        return super.list();
    }

    @Override
    public PageSet<? extends StorageMetadata> list(String container, ListContainerOptions options) {
        simulateLatency(OP_LIST);
        return super.list(container, options);
    }

    @Override
    public boolean containerExists(String container) {
        simulateLatency(OP_CONTAINER_EXISTS);
        return super.containerExists(container);
    }

    @Override
    public boolean createContainer(String container,
            CreateContainerOptions createContainerOptions) {
        simulateLatency(OP_CREATE_CONTAINER);
        return super.createContainer(container, createContainerOptions);
    }

    @Override
    public ContainerAccess getContainerAccess(String container) {
        simulateLatency(OP_CONTAINER_ACCESS);
        return super.getContainerAccess(container);
    }

    @Override
    public void setContainerAccess(String container, ContainerAccess containerAccess) {
        simulateLatency(OP_CONTAINER_ACCESS);
        super.setContainerAccess(container, containerAccess);
    }

    @Override
    public void clearContainer(String container, ListContainerOptions options) {
        simulateLatency(OP_CLEAR_CONTAINER);
        super.clearContainer(container, options);
    }

    @Override
    public void deleteContainer(String container) {
        simulateLatency(OP_DELETE_CONTAINER);
        super.deleteContainer(container);
    }

    @Override
    public boolean deleteContainerIfEmpty(String container) {
        simulateLatency(OP_DELETE_CONTAINER);
        return super.deleteContainerIfEmpty(container);
    }

    @Override
    public boolean blobExists(String container, String name) {
        simulateLatency(OP_BLOB_EXISTS);
        return super.blobExists(container, name);
    }

    @Override
    public String putBlob(String containerName, Blob blob, PutOptions putOptions) {
        simulateLatency(OP_PUT_BLOB);
        Blob newBlob = replaceStream(blob, new ThrottledInputStream(blob.getPayload(), getSpeed(OP_PUT_BLOB)));
        return super.putBlob(containerName, newBlob, PutOptions.NONE);
    }

    @Override
    public String copyBlob(String fromContainer, String fromName, String toContainer, String toName, CopyOptions options) {
        simulateLatency(OP_COPY_BLOB);
        return super.copyBlob(fromContainer, fromName, toContainer, toName, options);
    }

    @Override
    public BlobMetadata blobMetadata(String container, String name) {
        simulateLatency(OP_BLOB_METADATA);
        return super.blobMetadata(container, name);
    }

    @Override
    public Blob getBlob(String containerName, String blobName, GetOptions getOptions) {
        simulateLatency(OP_GET_BLOB);
        Blob blob = super.getBlob(containerName, blobName, getOptions);
        if (blob == null) {
            return null;
        }
        return replaceStream(blob, new ThrottledInputStream(blob.getPayload(), getSpeed(OP_GET_BLOB)));
    }

    @Override
    public void removeBlob(String container, String name) {
        simulateLatency(OP_REMOVE_BLOB);
        super.removeBlob(container, name);
    }

    @Override
    public void removeBlobs(String container, Iterable<String> iterable) {
        simulateLatency(OP_REMOVE_BLOB);
        super.removeBlobs(container, iterable);
    }

    @Override
    public BlobAccess getBlobAccess(String container, String name) {
        simulateLatency(OP_BLOB_ACCESS);
        return super.getBlobAccess(container, name);
    }

    @Override
    public void setBlobAccess(String container, String name, BlobAccess access) {
        simulateLatency(OP_BLOB_ACCESS);
        super.setBlobAccess(container, name, access);
    }

    @Override
    public MultipartUpload initiateMultipartUpload(String container, BlobMetadata blobMetadata, PutOptions options) {
        simulateLatency(OP_MULTIPART_MESSAGE);
        return super.initiateMultipartUpload(container, blobMetadata, options);
    }

    @Override
    public void abortMultipartUpload(MultipartUpload mpu) {
        simulateLatency(OP_MULTIPART_MESSAGE);
        super.abortMultipartUpload(mpu);
    }

    @Override
    public String completeMultipartUpload(MultipartUpload mpu, List<MultipartPart> parts) {
        simulateLatency(OP_MULTIPART_MESSAGE);
        return super.completeMultipartUpload(mpu, parts);
    }

    @Override
    public MultipartPart uploadMultipartPart(MultipartUpload mpu, int partNumber, InputStream is, long contentLength, @Nullable HashCode contentMD5) {
        simulateLatency(OP_UPLOAD_PART);
        return super.uploadMultipartPart(mpu, partNumber, new ThrottledInputStream(is, getSpeed(OP_UPLOAD_PART)), contentLength, contentMD5);
    }

    @Override
    public List<MultipartPart> listMultipartUpload(MultipartUpload mpu) {
        simulateLatency(OP_LIST_MULTIPART);
        return super.listMultipartUpload(mpu);
    }

    @Override
    public List<MultipartUpload> listMultipartUploads(String container) {
        simulateLatency(OP_LIST_MULTIPART);
        return super.listMultipartUploads(container);
    }

    @Override
    public long getMinimumMultipartPartSize() {
        simulateLatency(OP_MULTIPART_PARAM);
        return super.getMinimumMultipartPartSize();
    }

    private long getLatency(String op) {
        return latencies.getOrDefault(op, latencies.getOrDefault(OP_ALL, 0L));
    }

    private Long getSpeed(String op) {
        return speeds.getOrDefault(op, speeds.getOrDefault(OP_ALL, null));
    }

    private void simulateLatency(String op) {
        long latency = getLatency(op);
        if (latency > 0) {
            try {
                Thread.sleep(latency);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private Blob replaceStream(Blob blob, InputStream is) {
        BlobMetadata blobMeta = blob.getMetadata();
        ContentMetadata contentMeta = blobMeta.getContentMetadata();
        Map<String, String> userMetadata = blobMeta.userMetadata();

        return Blob.builder(blobMeta.name())
                .type(blobMeta.type())
                .storageClass(blobMeta.storageClass())
                .userMetadata(userMetadata)
                .payload(is)
                .cacheControl(contentMeta.cacheControl())
                .contentDisposition(contentMeta.contentDisposition())
                .contentEncoding(contentMeta.contentEncoding())
                .contentLanguage(contentMeta.contentLanguage())
                .contentLength(contentMeta.contentLength())
                .contentMD5(contentMeta.contentMD5())
                .contentType(contentMeta.contentType())
                .expires(contentMeta.expires())
                .eTag(blobMeta.eTag())
                .lastModified(blobMeta.lastModified())
                .container(blobMeta.getContainer())
                // Preserve the Content-Range response header, which the
                // handler reads for ranged GET responses.
                .contentRange(blob.getContentRange())
                .build();
    }
}
