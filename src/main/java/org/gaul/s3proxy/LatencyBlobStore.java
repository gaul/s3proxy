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

import com.google.common.collect.ImmutableMap;
import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.domain.*;
import org.jclouds.blobstore.options.*;
import org.jclouds.blobstore.util.ForwardingBlobStore;
import org.jclouds.domain.Location;
import org.jclouds.io.ContentMetadata;
import org.jclouds.io.Payload;
import org.jclouds.io.payloads.InputStreamPayload;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.google.common.base.Preconditions.checkArgument;
import static java.util.Objects.requireNonNull;

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
    private static final String OP_DIRECTORY_EXISTS = "directory-exists";
    private static final String OP_CREATE_DIRECTORY = "create-directory";
    private static final String OP_DELETE_DIRECTORY = "delete-directory";
    private static final String OP_BLOB_EXISTS = "blob-exists";
    private static final String OP_PUT_BLOB = "put";
    private static final String OP_COPY_BLOB = "copy";
    private static final String OP_BLOB_METADATA = "metadata";
    private static final String OP_GET_BLOB = "get";
    private static final String OP_REMOVE_BLOB = "remove";
    private static final String OP_BLOB_ACCESS = "blob-access";
    private static final String OP_COUNT_BLOBS = "count";
    private static final String OP_MULTIPART_MESSAGE = "multipart-message";
    private static final String OP_UPLOAD_PART = "upload-part";
    private static final String OP_LIST_MULTIPART = "list-multipart";
    private static final String OP_MULTIPART_PARAM = "multipart-param";
    private static final String OP_DOWNLOAD_BLOB = "download";
    private static final String OP_STREAM_BLOB = "stream";
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
    public Set<? extends Location> listAssignableLocations() {
        simulateLatency(OP_LIST);
        return super.listAssignableLocations();
    }

    @Override
    public PageSet<? extends StorageMetadata> list() {
        simulateLatency(OP_LIST);
        return super.list();
    }

    @Override
    public boolean containerExists(String container) {
        simulateLatency(OP_CONTAINER_EXISTS);
        return super.containerExists(container);
    }

    @Override
    public boolean createContainerInLocation(Location location, String container) {
        simulateLatency(OP_CREATE_CONTAINER);
        return super.createContainerInLocation(location, container);
    }

    @Override
    public boolean createContainerInLocation(Location location, String container, CreateContainerOptions createContainerOptions) {
        simulateLatency(OP_CREATE_CONTAINER);
        return super.createContainerInLocation(location, container, createContainerOptions);
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
    public PageSet<? extends StorageMetadata> list(String container) {
        simulateLatency(OP_LIST);
        return super.list(container);
    }

    @Override
    public PageSet<? extends StorageMetadata> list(String container, ListContainerOptions options) {
        simulateLatency(OP_LIST);
        return super.list(container, options);
    }

    @Override
    public void clearContainer(String container) {
        simulateLatency(OP_CLEAR_CONTAINER);
        super.clearContainer(container);
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
    public boolean directoryExists(String container, String directory) {
        simulateLatency(OP_DIRECTORY_EXISTS);
        return super.directoryExists(container, directory);
    }

    @Override
    public void createDirectory(String container, String directory) {
        simulateLatency(OP_CREATE_DIRECTORY);
        super.createDirectory(container, directory);
    }

    @Override
    public void deleteDirectory(String container, String directory) {
        simulateLatency(OP_DELETE_DIRECTORY);
        super.deleteDirectory(container, directory);
    }

    @Override
    public boolean blobExists(String container, String name) {
        simulateLatency(OP_BLOB_EXISTS);
        return super.blobExists(container, name);
    }

    @Override
    public String putBlob(String containerName, Blob blob) {
        simulateLatency(OP_PUT_BLOB);
        try {
            InputStream is = blob.getPayload().openStream();
            Blob newBlob = replaceStream(blob, new ThrottledInputStream(is, getSpeed(OP_PUT_BLOB)));
            return super.putBlob(containerName, newBlob);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public String putBlob(String containerName, Blob blob, PutOptions putOptions) {
        simulateLatency(OP_PUT_BLOB);
        try {
            InputStream is = blob.getPayload().openStream();
            Blob newBlob = replaceStream(blob, new ThrottledInputStream(is, getSpeed(OP_PUT_BLOB)));
            return super.putBlob(containerName, newBlob);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
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
    public Blob getBlob(String containerName, String blobName) {
        simulateLatency(OP_GET_BLOB);
        Blob blob = super.getBlob(containerName, blobName);
        try {
            InputStream is = blob.getPayload().openStream();
            return replaceStream(blob, new ThrottledInputStream(is, getSpeed(OP_GET_BLOB)));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Blob getBlob(String containerName, String blobName, GetOptions getOptions) {
        simulateLatency(OP_GET_BLOB);
        Blob blob = super.getBlob(containerName, blobName, getOptions);
        try {
            InputStream is = blob.getPayload().openStream();
            return replaceStream(blob, new ThrottledInputStream(is, getSpeed(OP_GET_BLOB)));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
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
    public long countBlobs(String container) {
        simulateLatency(OP_COUNT_BLOBS);
        return super.countBlobs(container);
    }

    @Override
    public long countBlobs(String container, ListContainerOptions options) {
        simulateLatency(OP_COUNT_BLOBS);
        return super.countBlobs(container, options);
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
    public MultipartPart uploadMultipartPart(MultipartUpload mpu, int partNumber, Payload payload) {
        simulateLatency(OP_UPLOAD_PART);
        try {
            InputStream is = payload.openStream();
            payload = new InputStreamPayload(new ThrottledInputStream(is, getSpeed(OP_UPLOAD_PART)));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return super.uploadMultipartPart(mpu, partNumber, payload);
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

    @Override
    public long getMaximumMultipartPartSize() {
        simulateLatency(OP_MULTIPART_PARAM);
        return super.getMaximumMultipartPartSize();
    }

    @Override
    public int getMaximumNumberOfParts() {
        simulateLatency(OP_MULTIPART_PARAM);
        return super.getMaximumNumberOfParts();
    }

    @Override
    public void downloadBlob(String container, String name, File destination) {
        simulateLatency(OP_DOWNLOAD_BLOB);
        super.downloadBlob(container, name, destination);
    }

    @Override
    public void downloadBlob(String container, String name, File destination, ExecutorService executor) {
        simulateLatency(OP_DOWNLOAD_BLOB);
        super.downloadBlob(container, name, destination, executor);
    }

    @Override
    public InputStream streamBlob(String container, String name) {
        simulateLatency(OP_STREAM_BLOB);
        InputStream is = super.streamBlob(container, name);
        return new ThrottledInputStream(is, getSpeed(OP_STREAM_BLOB));
    }

    @Override
    public InputStream streamBlob(String container, String name, ExecutorService executor) {
        simulateLatency(OP_STREAM_BLOB);
        InputStream is = super.streamBlob(container, name, executor);
        return new ThrottledInputStream(is, getSpeed(OP_STREAM_BLOB));
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
        Map<String, String> userMetadata = blobMeta.getUserMetadata();

        Blob newBlob = blobBuilder(blobMeta.getName())
                .type(blobMeta.getType())
                .tier(blobMeta.getTier())
                .userMetadata(userMetadata)
                .payload(is)
                .cacheControl(contentMeta.getCacheControl())
                .contentDisposition(contentMeta.getContentDisposition())
                .contentEncoding(contentMeta.getContentEncoding())
                .contentLanguage(contentMeta.getContentLanguage())
                .contentLength(contentMeta.getContentLength())
                .contentType(contentMeta.getContentType())
                .build();

        newBlob.getMetadata().setUri(blobMeta.getUri());
        newBlob.getMetadata().setETag(blobMeta.getETag());
        newBlob.getMetadata().setLastModified(blobMeta.getLastModified());
        newBlob.getMetadata().setSize(blobMeta.getSize());
        newBlob.getMetadata().setPublicUri(blobMeta.getPublicUri());
        newBlob.getMetadata().setContainer(blobMeta.getContainer());

        return newBlob;
    }
}
