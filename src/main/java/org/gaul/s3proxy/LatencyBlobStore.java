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

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.ForwardingBlobStore;
import org.gaul.s3proxy.blobstore.SdkResponses;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.jspecify.annotations.Nullable;

import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.services.s3.model.BucketCannedACL;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadResponse;
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
import software.amazon.awssdk.services.s3.model.ObjectCannedACL;
import software.amazon.awssdk.services.s3.model.Part;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.awssdk.services.s3.model.UploadPartRequest;
import software.amazon.awssdk.services.s3.model.UploadPartResponse;

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
    public ListBucketsResponse list() {
        simulateLatency(OP_LIST);
        return super.list();
    }

    @Override
    public ListObjectsV2Response list(ListObjectsV2Request request) {
        simulateLatency(OP_LIST);
        return super.list(request);
    }

    @Override
    public boolean containerExists(String container) {
        simulateLatency(OP_CONTAINER_EXISTS);
        return super.containerExists(container);
    }

    @Override
    public boolean createContainer(CreateBucketRequest request) {
        simulateLatency(OP_CREATE_CONTAINER);
        return super.createContainer(request);
    }

    @Override
    public BucketCannedACL getContainerAccess(String container) {
        simulateLatency(OP_CONTAINER_ACCESS);
        return super.getContainerAccess(container);
    }

    @Override
    public void setContainerAccess(String container, BucketCannedACL containerAccess) {
        simulateLatency(OP_CONTAINER_ACCESS);
        super.setContainerAccess(container, containerAccess);
    }

    @Override
    public void clearContainer(ListObjectsV2Request request) {
        simulateLatency(OP_CLEAR_CONTAINER);
        super.clearContainer(request);
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
    public PutObjectResponse putBlob(PutObjectRequest request, InputStream payload) {
        simulateLatency(OP_PUT_BLOB);
        return super.putBlob(request, new ThrottledInputStream(payload, getSpeed(OP_PUT_BLOB)));
    }

    @Override
    public CopyObjectResponse copyBlob(CopyObjectRequest request) {
        simulateLatency(OP_COPY_BLOB);
        return super.copyBlob(request);
    }

    @Override
    @Nullable
    public HeadObjectResponse blobMetadata(HeadObjectRequest request) {
        simulateLatency(OP_BLOB_METADATA);
        return super.blobMetadata(request);
    }

    @Override
    @Nullable
    public ResponseInputStream<GetObjectResponse> getBlob(
            GetObjectRequest request) {
        simulateLatency(OP_GET_BLOB);
        var blob = super.getBlob(request);
        if (blob == null) {
            return null;
        }
        return SdkResponses.getResponse(blob.response(),
                new ThrottledInputStream(blob, getSpeed(OP_GET_BLOB)));
    }

    @Override
    public void removeBlob(String container, String name) {
        simulateLatency(OP_REMOVE_BLOB);
        super.removeBlob(container, name);
    }

    @Override
    public ObjectCannedACL getBlobAccess(String container, String name) {
        simulateLatency(OP_BLOB_ACCESS);
        return super.getBlobAccess(container, name);
    }

    @Override
    public void setBlobAccess(String container, String name, ObjectCannedACL access) {
        simulateLatency(OP_BLOB_ACCESS);
        super.setBlobAccess(container, name, access);
    }

    @Override
    public MultipartUpload initiateMultipartUpload(CreateMultipartUploadRequest request) {
        simulateLatency(OP_MULTIPART_MESSAGE);
        return super.initiateMultipartUpload(request);
    }

    @Override
    public void abortMultipartUpload(MultipartUpload mpu) {
        simulateLatency(OP_MULTIPART_MESSAGE);
        super.abortMultipartUpload(mpu);
    }

    @Override
    public CompleteMultipartUploadResponse completeMultipartUpload(MultipartUpload mpu, CompleteMultipartUploadRequest request) {
        simulateLatency(OP_MULTIPART_MESSAGE);
        return super.completeMultipartUpload(mpu, request);
    }

    @Override
    public UploadPartResponse uploadMultipartPart(MultipartUpload mpu, UploadPartRequest request, InputStream is) {
        simulateLatency(OP_UPLOAD_PART);
        return super.uploadMultipartPart(mpu, request, new ThrottledInputStream(is, getSpeed(OP_UPLOAD_PART)));
    }

    @Override
    public List<Part> listMultipartUpload(MultipartUpload mpu) {
        simulateLatency(OP_LIST_MULTIPART);
        return super.listMultipartUpload(mpu);
    }

    @Override
    public List<software.amazon.awssdk.services.s3.model.MultipartUpload>
            listMultipartUploads(String container) {
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

    @Nullable
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

}
