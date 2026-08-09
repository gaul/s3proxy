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
import java.util.Deque;
import java.util.Random;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.ForwardingBlobStore;
import org.gaul.s3proxy.blobstore.SdkResponses;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import software.amazon.awssdk.services.s3.model.BucketCannedACL;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.CopyObjectRequest;
import software.amazon.awssdk.services.s3.model.CopyObjectResponse;
import software.amazon.awssdk.services.s3.model.CreateBucketRequest;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.DeleteObjectResponse;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.awssdk.services.s3.model.UploadPartRequest;
import software.amazon.awssdk.services.s3.model.UploadPartResponse;

/**
 * This class is a BlobStore wrapper which emulates eventual consistency
 * using two blobstores.  It writes objects to one store and reads objects
 * from another.  An asynchronous process copies objects between stores.  Note
 * that container operations are not eventually consistent.
 */
final class EventualBlobStore extends ForwardingBlobStore {
    private static final Logger logger =
            LoggerFactory.getLogger(EventualBlobStore.class);

    private final BlobStore writeStore;  // read from delegate
    private final ScheduledExecutorService executorService;
    private final Deque<Callable<?>> deque = new ConcurrentLinkedDeque<>();
    private final int delay;
    private final TimeUnit delayUnit;
    private final double probability;
    private final Random random = new Random();

    private EventualBlobStore(BlobStore writeStore, BlobStore readStore,
            ScheduledExecutorService executorService, int delay,
            TimeUnit delayUnit, double probability) {
        super(readStore);
        this.writeStore = requireNonNull(writeStore);
        this.executorService = requireNonNull(executorService);
        checkArgument(delay >= 0, "Delay must be at least zero, was: %s",
                delay);
        this.delay = delay;
        this.delayUnit = requireNonNull(delayUnit);
        checkArgument(probability >= 0.0 && probability <= 1.0,
                "Probability must be between 0.0 and 1.0, was: %s",
                probability);
        this.probability = probability;
    }

    static BlobStore newEventualBlobStore(BlobStore writeStore,
            BlobStore readStore, ScheduledExecutorService executorService,
            int delay, TimeUnit delayUnit, double probability) {
        return new EventualBlobStore(writeStore, readStore, executorService,
                delay, delayUnit, probability);
    }

    @Override
    public boolean createContainer(CreateBucketRequest request) {
        return delegate().createContainer(request) &&
                writeStore.createContainer(request);
    }

    // Container operations are not eventually consistent: apply them
    // synchronously to both the read (delegate) and write stores so the two
    // stores keep the same container structure.
    @Override
    public void setContainerAccess(String container, BucketCannedACL access) {
        delegate().setContainerAccess(container, access);
        writeStore.setContainerAccess(container, access);
    }

    @Override
    public void clearContainer(ListObjectsV2Request request) {
        delegate().clearContainer(request);
        writeStore.clearContainer(request);
    }

    @Override
    public void deleteContainer(String container) {
        delegate().deleteContainer(container);
        writeStore.deleteContainer(container);
    }

    @Override
    public boolean deleteContainerIfEmpty(String container) {
        return delegate().deleteContainerIfEmpty(container) &&
                writeStore.deleteContainerIfEmpty(container);
    }

    @Override
    public PutObjectResponse putBlob(final PutObjectRequest request,
            InputStream payload) {
        final String containerName = request.bucket();
        final String nearName = request.key();
        PutObjectResponse nearResult = writeStore.putBlob(request, payload);
        schedule(new Callable<@Nullable PutObjectResponse>() {
                @Override
                public @Nullable PutObjectResponse call() {
                    var near = writeStore.getBlob(containerName, nearName);
                    if (near == null) {
                        // a racing removeBlob already deleted the near blob;
                        // the far copy will converge via its scheduled removal
                        logger.warn("near blob {}/{} removed before" +
                                " replication", containerName, nearName);
                        return null;
                    }
                    // replay what the near store kept, not the consumed
                    // payload; its response supplies the content metadata
                    return delegate().putBlob(request.toBuilder()
                            .contentLength(near.response().contentLength())
                            .contentMD5(null)
                            .build(), near);
                }
            });
        return nearResult;
    }

    @Override
    public void removeBlob(final String containerName, final String blobName) {
        writeStore.removeBlob(containerName, blobName);
        schedule(new Callable<Void>() {
                @Override
                public Void call() {
                    delegate().removeBlob(containerName, blobName);
                    return null;
                }
            });
    }

    @Override
    public DeleteObjectResponse removeBlob(final DeleteObjectRequest request) {
        // The near store holds the freshest state, so it is the one that
        // judges the condition; the far copy follows unconditionally, as it
        // does for the plain removal above.
        DeleteObjectResponse result = writeStore.removeBlob(request);
        schedule(new Callable<Void>() {
                @Override
                public Void call() {
                    delegate().removeBlob(request.bucket(), request.key());
                    return null;
                }
            });
        return result;
    }

    @Override
    public CopyObjectResponse copyBlob(final CopyObjectRequest request) {
        CopyObjectResponse nearResult = writeStore.copyBlob(request);
        schedule(new Callable<CopyObjectResponse>() {
                @Override
                public CopyObjectResponse call() {
                    return delegate().copyBlob(request);
                }
            });
        return nearResult;
    }

    @Override
    public MultipartUpload initiateMultipartUpload(
            CreateMultipartUploadRequest request) {
        return delegate().initiateMultipartUpload(request);
    }

    @Override
    public void abortMultipartUpload(MultipartUpload mpu) {
        delegate().abortMultipartUpload(mpu);
    }

    @Override
    public CompleteMultipartUploadResponse completeMultipartUpload(final MultipartUpload mpu,
            final CompleteMultipartUploadRequest request) {
        schedule(new Callable<CompleteMultipartUploadResponse>() {
                @Override
                public CompleteMultipartUploadResponse call() {
                    return delegate().completeMultipartUpload(mpu, request);
                }
            });
        return SdkResponses.completeResponse("");  // TODO: fake ETag
    }

    @Override
    public UploadPartResponse uploadMultipartPart(MultipartUpload mpu,
            UploadPartRequest request, InputStream is) {
        return delegate().uploadMultipartPart(mpu, request, is);
    }

    @SuppressWarnings("FutureReturnValueIgnored")
    private void schedule(Callable<?> callable) {
        if (random.nextDouble() < probability) {
            // exhibit eventual-consistency delay
            deque.add(callable);
            executorService.schedule(new DequeCallable(), delay, delayUnit);
        } else {
            // propagate immediately (strongly-consistent this time)
            executorService.submit(callable);
        }
    }

    private final class DequeCallable implements Callable<Void> {
        @Override
        public Void call() throws Exception {
            deque.poll().call();
            return null;
        }
    }
    // Disable versioning: the near and far stores disagree about
    // versions.
    @Override
    public boolean supportsVersioning() {
        return false;
    }

}
