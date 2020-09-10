/*
 * Copyright 2014-2020 Andrew Gaul <andrew@gaul.org>
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

import static java.util.Objects.requireNonNull;

import static com.google.common.base.Preconditions.checkArgument;

import java.util.Deque;
import java.util.List;
import java.util.Random;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.domain.Blob;
import org.jclouds.blobstore.domain.BlobMetadata;
import org.jclouds.blobstore.domain.MultipartPart;
import org.jclouds.blobstore.domain.MultipartUpload;
import org.jclouds.blobstore.options.CopyOptions;
import org.jclouds.blobstore.options.CreateContainerOptions;
import org.jclouds.blobstore.options.PutOptions;
import org.jclouds.blobstore.util.ForwardingBlobStore;
import org.jclouds.domain.Location;
import org.jclouds.io.Payload;

/**
 * This class is a BlobStore wrapper which emulates eventual consistency
 * using two blobstores.  It writes objects to one store and reads objects
 * from another.  An asynchronous process copies objects between stores.  Note
 * that container operations are not eventually consistent.
 */
final class EventualBlobStore extends ForwardingBlobStore {
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
    public boolean createContainerInLocation(Location location,
            String container, CreateContainerOptions options) {
        return delegate().createContainerInLocation(
                        location, container, options) &&
                writeStore.createContainerInLocation(
                        location, container, options);
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
    public String putBlob(String containerName, Blob blob) {
        return putBlob(containerName, blob, PutOptions.NONE);
    }

    @Override
    public String putBlob(final String containerName, Blob blob,
            final PutOptions options) {
        final String nearName = blob.getMetadata().getName();
        String nearETag = writeStore.putBlob(containerName, blob, options);
        schedule(new Callable<String>() {
                @Override
                public String call() {
                    Blob nearBlob = writeStore.getBlob(containerName, nearName);
                    String farETag = delegate().putBlob(containerName,
                            nearBlob, options);
                    return farETag;
                }
            });
        return nearETag;
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
    public void removeBlobs(final String containerName,
            final Iterable<String> blobNames) {
        writeStore.removeBlobs(containerName, blobNames);
        schedule(new Callable<Void>() {
                @Override
                public Void call() {
                    delegate().removeBlobs(containerName, blobNames);
                    return null;
                }
            });
    }

    @Override
    public String copyBlob(final String fromContainer, final String fromName,
            final String toContainer, final String toName,
            final CopyOptions options) {
        String nearETag = writeStore.copyBlob(fromContainer, fromName,
                toContainer, toName, options);
        schedule(new Callable<String>() {
                @Override
                public String call() {
                    return delegate().copyBlob(fromContainer, fromName,
                            toContainer, toName, options);
                }
            });
        return nearETag;
    }

    @Override
    public MultipartUpload initiateMultipartUpload(String container,
            BlobMetadata blobMetadata, PutOptions options) {
        MultipartUpload mpu = delegate().initiateMultipartUpload(container,
                blobMetadata, options);
        return mpu;
    }

    @Override
    public void abortMultipartUpload(MultipartUpload mpu) {
        delegate().abortMultipartUpload(mpu);
    }

    @Override
    public String completeMultipartUpload(final MultipartUpload mpu,
            final List<MultipartPart> parts) {
        schedule(new Callable<String>() {
                @Override
                public String call() {
                    String farETag = delegate().completeMultipartUpload(mpu,
                            parts);
                    return farETag;
                }
            });
        return "";  // TODO: fake ETag
    }

    @Override
    public MultipartPart uploadMultipartPart(MultipartUpload mpu,
            int partNumber, Payload payload) {
        MultipartPart part = delegate().uploadMultipartPart(mpu, partNumber,
                payload);
        return part;
    }

    private void schedule(Callable<?> callable) {
        if (random.nextDouble() < probability) {
            deque.add(callable);
            executorService.schedule(new DequeCallable(), delay, delayUnit);
        }
    }

    private final class DequeCallable implements Callable<Void> {
        @Override
        public Void call() throws Exception {
            deque.poll().call();
            return null;
        }
    }
}
