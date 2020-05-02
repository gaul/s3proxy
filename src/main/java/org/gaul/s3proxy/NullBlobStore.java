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

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.List;

import javax.annotation.Nullable;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.hash.HashCode;
import com.google.common.io.ByteSource;
import com.google.common.io.ByteStreams;
import com.google.common.primitives.Longs;

import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.domain.Blob;
import org.jclouds.blobstore.domain.BlobMetadata;
import org.jclouds.blobstore.domain.MultipartPart;
import org.jclouds.blobstore.domain.MultipartUpload;
import org.jclouds.blobstore.domain.MutableStorageMetadata;
import org.jclouds.blobstore.domain.PageSet;
import org.jclouds.blobstore.domain.StorageMetadata;
import org.jclouds.blobstore.domain.internal.MutableStorageMetadataImpl;
import org.jclouds.blobstore.domain.internal.PageSetImpl;
import org.jclouds.blobstore.options.GetOptions;
import org.jclouds.blobstore.options.PutOptions;
import org.jclouds.blobstore.util.ForwardingBlobStore;
import org.jclouds.io.Payload;
import org.jclouds.io.payloads.ByteSourcePayload;

final class NullBlobStore extends ForwardingBlobStore {
    private NullBlobStore(BlobStore blobStore) {
        super(blobStore);
    }

    static BlobStore newNullBlobStore(BlobStore blobStore) {
        return new NullBlobStore(blobStore);
    }

    @Override
    @Nullable
    public BlobMetadata blobMetadata(String container, String name) {
        Blob blob = getBlob(container, name);
        if (blob == null) {
            return null;
        }
        return blob.getMetadata();
    }

    @Override
    @Nullable
    public Blob getBlob(String container, String name) {
        return getBlob(container, name, GetOptions.NONE);
    }

    @Override
    @Nullable
    public Blob getBlob(String container, String name, GetOptions options) {
        Blob blob = super.getBlob(container, name, options);
        if (blob == null) {
            return null;
        }

        byte[] array;
        try (InputStream is = blob.getPayload().openStream()) {
            array = ByteStreams.toByteArray(is);
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }

        long length = Longs.fromByteArray(array);
        ByteSourcePayload payload = new ByteSourcePayload(
                new NullByteSource().slice(0, length));
        payload.setContentMetadata(blob.getPayload().getContentMetadata());
        payload.getContentMetadata().setContentLength(length);
        payload.getContentMetadata().setContentMD5((HashCode) null);
        blob.setPayload(payload);
        blob.getMetadata().setSize(length);
        return blob;
    }

    @Override
    public PageSet<? extends StorageMetadata> list(String container) {
        ImmutableSet.Builder<StorageMetadata> builder = ImmutableSet.builder();
        PageSet<? extends StorageMetadata> pageSet = super.list(container);
        for (StorageMetadata sm : pageSet) {
            MutableStorageMetadata msm = new MutableStorageMetadataImpl(sm);
            msm.setSize(0L);
            builder.add(msm);
        }
        return new PageSetImpl<>(builder.build(), pageSet.getNextMarker());
    }

    @Override
    public String putBlob(String containerName, Blob blob) {
        return putBlob(containerName, blob, PutOptions.NONE);
    }

    @Override
    public String putBlob(String containerName, Blob blob,
            PutOptions options) {
        long length;
        try (InputStream is = blob.getPayload().openStream()) {
            length = ByteStreams.copy(is, ByteStreams.nullOutputStream());
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }

        byte[] array = Longs.toByteArray(length);
        ByteSourcePayload payload = new ByteSourcePayload(
                ByteSource.wrap(array));
        payload.setContentMetadata(blob.getPayload().getContentMetadata());
        payload.getContentMetadata().setContentLength((long) array.length);
        payload.getContentMetadata().setContentMD5((HashCode) null);
        blob.setPayload(payload);

        return super.putBlob(containerName, blob, options);
    }

    @Override
    public String completeMultipartUpload(final MultipartUpload mpu,
            final List<MultipartPart> parts) {
        long length = 0;
        for (MultipartPart part : parts) {
            length += part.partSize();
            super.removeBlob(mpu.containerName(), mpu.id() + "-" +
                    part.partNumber());
        }

        byte[] array = Longs.toByteArray(length);
        ByteSourcePayload payload = new ByteSourcePayload(
                ByteSource.wrap(array));
        payload.getContentMetadata().setContentLength((long) array.length);

        super.abortMultipartUpload(mpu);

        MultipartUpload mpu2 = super.initiateMultipartUpload(
                mpu.containerName(), mpu.blobMetadata(), mpu.putOptions());

        MultipartPart part = super.uploadMultipartPart(mpu2, 1, payload);

        return super.completeMultipartUpload(mpu2, ImmutableList.of(part));
    }

    @Override
    public void abortMultipartUpload(MultipartUpload mpu) {
        for (MultipartPart part : super.listMultipartUpload(mpu)) {
            super.removeBlob(mpu.containerName(), mpu.id() + "-" +
                    part.partNumber());
        }

        super.abortMultipartUpload(mpu);
    }

    @Override
    public MultipartPart uploadMultipartPart(MultipartUpload mpu,
            int partNumber, Payload payload) {
        long length;
        try (InputStream is = payload.openStream()) {
            length = ByteStreams.copy(is, ByteStreams.nullOutputStream());
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }

        byte[] array = Longs.toByteArray(length);
        ByteSourcePayload newPayload = new ByteSourcePayload(
                ByteSource.wrap(array));
        newPayload.setContentMetadata(payload.getContentMetadata());
        newPayload.getContentMetadata().setContentLength((long) array.length);
        newPayload.getContentMetadata().setContentMD5((HashCode) null);

        // create a single-part object which contains the logical length which
        // list and complete will read later
        Blob blob = blobBuilder(mpu.id() + "-" + partNumber)
                .payload(newPayload)
                .build();
        super.putBlob(mpu.containerName(), blob);

        MultipartPart part = super.uploadMultipartPart(mpu, partNumber,
                newPayload);
        return MultipartPart.create(part.partNumber(), length, part.partETag(),
                part.lastModified());
    }

    @Override
    public List<MultipartPart> listMultipartUpload(MultipartUpload mpu) {
        ImmutableList.Builder<MultipartPart> builder = ImmutableList.builder();
        for (MultipartPart part : super.listMultipartUpload(mpu)) {
            // get real blob size from stub blob
            Blob blob = getBlob(mpu.containerName(),
                    mpu.id() + "-" + part.partNumber());
            long length = blob.getPayload().getContentMetadata()
                    .getContentLength();
            builder.add(MultipartPart.create(part.partNumber(), length,
                    part.partETag(), part.lastModified()));
        }
        return builder.build();
    }

    private static final class NullByteSource extends ByteSource {
        @Override
        public InputStream openStream() throws IOException {
            return new NullInputStream();
        }
    }

    private static final class NullInputStream extends InputStream {
        private boolean closed;

        @Override
        public int read() throws IOException {
            if (closed) {
                throw new IOException("Stream already closed");
            }
            return 0;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (closed) {
                throw new IOException("Stream already closed");
            }
            Arrays.fill(b, off, off + len, (byte) 0);
            return len;
        }

        @Override
        public void close() throws IOException {
            super.close();
            closed = true;
        }
    }
}
