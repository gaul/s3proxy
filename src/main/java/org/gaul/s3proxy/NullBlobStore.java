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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.List;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.io.ByteSource;
import com.google.common.primitives.Longs;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.ByteSourcePayload;
import org.gaul.s3proxy.blobstore.ForwardingBlobStore;
import org.gaul.s3proxy.blobstore.Payload;
import org.gaul.s3proxy.blobstore.domain.Blob;
import org.gaul.s3proxy.blobstore.domain.BlobMetadata;
import org.gaul.s3proxy.blobstore.domain.ContainerMetadata;
import org.gaul.s3proxy.blobstore.domain.MultipartPart;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.gaul.s3proxy.blobstore.domain.PageSet;
import org.gaul.s3proxy.blobstore.domain.StorageMetadata;
import org.gaul.s3proxy.blobstore.options.GetOptions;
import org.gaul.s3proxy.blobstore.options.PutOptions;
import org.jspecify.annotations.Nullable;

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
        // Ranges apply to the virtual content, not the 8-byte length stub.
        List<String> originalRanges = options.ranges();
        Blob blob;
        if (originalRanges.isEmpty()) {
            blob = super.getBlob(container, name, options);
        } else {
            originalRanges = List.copyOf(originalRanges);
            options.ranges().clear();
            try {
                blob = super.getBlob(container, name, options);
            } finally {
                options.ranges().addAll(originalRanges);
            }
        }
        if (blob == null) {
            return null;
        }

        byte[] array;
        try (InputStream is = blob.getPayload().openStream()) {
            array = is.readAllBytes();
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }

        long fullLength = Longs.fromByteArray(array);
        long length = fullLength;
        if (!originalRanges.isEmpty()) {
            String[] parts = originalRanges.get(0).split("-", 2);
            if (parts[0].isEmpty()) {
                // bytes=-N: last N bytes
                length = Math.min(Long.parseLong(parts[1]), fullLength);
            } else if (parts[1].isEmpty()) {
                // bytes=A-: from offset to end
                long offset = Long.parseLong(parts[0]);
                length = Math.max(0, fullLength - offset);
            } else {
                // bytes=A-B
                long offset = Long.parseLong(parts[0]);
                long end = Long.parseLong(parts[1]);
                length = Math.max(0,
                        Math.min(end + 1, fullLength) - offset);
            }
        }

        var contentMetadata = blob.getPayload().getContentMetadata().toBuilder()
                .contentLength(length)
                .contentMD5(null)
                .build();
        var payload = new ByteSourcePayload(
                new NullByteSource().slice(0, length), contentMetadata);
        return blob.toBuilder()
                .payload(payload)
                .build();
    }

    @Override
    public PageSet<? extends StorageMetadata> list(String container) {
        var builder = ImmutableSet.<StorageMetadata>builder();
        PageSet<? extends StorageMetadata> pageSet = super.list(container);
        for (StorageMetadata sm : pageSet) {
            if (sm instanceof BlobMetadata bm) {
                builder.add(bm.toBuilder().contentLength(0L).build());
            } else if (sm instanceof ContainerMetadata cm) {
                builder.add(cm.toBuilder().size(0L).build());
            }
        }
        return new PageSet<>(builder.build(), pageSet.getNextMarker());
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
            length = is.transferTo(OutputStream.nullOutputStream());
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }

        byte[] array = Longs.toByteArray(length);
        var contentMetadata = blob.getPayload().getContentMetadata().toBuilder()
                .contentLength((long) array.length)
                .contentMD5(null)
                .build();
        var payload = new ByteSourcePayload(
                ByteSource.wrap(array), contentMetadata);

        return super.putBlob(containerName,
                blob.toBuilder().payload(payload).build(), options);
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
        var payload = new ByteSourcePayload(ByteSource.wrap(array));

        super.abortMultipartUpload(mpu);

        MultipartUpload mpu2 = super.initiateMultipartUpload(
                mpu.containerName(), mpu.blobMetadata(), mpu.putOptions());

        MultipartPart part = super.uploadMultipartPart(mpu2, 1, payload);

        return super.completeMultipartUpload(mpu2, List.of(part));
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
            length = is.transferTo(OutputStream.nullOutputStream());
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }

        byte[] array = Longs.toByteArray(length);
        var newContentMetadata = payload.getContentMetadata().toBuilder()
                .contentLength((long) array.length)
                .contentMD5(null)
                .build();
        var newPayload = new ByteSourcePayload(
                ByteSource.wrap(array), newContentMetadata);

        // create a single-part object which contains the logical length which
        // list and complete will read later
        Blob blob = Blob.builder(mpu.id() + "-" + partNumber)
                .payload(newPayload)
                .build();
        super.putBlob(mpu.containerName(), blob);

        MultipartPart part = super.uploadMultipartPart(mpu, partNumber,
                newPayload);
        return new MultipartPart(part.partNumber(), length, part.partETag(),
                part.lastModified());
    }

    @Override
    public List<MultipartPart> listMultipartUpload(MultipartUpload mpu) {
        var builder = ImmutableList.<MultipartPart>builder();
        for (MultipartPart part : super.listMultipartUpload(mpu)) {
            // get real blob size from stub blob
            Blob blob = getBlob(mpu.containerName(),
                    mpu.id() + "-" + part.partNumber());
            long length = blob.getPayload().getContentMetadata()
                    .contentLength();
            builder.add(new MultipartPart(part.partNumber(), length,
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
