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

import static java.util.Objects.requireNonNull;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.util.Arrays;
import java.util.List;

import com.google.common.collect.ImmutableList;
import com.google.common.hash.HashCode;
import com.google.common.io.ByteSource;
import com.google.common.primitives.Longs;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.ForwardingBlobStore;
import org.gaul.s3proxy.blobstore.SdkRequests;
import org.gaul.s3proxy.blobstore.SdkResponses;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.gaul.s3proxy.blobstore.options.ListContainerOptions;
import org.jspecify.annotations.Nullable;

import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.CompletedPart;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.HeadObjectRequest;
import software.amazon.awssdk.services.s3.model.HeadObjectResponse;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Response;
import software.amazon.awssdk.services.s3.model.Part;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.awssdk.services.s3.model.S3Object;
import software.amazon.awssdk.services.s3.model.UploadPartResponse;

final class NullBlobStore extends ForwardingBlobStore {
    private NullBlobStore(BlobStore blobStore) {
        super(blobStore);
    }

    static BlobStore newNullBlobStore(BlobStore blobStore) {
        return new NullBlobStore(blobStore);
    }

    @Override
    @Nullable
    public HeadObjectResponse blobMetadata(HeadObjectRequest request) {
        var blob = getBlob(request.bucket(), request.key());
        if (blob == null) {
            return null;
        }
        try (blob) {
            return SdkResponses.toHead(blob.response());
        } catch (IOException ioe) {
            throw new UncheckedIOException(ioe);
        }
    }

    @Override
    @Nullable
    public ResponseInputStream<GetObjectResponse> getBlob(
            GetObjectRequest request) {
        // Ranges apply to the virtual content, not the 8-byte length stub.
        var range = SdkRequests.parseRange(request.range());
        ResponseInputStream<GetObjectResponse> blob;
        if (range == null) {
            blob = super.getBlob(request);
        } else {
            blob = super.getBlob(request.toBuilder().range(null).build());
        }
        if (blob == null) {
            return null;
        }

        byte[] array;
        try (InputStream is = blob) {
            array = is.readAllBytes();
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }

        long fullLength = Longs.fromByteArray(array);
        long length = fullLength;
        if (range != null) {
            if (range.first() == null) {
                // bytes=-N: last N bytes
                length = Math.min(requireNonNull(range.last()),
                        fullLength);
            } else if (range.last() == null) {
                // bytes=A-: from offset to end
                length = Math.max(0, fullLength - range.first());
            } else {
                // bytes=A-B
                length = Math.max(0,
                        Math.min(range.last() + 1, fullLength) -
                                range.first());
            }
        }

        try {
            return SdkResponses.getResponse(
                    blob.response().toBuilder()
                            .contentLength(length)
                            .build(),
                    new NullByteSource().slice(0, length).openStream());
        } catch (IOException ioe) {
            throw new UncheckedIOException(ioe);
        }
    }

    @Override
    public ListObjectsV2Response list(String container,
            ListContainerOptions options) {
        ListObjectsV2Response page = super.list(container, options);
        var contents = ImmutableList.<S3Object>builder();
        for (S3Object object : page.contents()) {
            contents.add(object.toBuilder().size(0L).build());
        }
        return page.toBuilder().contents(contents.build()).build();
    }

    @Override
    public PutObjectResponse putBlob(PutObjectRequest request,
            InputStream payload) {
        long length;
        try (InputStream is = payload) {
            length = is.transferTo(OutputStream.nullOutputStream());
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }

        byte[] array = Longs.toByteArray(length);

        return super.putBlob(request.toBuilder()
                        .contentLength((long) array.length)
                        .contentMD5(null)
                        .build(),
                new ByteArrayInputStream(array));
    }

    @Override
    public CompleteMultipartUploadResponse completeMultipartUpload(final MultipartUpload mpu,
            final CompleteMultipartUploadRequest request) {
        List<CompletedPart> parts = request.multipartUpload() == null ?
                List.of() : request.multipartUpload().parts();
        long length = 0;
        var sizeByPart = new java.util.HashMap<Integer, Long>();
        for (Part listed : listMultipartUpload(mpu)) {
            sizeByPart.put(listed.partNumber(), listed.size());
        }
        for (CompletedPart part : parts) {
            length += requireNonNull(sizeByPart.get(part.partNumber()));
            super.removeBlob(mpu.containerName(), mpu.id() + "-" +
                    part.partNumber());
        }

        byte[] array = Longs.toByteArray(length);

        super.abortMultipartUpload(mpu);

        // Re-initiate a single-part upload holding the logical length.
        MultipartUpload mpu2 = super.initiateMultipartUpload(mpu.request());

        var part = super.uploadMultipartPart(mpu2, 1,
                new ByteArrayInputStream(array), array.length, null);

        return super.completeMultipartUpload(mpu2,
                SdkRequests.completeRequest(mpu2, List.of(
                        CompletedPart.builder()
                                .partNumber(1)
                                .eTag(part.eTag())
                                .build())));
    }

    @Override
    public void abortMultipartUpload(MultipartUpload mpu) {
        for (Part part : super.listMultipartUpload(mpu)) {
            super.removeBlob(mpu.containerName(), mpu.id() + "-" +
                    part.partNumber());
        }

        super.abortMultipartUpload(mpu);
    }

    @Override
    public UploadPartResponse uploadMultipartPart(MultipartUpload mpu,
            int partNumber, InputStream is, long contentLength,
            @Nullable HashCode contentMD5) {
        long length;
        try (is) {
            length = is.transferTo(OutputStream.nullOutputStream());
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }

        byte[] array = Longs.toByteArray(length);

        // create a single-part object which contains the logical length which
        // list and complete will read later
        super.putBlob(PutObjectRequest.builder()
                        .bucket(mpu.containerName())
                        .key(mpu.id() + "-" + partNumber)
                        .contentLength((long) array.length)
                        .build(),
                new ByteArrayInputStream(array));

        return super.uploadMultipartPart(mpu, partNumber,
                new ByteArrayInputStream(array), array.length, null);
    }

    @Override
    public List<Part> listMultipartUpload(MultipartUpload mpu) {
        var builder = ImmutableList.<Part>builder();
        for (Part part : super.listMultipartUpload(mpu)) {
            // get real blob size from stub blob
            var blob = requireNonNull(getBlob(mpu.containerName(),
                    mpu.id() + "-" + part.partNumber()));
            long length = requireNonNull(blob.response().contentLength());
            builder.add(part.toBuilder().size(length).build());
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
    // Disable versioning: versioned reads would return the stored stub
    // rather than fake content.
    @Override
    public boolean supportsVersioning() {
        return false;
    }

}
