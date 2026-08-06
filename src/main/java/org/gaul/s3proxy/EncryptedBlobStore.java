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

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.security.GeneralSecurityException;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.regex.Matcher;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import com.google.common.hash.HashCode;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.ContentMetadata;
import org.gaul.s3proxy.blobstore.ForwardingBlobStore;
import org.gaul.s3proxy.blobstore.SdkResponses;
import org.gaul.s3proxy.blobstore.domain.Blob;
import org.gaul.s3proxy.blobstore.domain.BlobAccess;
import org.gaul.s3proxy.blobstore.domain.BlobMetadata;
import org.gaul.s3proxy.blobstore.domain.MultipartPart;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.gaul.s3proxy.blobstore.options.CopyOptions;
import org.gaul.s3proxy.blobstore.options.GetOptions;
import org.gaul.s3proxy.blobstore.options.ListContainerOptions;
import org.gaul.s3proxy.blobstore.options.PutOptions;
import org.gaul.s3proxy.crypto.Constants;
import org.gaul.s3proxy.crypto.Decryption;
import org.gaul.s3proxy.crypto.Encryption;
import org.gaul.s3proxy.crypto.PartPadding;
import org.jspecify.annotations.Nullable;

import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.services.s3.model.Bucket;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.CopyObjectResponse;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.HeadObjectResponse;
import software.amazon.awssdk.services.s3.model.ListBucketsResponse;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Response;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.awssdk.services.s3.model.S3Object;

@SuppressWarnings("UnstableApiUsage")
public final class EncryptedBlobStore extends ForwardingBlobStore {
    private SecretKeySpec secretKey;

    private EncryptedBlobStore(BlobStore blobStore, Properties properties)
            throws IllegalArgumentException {
        super(blobStore);

        String password = properties.getProperty(
            S3ProxyConstants.PROPERTY_ENCRYPTED_BLOBSTORE_PASSWORD);
        checkArgument(!Strings.isNullOrEmpty(password),
            "Password for encrypted blobstore is not set");

        String salt = properties.getProperty(
            S3ProxyConstants.PROPERTY_ENCRYPTED_BLOBSTORE_SALT);
        checkArgument(!Strings.isNullOrEmpty(salt),
            "Salt for encrypted blobstore is not set");
        initStore(password, salt);
    }

    static BlobStore newEncryptedBlobStore(BlobStore blobStore,
        Properties properties) throws IOException {
        return new EncryptedBlobStore(blobStore, properties);
    }

    private void initStore(String password, String salt)
            throws IllegalArgumentException {
        try {
            SecretKeyFactory factory =
                SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec =
                new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536,
                    128);
            SecretKey tmp = factory.generateSecret(spec);
            secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private Blob cipheredBlob(Blob blob, InputStream payload,
        long contentLength,
        boolean addEncryptedMetadata) {

        // make a copy of the blob with the new payload stream
        BlobMetadata blobMeta = blob.getMetadata();
        ContentMetadata contentMeta = blob.getMetadata().contentMetadata();
        Map<String, String> userMetadata = blobMeta.userMetadata();
        String contentType = contentMeta.contentType();

        // suffix the content type with -s3enc if we need to encrypt
        if (addEncryptedMetadata) {
            blobMeta = setEncryptedSuffix(blobMeta);
        } else {
            // remove the -s3enc suffix while decrypting
            // but not if it contains a multipart meta
            if (!blobMeta.userMetadata()
                .containsKey(Constants.METADATA_IS_ENCRYPTED_MULTIPART)) {
                blobMeta = removeEncryptedSuffix(blobMeta);
            }
        }

        // we do not set contentMD5 as it will not match due to the encryption
        return Blob.builder(blobMeta.name())
            .storageClass(blobMeta.storageClass())
            .userMetadata(userMetadata)
            .payload(payload)
            .cacheControl(contentMeta.cacheControl())
            .contentDisposition(contentMeta.contentDisposition())
            .contentEncoding(contentMeta.contentEncoding())
            .contentLanguage(contentMeta.contentLanguage())
            .contentLength(contentLength)
            .contentType(contentType)
            .eTag(blobMeta.eTag())
            .lastModified(blobMeta.lastModified())
            .container(blobMeta.container())
            .build();
    }

    private Blob encryptBlob(Blob blob) {

        try {
            // open the streams and pass them through the encryption
            InputStream isRaw = requireNonNull(blob.getPayload());
            Encryption encryption =
                new Encryption(secretKey, isRaw, 1);
            InputStream is = encryption.openStream();

            // adjust the encrypted content length by
            // adding the padding block size
            long contentLength = requireNonNull(
                blob.getMetadata().contentMetadata().contentLength()) +
                    Constants.PADDING_BLOCK_SIZE;

            return cipheredBlob(blob, is, contentLength, true);
        } catch (IOException | GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    // filter the list by showing the unencrypted blob size
    private ListBucketsResponse filteredBuckets(ListBucketsResponse page) {
        var builder = ImmutableList.<Bucket>builder();
        for (Bucket bucket : page.buckets()) {
            if (isEncrypted(bucket.name())) {
                builder.add(bucket.toBuilder()
                        .name(removeEncryptedSuffix(bucket.name()))
                        .build());
            } else {
                builder.add(bucket);
            }
        }
        return page.toBuilder().buckets(builder.build()).build();
    }

    private ListObjectsV2Response filteredList(String container,
            ListObjectsV2Response page) {
        var builder = ImmutableList.<S3Object>builder();
        for (S3Object object : page.contents()) {
            // an encrypted blob drops the .s3enc suffix and reports the
            // plaintext size rather than the padded stored size
            if (isEncrypted(object.key())) {
                builder.add(object.toBuilder()
                        .key(removeEncryptedSuffix(object.key()))
                        .size(plaintextSize(container, object))
                        .build());
            } else {
                builder.add(object);
            }
        }

        // make sure the marker do not show blob with .s3enc suffix
        String marker = page.nextContinuationToken();
        if (marker != null && isEncrypted(marker)) {
            marker = removeEncryptedSuffix(marker);
        }
        return page.toBuilder()
                .contents(builder.build())
                .nextContinuationToken(marker)
                .build();
    }

    /**
     * The plaintext size of a listed encrypted object: the stored size less
     * the padding, counted from the eTag's part suffix or, failing that, by
     * reading the final part padding -- the same fallbacks blobMetadata
     * takes.
     */
    private long plaintextSize(String container, S3Object object) {
        long blobSize = requireNonNull(object.size());
        Matcher matcher =
            Constants.MPU_ETAG_SUFFIX_PATTERN.matcher(object.eTag());
        if (matcher.find()) {
            int parts = Integer.parseInt(matcher.group(1));
            return blobSize - (long) Constants.PADDING_BLOCK_SIZE * parts;
        }
        var options = GetOptions.builder()
            .range(blobSize - Constants.PADDING_BLOCK_SIZE, blobSize - 1)
            .build();
        var blob = requireNonNull(delegate().getBlob(
                container, object.key(), options));
        try {
            PartPadding lastPartPadding =
                PartPadding.readPartPadding(blob);
            int parts = lastPartPadding.getPart();
            return blobSize - (long) Constants.PADDING_BLOCK_SIZE * parts;
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }

    private boolean isEncrypted(String blobName) {
        return blobName.endsWith(Constants.S3_ENC_SUFFIX);
    }

    private BlobMetadata setEncryptedSuffix(BlobMetadata blobMeta) {
        if (blobMeta.name() != null && !isEncrypted(blobMeta.name())) {
            return blobMeta.toBuilder()
                    .name(blobNameWithSuffix(blobMeta.name()))
                    .build();
        }
        return blobMeta;
    }

    private String removeEncryptedSuffix(String blobName) {
        return blobName.substring(0,
            blobName.length() - Constants.S3_ENC_SUFFIX.length());
    }

    private BlobMetadata removeEncryptedSuffix(BlobMetadata blobMeta) {
        if (isEncrypted(blobMeta.name())) {
            return blobMeta.toBuilder()
                    .name(removeEncryptedSuffix(blobMeta.name()))
                    .build();
        }
        return blobMeta;
    }

    /**
     * The plaintext size of an encrypted object's HEAD: the stored size
     * less the padding, counted from the parts metadata, the eTag's part
     * suffix or, failing both, by reading the final part padding.
     */
    private long plaintextHeadSize(String container, String storedName,
            HeadObjectResponse head) {
        long blobSize = requireNonNull(head.contentLength());
        String partsMetadata = head.metadata().get(
                Constants.METADATA_ENCRYPTION_PARTS);
        if (partsMetadata != null) {
            int parts = Integer.parseInt(partsMetadata);
            return blobSize - (long) Constants.PADDING_BLOCK_SIZE * parts;
        }
        Matcher matcher = Constants.MPU_ETAG_SUFFIX_PATTERN.matcher(
                requireNonNull(head.eTag()));
        if (matcher.find()) {
            int parts = Integer.parseInt(matcher.group(1));
            return blobSize - (long) Constants.PADDING_BLOCK_SIZE * parts;
        }
        var options = GetOptions.builder()
            .range(blobSize - Constants.PADDING_BLOCK_SIZE, blobSize - 1)
            .build();
        var blob = requireNonNull(delegate().getBlob(
                container, storedName, options));
        try {
            int parts = PartPadding.readPartPadding(blob).getPart();
            return blobSize - (long) Constants.PADDING_BLOCK_SIZE * parts;
        } catch (IOException e) {
            throw new UncheckedIOException(
                "Failed to read part-padding from encrypted blob", e);
        }
    }

    private String blobNameWithSuffix(String container, String name) {
        String nameWithSuffix = blobNameWithSuffix(name);
        if (delegate().blobExists(container, nameWithSuffix)) {
            name = nameWithSuffix;
        }
        return name;
    }

    private String blobNameWithSuffix(String name) {
        return name + Constants.S3_ENC_SUFFIX;
    }

    @Override
    public @Nullable ResponseInputStream<GetObjectResponse> getBlob(
        String containerName, String blobName, GetOptions getOptions) {

        // adjust the blob name
        blobName = blobNameWithSuffix(blobName);

        // get the metadata to determine the blob size
        HeadObjectResponse meta = delegate().blobMetadata(containerName,
                blobName);

        try {
            // we have a blob that ends with .s3enc
            if (meta != null) {
                // init defaults
                long offset = 0;
                long end = 0;
                long length = -1;

                if (getOptions.ranges().size() > 0) {
                    // S3 doesn't allow multiple ranges
                    String range = getOptions.ranges().get(0);
                    String[] ranges = range.split("-", 2);

                    if (ranges[0].isEmpty()) {
                        // handle to read from the end
                        end = Long.parseLong(ranges[1]);
                        length = end;
                    } else if (ranges[1].isEmpty()) {
                        // handle to read from an offset till the end
                        offset = Long.parseLong(ranges[0]);
                    } else {
                        // handle to read from an offset
                        offset = Long.parseLong(ranges[0]);
                        end = Long.parseLong(ranges[1]);
                        length = end - offset + 1;
                    }
                }

                // init decryption
                Decryption decryption = new Decryption(secretKey, delegate(),
                    meta, containerName, blobName, offset, length);

                GetOptions delegateOptions = getOptions;
                if (decryption.isEncrypted() &&
                    getOptions.ranges().size() > 0) {
                    long startAt = decryption.getStartAt();
                    long endAt = decryption.getEncryptedSize();

                    if (offset == 0 && end > 0 && length == end) {
                        // handle to read from the end
                        startAt = decryption.calculateTail();
                    } else if (offset > 0 && end > 0) {
                        // handle to read from an offset
                        endAt = decryption.calculateEndAt(end);
                    }

                    // replace existing ranges with our single computed range
                    delegateOptions = new GetOptions(
                        List.of("%d-%d".formatted(startAt, endAt)),
                        getOptions.ifModifiedSince(),
                        getOptions.ifUnmodifiedSince(),
                        getOptions.ifMatch(), getOptions.ifNoneMatch(),
                        getOptions.versionId());
                }

                var blob = delegate().getBlob(containerName, blobName,
                    delegateOptions);
                if (blob == null) {
                    return null;
                }

                // open the streams and pass them through the decryption
                InputStream is = decryption.openStream(blob);

                // adjust the content length if the blob is encrypted
                long contentLength = requireNonNull(
                    blob.response().contentLength());
                if (decryption.isEncrypted()) {
                    contentLength = decryption.getContentLength();
                }

                var responseBuilder = blob.response().toBuilder()
                        .contentLength(contentLength);
                if (!getOptions.ranges().isEmpty()) {
                    long decryptedSize = decryption.getUnencryptedSize();
                    long startRange;
                    long endRange;
                    if (offset == 0 && end > 0 && length == end) {
                        // bytes=-N: last N bytes, clamped to the whole object
                        // when N exceeds the size
                        startRange = Math.max(0, decryptedSize - end);
                        endRange = decryptedSize - 1;
                    } else if (length < 0) {
                        // bytes=A-: from offset to end
                        startRange = offset;
                        endRange = decryptedSize - 1;
                    } else {
                        // bytes=A-B, with the end clamped to the last byte so
                        // an over-length range reports what is actually sent
                        startRange = offset;
                        endRange = Math.min(end, decryptedSize - 1);
                    }
                    responseBuilder.contentRange("bytes " + startRange + "-" +
                            endRange + "/" + decryptedSize);
                }
                return SdkResponses.getResponse(responseBuilder.build(), is);
            } else {
                // we suppose to return a unencrypted blob
                // since no metadata was found
                blobName = removeEncryptedSuffix(blobName);
                return delegate().getBlob(containerName, blobName, getOptions);
            }

        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public PutObjectResponse putBlob(String containerName, Blob blob,
        PutOptions putOptions) {
        return delegate().putBlob(containerName,
            encryptBlob(blob), putOptions);
    }

    @Override
    public CopyObjectResponse copyBlob(String fromContainer, String fromName,
        String toContainer, String toName, CopyOptions options) {

        // if we copy an encrypted blob
        // make sure to add suffix to the destination blob name
        String blobName = blobNameWithSuffix(fromName);
        if (delegate().blobExists(fromContainer, blobName)) {
            fromName = blobName;
            toName = blobNameWithSuffix(toName);
        }

        return delegate().copyBlob(fromContainer, fromName, toContainer, toName,
            options);
    }

    @Override
    public void removeBlob(String container, String name) {
        name = blobNameWithSuffix(container, name);
        delegate().removeBlob(container, name);
    }

    @Override
    public void removeBlobs(String container, Iterable<String> names) {
        List<String> filteredNames = new ArrayList<>();

        // filter the list of blobs to determine
        // if we need to delete encrypted blobs
        for (String name : names) {
            name = blobNameWithSuffix(container, name);
            filteredNames.add(name);
        }

        delegate().removeBlobs(container, filteredNames);
    }

    @Override
    public BlobAccess getBlobAccess(String container, String name) {
        name = blobNameWithSuffix(container, name);
        return delegate().getBlobAccess(container, name);
    }

    @Override
    public boolean blobExists(String container, String name) {
        name = blobNameWithSuffix(container, name);
        return delegate().blobExists(container, name);
    }

    @Override
    public void setBlobAccess(String container, String name,
        BlobAccess access) {
        name = blobNameWithSuffix(container, name);
        delegate().setBlobAccess(container, name, access);
    }

    @Override
    public ListBucketsResponse list() {
        return filteredBuckets(delegate().list());
    }

    @Override
    public ListObjectsV2Response list(String container,
        ListContainerOptions options) {
        var marker = options.marker();
        if (marker != null && !isEncrypted(marker)) {
            // filteredList strips the .s3enc suffix from the marker it returns;
            // re-add it so the backend resumes after the encrypted key rather
            // than re-listing it (which duplicates or stalls pagination).
            options = options.toBuilder()
                    .afterMarker(blobNameWithSuffix(marker))
                    .build();
        }
        return filteredList(container, delegate().list(container, options));
    }

    @Override
    public MultipartUpload initiateMultipartUpload(String container,
        BlobMetadata blobMetadata, PutOptions options) {
        return delegate().initiateMultipartUpload(container,
            setEncryptedSuffix(blobMetadata), options);
    }

    @Override
    public List<MultipartUpload> listMultipartUploads(String container) {
        List<MultipartUpload> filtered = new ArrayList<>();
        // filter the list uploads by removing the .s3enc suffix
        for (MultipartUpload mpu :
                delegate().listMultipartUploads(container)) {
            String blobName = mpu.blobName();
            if (isEncrypted(blobName)) {
                filtered.add(new MultipartUpload(mpu.containerName(),
                    removeEncryptedSuffix(blobName), mpu.id(),
                    mpu.blobMetadata(), mpu.putOptions()));
            } else {
                filtered.add(mpu);
            }
        }
        return filtered;
    }

    @Override
    public List<MultipartPart> listMultipartUpload(MultipartUpload mpu) {
        mpu = filterMultipartUpload(mpu);
        List<MultipartPart> parts = delegate().listMultipartUpload(mpu);
        List<MultipartPart> filteredParts = new ArrayList<>();

        // fix wrong multipart size due to the part padding
        for (MultipartPart part : parts) {
            MultipartPart newPart = new MultipartPart(
                part.partNumber(),
                part.partSize() - Constants.PADDING_BLOCK_SIZE,
                part.partETag(),
                part.lastModified()
            );
            filteredParts.add(newPart);
        }
        return filteredParts;
    }

    @Override
    public MultipartPart uploadMultipartPart(MultipartUpload mpu,
        int partNumber, InputStream is, long contentLength,
        @Nullable HashCode contentMD5) {

        mpu = filterMultipartUpload(mpu);
        InputStream encrypted;
        try {
            // pass the stream through the encryption
            encrypted = new Encryption(secretKey, is, partNumber).openStream();
        } catch (IOException | GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
        // adjust the encrypted content length by adding the padding block
        // size; also drop the MD5 since encryption changes the bytes
        return delegate().uploadMultipartPart(mpu, partNumber, encrypted,
            contentLength + Constants.PADDING_BLOCK_SIZE, null);
    }

    private MultipartUpload filterMultipartUpload(MultipartUpload mpu) {
        BlobMetadata mbm = null;
        if (mpu.blobMetadata() != null) {
            mbm = setEncryptedSuffix(mpu.blobMetadata());
        }

        String blobName = mpu.blobName();
        if (!isEncrypted(blobName)) {
            blobName = blobNameWithSuffix(blobName);
        }

        return new MultipartUpload(mpu.containerName(), blobName, mpu.id(),
            mbm, mpu.putOptions());
    }

    @Override
    public CompleteMultipartUploadResponse completeMultipartUpload(MultipartUpload mpu,
        List<MultipartPart> parts) {

        return delegate().completeMultipartUpload(filterMultipartUpload(mpu),
            parts);
    }

    @Override
    public void abortMultipartUpload(MultipartUpload mpu) {
        // Reconstruct the upload under the encrypted (.s3enc) name, the same
        // transform uploadMultipartPart and completeMultipartUpload apply, so
        // the abort targets the object initiateMultipartUpload created rather
        // than the plaintext key -- otherwise the real upload is left dangling
        // on backends that key uploads by object name.
        delegate().abortMultipartUpload(filterMultipartUpload(mpu));
    }

    @Override
    @Nullable
    public HeadObjectResponse blobMetadata(String container, String name) {

        String stored = blobNameWithSuffix(container, name);
        HeadObjectResponse head = delegate().blobMetadata(container, stored);
        if (head != null &&
            // report the plaintext size only for an encrypted blob that is
            // not a multipart stub
            isEncrypted(stored) &&
            !head.metadata().containsKey(
                Constants.METADATA_IS_ENCRYPTED_MULTIPART)) {
            head = head.toBuilder()
                    .contentLength(plaintextHeadSize(container, stored, head))
                    .build();
        }
        return head;
    }
    // Disable versioning: versioned reads would return ciphertext and
    // suffixed names.
    @Override
    public boolean supportsVersioning() {
        return false;
    }

}
