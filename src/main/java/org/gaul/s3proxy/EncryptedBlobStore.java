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

import static com.google.common.base.Preconditions.checkArgument;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
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
import com.google.common.collect.ImmutableSet;
import com.google.common.hash.HashCode;
import com.google.common.hash.Hashing;

import org.gaul.s3proxy.crypto.Constants;
import org.gaul.s3proxy.crypto.Decryption;
import org.gaul.s3proxy.crypto.Encryption;
import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.domain.Blob;
import org.jclouds.blobstore.domain.BlobAccess;
import org.jclouds.blobstore.domain.BlobBuilder;
import org.jclouds.blobstore.domain.BlobMetadata;
import org.jclouds.blobstore.domain.MultipartPart;
import org.jclouds.blobstore.domain.MultipartUpload;
import org.jclouds.blobstore.domain.MutableBlobMetadata;
import org.jclouds.blobstore.domain.PageSet;
import org.jclouds.blobstore.domain.StorageMetadata;
import org.jclouds.blobstore.domain.internal.MutableBlobMetadataImpl;
import org.jclouds.blobstore.domain.internal.PageSetImpl;
import org.jclouds.blobstore.options.CopyOptions;
import org.jclouds.blobstore.options.GetOptions;
import org.jclouds.blobstore.options.ListContainerOptions;
import org.jclouds.blobstore.options.PutOptions;
import org.jclouds.blobstore.util.ForwardingBlobStore;
import org.jclouds.io.ContentMetadata;
import org.jclouds.io.MutableContentMetadata;
import org.jclouds.io.Payload;
import org.jclouds.io.Payloads;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@SuppressWarnings("UnstableApiUsage")
public final class EncryptedBlobStore extends ForwardingBlobStore {
    private final Logger logger =
        LoggerFactory.getLogger(EncryptedBlobStore.class);
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
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    private Blob cipheredBlob(String container, Blob blob, InputStream payload,
        long contentLength,
        boolean addEncryptedMetadata) {

        // make a copy of the blob with the new payload stream
        BlobMetadata blobMeta = blob.getMetadata();
        ContentMetadata contentMeta = blob.getMetadata().getContentMetadata();
        Map<String, String> userMetadata = blobMeta.getUserMetadata();
        String contentType = contentMeta.getContentType();

        // suffix the content type with -s3enc if we need to encrypt
        if (addEncryptedMetadata) {
            blobMeta = setEncryptedSuffix(blobMeta);
        } else {
            // remove the -s3enc suffix while decrypting
            // but not if it contains a multipart meta
            if (!blobMeta.getUserMetadata()
                .containsKey(Constants.METADATA_IS_ENCRYPTED_MULTIPART)) {
                blobMeta = removeEncryptedSuffix(blobMeta);
            }
        }

        // we do not set contentMD5 as it will not match due to the encryption
        Blob cipheredBlob = blobBuilder(container)
            .name(blobMeta.getName())
            .type(blobMeta.getType())
            .tier(blobMeta.getTier())
            .userMetadata(userMetadata)
            .payload(payload)
            .cacheControl(contentMeta.getCacheControl())
            .contentDisposition(contentMeta.getContentDisposition())
            .contentEncoding(contentMeta.getContentEncoding())
            .contentLanguage(contentMeta.getContentLanguage())
            .contentLength(contentLength)
            .contentType(contentType)
            .build();

        cipheredBlob.getMetadata().setUri(blobMeta.getUri());
        cipheredBlob.getMetadata().setETag(blobMeta.getETag());
        cipheredBlob.getMetadata().setLastModified(blobMeta.getLastModified());
        cipheredBlob.getMetadata().setSize(blobMeta.getSize());
        cipheredBlob.getMetadata().setPublicUri(blobMeta.getPublicUri());
        cipheredBlob.getMetadata().setContainer(blobMeta.getContainer());

        return cipheredBlob;
    }

    private Blob encryptBlob(String container, Blob blob) {

        try {
            // open the streams and pass them through the encryption
            InputStream isRaw = blob.getPayload().openStream();
            Encryption encryption =
                new Encryption(secretKey, isRaw, 1);
            InputStream is = encryption.openStream();

            // adjust the encrypted content length by
            // adding the padding block size
            long contentLength =
                blob.getMetadata().getContentMetadata().getContentLength() +
                    Constants.PADDING_BLOCK_SIZE;

            return cipheredBlob(container, blob, is, contentLength, true);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private Payload encryptPayload(Payload payload, int partNumber) {

        try {
            // open the streams and pass them through the encryption
            InputStream isRaw = payload.openStream();
            Encryption encryption =
                new Encryption(secretKey, isRaw, partNumber);
            InputStream is = encryption.openStream();

            Payload cipheredPayload = Payloads.newInputStreamPayload(is);
            MutableContentMetadata contentMetadata =
                payload.getContentMetadata();
            HashCode md5 = null;
            contentMetadata.setContentMD5(md5);
            cipheredPayload.setContentMetadata(payload.getContentMetadata());
            cipheredPayload.setSensitive(payload.isSensitive());

            // adjust the encrypted content length by
            // adding the padding block size
            long contentLength =
                payload.getContentMetadata().getContentLength() +
                    Constants.PADDING_BLOCK_SIZE;
            cipheredPayload.getContentMetadata()
                .setContentLength(contentLength);

            return cipheredPayload;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private Blob decryptBlob(Decryption decryption, String container,
        Blob blob) {
        try {
            // handle blob does not exist
            if (blob == null) {
                return null;
            }

            // open the streams and pass them through the decryption
            InputStream isRaw = blob.getPayload().openStream();
            InputStream is = decryption.openStream(isRaw);

            // adjust the content length if the blob is encrypted
            long contentLength =
                blob.getMetadata().getContentMetadata().getContentLength();
            if (decryption.isEncrypted()) {
                contentLength = decryption.getContentLength();
            }

            return cipheredBlob(container, blob, is, contentLength, false);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // filter the list by showing the unencrypted blob size
    private PageSet<? extends StorageMetadata> filteredList(
        PageSet<? extends StorageMetadata> pageSet) {
        var builder = ImmutableSet.<StorageMetadata>builder();
        for (StorageMetadata sm : pageSet) {
            if (sm instanceof BlobMetadata) {
                MutableBlobMetadata mbm =
                    new MutableBlobMetadataImpl((BlobMetadata) sm);

                // if blob is encrypted remove the -s3enc suffix
                // from content type
                if (isEncrypted(mbm)) {
                    mbm = removeEncryptedSuffix((BlobMetadata) sm);
                    mbm = calculateBlobSize(mbm);
                }

                builder.add(mbm);
            } else {
                builder.add(sm);
            }
        }

        // make sure the marker do not show blob with .s3enc suffix
        String marker = pageSet.getNextMarker();
        if (marker != null && isEncrypted(marker)) {
            marker = removeEncryptedSuffix(marker);
        }
        return new PageSetImpl<>(builder.build(), marker);
    }

    private boolean isEncrypted(BlobMetadata blobMeta) {
        return isEncrypted(blobMeta.getName());
    }

    private boolean isEncrypted(String blobName) {
        return blobName.endsWith(Constants.S3_ENC_SUFFIX);
    }

    private MutableBlobMetadata setEncryptedSuffix(BlobMetadata blobMeta) {
        var bm = new MutableBlobMetadataImpl(blobMeta);
        if (blobMeta.getName() != null && !isEncrypted(blobMeta.getName())) {
            bm.setName(blobNameWithSuffix(blobMeta.getName()));
        }

        return bm;
    }

    private String removeEncryptedSuffix(String blobName) {
        return blobName.substring(0,
            blobName.length() - Constants.S3_ENC_SUFFIX.length());
    }

    private MutableBlobMetadata removeEncryptedSuffix(BlobMetadata blobMeta) {
        var bm = new MutableBlobMetadataImpl(blobMeta);
        if (isEncrypted(bm.getName())) {
            String blobName = bm.getName();
            bm.setName(removeEncryptedSuffix(blobName));
        }

        return bm;
    }

    private MutableBlobMetadata calculateBlobSize(BlobMetadata blobMeta) {
        MutableBlobMetadata mbm = removeEncryptedSuffix(blobMeta);

        // we are using on non-s3 backends like azure or gcp a metadata key to
        // calculate the part padding sizes that needs to be removed
        if (mbm.getUserMetadata()
            .containsKey(Constants.METADATA_ENCRYPTION_PARTS)) {
            int parts = Integer.parseInt(
                mbm.getUserMetadata().get(Constants.METADATA_ENCRYPTION_PARTS));
            int partPaddingSizes = Constants.PADDING_BLOCK_SIZE * parts;
            long size = blobMeta.getSize() - partPaddingSizes;
            mbm.setSize(size);
            mbm.getContentMetadata().setContentLength(size);
        } else {
            // on s3 backends like aws or minio we rely on the eTag suffix
            Matcher matcher =
                Constants.MPU_ETAG_SUFFIX_PATTERN.matcher(blobMeta.getETag());
            if (matcher.find()) {
                int parts = Integer.parseInt(matcher.group(1));
                int partPaddingSizes = Constants.PADDING_BLOCK_SIZE * parts;
                long size = blobMeta.getSize() - partPaddingSizes;
                mbm.setSize(size);
                mbm.getContentMetadata().setContentLength(size);
            } else {
                long size = blobMeta.getSize() - Constants.PADDING_BLOCK_SIZE;
                mbm.setSize(size);
                mbm.getContentMetadata().setContentLength(size);
            }
        }

        return mbm;
    }

    private boolean multipartRequiresStub() {
        String blobStoreType = getBlobStoreType();
        return Quirks.MULTIPART_REQUIRES_STUB.contains(blobStoreType);
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

    private String getBlobStoreType() {
        return delegate().getContext().unwrap().getProviderMetadata().getId();
    }

    private String generateUploadId(String container, String blobName) {
        String path = container + "/" + blobName;
        return Hashing.md5().hashBytes(path.getBytes(StandardCharsets.UTF_8)).toString();
    }

    @Override
    public Blob getBlob(String containerName, String blobName) {
        return getBlob(containerName, blobName, new GetOptions());
    }

    @Override
    public Blob getBlob(String containerName, String blobName,
        GetOptions getOptions) {

        // adjust the blob name
        blobName = blobNameWithSuffix(blobName);

        // get the metadata to determine the blob size
        BlobMetadata meta = delegate().blobMetadata(containerName, blobName);

        try {
            // we have a blob that ends with .s3enc
            if (meta != null) {
                // init defaults
                long offset = 0;
                long end = 0;
                long length = -1;

                if (getOptions.getRanges().size() > 0) {
                    // S3 doesn't allow multiple ranges
                    String range = getOptions.getRanges().get(0);
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
                Decryption decryption =
                    new Decryption(secretKey, delegate(), meta, offset, length);

                if (decryption.isEncrypted() &&
                    getOptions.getRanges().size() > 0) {
                    // clear current ranges to avoid multiple ranges
                    getOptions.getRanges().clear();

                    long startAt = decryption.getStartAt();
                    long endAt = decryption.getEncryptedSize();

                    if (offset == 0 && end > 0 && length == end) {
                        // handle to read from the end
                        startAt = decryption.calculateTail();
                    } else if (offset > 0 && end > 0) {
                        // handle to read from an offset
                        endAt = decryption.calculateEndAt(end);
                    }

                    getOptions.range(startAt, endAt);
                }

                Blob blob =
                    delegate().getBlob(containerName, blobName, getOptions);
                return decryptBlob(decryption, containerName, blob);
            } else {
                // we suppose to return a unencrypted blob
                // since no metadata was found
                blobName = removeEncryptedSuffix(blobName);
                return delegate().getBlob(containerName, blobName, getOptions);
            }

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public String putBlob(String containerName, Blob blob) {
        return delegate().putBlob(containerName,
            encryptBlob(containerName, blob));
    }

    @Override
    public String putBlob(String containerName, Blob blob,
        PutOptions putOptions) {
        return delegate().putBlob(containerName,
            encryptBlob(containerName, blob), putOptions);
    }

    @Override
    public String copyBlob(String fromContainer, String fromName,
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
    public PageSet<? extends StorageMetadata> list() {
        PageSet<? extends StorageMetadata> pageSet = delegate().list();
        return filteredList(pageSet);
    }

    @Override
    public PageSet<? extends StorageMetadata> list(String container) {
        PageSet<? extends StorageMetadata> pageSet = delegate().list(container);
        return filteredList(pageSet);
    }

    @Override
    public PageSet<? extends StorageMetadata> list(String container,
        ListContainerOptions options) {
        PageSet<? extends StorageMetadata> pageSet =
            delegate().list(container, options);
        return filteredList(pageSet);
    }

    @Override
    public MultipartUpload initiateMultipartUpload(String container,
        BlobMetadata blobMetadata, PutOptions options) {
        MutableBlobMetadata mbm = new MutableBlobMetadataImpl(blobMetadata);
        mbm = setEncryptedSuffix(mbm);

        MultipartUpload mpu =
            delegate().initiateMultipartUpload(container, mbm, options);

        // handle non-s3 backends
        // by setting a metadata key for multipart stubs
        if (multipartRequiresStub()) {
            mbm.getUserMetadata()
                .put(Constants.METADATA_IS_ENCRYPTED_MULTIPART, "true");

            if (getBlobStoreType().equals("azureblob")) {
                // use part 0 as a placeholder
                delegate().uploadMultipartPart(mpu, 0,
                    Payloads.newStringPayload("dummy"));

                // since azure does not have a uploadId
                // we use the sha256 of the path
                String uploadId = generateUploadId(container, mbm.getName());

                mpu = MultipartUpload.create(mpu.containerName(),
                    mpu.blobName(), uploadId, mpu.blobMetadata(), options);
            } else if (getBlobStoreType().equals("google-cloud-storage")) {
                mbm.getUserMetadata()
                    .put(Constants.METADATA_MULTIPART_KEY, mbm.getName());

                // since gcp does not have a uploadId
                // we use the sha256 of the path
                String uploadId = generateUploadId(container, mbm.getName());

                // to emulate later the list of multipart uploads
                // we create a placeholer
                BlobBuilder builder =
                    blobBuilder(Constants.MPU_FOLDER + uploadId)
                        .payload("")
                        .userMetadata(mbm.getUserMetadata());
                delegate().putBlob(container, builder.build(), options);

                // final mpu on gcp
                mpu = MultipartUpload.create(mpu.containerName(),
                    mpu.blobName(), uploadId, mpu.blobMetadata(), options);
            }
        }

        return mpu;
    }

    @Override
    public List<MultipartUpload> listMultipartUploads(String container) {
        List<MultipartUpload> mpus = new ArrayList<>();

        // emulate list of multipart uploads on gcp
        if (getBlobStoreType().equals("google-cloud-storage")) {
            var options = new ListContainerOptions();
            PageSet<? extends StorageMetadata> mpuList =
                delegate().list(container,
                    options.prefix(Constants.MPU_FOLDER));

            // find all blobs in .mpu folder and build the list
            for (StorageMetadata blob : mpuList) {
                Map<String, String> meta = blob.getUserMetadata();
                if (meta.containsKey(Constants.METADATA_MULTIPART_KEY)) {
                    String blobName =
                        meta.get(Constants.METADATA_MULTIPART_KEY);
                    String uploadId =
                        blob.getName()
                            .substring(blob.getName().lastIndexOf("/") + 1);
                    MultipartUpload mpu =
                        MultipartUpload.create(container,
                            blobName, uploadId, null, null);
                    mpus.add(mpu);
                }
            }
        } else {
            mpus = delegate().listMultipartUploads(container);
        }

        List<MultipartUpload> filtered = new ArrayList<>();
        // filter the list uploads by removing the .s3enc suffix
        for (MultipartUpload mpu : mpus) {
            String blobName = mpu.blobName();
            if (isEncrypted(blobName)) {
                blobName = removeEncryptedSuffix(mpu.blobName());

                String uploadId = mpu.id();

                // since azure not have a uploadId
                // we use the sha256 of the path
                if (getBlobStoreType().equals("azureblob")) {
                    uploadId = generateUploadId(container, mpu.blobName());
                }

                MultipartUpload mpuWithoutSuffix =
                    MultipartUpload.create(mpu.containerName(),
                        blobName, uploadId, mpu.blobMetadata(),
                        mpu.putOptions());

                filtered.add(mpuWithoutSuffix);
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

            // we use part 0 as a placeholder and hide it on azure
            if (getBlobStoreType().equals("azureblob") &&
                part.partNumber() == 0) {
                continue;
            }

            MultipartPart newPart = MultipartPart.create(
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
        int partNumber, Payload payload) {

        mpu = filterMultipartUpload(mpu);
        return delegate().uploadMultipartPart(mpu, partNumber,
            encryptPayload(payload, partNumber));
    }

    private MultipartUpload filterMultipartUpload(MultipartUpload mpu) {
        MutableBlobMetadata mbm = null;
        if (mpu.blobMetadata() != null) {
            mbm = new MutableBlobMetadataImpl(mpu.blobMetadata());
            mbm = setEncryptedSuffix(mbm);
        }

        String blobName = mpu.blobName();
        if (!isEncrypted(blobName)) {
            blobName = blobNameWithSuffix(blobName);
        }

        return MultipartUpload.create(mpu.containerName(), blobName, mpu.id(),
            mbm, mpu.putOptions());
    }

    @Override
    public String completeMultipartUpload(MultipartUpload mpu,
        List<MultipartPart> parts) {

        MutableBlobMetadata mbm =
            new MutableBlobMetadataImpl(mpu.blobMetadata());
        String blobName = mpu.blobName();

        // always set .s3enc suffix except on gcp
        // and blob name starts with multipart upload id
        if (getBlobStoreType().equals("google-cloud-storage") &&
            mpu.blobName().startsWith(mpu.id())) {
            logger.debug("skip suffix on gcp");
        } else {
            mbm = setEncryptedSuffix(mbm);
            if (!isEncrypted(mpu.blobName())) {
                blobName = blobNameWithSuffix(blobName);
            }
        }

        MultipartUpload mpuWithSuffix =
            MultipartUpload.create(mpu.containerName(),
                blobName, mpu.id(), mbm, mpu.putOptions());

        // this will only work for non s3 backends like azure and gcp
        if (multipartRequiresStub()) {
            long partCount = parts.size();

            // special handling for GCP to sum up all parts
            if (getBlobStoreType().equals("google-cloud-storage")) {
                partCount = 0;
                for (MultipartPart part : parts) {
                    blobName =
                        String.format("%s_%08d",
                            mpu.id(),
                            part.partNumber());
                    BlobMetadata metadata =
                        delegate().blobMetadata(mpu.containerName(), blobName);
                    if (metadata != null && metadata.getUserMetadata()
                        .containsKey(Constants.METADATA_ENCRYPTION_PARTS)) {
                        String partMetaCount = metadata.getUserMetadata()
                            .get(Constants.METADATA_ENCRYPTION_PARTS);
                        partCount = partCount + Long.parseLong(partMetaCount);
                    } else {
                        partCount++;
                    }
                }
            }

            mpuWithSuffix.blobMetadata().getUserMetadata()
                .put(Constants.METADATA_ENCRYPTION_PARTS,
                    String.valueOf(partCount));
            mpuWithSuffix.blobMetadata().getUserMetadata()
                .remove(Constants.METADATA_IS_ENCRYPTED_MULTIPART);
        }

        String eTag = delegate().completeMultipartUpload(mpuWithSuffix, parts);

        // cleanup mpu placeholder on gcp
        if (getBlobStoreType().equals("google-cloud-storage")) {
            delegate().removeBlob(mpu.containerName(),
                Constants.MPU_FOLDER + mpu.id());
        }

        return eTag;
    }

    @Override
    public BlobMetadata blobMetadata(String container, String name) {

        name = blobNameWithSuffix(container, name);
        BlobMetadata blobMetadata = delegate().blobMetadata(container, name);
        if (blobMetadata != null) {
            // only remove the -s3enc suffix
            // if the blob is encrypted and not a multipart stub
            if (isEncrypted(blobMetadata) &&
                !blobMetadata.getUserMetadata()
                    .containsKey(Constants.METADATA_IS_ENCRYPTED_MULTIPART)) {
                blobMetadata = removeEncryptedSuffix(blobMetadata);
                blobMetadata = calculateBlobSize(blobMetadata);
            }
        }
        return blobMetadata;
    }

    @Override
    public long getMaximumMultipartPartSize() {
        long max = delegate().getMaximumMultipartPartSize();
        return max - Constants.PADDING_BLOCK_SIZE;
    }
}
