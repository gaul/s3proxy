package org.gaul.s3proxy;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.SequenceInputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.spec.KeySpec;
import java.util.List;
import java.util.Properties;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import com.google.common.base.Throwables;

import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.domain.Blob;
import org.jclouds.blobstore.domain.BlobMetadata;
import org.jclouds.blobstore.domain.MultipartPart;
import org.jclouds.blobstore.domain.MultipartUpload;
import org.jclouds.blobstore.options.GetOptions;
import org.jclouds.blobstore.options.PutOptions;
import org.jclouds.blobstore.util.ForwardingBlobStore;
import org.jclouds.io.ContentMetadata;
import org.jclouds.io.Payload;

public final class EncryptedBlobStore extends ForwardingBlobStore {

    public static final int IV_SIZE = 32;
    private SecretKey secretKey;

    private EncryptedBlobStore(BlobStore blobStore, Properties properties) {
        super(blobStore);

        char[] password = properties.getProperty(
            S3ProxyConstants.PROPERTY_ENCRYPTION_KEY).toCharArray();
        byte[] salt = properties.getProperty(
            S3ProxyConstants.PROPERTY_ENCRYPTION_SALT).getBytes(
                StandardCharsets.UTF_8);
        initStore(password, salt);
    }

    static BlobStore newEncryptedBlobStore(BlobStore blobStore,
                                           Properties properties) {
        return new EncryptedBlobStore(blobStore, properties);
    }

    private void initStore(char[] password, byte[] salt) {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(
                "PBKDF2WithHmacSHA1");
            KeySpec spec = new PBEKeySpec(password, salt, 100000, 128);
            SecretKey tmpSecretKey = factory.generateSecret(spec);
            secretKey = new SecretKeySpec(tmpSecretKey.getEncoded(), "AES");
        } catch (GeneralSecurityException e) {
            throw Throwables.propagate(e);
        }
    }

    private Blob cipheredBlob(String container, Blob blob, InputStream payload,
                              boolean setHash, long ivDifference) {
        BlobMetadata blobMeta = blob.getMetadata();
        ContentMetadata contentMeta = blob.getMetadata().getContentMetadata();
        Blob cipheredBlob = blobBuilder(container)
                .name(blobMeta.getName())
                .type(blobMeta.getType())
                .tier(blobMeta.getTier())
                .userMetadata(blobMeta.getUserMetadata())
                .payload(payload)
                .cacheControl(contentMeta.getCacheControl())
                .contentDisposition(contentMeta.getContentDisposition())
                .contentEncoding(contentMeta.getContentEncoding())
                .contentLanguage(contentMeta.getContentLanguage())
                .contentLength(blob.getMetadata().getContentMetadata()
                    .getContentLength() + ivDifference)
                .contentMD5(setHash ? contentMeta.getContentMD5AsHashCode() :
                    null)
                .contentType(contentMeta.getContentType())
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
            Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            // store the IV in the beginning of the blob
            byte[] iv = cipher.getParameters().getParameterSpec(IvParameterSpec
                .class).getIV();
            ByteArrayOutputStream ivStream = new ByteArrayOutputStream(IV_SIZE);
            if (iv.length >= 256) {
                throw new UnsupportedOperationException("IV is too long: " +
                    iv.length);
            }
            ivStream.write(iv.length);
            ivStream.write(iv);
            InputStream is = new SequenceInputStream(
                    new ByteArrayInputStream(ivStream.toByteArray()),
                    new CipherInputStream(blob.getPayload().openStream(),
                        cipher));

            return cipheredBlob(container, blob, is, false,
                iv.length + 1);

        } catch (IOException | GeneralSecurityException e) {
            throw Throwables.propagate(e);
        }
    }

    private Blob decryptBlob(String container, Blob blob) {
        try {
            DataInputStream in = new DataInputStream(blob.getPayload()
                .openStream());
            int len = in.read();
            byte[] iv = new byte[len];
            in.readFully(iv);
            Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey,
                new IvParameterSpec(iv));
            CipherInputStream is = new CipherInputStream(in, cipher);

            return cipheredBlob(container, blob, is, true,
                -(iv.length + 1));

        } catch (IOException | GeneralSecurityException e) {
            throw Throwables.propagate(e);
        }
    }

    @Override
    public Blob getBlob(String containerName, String blobName) {
        return decryptBlob(containerName, delegate().getBlob(containerName,
            blobName));
    }

    @Override
    public Blob getBlob(String containerName, String blobName,
                        GetOptions getOptions) {
        return decryptBlob(containerName, delegate().getBlob(containerName,
            blobName, getOptions));
    }

    @Override
    public String putBlob(String containerName, Blob blob) {
        return delegate().putBlob(containerName, encryptBlob(containerName,
            blob));
    }

    @Override
    public String putBlob(String containerName, Blob blob,
                          PutOptions putOptions) {
        return delegate().putBlob(containerName, encryptBlob(containerName,
            blob), putOptions);
    }

    @Override
    public void abortMultipartUpload(MultipartUpload mpu) {
        throw new UnsupportedOperationException();
    }

    @Override
    public MultipartUpload initiateMultipartUpload(String container,
                                                   BlobMetadata blobMetadata,
                                                   PutOptions options) {
        throw new UnsupportedOperationException();
    }

    @Override
    public String completeMultipartUpload(MultipartUpload mpu,
                                          List<MultipartPart> parts) {
        throw new UnsupportedOperationException();
    }

    @Override
    public MultipartPart uploadMultipartPart(MultipartUpload mpu,
                                             int partNumber, Payload payload) {
        throw new UnsupportedOperationException();
    }

    @Override
    public List<MultipartPart> listMultipartUpload(MultipartUpload mpu) {
        throw new UnsupportedOperationException();
    }
}
