package org.gaul.s3proxy;

import com.amazonaws.auth.AWSCredentials;
import com.google.common.collect.Maps;
import org.jclouds.blobstore.BlobStore;

import javax.annotation.Nullable;
import java.util.Map;

public class TestBlobStoreLocator implements BlobStoreLocator {

    AWSCredentials awsCreds;
    BlobStore blobStore1;
    BlobStore blobStore2;

    public TestBlobStoreLocator(AWSCredentials awsCreds,
                                BlobStore blobStore1,
                                BlobStore blobStore2) {
        this.awsCreds = awsCreds;
        this.blobStore1 = blobStore1;
        this.blobStore2 = blobStore2;
    }

    @Nullable
    @Override
    public Map.Entry<String, BlobStore> locateBlobStore(
            String identity, String container, String blob) {
        if (identity.equals(awsCreds.getAWSAccessKeyId())) {
            return Maps.immutableEntry(awsCreds.getAWSSecretKey(),
                    blobStore1);
        } else if (identity.equals("other-identity")) {
            return Maps.immutableEntry("credential", blobStore2);
        } else {
            return null;
        }
    }
}
