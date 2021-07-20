package org.gaul.s3proxy;

import com.google.common.collect.Maps;
import org.jclouds.blobstore.BlobStore;

import javax.annotation.Nullable;
import java.util.Map;

public class S3ProxyBlobStoreLocator implements SingleBlobStoreLocator {
    
    String identity;
    String credential;
    BlobStore blobStore;
            
    public S3ProxyBlobStoreLocator() {

    }

    @Nullable
    @Override
    public Map.Entry<String, BlobStore> locateBlobStore(
            String identityArg, String container, String blob) {

        if (!identity.equals(identityArg)) {
            return null;
        }
        return Maps.immutableEntry(credential, blobStore);
    }

    @Override
    public void setIdentity(String identity) {
        this.identity = identity;
    }

    @Override
    public void setCredential(String credential) {
        this.credential = credential;
    }

    @Override
    public void setBlobStore(BlobStore blobStore) {
        this.blobStore = blobStore;
    }
}
