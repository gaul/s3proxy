package org.gaul.s3proxy;

import org.jclouds.blobstore.BlobStore;

import java.util.Map;


public class AnonBlobStoreLocator implements AnonymousBlobStoreLocator {

    Map.Entry<String, BlobStore> anonymousBlobStore;

    @Override
    public Map.Entry<String, BlobStore> locateBlobStore(
            String identityArg, String container, String blob) {
        return anonymousBlobStore;
    }

    @Override
    public void setBlobStoreMap(Map.Entry<String, BlobStore> anonymousBlobStore) {
        this.anonymousBlobStore = anonymousBlobStore;
    }
}
