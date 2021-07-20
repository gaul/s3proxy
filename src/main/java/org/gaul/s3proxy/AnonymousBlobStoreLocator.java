package org.gaul.s3proxy;

import org.jclouds.blobstore.BlobStore;

import java.util.Map;

public interface AnonymousBlobStoreLocator extends BlobStoreLocator {

    void setBlobStoreMap(Map.Entry<String, BlobStore> anonymousBlobStore);

}
