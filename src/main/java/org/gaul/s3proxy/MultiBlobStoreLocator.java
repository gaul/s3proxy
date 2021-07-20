package org.gaul.s3proxy;

import org.jclouds.blobstore.BlobStore;

import java.util.Map;

public interface MultiBlobStoreLocator extends BlobStoreLocator {
    void setLocator(Map<String,
            Map.Entry<String, BlobStore>> locator);
}
