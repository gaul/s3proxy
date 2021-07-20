package org.gaul.s3proxy;

import org.jclouds.blobstore.BlobStore;

import java.util.Map;


public class S3ProxyMultiBlobStoreLocator implements MultiBlobStoreLocator {

    Map<String, Map.Entry<String, BlobStore>> locator;

    public S3ProxyMultiBlobStoreLocator() {

    }

    public void setLocator(Map<String,
            Map.Entry<String, BlobStore>> locator) {
        this.locator = locator;
    }

    @Override
    public Map.Entry<String, BlobStore> locateBlobStore(
            String identity, String container, String blob) {

        if (identity == null) {
            if (locator.size() == 1) {
                return locator.entrySet().iterator().next()
                        .getValue();
            }
            throw new IllegalArgumentException(
                    "cannot use anonymous access with multiple" +
                            " backends");
        }
        return locator.get(identity);
    }
}
