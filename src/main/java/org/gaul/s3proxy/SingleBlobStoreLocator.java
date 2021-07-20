package org.gaul.s3proxy;

import org.jclouds.blobstore.BlobStore;

public interface SingleBlobStoreLocator extends BlobStoreLocator {

    void setIdentity(String identity);
    void setCredential(String credential);
    void setBlobStore(BlobStore blobStore);

}
