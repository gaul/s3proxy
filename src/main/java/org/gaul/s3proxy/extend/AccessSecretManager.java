package org.gaul.s3proxy.extend;

import org.jclouds.blobstore.BlobStore;

import java.util.List;
import java.util.Map;

/**
 * @author yangyanbo
 */
public interface AccessSecretManager {


    CacheManager createCacheManager() throws Exception;

    void createAKSKForBucket(String bucket, String access_key, String secret_key) throws Exception;

    Map<String, AkSkPair> loads2Cache() throws Exception;

    Map<String, AkSkPair> getBucketAkSkList() throws Exception;

    String getBucketFromAccessKey(String ak);

    void registerBlobStore(BlobStore blobStore);

    List<BlobStore> listBlobStores();


}
