package org.gaul.s3proxy.extend;

import org.jclouds.blobstore.BlobStore;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * @author yangyanbo
 */
public class AbStractAKSKManager implements AccessSecretManager {

    public String cacheType = "memory";

    static public List<BlobStore> blobStores = new ArrayList<>();

    public CacheManager cacheManager;
    Map<String, Map.Entry<String, BlobStore>>  locator;

    /** static variable save last config
     *
     */
    public static Map<String, AkSkPair> save;

    public AbStractAKSKManager() {
        cacheManager = createCacheManager();
    }
    public Map<String, Map.Entry<String, BlobStore>> getLocator() {
        return locator;
    }

    public void setLocator(Map<String, Map.Entry<String, BlobStore>> locator) {
        this.locator = locator;
    }

    @Override
    public CacheManager createCacheManager() {
        switch (cacheType) {
            case "memory":
                cacheManager = new MemoryCache();
                break;
            default:
                cacheManager = new MemoryCache();
        }
        return cacheManager;
    }

    @Override
    public void createAKSKForBucket(String bucket, String access_key, String secret_key) {
        throw new NotImplementedException();
    }

    @Override
    public Map<String, AkSkPair> loads2Cache() {
        throw new NotImplementedException();

    }

    @Override
    public Map<String, AkSkPair> getBucketAkSkList() throws Exception {
        throw new NotImplementedException();
    }

    @Override
    public String getBucketFromAccessKey(String ak) {
        throw new NotImplementedException();
    }

    @Override
    public void registerBlobStore(BlobStore blobStore) {
        blobStores.add(blobStore);
    }

    @Override
    public List<BlobStore> listBlobStores() {
        return blobStores;
    }

    public CacheManager getCacheManager() {
        return cacheManager;
    }

    public static Map<String, AkSkPair> getSave() {
        return save;
    }

    public static void setSave(Map<String, AkSkPair> save) {
        AbStractAKSKManager.save = save;
    }
}
