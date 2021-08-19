package org.gaul.s3proxy.extend;

import sun.reflect.generics.reflectiveObjects.NotImplementedException;

import java.util.List;
import java.util.Map;

/**
 * @author yangyanbo
 */
public class AbStractAKSKManager implements AccessSecretManager {

    public String cacheType = "memory";


    public CacheManager cacheManager;

    public AbStractAKSKManager() {
        cacheManager = createCacheManager();
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
    public void loads2Cache() {
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

    public CacheManager getCacheManager() {
        return cacheManager;
    }

}
