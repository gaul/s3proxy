package org.gaul.s3proxy.extend;

import java.util.HashMap;
import java.util.Map;

/**
 * @author yangyanbo
 */
public class MemoryCache implements CacheManager {
    public static Map<String, Object> cache = new HashMap<>();

    @Override
    public int setKey(String key, Object o) {
        int ret = 0;
        try {
            cache.put(key, o);
            return ret;
        } catch (Exception e) {
            System.out.println(e.getMessage());
            return -1;
        }
    }

    @Override
    public Object getKey(String key) {
        return cache.get(key);
    }

    @Override
    public Map<String, Object> getAll() throws Exception {
        return cache;
    }
}
