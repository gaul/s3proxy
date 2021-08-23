package org.gaul.s3proxy.extend;

import java.util.Map;

/**
 * @author yangyanbo
 */
public interface CacheManager {

    /**
     * @param key
     * @param o
     * @return int
     */
    int setKey(String key, Object o) throws Exception;

    /**
     * @param key
     * @return
     */
    Object getKey(String key) throws Exception;

    Map<String, Object> getAll() throws Exception;
}
