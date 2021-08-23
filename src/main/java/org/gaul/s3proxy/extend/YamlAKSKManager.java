package org.gaul.s3proxy.extend;

import com.google.common.collect.ImmutableMap;
import org.apache.commons.io.filefilter.FileFilterUtils;
import org.apache.commons.io.monitor.FileAlterationListenerAdaptor;
import org.apache.commons.io.monitor.FileAlterationMonitor;
import org.apache.commons.io.monitor.FileAlterationObserver;
import org.jclouds.blobstore.BlobStore;
import org.yaml.snakeyaml.Yaml;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

/**
 * @author yangyanbo
 */
public class YamlAKSKManager extends AbStractAKSKManager {

    String defaultBucketAccessYamlPath = "src/main/resources/bucket_access.yml";
    String confPath;
    private FileAlterationListenerAdaptor listener;
    ImmutableMap.Builder<String, Map.Entry<String, BlobStore>> locators;

    public YamlAKSKManager(String configPath) {
        super();
        if (configPath.equalsIgnoreCase("")) {
            this.confPath = defaultBucketAccessYamlPath;
        }

        this.loads2Cache();
        this.startReloadMonitor(locators);

    }

    @Override
    public void createAKSKForBucket(String bucket, String access_key, String secret_key) {
        try {

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    @Override
    public Map<String, AkSkPair> loads2Cache() {
        try {
            Map<String, AkSkPair> bucketAkList = this.getBucketAkSkList();
            for (String key : bucketAkList.keySet()) {
                this.getCacheManager().setKey(key, bucketAkList.get(key));
            }
            // save
            setSave(bucketAkList);

            return bucketAkList;
        } catch (Exception e) {
            System.out.println("Take record from db to cache fail.");
            return null;
        }


    }

    @Override
    public Map<String, AkSkPair> getBucketAkSkList() throws Exception {
        InputStream inputStream = null;
        try {
            inputStream = new FileInputStream(this.confPath);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        Yaml yaml = new Yaml();
        Map<String, Object> properties = yaml.loadAs(inputStream, Map.class);
        Map<String, AkSkPair> m = new HashMap<>();
        for (String k : properties.keySet()) {
            Map mm = (Map) properties.get(k);
            AkSkPair akSkPair = new AkSkPair((String) mm.get("access_key"), (String) mm.get("secret_key"));
            m.put(k, akSkPair);
        }
        return m;
    }

    @Override
    public String getBucketFromAccessKey(String ak) {
        // ugly here but work
        String bucket = "";
        try {
            Map<String, Object> m = this.getCacheManager().getAll();
            for (String k : m.keySet()) {
                AkSkPair akSkPair = (AkSkPair) m.get(k);
                if (akSkPair.getAccess_key().equalsIgnoreCase(ak)) {
                    bucket = k;
                    break;
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
            return bucket;
        } finally {
            return bucket;
        }
    }

    public void startReloadMonitor(ImmutableMap.Builder<String, Map.Entry<String, BlobStore>> locators) {
        // set monitor monitor the yml file change
        File conf = new File(this.confPath);
        FileAlterationObserver observer = new FileAlterationObserver(conf.getParentFile().getAbsolutePath(),
                FileFilterUtils.suffixFileFilter(".yml"));
        // add event
        listener = new YamlConfigReloadAdaptor(this);
        observer.addListener(listener);

        // 5s
        FileAlterationMonitor monitor = new FileAlterationMonitor(5);
        monitor.addObserver(observer);

        try {
            monitor.start();
        } catch (Exception e) {
            e.printStackTrace();
        }


    }

}
