package org.gaul.s3proxy.extend;

import com.google.common.collect.Maps;
import org.apache.commons.io.monitor.FileAlterationListenerAdaptor;
import org.jclouds.blobstore.BlobStore;

import java.io.File;
import java.util.Map;

/**
 * @author yangyanbo
 */
public class YamlConfigReloadAdaptor extends FileAlterationListenerAdaptor {

    private YamlAKSKManager accessSecretManager;

    public YamlConfigReloadAdaptor(YamlAKSKManager manager) {
        this.accessSecretManager = manager;
    }

    @Override
    public void onFileChange(File file) {
        System.out.println("Yaml Config changed... config.....reload.....");
        super.onFileChange(file);
        Map<String, AkSkPair>  last = AbStractAKSKManager.getSave();
        Map<String, AkSkPair> modify = this.accessSecretManager.loads2Cache();
        // compaire two map to find out which is update or delete.
        // two loop ugly.
        for (BlobStore blobStore : this.accessSecretManager.listBlobStores()) {
            if (this.accessSecretManager.getCacheManager() != null) {
                for (Map.Entry<String, AkSkPair> entry : modify.entrySet()) {
                    // add  access key to locators
                    this.accessSecretManager.getLocator().put(entry.getValue().getAccess_key(), Maps.immutableEntry(
                            entry.getValue().getSecret_key(), blobStore));

                }
                // delete this time yaml delete
                for (Map.Entry<String, AkSkPair> entry : last.entrySet()) {
                    if (!modify.containsKey(entry.getKey())){
                        this.accessSecretManager.getLocator().remove(entry.getValue().access_key);
                    }

                }
            }
        }

    }

}
