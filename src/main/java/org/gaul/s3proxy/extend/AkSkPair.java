package org.gaul.s3proxy.extend;

/**
 * @author yangyanbo
 */
public class AkSkPair {
    String access_key;
    String secret_key;

    public String getSecret_key() {
        return secret_key;
    }

    public void setSecret_key(String secret_key) {
        this.secret_key = secret_key;
    }

    public AkSkPair(String ak, String sk) {
        this.access_key = ak;
        this.secret_key = sk;
    }

    public String getAccess_key() {
        return access_key;
    }

    public void setAccess_key(String access_key) {
        this.access_key = access_key;
    }
}
