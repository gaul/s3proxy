package org.gaul.s3proxy;

import org.jclouds.blobstore.BlobStore;

import java.util.Map;
import java.util.ServiceLoader;

public class S3ProxyBlobStoreLocatorLoader {

    public static BlobStoreLocator getMultiLocator(Map<String,
            Map.Entry<String, BlobStore>> locator) {

        final String implClassName =
                String.valueOf(System.getProperties().getOrDefault(
                        S3ProxyConstants.PROPERTY_BLOBSTORE_LOCATOR_IMPL_MULTI,
                        "org.gaul.s3proxy.S3ProxyMultiBlobStoreLocator"));

        ServiceLoader<MultiBlobStoreLocator> loader = ServiceLoader.load(
                MultiBlobStoreLocator.class);

        for (MultiBlobStoreLocator localLocator : loader) {
            if (localLocator.getClass().getName().equals(
                    implClassName)) {
                S3ProxyMultiBlobStoreLocator multiLocator =
                        (S3ProxyMultiBlobStoreLocator) localLocator;
                multiLocator.setLocator(locator);
                return (BlobStoreLocator) multiLocator;
            }
        }
        throw new IllegalArgumentException(implClassName + " not found.");
    }

    public static BlobStoreLocator getSingleLocator(String identity,
                                                    String credential,
                                                    BlobStore blobStore) {

        final String implClassName =
                String.valueOf(System.getProperties().getOrDefault(
                        S3ProxyConstants.PROPERTY_BLOBSTORE_LOCATOR_IMPL_SINGLE,
                        "org.gaul.s3proxy.S3ProxyBlobStoreLocator"));


        ServiceLoader<SingleBlobStoreLocator> loader =
                ServiceLoader.load(SingleBlobStoreLocator.class);

        for (SingleBlobStoreLocator localLocator : loader) {
            if (localLocator.getClass().getName().equals(implClassName)) {

                S3ProxyBlobStoreLocator singleStoreLocator =
                        (S3ProxyBlobStoreLocator) localLocator;
                singleStoreLocator.
                        setIdentity(identity);
                singleStoreLocator.
                        setCredential(credential);
                singleStoreLocator.
                        setBlobStore(blobStore);

                return (BlobStoreLocator) singleStoreLocator;
            }
        }
        throw new IllegalArgumentException(implClassName + " not found.");
    }

    public static BlobStoreLocator getAnonymousLocator( Map.Entry<String,
            BlobStore> anonymousBlobStore) {

        final String implClassName =
                String.valueOf(System.getProperties().getOrDefault(
                        S3ProxyConstants.PROPERTY_BLOBSTORE_LOCATOR_IMPL_ANON,
                        "org.gaul.s3proxy.AnonBlobStoreLocator"));

        ServiceLoader<AnonymousBlobStoreLocator> loader =
                ServiceLoader.load(AnonymousBlobStoreLocator.class);

        for (AnonymousBlobStoreLocator localLocator : loader) {
            if (localLocator.getClass().getName().equals(implClassName)) {

                AnonBlobStoreLocator anonLocator = (AnonBlobStoreLocator)
                        localLocator;

                anonLocator.setBlobStoreMap(anonymousBlobStore);
                return (BlobStoreLocator) anonLocator;
            }
        }
        throw new IllegalArgumentException(implClassName + " not found.");
    }
}
