/*
 * Copyright 2014-2021 Andrew Gaul <andrew@gaul.org>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.gaul.s3proxy;

import java.lang.reflect.InvocationTargetException;
import java.util.Map;

import com.google.common.collect.Maps;

import org.jclouds.blobstore.BlobStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Abstract BlobstoreLocator to handle multiple local Identities.
 */
public abstract class AbstractMultiIdentityBlobStoreLocator
    implements BlobStoreLocator {

    protected Map<String, Map.Entry<String, BlobStore>> locator;
    protected Map<String, Map<String, String>> identityCommMap;

    public final void setLocator(
        Map<String, Map.Entry<String, BlobStore>> loc) {
        this.locator = loc;
    }

    public final void setIdentityCommunicationMapping(
        Map<String, Map<String, String>> identityCommMap) {
        this.identityCommMap = identityCommMap;
    }
}

/**
 * Custom BlobstoreLocator to handle multiple local Identities.
 */
class CustomMultiIdentityBlobStoreLocator
    extends AbstractMultiIdentityBlobStoreLocator {

    private static final Logger logger =
        LoggerFactory.getLogger(CustomMultiIdentityBlobStoreLocator.class);

    @Override
    public Map.Entry<String, BlobStore> locateBlobStore(String identity,
                                                        String container,
                                                        String blob) {
        logger.debug("locateBlobStore for the identity:{}", identity);
        if (identity == null) {
            if (locator.size() == 1) {
                return locator.entrySet().iterator().next()
                    .getValue();
            }
            throw new IllegalArgumentException(
                "cannot use anonymous access with multiple" +
                    " backends");
        } else if (null != locator.get(identity)) {
            return locator.get(identity);
        } else {
            //lookup for the identity and retrieve the secretAccessKey
            String mappedIdentity = getMappedIdentity(identity);
            String localCredential =
                verifyIdentityAndGetCredential(mappedIdentity, identity);
            if (null != localCredential) {
                BlobStore blobStore = locator.get(mappedIdentity).getValue();
                return Maps.immutableEntry(localCredential, blobStore);
            }
            return null;
        }
    }

    private String verifyIdentityAndGetCredential(String mappedIdentity,
                                                  String identity) {
        String credentialStr = null;
        if (null != identity) {
            String callBackClass = identityCommMap.get(mappedIdentity)
                .get(S3ProxyConstants.PROPERTY_IDENTITY_CALLBACK);
            try {
                ExternalAuthenticator externalAuthenticator =
                    (ExternalAuthenticator) Class.forName(callBackClass)
                        .getConstructor().newInstance();
                credentialStr =
                    externalAuthenticator.retrieveCredential(identity);
                logger.debug("retrieved credential for identity:{}", identity);
            } catch (ClassNotFoundException | NoSuchMethodException e) {
                logger.error("Exception while verifyIdentityAndGetCredential",
                    e);
            } catch (InvocationTargetException e) {
                logger.error("Exception while verifyIdentityAndGetCredential",
                    e);
            } catch (InstantiationException | IllegalAccessException e) {
                logger.error("Exception while verifyIdentityAndGetCredential",
                    e);
            }
        }
        return credentialStr;
    }

    //To identify the mapped identity for the given identity from the locator
    private String getMappedIdentity(String identity) {
        //Returning the first blobstore in the locator
        return locator.keySet().stream().findFirst().get();
    }
}
