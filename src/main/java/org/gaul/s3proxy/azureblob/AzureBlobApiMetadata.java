/*
 * Copyright 2014-2025 Andrew Gaul <andrew@gaul.org>
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

package org.gaul.s3proxy.azureblob;

import java.net.URI;
import java.util.Properties;
import java.util.Set;

import org.jclouds.azure.storage.config.AuthType;
import org.jclouds.azure.storage.config.AzureStorageProperties;
import org.jclouds.blobstore.BlobStoreContext;
import org.jclouds.blobstore.reference.BlobStoreConstants;
import org.jclouds.reflect.Reflection2;
import org.jclouds.rest.internal.BaseHttpApiMetadata;


public final class AzureBlobApiMetadata extends BaseHttpApiMetadata {
    public AzureBlobApiMetadata() {
        this(builder());
    }

    protected AzureBlobApiMetadata(Builder builder) {
        super(builder);
    }

    private static Builder builder() {
        return new Builder();
    }

    @Override
    public Builder toBuilder() {
        return builder().fromApiMetadata(this);
    }

    public static Properties defaultProperties() {
        Properties properties = BaseHttpApiMetadata.defaultProperties();
        properties.setProperty(BlobStoreConstants.PROPERTY_USER_METADATA_PREFIX,
                "x-ms-meta-");
        properties.setProperty(AzureStorageProperties.AUTH_TYPE,
                AuthType.AZURE_KEY.toString());
        properties.setProperty(AzureStorageProperties.ACCOUNT, "");
        properties.setProperty(AzureStorageProperties.TENANT_ID, "");
        return properties;
    }

    // Fake API client
    private interface AzureBlobClient {
    }

    public static final class Builder
            extends BaseHttpApiMetadata.Builder<AzureBlobClient, Builder> {
        protected Builder() {
            super(AzureBlobClient.class);
            id("azureblob-sdk")
                .name("Microsoft Azure Blob Service API")
                .identityName("Account Name")
                .credentialName("Access Key")
                // TODO: update
                .version("2017-11-09")
                .defaultEndpoint(
                        "https://${jclouds.identity}.blob.core.windows.net")
                .documentation(URI.create(
                        "https://learn.microsoft.com/en-us/rest/api/" +
                        "storageservices/Blob-Service-REST-API"))
                .defaultProperties(AzureBlobApiMetadata.defaultProperties())
                .view(Reflection2.typeToken(BlobStoreContext.class))
                .defaultModules(Set.of(AzureBlobStoreContextModule.class));
        }

        @Override
        public AzureBlobApiMetadata build() {
            return new AzureBlobApiMetadata(this);
        }

        @Override
        protected Builder self() {
            return this;
        }
    }
}
