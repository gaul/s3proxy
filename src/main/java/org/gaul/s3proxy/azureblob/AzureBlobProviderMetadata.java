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

import com.google.auto.service.AutoService;

import org.jclouds.azure.storage.config.AzureStorageProperties;
import org.jclouds.oauth.v2.config.CredentialType;
import org.jclouds.oauth.v2.config.OAuthProperties;
import org.jclouds.providers.ProviderMetadata;
import org.jclouds.providers.internal.BaseProviderMetadata;

/**
 * Implementation of org.jclouds.types.ProviderMetadata for Microsoft Azure
 * Blob Service.
 */
@AutoService(ProviderMetadata.class)
public final class AzureBlobProviderMetadata extends BaseProviderMetadata {
    public AzureBlobProviderMetadata() {
        super(builder());
    }

    public AzureBlobProviderMetadata(Builder builder) {
        super(builder);
    }

    public static Builder builder() {
        return new Builder();
    }

    @Override
    public Builder toBuilder() {
        return builder().fromProviderMetadata(this);
    }

    public static Properties defaultProperties() {
        var properties = new Properties();
        properties.put("oauth.endpoint", "https://login.microsoft.com/${" +
                AzureStorageProperties.TENANT_ID + "}/oauth2/token");
        properties.put(OAuthProperties.RESOURCE, "https://storage.azure.com");
        properties.put(OAuthProperties.CREDENTIAL_TYPE,
                CredentialType.CLIENT_CREDENTIALS_SECRET.toString());
        properties.put(AzureStorageProperties.ACCOUNT, "${jclouds.identity}");
        return properties;
    }
    public static final class Builder extends BaseProviderMetadata.Builder {
        protected Builder() {
            id("azureblob-sdk")
                .name("Microsoft Azure Blob Service")
                .apiMetadata(new AzureBlobApiMetadata())
                .endpoint("https://${" + AzureStorageProperties.ACCOUNT +
                        "}.blob.core.windows.net")
                .homepage(URI.create(
                        "http://www.microsoft.com/windowsazure/storage/"))
                .console(URI.create("https://windows.azure.com/default.aspx"))
                .linkedServices("azureblob", "azurequeue", "azuretable")
                .iso3166Codes("US-TX", "US-IL", "IE-D", "SG", "NL-NH", "HK")
                .defaultProperties(
                        AzureBlobProviderMetadata.defaultProperties());
        }

        @Override
        public AzureBlobProviderMetadata build() {
            return new AzureBlobProviderMetadata(this);
        }

        @Override
        public Builder fromProviderMetadata(
                ProviderMetadata in) {
            super.fromProviderMetadata(in);
            return this;
        }
    }
}
