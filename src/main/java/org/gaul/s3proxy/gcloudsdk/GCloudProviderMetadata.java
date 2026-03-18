/*
 * Copyright 2014-2026 Andrew Gaul <andrew@gaul.org>
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

package org.gaul.s3proxy.gcloudsdk;

import java.net.URI;
import java.util.Properties;

import com.google.auto.service.AutoService;

import org.jclouds.providers.ProviderMetadata;
import org.jclouds.providers.internal.BaseProviderMetadata;

/**
 * Implementation of org.jclouds.types.ProviderMetadata for Google Cloud
 * Storage using the official Google Cloud Storage SDK.
 */
@AutoService(ProviderMetadata.class)
public final class GCloudProviderMetadata extends BaseProviderMetadata {
    public GCloudProviderMetadata() {
        super(builder());
    }

    public GCloudProviderMetadata(Builder builder) {
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
        return properties;
    }

    public static final class Builder extends BaseProviderMetadata.Builder {
        protected Builder() {
            id("google-cloud-storage-sdk")
                .name("Google Cloud Storage")
                .apiMetadata(new GCloudApiMetadata())
                .endpoint("https://storage.googleapis.com")
                .homepage(URI.create(
                        "https://cloud.google.com/storage"))
                .console(URI.create(
                        "https://console.cloud.google.com/storage"))
                .linkedServices("google-cloud-storage")
                .iso3166Codes("US", "EU")
                .defaultProperties(
                        GCloudProviderMetadata.defaultProperties());
        }

        @Override
        public GCloudProviderMetadata build() {
            return new GCloudProviderMetadata(this);
        }

        @Override
        public Builder fromProviderMetadata(ProviderMetadata in) {
            super.fromProviderMetadata(in);
            return this;
        }
    }
}
