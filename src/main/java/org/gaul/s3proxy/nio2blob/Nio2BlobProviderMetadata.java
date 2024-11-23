/*
 * Copyright 2014-2024 Andrew Gaul <andrew@gaul.org>
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

package org.gaul.s3proxy.nio2blob;

import java.util.Properties;

import com.google.auto.service.AutoService;

import org.jclouds.providers.ProviderMetadata;
import org.jclouds.providers.internal.BaseProviderMetadata;

/**
 * Implementation of org.jclouds.types.ProviderMetadata for NIO.2 filesystems.
 */
@AutoService(ProviderMetadata.class)
public final class Nio2BlobProviderMetadata extends BaseProviderMetadata {
    public Nio2BlobProviderMetadata() {
        super(builder());
    }

    public Nio2BlobProviderMetadata(Builder builder) {
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
        Properties properties = new Properties();
        // TODO: filesystem basedir
        return properties;
    }
    public static final class Builder extends BaseProviderMetadata.Builder {
        protected Builder() {
            id("transient-nio2")
                .name("NIO.2 filesystem blobstore")
                .apiMetadata(new Nio2BlobApiMetadata())
                .endpoint("https://127.0.0.1")  // TODO:
                .defaultProperties(
                        Nio2BlobProviderMetadata.defaultProperties());
        }

        @Override
        public Nio2BlobProviderMetadata build() {
            return new Nio2BlobProviderMetadata(this);
        }

        @Override
        public Builder fromProviderMetadata(
                ProviderMetadata in) {
            super.fromProviderMetadata(in);
            return this;
        }
    }
}
