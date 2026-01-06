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

package org.gaul.s3proxy.awssdk;

import java.util.Properties;

import com.google.auto.service.AutoService;

import org.jclouds.providers.ProviderMetadata;
import org.jclouds.providers.internal.BaseProviderMetadata;

@AutoService(ProviderMetadata.class)
public final class AwsS3SdkProviderMetadata extends BaseProviderMetadata {
    public AwsS3SdkProviderMetadata() {
        super(builder());
    }

    public AwsS3SdkProviderMetadata(Builder builder) {
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
            id("aws-s3-sdk")
                .name("AWS S3 SDK Backend")
                .apiMetadata(new AwsS3SdkApiMetadata())
                .endpoint("https://s3.amazonaws.com")
                .defaultProperties(
                        AwsS3SdkProviderMetadata.defaultProperties());
        }

        @Override
        public AwsS3SdkProviderMetadata build() {
            return new AwsS3SdkProviderMetadata(this);
        }

        @Override
        public Builder fromProviderMetadata(ProviderMetadata in) {
            super.fromProviderMetadata(in);
            return this;
        }
    }
}
