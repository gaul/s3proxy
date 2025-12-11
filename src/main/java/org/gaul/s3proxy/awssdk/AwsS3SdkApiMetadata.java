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

package org.gaul.s3proxy.awssdk;

import java.net.URI;
import java.util.Properties;
import java.util.Set;

import org.jclouds.blobstore.BlobStoreContext;
import org.jclouds.reflect.Reflection2;
import org.jclouds.rest.internal.BaseHttpApiMetadata;


@SuppressWarnings("rawtypes")
public final class AwsS3SdkApiMetadata extends BaseHttpApiMetadata {
    /** Property for AWS region. */
    public static final String REGION = "aws-s3-sdk.region";

    public AwsS3SdkApiMetadata() {
        this(builder());
    }

    protected AwsS3SdkApiMetadata(Builder builder) {
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
        properties.setProperty(REGION, "us-east-1");
        return properties;
    }

    // Fake API client - required by jclouds but not actually used
    private interface AwsS3SdkClient {
    }

    public static final class Builder
            extends BaseHttpApiMetadata.Builder<AwsS3SdkClient, Builder> {
        protected Builder() {
            super(AwsS3SdkClient.class);
            id("aws-s3-sdk")
                .name("AWS S3 SDK Backend")
                .identityName("Access Key ID")
                .credentialName("Secret Access Key")
                .version("2006-03-01")
                .defaultEndpoint("https://s3.amazonaws.com")
                .documentation(URI.create(
                        "https://docs.aws.amazon.com/AmazonS3/latest/" +
                        "API/Welcome.html"))
                .defaultProperties(AwsS3SdkApiMetadata.defaultProperties())
                .view(Reflection2.typeToken(BlobStoreContext.class))
                .defaultModules(Set.of(AwsS3SdkBlobStoreContextModule.class));
        }

        @Override
        public AwsS3SdkApiMetadata build() {
            return new AwsS3SdkApiMetadata(this);
        }

        @Override
        protected Builder self() {
            return this;
        }
    }
}
