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
import java.util.Set;

import org.jclouds.blobstore.BlobStoreContext;
import org.jclouds.blobstore.reference.BlobStoreConstants;
import org.jclouds.reflect.Reflection2;
import org.jclouds.rest.internal.BaseHttpApiMetadata;


@SuppressWarnings("rawtypes")
public final class GCloudApiMetadata extends BaseHttpApiMetadata {
    public GCloudApiMetadata() {
        this(builder());
    }

    protected GCloudApiMetadata(Builder builder) {
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
                "x-goog-meta-");
        return properties;
    }

    // Fake API client
    private interface GCloudClient {
    }

    public static final class Builder
            extends BaseHttpApiMetadata.Builder<GCloudClient, Builder> {
        protected Builder() {
            super(GCloudClient.class);
            id("google-cloud-storage-sdk")
                .name("Google Cloud Storage API")
                .identityName("Project ID")
                .credentialName("JSON Key or Path")
                .version("v1")
                .defaultEndpoint("https://storage.googleapis.com")
                .documentation(URI.create(
                        "https://cloud.google.com/storage/docs/json_api"))
                .defaultProperties(GCloudApiMetadata.defaultProperties())
                .view(Reflection2.typeToken(BlobStoreContext.class))
                .defaultModules(Set.of(
                        GCloudBlobStoreContextModule.class));
        }

        @Override
        public GCloudApiMetadata build() {
            return new GCloudApiMetadata(this);
        }

        @Override
        protected Builder self() {
            return this;
        }
    }
}
