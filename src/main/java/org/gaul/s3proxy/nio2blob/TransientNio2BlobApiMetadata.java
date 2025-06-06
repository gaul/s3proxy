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

package org.gaul.s3proxy.nio2blob;

import java.net.URI;
import java.util.Properties;
import java.util.Set;

import org.jclouds.blobstore.BlobStoreContext;
import org.jclouds.reflect.Reflection2;
import org.jclouds.rest.internal.BaseHttpApiMetadata;

@SuppressWarnings("rawtypes")
public final class TransientNio2BlobApiMetadata extends BaseHttpApiMetadata {
    public TransientNio2BlobApiMetadata() {
        this(builder());
    }

    protected TransientNio2BlobApiMetadata(Builder builder) {
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
        return BaseHttpApiMetadata.defaultProperties();
    }

    // Fake API client
    private interface TransientNio2BlobClient {
    }

    public static final class Builder
            extends BaseHttpApiMetadata.Builder<TransientNio2BlobClient, Builder> {
        protected Builder() {
            super(TransientNio2BlobClient.class);
            id("transient-nio2")
                .name("Transient NIO.2 Blobstore")
                .identityName("Account Name")
                .credentialName("Access Key")
                .defaultEndpoint("http://localhost/")
                .documentation(URI.create(
                        "http://www.jclouds.org/documentation/userguide" +
                        "/blobstore-guide"))
                .defaultProperties(TransientNio2BlobApiMetadata.defaultProperties())
                .view(Reflection2.typeToken(BlobStoreContext.class))
                .defaultModules(Set.of(TransientNio2BlobStoreContextModule.class));
        }

        @Override
        public TransientNio2BlobApiMetadata build() {
            return new TransientNio2BlobApiMetadata(this);
        }

        @Override
        protected Builder self() {
            return this;
        }
    }
}
