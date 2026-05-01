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

package org.gaul.s3proxy.sftp;

import java.net.URI;
import java.util.Properties;
import java.util.Set;

import org.jclouds.blobstore.BlobStoreContext;
import org.jclouds.reflect.Reflection2;
import org.jclouds.rest.internal.BaseHttpApiMetadata;

@SuppressWarnings("rawtypes")
public final class SftpBlobStoreApiMetadata extends BaseHttpApiMetadata {
    public static final String BASEDIR = "jclouds.sftp.basedir";

    public SftpBlobStoreApiMetadata() {
        this(builder());
    }

    protected SftpBlobStoreApiMetadata(Builder builder) {
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
        properties.setProperty(BASEDIR, "/");
        return properties;
    }

    // Fake API client
    private interface SftpBlobStoreClient {
    }

    public static final class Builder
            extends BaseHttpApiMetadata.Builder<SftpBlobStoreClient, Builder> {
        protected Builder() {
            super(SftpBlobStoreClient.class);
            id("sftp")
                .name("SFTP Blobstore")
                .identityName("Username")
                .credentialName("Password")
                .defaultEndpoint("sftp://127.0.0.1:22/")
                .documentation(URI.create(
                        "http://www.jclouds.org/documentation/userguide" +
                        "/blobstore-guide"))
                .defaultProperties(SftpBlobStoreApiMetadata.defaultProperties())
                .view(Reflection2.typeToken(BlobStoreContext.class))
                .defaultModules(Set.of(SftpBlobStoreContextModule.class));
        }

        @Override
        public SftpBlobStoreApiMetadata build() {
            return new SftpBlobStoreApiMetadata(this);
        }

        @Override
        protected Builder self() {
            return this;
        }
    }
}
