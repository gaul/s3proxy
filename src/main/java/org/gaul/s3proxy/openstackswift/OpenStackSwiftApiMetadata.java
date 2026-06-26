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

package org.gaul.s3proxy.openstackswift;

import java.net.URI;
import java.util.Properties;
import java.util.Set;

import org.jclouds.blobstore.BlobStoreContext;
import org.jclouds.reflect.Reflection2;
import org.jclouds.rest.internal.BaseHttpApiMetadata;

@SuppressWarnings("rawtypes")
public final class OpenStackSwiftApiMetadata extends BaseHttpApiMetadata {
    /**
     * Keystone project (tenant) name to scope the token to.  Required:
     * Swift object storage is only reachable through a project-scoped token.
     */
    public static final String PROJECT_NAME = "openstack-swift-sdk.project-name";

    /** Keystone domain that owns the project.  Defaults to "Default". */
    public static final String PROJECT_DOMAIN_NAME =
            "openstack-swift-sdk.project-domain-name";

    /** Keystone domain that owns the user.  Defaults to "Default". */
    public static final String USER_DOMAIN_NAME =
            "openstack-swift-sdk.user-domain-name";

    /**
     * Region whose object-store endpoint should be selected from the service
     * catalog.  Empty selects the first/default region.
     */
    public static final String REGION = "openstack-swift-sdk.region";

    public OpenStackSwiftApiMetadata() {
        this(builder());
    }

    protected OpenStackSwiftApiMetadata(Builder builder) {
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
        properties.setProperty(PROJECT_NAME, "");
        properties.setProperty(PROJECT_DOMAIN_NAME, "Default");
        properties.setProperty(USER_DOMAIN_NAME, "Default");
        properties.setProperty(REGION, "");
        return properties;
    }

    // Fake API client - required by jclouds but not actually used
    interface OpenStackSwiftClient {
    }

    public static final class Builder
            extends BaseHttpApiMetadata.Builder<OpenStackSwiftClient, Builder> {
        protected Builder() {
            super(OpenStackSwiftClient.class);
            id("openstack-swift-sdk")
                .name("OpenStack Swift SDK Backend")
                .identityName("User Name")
                .credentialName("Password")
                .version("1")
                .defaultEndpoint("http://localhost:5000/v3")
                .documentation(URI.create(
                        "https://docs.openstack.org/api-ref/object-store/"))
                .defaultProperties(
                        OpenStackSwiftApiMetadata.defaultProperties())
                .view(Reflection2.typeToken(BlobStoreContext.class))
                .defaultModules(
                        Set.of(OpenStackSwiftBlobStoreContextModule.class));
        }

        @Override
        public OpenStackSwiftApiMetadata build() {
            return new OpenStackSwiftApiMetadata(this);
        }

        @Override
        protected Builder self() {
            return this;
        }
    }
}
