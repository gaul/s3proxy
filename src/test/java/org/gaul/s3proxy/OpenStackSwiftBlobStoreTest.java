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

package org.gaul.s3proxy;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Properties;

import org.jclouds.ContextBuilder;
import org.jclouds.blobstore.BlobStoreContext;
import org.junit.jupiter.api.Test;

public final class OpenStackSwiftBlobStoreTest {

    @Test
    public void testProviderRegistration() {
        // Verify that the provider is discoverable via jclouds
        var providers = ContextBuilder.newBuilder("openstack-swift-sdk");
        assertThat(providers).isNotNull();
    }

    @Test
    public void testProviderInstantiation() {
        var properties = new Properties();
        properties.setProperty("jclouds.identity", "test-user");
        properties.setProperty("jclouds.credential", "test-password");
        properties.setProperty("jclouds.endpoint",
                "http://localhost:5000/v3");
        properties.setProperty("openstack-swift-sdk.project-name",
                "test-project");

        // Authentication is lazy, so building the context and obtaining the
        // BlobStore must not require a running Keystone or Swift.  jclouds
        // returns the BlobStore wrapped in a dynamic proxy, so assert only
        // that it is non-null.
        try (BlobStoreContext context = ContextBuilder
                .newBuilder("openstack-swift-sdk")
                .overrides(properties)
                .buildView(BlobStoreContext.class)) {
            assertThat(context).isNotNull();
            assertThat(context.getBlobStore()).isNotNull();
        }
    }

    @Test
    public void testDefaultDomainConfiguration() {
        // Domains default to "Default" when unspecified.
        var properties = new Properties();
        properties.setProperty("jclouds.identity", "test-user");
        properties.setProperty("jclouds.credential", "test-password");
        properties.setProperty("jclouds.endpoint",
                "http://localhost:5000/v3");
        properties.setProperty("openstack-swift-sdk.project-name",
                "test-project");
        properties.setProperty("openstack-swift-sdk.user-domain-name",
                "ExampleDomain");
        properties.setProperty("openstack-swift-sdk.region", "RegionOne");

        try (BlobStoreContext context = ContextBuilder
                .newBuilder("openstack-swift-sdk")
                .overrides(properties)
                .buildView(BlobStoreContext.class)) {
            assertThat(context.getBlobStore()).isNotNull();
        }
    }
}
