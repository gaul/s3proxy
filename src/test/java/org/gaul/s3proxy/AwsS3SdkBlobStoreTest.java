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

package org.gaul.s3proxy;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Properties;

import org.jclouds.ContextBuilder;
import org.jclouds.blobstore.BlobStoreContext;
import org.junit.Test;

public final class AwsS3SdkBlobStoreTest {

    @Test
    public void testProviderRegistration() {
        // Verify that the provider is discoverable via jclouds
        var providers = ContextBuilder.newBuilder("aws-s3-sdk");
        assertThat(providers).isNotNull();
    }

    @Test
    public void testProviderMetadata() {
        var properties = new Properties();
        properties.setProperty("jclouds.identity", "test-identity");
        properties.setProperty("jclouds.credential", "test-credential");
        properties.setProperty("jclouds.endpoint", "http://localhost:9000");

        // This validates that the provider can be instantiated
        // without actually connecting to a backend
        try (BlobStoreContext context = ContextBuilder.newBuilder("aws-s3-sdk")
                .overrides(properties)
                .buildView(BlobStoreContext.class)) {
            assertThat(context).isNotNull();
            assertThat(context.getBlobStore()).isNotNull();
        }
    }

    @Test
    public void testCustomRegionConfiguration() {
        var properties = new Properties();
        properties.setProperty("jclouds.identity", "test-identity");
        properties.setProperty("jclouds.credential", "test-credential");
        properties.setProperty("jclouds.endpoint", "http://localhost:9000");
        properties.setProperty("aws-s3-sdk.region", "eu-west-1");

        // Verify that custom region configuration is accepted
        try (BlobStoreContext context = ContextBuilder.newBuilder("aws-s3-sdk")
                .overrides(properties)
                .buildView(BlobStoreContext.class)) {
            assertThat(context).isNotNull();
            assertThat(context.getBlobStore()).isNotNull();
        }
    }
}
