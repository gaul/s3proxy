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

import org.gaul.s3proxy.blobstore.BlobStore;
import org.junit.jupiter.api.Test;

public final class AwsS3SdkBlobStoreTest {

    @Test
    public void testProviderMetadata() {
        var properties = new Properties();
        properties.setProperty("jclouds.identity", "test-identity");
        properties.setProperty("jclouds.credential", "test-credential");
        properties.setProperty("jclouds.endpoint", "http://localhost:9000");

        BlobStore blobStore = BlobStores.create("aws-s3-sdk", properties);
        assertThat(blobStore).isNotNull();
    }

    @Test
    public void testCustomRegionConfiguration() {
        var properties = new Properties();
        properties.setProperty("jclouds.identity", "test-identity");
        properties.setProperty("jclouds.credential", "test-credential");
        properties.setProperty("jclouds.endpoint", "http://localhost:9000");
        properties.setProperty("jclouds.region", "eu-west-1");

        BlobStore blobStore = BlobStores.create("aws-s3-sdk", properties);
        assertThat(blobStore).isNotNull();
    }
}
