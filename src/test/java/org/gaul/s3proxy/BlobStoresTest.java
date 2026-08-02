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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import java.util.Properties;

import org.junit.jupiter.api.Test;

/** A configuration naming a jclouds backend still reaches its replacement. */
public final class BlobStoresTest {
    @Test
    public void testResolvesEveryRetiredName() {
        assertThat(BlobStores.resolveProviderAlias("transient"))
                .isEqualTo("transient-nio2");
        assertThat(BlobStores.resolveProviderAlias("filesystem"))
                .isEqualTo("filesystem-nio2");
        assertThat(BlobStores.resolveProviderAlias("aws-s3"))
                .isEqualTo("aws-s3-sdk");
        assertThat(BlobStores.resolveProviderAlias("s3"))
                .isEqualTo("aws-s3-sdk");
        assertThat(BlobStores.resolveProviderAlias("azureblob"))
                .isEqualTo("azureblob-sdk");
        assertThat(BlobStores.resolveProviderAlias("google-cloud-storage"))
                .isEqualTo("google-cloud-storage-sdk");
        assertThat(BlobStores.resolveProviderAlias("openstack-swift"))
                .isEqualTo("openstack-swift-sdk");
    }

    /** A current name resolves to itself, so resolving twice is harmless. */
    @Test
    public void testLeavesCurrentNamesAlone() {
        var current = List.of("filesystem-nio2", "transient-nio2",
                "aws-s3-sdk", "azureblob-sdk", "google-cloud-storage-sdk",
                "openstack-swift-sdk", "sftp");
        for (String provider : current) {
            assertThat(BlobStores.resolveProviderAlias(provider))
                    .isEqualTo(provider);
        }
    }

    /** An unknown name is left for create to reject by name. */
    @Test
    public void testRejectsAnUnknownName() {
        assertThat(BlobStores.resolveProviderAlias("no-such-provider"))
                .isEqualTo("no-such-provider");
        assertThatThrownBy(() -> BlobStores.create("no-such-provider",
                        new Properties()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("no-such-provider");
    }

    /** create resolves the name itself, for callers that do not. */
    @Test
    public void testCreateResolvesTheAlias() {
        try (var blobStore = BlobStores.create("transient",
                new Properties())) {
            assertThat(blobStore).isInstanceOf(
                    org.gaul.s3proxy.nio2blob.TransientNio2BlobStore.class);
        }
    }
}
