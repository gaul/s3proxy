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

package org.gaul.s3proxy.middleware;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Properties;

import org.gaul.s3proxy.S3ProxyConstants;
import org.gaul.s3proxy.TestUtils;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.junit.jupiter.api.Test;

/**
 * The sharded middleware renames a sharded bucket before the alias and
 * prefix middlewares beneath it look the bucket up, so neither can be keyed
 * by the bucket itself.
 */
public final class MiddlewaresTest {
    private static final String CONTAINER = "shared";

    private static Properties shardedProperties() {
        var properties = new Properties();
        properties.setProperty(S3ProxyConstants.PROPERTY_SHARDED_BLOBSTORE +
                "." + CONTAINER + ".shards", "2");
        return properties;
    }

    private static BlobStore wrap(BlobStore blobStore, Properties properties)
            throws Exception {
        return Middlewares.wrap(blobStore, properties, unused -> {
            throw new UnsupportedOperationException();
        });
    }

    @Test
    public void testPrefixOnShardedBucketIsRefused() {
        var properties = shardedProperties();
        properties.setProperty(S3ProxyConstants.PROPERTY_PREFIX_BLOBSTORE +
                "." + CONTAINER, "team-a/");

        assertThatThrownBy(() -> wrap(TestUtils.createTransientBlobStore(),
                properties))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining(CONTAINER)
                .hasMessageContaining("prefix and shards");
    }

    @Test
    public void testAliasOnShardedBucketIsRefused() {
        var properties = shardedProperties();
        properties.setProperty(S3ProxyConstants.PROPERTY_ALIAS_BLOBSTORE +
                "." + CONTAINER, "backend");

        assertThatThrownBy(() -> wrap(TestUtils.createTransientBlobStore(),
                properties))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining(CONTAINER)
                .hasMessageContaining("alias and shards");
    }

    @Test
    public void testPrefixOnShardsStillApplies() throws Exception {
        var properties = shardedProperties();
        properties.setProperty(S3ProxyConstants.PROPERTY_PREFIX_BLOBSTORE +
                "." + CONTAINER + "-0", "team-a/");
        properties.setProperty(S3ProxyConstants.PROPERTY_PREFIX_BLOBSTORE +
                "." + CONTAINER + "-1", "team-a/");
        BlobStore blobStore = TestUtils.createTransientBlobStore();
        BlobStore wrapped = wrap(blobStore, properties);

        wrapped.createContainer(CONTAINER);
        TestUtils.putBlob(wrapped, CONTAINER, "plan",
                TestUtils.randomByteSource().slice(0, 1));

        assertThat(wrapped.blobExists(CONTAINER, "plan")).isTrue();
        assertThat(blobStore.blobExists(CONTAINER + "-0", "team-a/plan") ||
                blobStore.blobExists(CONTAINER + "-1", "team-a/plan"))
                .isTrue();
    }
}
