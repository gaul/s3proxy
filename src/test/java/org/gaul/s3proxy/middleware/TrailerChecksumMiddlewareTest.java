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

import java.util.AbstractMap.SimpleEntry;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import com.google.common.collect.ImmutableBiMap;

import org.gaul.s3proxy.TestUtils;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.ForwardingBlobStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * A checksum that arrives as an aws-chunked trailer is attached to the
 * object after the write, by a call of its own.  A middleware that did not
 * forward that call left the object with no checksum at all -- and the
 * trailer is how current SDKs send one by default.
 */
public final class TrailerChecksumMiddlewareTest {
    private static final String KEY = "s3proxy_checksum_crc32";
    private static final String VALUE = "AAAAAA==";

    private String containerName;
    private BlobStore delegate;

    @BeforeEach
    public void setUp() throws Exception {
        containerName = TestUtils.createRandomContainerName();
        delegate = TestUtils.createTransientBlobStore();
        delegate.createContainer(containerName);
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (delegate != null) {
            delegate.close();
        }
    }

    @Test
    public void testForwarding() throws Exception {
        assertRecorded(new ForwardingBlobStore(delegate) { }, containerName);
    }

    @Test
    public void testAlias() throws Exception {
        assertRecorded(AliasBlobStore.newAliasBlobStore(delegate,
                ImmutableBiMap.of("alias", containerName)), "alias");
    }

    @Test
    public void testPrefix() throws Exception {
        assertRecorded(PrefixBlobStore.newPrefixBlobStore(delegate,
                Map.of(containerName, "prefix/")), containerName);
    }

    @Test
    public void testRegex() throws Exception {
        assertRecorded(RegexBlobStore.newRegexBlobStore(delegate,
                List.<Map.Entry<Pattern, String>>of(new SimpleEntry<>(
                        Pattern.compile("k"), "renamed-k"))), containerName);
    }

    @Test
    public void testUserMetadataReplacer() throws Exception {
        assertRecorded(UserMetadataReplacerBlobStore
                .newUserMetadataReplacerBlobStore(delegate, "_=", "-+"),
                containerName);
    }

    private static void assertRecorded(BlobStore blobStore, String container)
            throws Exception {
        String eTag = TestUtils.putBlob(blobStore, container, "key",
                TestUtils.randomByteSource().slice(0, 16)).eTag();
        assertThat(blobStore.recordChecksumMetadata(container, "key", eTag,
                KEY, VALUE)).isTrue();
        var head = blobStore.blobMetadataIfPresent(container, "key");
        assertThat(head).isNotNull();
        assertThat(head.metadata()).containsEntry(KEY, VALUE);
    }
}
