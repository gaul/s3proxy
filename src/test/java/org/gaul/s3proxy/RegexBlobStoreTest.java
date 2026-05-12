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

import java.io.IOException;
import java.io.InputStream;
import java.util.AbstractMap.SimpleEntry;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Random;
import java.util.regex.Pattern;

import com.google.common.hash.Hashing;
import com.google.common.io.ByteSource;

import org.assertj.core.api.Assertions;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.domain.Blob;
import org.gaul.s3proxy.blobstore.domain.BlobMetadata;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public final class RegexBlobStoreTest {
    private BlobStore delegate;
    private String containerName;

    @BeforeEach
    public void setUp() throws Exception {
        containerName = createRandomContainerName();

        delegate = TestUtils.createTransientBlobStore();
        delegate.createContainer(containerName);

    }

    @AfterEach
    public void tearDown() throws Exception {
        if (delegate != null) {
            delegate.deleteContainer(containerName);
        }
    }

    @Test
    public void testRemoveSomeCharsFromName() throws IOException {
        var regexes = List.<Map.Entry<Pattern, String>>of(
                new SimpleEntry<Pattern, String>(
                        Pattern.compile("[^a-zA-Z0-9/_.]"), "_"));
        BlobStore regexBlobStore = RegexBlobStore.newRegexBlobStore(delegate,
                regexes);

        String initialBlobName = "test/remove:badchars-folder/blob.txt";
        String targetBlobName = "test/remove_badchars_folder/blob.txt";
        ByteSource content = TestUtils.randomByteSource().slice(0, 1024);
        @SuppressWarnings("deprecation")
        String contentHash = Hashing.md5().hashBytes(content.read()).toString();
        Blob blob = Blob.builder(initialBlobName).payload(
                content).build();

        String eTag = regexBlobStore.putBlob(containerName, blob);
        assertThat(eTag).isEqualTo(contentHash);

        BlobMetadata blobMetadata = regexBlobStore.blobMetadata(
                containerName, targetBlobName);

        assertThat(blobMetadata.getETag()).isEqualTo(contentHash);
        blob = regexBlobStore.getBlob(containerName, targetBlobName);
        try (InputStream actual = blob.getPayload().openStream();
             InputStream expected = content.openStream()) {
            assertThat(actual).hasSameContentAs(expected);
        }

        blob = regexBlobStore.getBlob(containerName, initialBlobName);
        try (InputStream actual = blob.getPayload().openStream();
             InputStream expected = content.openStream()) {
            assertThat(actual).hasSameContentAs(expected);
        }
    }

    @Test
    public void testParseMatchWithoutReplace() {
        var properties = new Properties();
        properties.put(
                "%s.%s.sample1".formatted(
                        S3ProxyConstants.PROPERTY_REGEX_BLOBSTORE,
                        S3ProxyConstants.PROPERTY_REGEX_BLOBSTORE_MATCH),
                "test");
        properties.put(
                "%s.%s.sample2".formatted(
                        S3ProxyConstants.PROPERTY_REGEX_BLOBSTORE,
                        S3ProxyConstants.PROPERTY_REGEX_BLOBSTORE_MATCH),
                "test");
        properties.put(
                "%s.%s.sample1".formatted(
                        S3ProxyConstants.PROPERTY_REGEX_BLOBSTORE,
                        S3ProxyConstants.PROPERTY_REGEX_BLOBSTORE_REPLACE),
                "test");

        try {
            RegexBlobStore.parseRegexs(properties);
            Assertions.failBecauseExceptionWasNotThrown(
                    IllegalArgumentException.class);
        } catch (IllegalArgumentException exc) {
            assertThat(exc.getMessage()).isEqualTo(
                    "Regex sample2 has no replace property associated");
        }
    }

    private static String createRandomContainerName() {
        return "container-" + new Random().nextInt(Integer.MAX_VALUE);
    }
}
