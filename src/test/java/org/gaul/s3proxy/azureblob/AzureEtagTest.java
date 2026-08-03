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

package org.gaul.s3proxy.azureblob;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.google.common.base.Suppliers;

import org.gaul.s3proxy.blobstore.Credentials;
import org.junit.jupiter.api.Test;

/**
 * Azure mints an ETag S3 clients cannot parse, so S3Proxy reports it under the
 * suffix S3 gives an object assembled from parts -- the one shape every client
 * already treats as unverifiable.  A caller echoes back what it was given, so
 * the suffix comes off again on the way to a precondition and Azure evaluates
 * against the token it minted.
 */
public final class AzureEtagTest {
    private static final String AZURE_ETAG = "0x8DD3F4A5F0B2C1E";

    private static AzureBlobStore store(String eTagMode) {
        return new AzureBlobStore(
                Suppliers.ofInstance(new Credentials("identity", "credential")),
                "http://127.0.0.1:10000/devstoreaccount1", eTagMode);
    }

    /**
     * The AWS SDKs decide whether to verify before they decode: v1 skips the
     * check on {@code eTag.contains("-")} in SkipMd5CheckStrategy and only
     * then reaches BinaryUtils.fromHex, so the decode that failed never runs.
     */
    @Test
    public void testReportsTheAzureTokenUnderTheSuffix() {
        String reported = store("opaque").reportETag(AZURE_ETAG);

        assertThat(reported).isEqualTo(AZURE_ETAG + "-1");
        assertThat(reported).contains("-");
    }

    /** An ETag arrives quoted often enough to matter. */
    @Test
    public void testReportedETagDropsQuoting() {
        assertThat(store("opaque").reportETag("\"" + AZURE_ETAG + "\""))
                .isEqualTo(AZURE_ETAG + "-1");
    }

    /**
     * The round trip is what keeps a conditional request exact: Azure sees the
     * value it minted, so it adjudicates the condition itself and no window
     * opens between reading the object and writing it.
     */
    @Test
    public void testConditionRecoversTheAzureToken() {
        var store = store("opaque");

        assertThat(store.backendCondition(store.reportETag(AZURE_ETAG)))
                .isEqualTo(AZURE_ETAG);
        assertThat(store.backendCondition(
                "\"" + store.reportETag(AZURE_ETAG) + "\""))
                .isEqualTo(AZURE_ETAG);
    }

    /** A condition this store did not dress up passes through untouched. */
    @Test
    public void testConditionLeavesOtherValuesAlone() {
        var store = store("opaque");

        assertThat(store.backendCondition("*")).isEqualTo("*");
        assertThat(store.backendCondition(AZURE_ETAG)).isEqualTo(AZURE_ETAG);
        assertThat(store.backendCondition(null)).isNull();
    }

    /** The escape hatch reports Azure's truth and expects it back. */
    @Test
    public void testNativeModeLeavesTheETagBare() {
        var store = store("native");

        assertThat(store.reportETag(AZURE_ETAG)).isEqualTo(AZURE_ETAG);
        assertThat(store.backendCondition(AZURE_ETAG + "-1"))
                .isEqualTo(AZURE_ETAG + "-1");
    }

    @Test
    public void testRejectsAnUnknownETagMode() {
        assertThatThrownBy(() -> store("md5"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("md5");
    }
}
