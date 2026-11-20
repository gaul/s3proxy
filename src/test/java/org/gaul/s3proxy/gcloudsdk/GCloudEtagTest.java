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

package org.gaul.s3proxy.gcloudsdk;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.google.cloud.storage.BlobId;
import com.google.cloud.storage.BlobInfo;
import com.google.common.base.Suppliers;

import org.gaul.s3proxy.blobstore.Credentials;
import org.junit.jupiter.api.Test;

/**
 * GCS mints a base64 ETag that S3 SDKs decode as hex and reject, so md5 mode
 * reports what S3 would: the MD5 of an object written in one request, and
 * for a composed object, which GCS gives no MD5, a hex token under the
 * multipart suffix that clients do not verify.
 */
public final class GCloudEtagTest {
    // A GCS ETag and the MD5 of the same object, as GCS reports them.
    private static final String GCS_ETAG = "CISRiZr8lZgDEAE=";
    private static final String MD5_BASE64 = "LCB2nI4BS38mTHRR09WuQA==";
    private static final String MD5_HEX = "2c20769c8e014b7f264c7451d3d5ae40";
    // The GCS ETag's bytes in hex.
    private static final String GCS_ETAG_HEX = "088491899afc9598031001";

    private static GCloudBlobStore store(String eTagMode) {
        // An emulator endpoint, so building the client contacts nothing.
        return new GCloudBlobStore(Suppliers.ofInstance(
                new Credentials("project", /*credential=*/ "")),
                "http://127.0.0.1:1", eTagMode);
    }

    @Test
    public void testNativeModeReportsTheGcsETag() {
        assertThat(GCloudBlobStore.reportETag(false, GCS_ETAG, MD5_HEX))
                .isEqualTo(GCS_ETAG);
    }

    /**
     * The AWS SDK for .NET skips its download check only on an ETag with a
     * dash; any other ETag it decodes as hex and compares with the MD5 of
     * what it read, so the reported value has to be that MD5.
     */
    @Test
    public void testMd5ModeReportsTheObjectMd5InHex() {
        String reported = GCloudBlobStore.reportETag(true, GCS_ETAG, MD5_HEX);

        assertThat(reported).isEqualTo(MD5_HEX);
        assertThat(reported).matches("[0-9a-f]{32}");
    }

    @Test
    public void testMd5ModeReportsAComposedObjectUnderTheSuffix() {
        String reported = GCloudBlobStore.reportETag(true, GCS_ETAG, null);

        assertThat(reported).isEqualTo(GCS_ETAG_HEX + "-1");
        assertThat(reported).matches("[0-9a-f]+-1");
    }

    /** An emulator's token need not be base64; it still gets the suffix. */
    @Test
    public void testMd5ModeKeepsANonBase64TokenUnderTheSuffix() {
        assertThat(GCloudBlobStore.reportETag(true, "not base64!", null))
                .isEqualTo("not base64!-1");
    }

    /** The mode a store is built with decides which ETag it reports. */
    @Test
    public void testStoreReportsTheBlobMd5InMd5Mode() {
        var blob = BlobInfo.newBuilder(BlobId.of("bucket", "key"))
                .setMd5(MD5_BASE64)
                .build();

        assertThat(store("md5").reportETag(blob)).isEqualTo(MD5_HEX);
        assertThat(store("native").reportETag(blob))
                .isEqualTo(blob.getEtag());
    }

    @Test
    public void testDefaultModeIsNative() {
        var blob = BlobInfo.newBuilder(BlobId.of("bucket", "key"))
                .setMd5(MD5_BASE64)
                .build();
        var store = new GCloudBlobStore(Suppliers.ofInstance(
                new Credentials("project", /*credential=*/ "")),
                "http://127.0.0.1:1");

        assertThat(store.reportETag(blob)).isEqualTo(blob.getEtag());
    }

    @Test
    public void testRejectsAnUnknownETagMode() {
        assertThatThrownBy(() -> store("opaque"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("opaque");
    }
}
