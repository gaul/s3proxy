/*
 * Copyright 2014-2020 Andrew Gaul <andrew@gaul.org>
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

import java.util.Properties;
import java.util.concurrent.TimeUnit;

import com.google.common.util.concurrent.Uninterruptibles;

import org.jclouds.Constants;
import org.jclouds.blobstore.BlobStoreContext;
import org.jclouds.blobstore.domain.Blob;
import org.jclouds.s3.blobstore.integration.S3BlobIntegrationLiveTest;
import org.jclouds.s3.reference.S3Constants;
import org.testng.SkipException;
import org.testng.annotations.AfterClass;
import org.testng.annotations.Test;

@Test(testName = "JcloudsS3BlobIntegrationLiveTest")
public final class JcloudsS3BlobIntegrationLiveTest
        extends S3BlobIntegrationLiveTest {
    protected static final int AWAIT_CONSISTENCY_TIMEOUT_SECONDS =
            Integer.parseInt(
                    System.getProperty(
                            "test.blobstore.await-consistency-timeout-seconds",
                            "0"));
    private S3Proxy s3Proxy;
    private BlobStoreContext context;
    private String blobStoreType;

    @AfterClass
    public void tearDown() throws Exception {
        s3Proxy.stop();
        context.close();
    }

    @Override
    protected void awaitConsistency() {
        Uninterruptibles.sleepUninterruptibly(
                AWAIT_CONSISTENCY_TIMEOUT_SECONDS, TimeUnit.SECONDS);
    }

    @Override
    protected Properties setupProperties() {
        TestUtils.S3ProxyLaunchInfo info;
        try {
            info = TestUtils.startS3Proxy("s3proxy.conf");
            s3Proxy = info.getS3Proxy();
            context = info.getBlobStore().getContext();
            blobStoreType = context.unwrap().getProviderMetadata().getId();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        Properties props = super.setupProperties();
        props.setProperty(Constants.PROPERTY_IDENTITY, info.getS3Identity());
        props.setProperty(Constants.PROPERTY_CREDENTIAL,
                info.getS3Credential());
        props.setProperty(Constants.PROPERTY_ENDPOINT,
                info.getEndpoint().toString() + info.getServicePath());
        props.setProperty(S3Constants.PROPERTY_S3_SERVICE_PATH,
                info.getServicePath());
        props.setProperty(Constants.PROPERTY_STRIP_EXPECT_HEADER, "true");
        return props;
    }

    @Override
    public void testSetBlobAccess() throws Exception {
        if (Quirks.NO_BLOB_ACCESS_CONTROL.contains(blobStoreType)) {
            throw new SkipException("blob access control not supported");
        }
        super.testSetBlobAccess();
    }

    // TODO: investigate java.io.EOFException
    @Override
    public void testPutMultipartInputStream() throws Exception {
        throw new SkipException("unexpected EOFException");
    }

    @Override
    public void testPutBlobAccess() throws Exception {
        if (Quirks.NO_BLOB_ACCESS_CONTROL.contains(blobStoreType)) {
            throw new SkipException("blob access control not supported");
        }
        super.testPutBlobAccess();
    }

    @Override
    public void testPutBlobAccessMultipart() throws Exception {
        if (Quirks.NO_BLOB_ACCESS_CONTROL.contains(blobStoreType)) {
            throw new SkipException("blob access control not supported");
        }
        super.testPutBlobAccessMultipart();
    }

    @Override
    public void testCreateBlobWithExpiry() throws InterruptedException {
        if (Quirks.NO_EXPIRES.contains(blobStoreType)) {
            throw new SkipException("expiry not supported");
        }
        super.testCreateBlobWithExpiry();
    }

    @Override
    public void testCopyIfNoneMatch() throws Exception {
        if (Quirks.NO_COPY_IF_NONE_MATCH.contains(blobStoreType)) {
            throw new SkipException("copy If-None-Match not supported");
        }
        super.testCopyIfNoneMatch();
    }

    @Override
    public void testCopyIfNoneMatchNegative() throws Exception {
        if (Quirks.NO_COPY_IF_NONE_MATCH.contains(blobStoreType)) {
            throw new SkipException("copy If-None-Match not supported");
        }
        super.testCopyIfNoneMatchNegative();
    }

    @Override
    public void testListMultipartUploads() throws Exception {
        if (Quirks.NO_LIST_MULTIPART_UPLOADS.contains(blobStoreType)) {
            throw new SkipException("list multipart uploads not supported");
        }
        super.testListMultipartUploads();
    }

    @Override
    protected void checkCacheControl(Blob blob, String cacheControl) {
        if (!Quirks.NO_CACHE_CONTROL_SUPPORT.contains(blobStoreType)) {
            super.checkCacheControl(blob, cacheControl);
        }
    }

    @Override
    protected void checkContentLanguage(Blob blob, String contentLanguage) {
        if (!Quirks.NO_CONTENT_LANGUAGE.contains(blobStoreType)) {
            super.checkContentLanguage(blob, contentLanguage);
        }
    }
}
