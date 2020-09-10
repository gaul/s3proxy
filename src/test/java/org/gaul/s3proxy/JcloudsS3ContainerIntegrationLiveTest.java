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
import org.jclouds.s3.blobstore.integration.S3ContainerIntegrationLiveTest;
import org.jclouds.s3.reference.S3Constants;
import org.testng.SkipException;
import org.testng.annotations.AfterClass;
import org.testng.annotations.Test;

@Test(testName = "JcloudsS3ContainerIntegrationLiveTest")
public final class JcloudsS3ContainerIntegrationLiveTest
        extends S3ContainerIntegrationLiveTest {
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
    public void testListMarkerAfterLastKey() throws Exception {
        if (Quirks.OPAQUE_MARKERS.contains(blobStoreType)) {
            throw new SkipException("opaque markers not supported");
        }
        super.testListMarkerAfterLastKey();
    }

    @Override
    public void testListContainerWithZeroMaxResults() throws Exception {
        if (Quirks.NO_LIST_ZERO_KEYS.contains(blobStoreType)) {
            throw new SkipException("listing zero keys not supported");
        }
        super.testListContainerWithZeroMaxResults();
    }
}
