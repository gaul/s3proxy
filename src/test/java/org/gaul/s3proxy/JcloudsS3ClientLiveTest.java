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

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.util.Properties;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import com.google.common.util.concurrent.Uninterruptibles;

import org.assertj.core.api.Fail;
import org.jclouds.Constants;
import org.jclouds.aws.AWSResponseException;
import org.jclouds.blobstore.BlobStoreContext;
import org.jclouds.s3.S3ClientLiveTest;
import org.jclouds.s3.domain.S3Object;
import org.jclouds.s3.reference.S3Constants;
import org.testng.SkipException;
import org.testng.annotations.AfterClass;
import org.testng.annotations.Test;

@Test(testName = "JcloudsS3ClientLiveTest")
public final class JcloudsS3ClientLiveTest extends S3ClientLiveTest {
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
        props.setProperty(Constants.PROPERTY_STRIP_EXPECT_HEADER, "true");
        props.setProperty(S3Constants.PROPERTY_S3_SERVICE_PATH,
                info.getServicePath());
        endpoint = info.getEndpoint().toString() + info.getServicePath();
        return props;
    }

    @Override
    @Test
    public void testPublicWriteOnObject() throws InterruptedException,
            ExecutionException, TimeoutException, IOException {
        try {
            super.testPublicWriteOnObject();
            Fail.failBecauseExceptionWasNotThrown(AWSResponseException.class);
        } catch (AWSResponseException are) {
            assertThat(are.getError().getCode()).isEqualTo("NotImplemented");
            throw new SkipException("public-read-write-acl not supported", are);
        }
    }

    @Override
    @Test
    public void testUpdateObjectACL() throws InterruptedException,
            ExecutionException, TimeoutException, IOException {
        try {
            super.testUpdateObjectACL();
            Fail.failBecauseExceptionWasNotThrown(AWSResponseException.class);
        } catch (AWSResponseException are) {
            assertThat(are.getError().getCode()).isEqualTo("NotImplemented");
            throw new SkipException("XML ACLs not supported", are);
        }
    }

    // work around bucket-in-host and port 80 assumptions
    @Override
    protected URL getObjectURL(String containerName, String key)
            throws Exception {
        return new URL(String.format("%s/%s/%s", URI.create(endpoint),
                containerName, key));
    }

    @Override
    public void testPutCannedAccessPolicyPublic() throws Exception {
        if (Quirks.NO_BLOB_ACCESS_CONTROL.contains(blobStoreType)) {
            throw new SkipException("blob access control not supported");
        }
        super.testPutCannedAccessPolicyPublic();
    }

    @Override
    public void testCopyCannedAccessPolicyPublic() throws Exception {
        if (Quirks.NO_BLOB_ACCESS_CONTROL.contains(blobStoreType)) {
            throw new SkipException("blob access control not supported");
        }
        super.testCopyCannedAccessPolicyPublic();
    }

    @Override
    public void testPublicReadOnObject()
            throws InterruptedException, ExecutionException, TimeoutException,
            IOException {
        if (Quirks.NO_BLOB_ACCESS_CONTROL.contains(blobStoreType)) {
            throw new SkipException("blob access control not supported");
        }
        super.testPublicReadOnObject();
    }

    @Override
    public void testCopyIfNoneMatch()
            throws IOException, InterruptedException, ExecutionException,
            TimeoutException {
        if (Quirks.NO_COPY_IF_NONE_MATCH.contains(blobStoreType)) {
            throw new SkipException("copy If-None-Match not supported");
        }
        super.testCopyIfNoneMatch();
    }

    @Override
    public void testUpdateObjectCannedACL() throws Exception {
        if (Quirks.NO_BLOB_ACCESS_CONTROL.contains(blobStoreType)) {
            throw new SkipException("blob access control not supported");
        }
        super.testUpdateObjectCannedACL();
    }

    @Override
    public void testListMultipartUploads() throws Exception {
        if (Quirks.NO_LIST_MULTIPART_UPLOADS.contains(blobStoreType)) {
            throw new SkipException("list multipart uploads not supported");
        }
        super.testListMultipartUploads();
    }

    @Override
    protected void assertCacheControl(S3Object newObject, String string) {
        if (Quirks.NO_CACHE_CONTROL_SUPPORT.contains(blobStoreType)) {
            throw new SkipException("cache control not supported");
        }
        super.assertCacheControl(newObject, string);
    }
}
