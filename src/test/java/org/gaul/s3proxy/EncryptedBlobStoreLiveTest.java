/*
 * Copyright 2014-2021 Andrew Gaul <andrew@gaul.org>
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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Properties;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.stream.Collectors;

import com.google.common.collect.ImmutableMap;
import com.google.common.io.ByteSource;
import com.google.common.util.concurrent.Uninterruptibles;

import org.assertj.core.api.Fail;
import org.gaul.s3proxy.crypto.Constants;
import org.jclouds.aws.AWSResponseException;
import org.jclouds.blobstore.BlobStoreContext;
import org.jclouds.blobstore.domain.PageSet;
import org.jclouds.blobstore.domain.StorageMetadata;
import org.jclouds.blobstore.options.ListContainerOptions;
import org.jclouds.http.options.GetOptions;
import org.jclouds.io.Payload;
import org.jclouds.io.Payloads;
import org.jclouds.s3.S3ClientLiveTest;
import org.jclouds.s3.domain.ListMultipartUploadsResponse;
import org.jclouds.s3.domain.ObjectMetadataBuilder;
import org.jclouds.s3.domain.S3Object;
import org.jclouds.s3.reference.S3Constants;
import org.testng.SkipException;
import org.testng.annotations.AfterSuite;
import org.testng.annotations.Test;

@SuppressWarnings("UnstableApiUsage")
@Test(testName = "EncryptedBlobStoreLiveTest")
public final class EncryptedBlobStoreLiveTest extends S3ClientLiveTest {
    private static final int AWAIT_CONSISTENCY_TIMEOUT_SECONDS =
        Integer.parseInt(
            System.getProperty(
                "test.blobstore.await-consistency-timeout-seconds",
                "0"));
    private static final long MINIMUM_MULTIPART_SIZE = 5 * 1024 * 1024;

    private S3Proxy s3Proxy;
    private BlobStoreContext context;

    @AfterSuite
    @Override
    public void destroyResources() throws Exception {
        context.close();
        s3Proxy.stop();
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
            info = TestUtils.startS3Proxy("s3proxy-encryption.conf");
            s3Proxy = info.getS3Proxy();
            context = info.getBlobStore().getContext();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        Properties props = super.setupProperties();
        props.setProperty(org.jclouds.Constants.PROPERTY_IDENTITY,
            info.getS3Identity());
        props.setProperty(org.jclouds.Constants.PROPERTY_CREDENTIAL,
            info.getS3Credential());
        props.setProperty(org.jclouds.Constants.PROPERTY_ENDPOINT,
            info.getEndpoint().toString() + info.getServicePath());
        props.setProperty(org.jclouds.Constants.PROPERTY_STRIP_EXPECT_HEADER,
            "true");
        props.setProperty(S3Constants.PROPERTY_S3_SERVICE_PATH,
            info.getServicePath());
        endpoint = info.getEndpoint().toString() + info.getServicePath();
        return props;
    }

    @Test
    public void testOneCharAndCopy() throws InterruptedException {
        String blobName = TestUtils.createRandomBlobName();
        String containerName = this.getContainerName();

        S3Object object = this.getApi().newS3Object();
        object.getMetadata().setKey(blobName);
        object.setPayload("1");
        this.getApi().putObject(containerName, object);

        object = this.getApi().getObject(containerName, blobName);
        assertThat(object.getMetadata().getContentMetadata()
            .getContentLength()).isEqualTo(1L);

        PageSet<? extends StorageMetadata>
            list = view.getBlobStore().list(containerName);
        assertThat(list).hasSize(1);

        StorageMetadata md = list.iterator().next();
        assertThat(md.getName()).isEqualTo(blobName);
        assertThat(md.getSize()).isEqualTo(1L);

        this.getApi().copyObject(containerName, blobName, containerName,
            blobName + "-copy");
        list = view.getBlobStore().list(containerName);
        assertThat(list).hasSize(2);

        for (StorageMetadata sm : list) {
            assertThat(sm.getSize()).isEqualTo(1L);
            assertThat(sm.getName()).doesNotContain(
                Constants.S3_ENC_SUFFIX);
        }

        ListContainerOptions lco = new ListContainerOptions();
        lco.maxResults(1);
        list = view.getBlobStore().list(containerName, lco);
        assertThat(list).hasSize(1);
        assertThat(list.getNextMarker()).doesNotContain(
            Constants.S3_ENC_SUFFIX);
    }

    @Test
    public void testPartialContent() throws InterruptedException, IOException {
        String blobName = TestUtils.createRandomBlobName();
        String containerName = this.getContainerName();
        String content = "123456789A123456789B123456";

        S3Object object = this.getApi().newS3Object();
        object.getMetadata().setKey(blobName);
        object.setPayload(content);
        this.getApi().putObject(containerName, object);

        // get only 20 bytes
        GetOptions options = new GetOptions();
        options.range(0, 19);
        object = this.getApi().getObject(containerName, blobName, options);

        InputStreamReader r =
            new InputStreamReader(object.getPayload().openStream());
        BufferedReader reader = new BufferedReader(r);
        String partialContent = reader.lines().collect(Collectors.joining());
        assertThat(partialContent).isEqualTo(content.substring(0, 20));
    }

    @Test
    public void testMultipart() throws InterruptedException, IOException {
        String blobName = TestUtils.createRandomBlobName();
        String containerName = this.getContainerName();

        // 15mb of data
        ByteSource byteSource = TestUtils.randomByteSource().slice(
            0, MINIMUM_MULTIPART_SIZE * 3);

        // first 2 parts with 6mb and last part with 3mb
        long partSize = 6 * 1024 * 1024;
        long lastPartSize = 3 * 1024 * 1024;
        ByteSource byteSource1 = byteSource.slice(0, partSize);
        ByteSource byteSource2 = byteSource.slice(partSize, partSize);
        ByteSource byteSource3 = byteSource.slice(partSize * 2,
            lastPartSize);

        String uploadId = this.getApi().initiateMultipartUpload(containerName,
            ObjectMetadataBuilder.create().key(blobName).build());
        assertThat(this.getApi().listMultipartPartsFull(containerName,
            blobName, uploadId)).isEmpty();

        ListMultipartUploadsResponse
            response = this.getApi()
            .listMultipartUploads(containerName, null, null, null, blobName,
                null);
        assertThat(response.uploads()).hasSize(1);

        Payload part1 =
            Payloads.newInputStreamPayload(byteSource1.openStream());
        part1.getContentMetadata().setContentLength(byteSource1.size());
        Payload part2 =
            Payloads.newInputStreamPayload(byteSource2.openStream());
        part2.getContentMetadata().setContentLength(byteSource2.size());
        Payload part3 =
            Payloads.newInputStreamPayload(byteSource3.openStream());
        part3.getContentMetadata().setContentLength(byteSource3.size());

        String eTagOf1 = this.getApi()
            .uploadPart(containerName, blobName, 1, uploadId, part1);
        String eTagOf2 = this.getApi()
            .uploadPart(containerName, blobName, 2, uploadId, part2);
        String eTagOf3 = this.getApi()
            .uploadPart(containerName, blobName, 3, uploadId, part3);

        this.getApi().completeMultipartUpload(containerName, blobName, uploadId,
            ImmutableMap.of(1, eTagOf1, 2, eTagOf2, 3, eTagOf3));
        S3Object object = this.getApi().getObject(containerName, blobName);

        try (InputStream actual = object.getPayload().openStream();
             InputStream expected = byteSource.openStream()) {
            assertThat(actual).hasContentEqualTo(expected);
        }

        // get a 5mb slice that overlap parts
        long partialStart = 5 * 1024 * 1024;
        ByteSource partialContent =
            byteSource.slice(partialStart, partialStart);

        GetOptions options = new GetOptions();
        options.range(partialStart, (partialStart * 2) - 1);
        object = this.getApi().getObject(containerName, blobName, options);

        try (InputStream actual = object.getPayload().openStream();
             InputStream expected = partialContent.openStream()) {
            assertThat(actual).hasContentEqualTo(expected);
        }
    }

    @Override
    public void testMultipartSynchronously() {
        throw new SkipException("list multipart synchronously not supported");
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
    public void testCopyCannedAccessPolicyPublic() {
        throw new SkipException("blob access control not supported");
    }

    @Override
    public void testPutCannedAccessPolicyPublic() {
        throw new SkipException("blob access control not supported");
    }

    @Override
    public void testUpdateObjectCannedACL() {
        throw new SkipException("blob access control not supported");
    }
}
