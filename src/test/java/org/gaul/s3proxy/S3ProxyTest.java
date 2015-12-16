/*
 * Copyright 2014-2015 Andrew Gaul <andrew@gaul.org>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.gaul.s3proxy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assume.assumeTrue;

import java.io.InputStream;
import java.net.URI;
import java.util.Map;
import java.util.Properties;
import java.util.Random;
import java.util.Set;

import javax.servlet.http.HttpServletResponse;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.io.ByteSource;

import org.assertj.core.api.Fail;

import org.jclouds.Constants;
import org.jclouds.ContextBuilder;
import org.jclouds.aws.AWSResponseException;
import org.jclouds.blobstore.BlobRequestSigner;
import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.BlobStoreContext;
import org.jclouds.blobstore.domain.Blob;
import org.jclouds.blobstore.domain.BlobAccess;
import org.jclouds.blobstore.domain.BlobMetadata;
import org.jclouds.blobstore.domain.ContainerAccess;
import org.jclouds.blobstore.domain.MultipartPart;
import org.jclouds.blobstore.domain.MultipartUpload;
import org.jclouds.blobstore.domain.PageSet;
import org.jclouds.blobstore.domain.StorageMetadata;
import org.jclouds.blobstore.options.CopyOptions;
import org.jclouds.blobstore.options.GetOptions;
import org.jclouds.blobstore.options.ListContainerOptions;
import org.jclouds.http.HttpRequest;
import org.jclouds.http.HttpResponse;
import org.jclouds.http.HttpResponseException;
import org.jclouds.io.ContentMetadata;
import org.jclouds.io.ContentMetadataBuilder;
import org.jclouds.io.Payload;
import org.jclouds.io.Payloads;
import org.jclouds.rest.HttpClient;
import org.jclouds.s3.S3Client;

import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

public final class S3ProxyTest {
    private static final ByteSource BYTE_SOURCE = ByteSource.wrap(new byte[1]);
    private static final Set<String> SWIFT_BLOBSTORES = ImmutableSet.of(
            "rackspace-cloudfiles-uk",
            "rackspace-cloudfiles-us",
            "openstack-swift"
    );

    private URI s3Endpoint;
    private S3Proxy s3Proxy;
    private BlobStoreContext context;
    private BlobStore blobStore;
    private String blobStoreType;
    private BlobStoreContext s3Context;
    private BlobStore s3BlobStore;
    private String containerName;

    @Before
    public void setUp() throws Exception {
        TestUtils.S3ProxyLaunchInfo info = TestUtils.startS3Proxy();
        s3Proxy = info.getS3Proxy();
        context = info.getBlobStore().getContext();
        blobStore = info.getBlobStore();
        blobStoreType = context.unwrap().getProviderMetadata().getId();
        s3Endpoint = info.getEndpoint();

        containerName = createRandomContainerName();
        blobStore.createContainerInLocation(null, containerName);

        Properties s3Properties = new Properties();
        s3Properties.setProperty(Constants.PROPERTY_TRUST_ALL_CERTS, "true");
        s3Context = ContextBuilder
                .newBuilder("s3")
                .credentials(info.getS3Identity(), info.getS3Credential())
                .endpoint(s3Endpoint.toString())
                .overrides(s3Properties)
                .build(BlobStoreContext.class);
        s3BlobStore = s3Context.getBlobStore();
    }

    @After
    public void tearDown() throws Exception {
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
        if (s3Context != null) {
            s3Context.close();
        }
        if (context != null) {
            context.getBlobStore().deleteContainer(containerName);
            context.close();
        }
    }

    @Test
    public void testHttpClient() throws Exception {
        String blobName = "blob-name";
        Blob blob = blobStore.blobBuilder(blobName)
                .payload(BYTE_SOURCE)
                .contentLength(BYTE_SOURCE.size())
                .build();
        blobStore.putBlob(containerName, blob);

        if (blobStoreType.equals("azureblob") ||
                SWIFT_BLOBSTORES.contains(blobStoreType)) {
            // Azure and Swift do not support blob access control
            blobStore.setContainerAccess(containerName,
                    ContainerAccess.PUBLIC_READ);
        } else {
            blobStore.setBlobAccess(containerName, blobName,
                    BlobAccess.PUBLIC_READ);
        }

        HttpClient httpClient = s3Context.utils().http();
        URI uri = new URI(s3Endpoint.getScheme(), s3Endpoint.getUserInfo(),
                s3Endpoint.getHost(), s3Proxy.getPort(),
                "/" + containerName + "/" + blobName,
                /*query=*/ null, /*fragment=*/ null);
        try (InputStream actual = httpClient.get(uri);
             InputStream expected = BYTE_SOURCE.openStream()) {
            assertThat(actual).hasContentEqualTo(expected);
        }
    }

    @Test
    public void testJcloudsClient() throws Exception {
        ImmutableSet.Builder<String> builder = ImmutableSet.builder();
        for (StorageMetadata metadata : s3BlobStore.list()) {
            builder.add(metadata.getName());
        }
        assertThat(builder.build()).contains(containerName);
    }

    @Test
    public void testContainerExists() throws Exception {
        assertThat(s3BlobStore.containerExists(containerName)).isTrue();
        assertThat(s3BlobStore.containerExists(createRandomContainerName()))
                .isFalse();
    }

    @Test
    public void testContainerCreateDelete() throws Exception {
        String containerName2 = createRandomContainerName();
        assertThat(s3BlobStore.createContainerInLocation(null,
                containerName2)).isTrue();
        try {
            assertThat(s3BlobStore.createContainerInLocation(null,
                    containerName2)).isFalse();
        } finally {
            s3BlobStore.deleteContainer(containerName2);
        }
    }

    @Test
    public void testContainerDelete() throws Exception {
        assertThat(s3BlobStore.containerExists(containerName)).isTrue();
        s3BlobStore.deleteContainerIfEmpty(containerName);
        assertThat(s3BlobStore.containerExists(containerName)).isFalse();
    }

    private void putBlobAndCheckIt(String blobName) throws Exception {
        Blob blob = s3BlobStore.blobBuilder(blobName)
                .payload(BYTE_SOURCE)
                .contentLength(BYTE_SOURCE.size())
                .build();
        s3BlobStore.putBlob(containerName, blob);

        Blob blob2 = s3BlobStore.getBlob(containerName, blobName);
        assertThat(blob2.getMetadata().getName()).isEqualTo(blobName);
        try (InputStream actual = blob2.getPayload().openStream();
             InputStream expected = BYTE_SOURCE.openStream()) {
            assertThat(actual).hasContentEqualTo(expected);
        }
    }

    @Test
    public void testBlobPutGet() throws Exception {
        putBlobAndCheckIt("blob");
        putBlobAndCheckIt("blob%");
        putBlobAndCheckIt("blob%%");
    }

    @Test
    public void testBlobEscape() throws Exception {
        assertThat(s3BlobStore.list(containerName)).isEmpty();
        putBlobAndCheckIt("blob%");
        PageSet<? extends StorageMetadata> res =
                s3BlobStore.list(containerName);
        StorageMetadata meta = res.iterator().next();
        assertThat(meta.getName()).isEqualTo("blob%");
        assertThat(res).hasSize(1);
    }

    @Test
    public void testBlobList() throws Exception {
        assertThat(s3BlobStore.list(containerName)).isEmpty();

        ImmutableSet.Builder<String> builder = ImmutableSet.builder();
        Blob blob1 = s3BlobStore.blobBuilder("blob1")
                .payload(BYTE_SOURCE)
                .contentLength(BYTE_SOURCE.size())
                .build();
        s3BlobStore.putBlob(containerName, blob1);
        for (StorageMetadata metadata : s3BlobStore.list(containerName)) {
            builder.add(metadata.getName());
        }
        assertThat(builder.build()).containsOnly("blob1");

        builder = ImmutableSet.builder();
        Blob blob2 = s3BlobStore.blobBuilder("blob2")
                .payload(BYTE_SOURCE)
                .contentLength(BYTE_SOURCE.size())
                .build();
        s3BlobStore.putBlob(containerName, blob2);
        for (StorageMetadata metadata : s3BlobStore.list(containerName)) {
            builder.add(metadata.getName());
        }
        assertThat(builder.build()).containsOnly("blob1", "blob2");
    }

    @Test
    public void testBlobListRecursive() throws Exception {
        assertThat(s3BlobStore.list(containerName)).isEmpty();

        Blob blob1 = s3BlobStore.blobBuilder("prefix/blob1")
                .payload(BYTE_SOURCE)
                .contentLength(BYTE_SOURCE.size())
                .build();
        s3BlobStore.putBlob(containerName, blob1);

        Blob blob2 = s3BlobStore.blobBuilder("prefix/blob2")
                .payload(BYTE_SOURCE)
                .contentLength(BYTE_SOURCE.size())
                .build();
        s3BlobStore.putBlob(containerName, blob2);

        ImmutableSet.Builder<String> builder = ImmutableSet.builder();
        for (StorageMetadata metadata : s3BlobStore.list(containerName)) {
            builder.add(metadata.getName());
        }
        assertThat(builder.build()).containsOnly("prefix/");

        builder = ImmutableSet.builder();
        for (StorageMetadata metadata : s3BlobStore.list(containerName,
                new ListContainerOptions().recursive())) {
            builder.add(metadata.getName());
        }
        assertThat(builder.build()).containsOnly("prefix/blob1",
                "prefix/blob2");
    }

    @Test
    public void testBlobListRecursiveImplicitMarker() throws Exception {
        assertThat(s3BlobStore.list(containerName)).isEmpty();

        Blob blob1 = s3BlobStore.blobBuilder("blob1")
                .payload(BYTE_SOURCE)
                .contentLength(BYTE_SOURCE.size())
                .build();
        s3BlobStore.putBlob(containerName, blob1);

        Blob blob2 = s3BlobStore.blobBuilder("blob2")
                .payload(BYTE_SOURCE)
                .contentLength(BYTE_SOURCE.size())
                .build();
        s3BlobStore.putBlob(containerName, blob2);

        PageSet<? extends StorageMetadata> pageSet = s3BlobStore.list(
                containerName, new ListContainerOptions().maxResults(1));
        String blobName = pageSet.iterator().next().getName();
        assertThat(blobName).isEqualTo("blob1");

        pageSet = s3BlobStore.list(containerName,
                new ListContainerOptions().maxResults(1).afterMarker(blobName));
        blobName = pageSet.iterator().next().getName();
        assertThat(blobName).isEqualTo("blob2");
    }

    @Test
    public void testBlobMetadata() throws Exception {
        String blobName = "blob";
        Blob blob1 = s3BlobStore.blobBuilder(blobName)
                .payload(BYTE_SOURCE)
                .contentLength(BYTE_SOURCE.size())
                .build();
        s3BlobStore.putBlob(containerName, blob1);

        BlobMetadata metadata = s3BlobStore.blobMetadata(containerName,
                blobName);
        assertThat(metadata.getName()).isEqualTo(blobName);
        assertThat(metadata.getContentMetadata().getContentLength())
                .isEqualTo(BYTE_SOURCE.size());

        assertThat(s3BlobStore.blobMetadata(containerName,
                "fake-blob")).isNull();
    }

    @Test
    public void testBlobRemove() throws Exception {
        String blobName = "blob";
        Blob blob = s3BlobStore.blobBuilder(blobName)
                .payload(BYTE_SOURCE)
                .contentLength(BYTE_SOURCE.size())
                .build();
        s3BlobStore.putBlob(containerName, blob);
        assertThat(s3BlobStore.blobExists(containerName, blobName)).isTrue();

        s3BlobStore.removeBlob(containerName, blobName);
        assertThat(s3BlobStore.blobExists(containerName, blobName)).isFalse();

        s3BlobStore.removeBlob(containerName, blobName);
    }

    // TODO: this test fails since S3BlobRequestSigner does not implement the
    // same logic as AWSS3BlobRequestSigner.signForTemporaryAccess.
    @Ignore
    @Test
    public void testUrlSigning() throws Exception {
        HttpClient httpClient = s3Context.utils().http();
        BlobRequestSigner signer = s3Context.getSigner();

        String blobName = "blob";
        Blob blob = s3BlobStore.blobBuilder(blobName)
                .payload(BYTE_SOURCE)
                .contentLength(BYTE_SOURCE.size())
                .build();
        HttpRequest putRequest = signer.signPutBlob(containerName, blob, 10);
        HttpResponse putResponse = httpClient.invoke(putRequest);
        assertThat(putResponse.getStatusCode())
                .isEqualTo(HttpServletResponse.SC_OK);

        HttpRequest getRequest = signer.signGetBlob(containerName, blobName,
                10);
        HttpResponse getResponse = httpClient.invoke(getRequest);
        assertThat(getResponse.getStatusCode())
                .isEqualTo(HttpServletResponse.SC_OK);
    }

    @Test
    public void testSinglepartUpload() throws Exception {
        String blobName = "singlepart-upload";
        String contentDisposition = "attachment; filename=new.jpg";
        String contentEncoding = "gzip";
        String contentLanguage = "fr";
        String contentType = "audio/mp4";
        Map<String, String> userMetadata = ImmutableMap.of(
                "key1", "value1",
                "key2", "value2");
        Blob blob = s3BlobStore.blobBuilder(blobName)
                .payload(BYTE_SOURCE)
                .contentDisposition(contentDisposition)
                .contentEncoding(contentEncoding)
                .contentLanguage(contentLanguage)
                .contentLength(BYTE_SOURCE.size())
                .contentType(contentType)
                // TODO: expires
                .userMetadata(userMetadata)
                .build();

        s3BlobStore.putBlob(containerName, blob);

        Blob newBlob = s3BlobStore.getBlob(containerName, blobName);
        try (InputStream actual = newBlob.getPayload().openStream();
                InputStream expected = BYTE_SOURCE.openStream()) {
            assertThat(actual).hasContentEqualTo(expected);
        }
        ContentMetadata newContentMetadata =
                newBlob.getMetadata().getContentMetadata();
        assertThat(newContentMetadata.getContentDisposition()).isEqualTo(
                contentDisposition);
        assertThat(newContentMetadata.getContentEncoding()).isEqualTo(
                contentEncoding);
        if (!SWIFT_BLOBSTORES.contains(blobStoreType)) {
            assertThat(newContentMetadata.getContentLanguage()).isEqualTo(
                    contentLanguage);
        }
        assertThat(newContentMetadata.getContentType()).isEqualTo(
                contentType);
        // TODO: expires
        assertThat(newBlob.getMetadata().getUserMetadata()).isEqualTo(
                userMetadata);
    }

    // TODO: fails for GCS (jclouds not implemented)
    // TODO: fails for Swift (content and user metadata not set)
    @Test
    public void testMultipartUpload() throws Exception {
        String blobName = "multipart-upload";
        String contentDisposition = "attachment; filename=new.jpg";
        String contentEncoding = "gzip";
        String contentLanguage = "fr";
        String contentType = "audio/mp4";
        Map<String, String> userMetadata = ImmutableMap.of(
                "key1", "value1",
                "key2", "value2");
        BlobMetadata blobMetadata = s3BlobStore.blobBuilder(blobName)
                .payload(new byte[0])  // fake payload to add content metadata
                .contentDisposition(contentDisposition)
                .contentEncoding(contentEncoding)
                .contentLanguage(contentLanguage)
                .contentType(contentType)
                // TODO: expires
                .userMetadata(userMetadata)
                .build()
                .getMetadata();
        MultipartUpload mpu = s3BlobStore.initiateMultipartUpload(
                containerName, blobMetadata);

        ByteSource byteSource = TestUtils.randomByteSource().slice(
                0, s3BlobStore.getMinimumMultipartPartSize() + 1);
        ByteSource byteSource1 = byteSource.slice(
                0, s3BlobStore.getMinimumMultipartPartSize());
        ByteSource byteSource2 = byteSource.slice(
                s3BlobStore.getMinimumMultipartPartSize(), 1);
        Payload payload1 = Payloads.newByteSourcePayload(byteSource1);
        Payload payload2 = Payloads.newByteSourcePayload(byteSource2);
        payload1.getContentMetadata().setContentLength(byteSource1.size());
        payload2.getContentMetadata().setContentLength(byteSource2.size());
        MultipartPart part1 = s3BlobStore.uploadMultipartPart(mpu, 1, payload1);
        MultipartPart part2 = s3BlobStore.uploadMultipartPart(mpu, 2, payload2);

        s3BlobStore.completeMultipartUpload(mpu, ImmutableList.of(part1,
                part2));

        Blob newBlob = s3BlobStore.getBlob(containerName, blobName);
        try (InputStream actual = newBlob.getPayload().openStream();
                InputStream expected = byteSource.openStream()) {
            assertThat(actual).hasContentEqualTo(expected);
        }
        ContentMetadata newContentMetadata =
                newBlob.getMetadata().getContentMetadata();
        assertThat(newContentMetadata.getContentDisposition()).isEqualTo(
                contentDisposition);
        assertThat(newContentMetadata.getContentEncoding()).isEqualTo(
                contentEncoding);
        if (!SWIFT_BLOBSTORES.contains(blobStoreType)) {
            assertThat(newContentMetadata.getContentLanguage()).isEqualTo(
                    contentLanguage);
        }
        assertThat(newContentMetadata.getContentType()).isEqualTo(
                contentType);
        // TODO: expires
        assertThat(newBlob.getMetadata().getUserMetadata()).isEqualTo(
                userMetadata);
    }

    @Test
    public void testMaximumMultipartUpload() throws Exception {
        // skip with large part sizes to avoid excessive run-times
        assumeTrue(blobStore.getMinimumMultipartPartSize() == 1);

        String blobName = "multipart-upload";
        int numParts = 10_000;
        ByteSource byteSource = TestUtils.randomByteSource().slice(0, numParts);

        BlobMetadata blobMetadata = s3BlobStore.blobBuilder(blobName)
                .payload(new byte[0])  // fake payload to add content metadata
                .build()
                .getMetadata();
        MultipartUpload mpu = s3BlobStore.initiateMultipartUpload(
                containerName, blobMetadata);
        ImmutableList.Builder<MultipartPart> parts = ImmutableList.builder();

        for (int i = 0; i < numParts; ++i) {
            ByteSource partByteSource = byteSource.slice(i, 1);
            Payload payload = Payloads.newByteSourcePayload(partByteSource);
            payload.getContentMetadata().setContentLength(
                    partByteSource.size());
            parts.add(s3BlobStore.uploadMultipartPart(mpu, i + 1, payload));
        }

        s3BlobStore.completeMultipartUpload(mpu, parts.build());

        Blob newBlob = s3BlobStore.getBlob(containerName, blobName);
        try (InputStream actual = newBlob.getPayload().openStream();
                InputStream expected = byteSource.openStream()) {
            assertThat(actual).hasContentEqualTo(expected);
        }
    }

    @Test
    public void testCopyObjectPreserveMetadata() throws Exception {
        String fromName = "from-name";
        String toName = "to-name";
        String contentDisposition = "attachment; filename=old.jpg";
        String contentEncoding = "gzip";
        String contentLanguage = "en";
        String contentType = "audio/ogg";
        Map<String, String> userMetadata = ImmutableMap.of(
                "key1", "value1",
                "key2", "value2");
        Blob fromBlob = s3BlobStore.blobBuilder(fromName)
                .payload(BYTE_SOURCE)
                .contentLength(BYTE_SOURCE.size())
                .contentDisposition(contentDisposition)
                .contentEncoding(contentEncoding)
                .contentLanguage(contentLanguage)
                .contentType(contentType)
                // TODO: expires
                .userMetadata(userMetadata)
                .build();
        s3BlobStore.putBlob(containerName, fromBlob);

        s3BlobStore.copyBlob(containerName, fromName, containerName, toName,
                CopyOptions.NONE);

        Blob toBlob = s3BlobStore.getBlob(containerName, toName);
        try (InputStream actual = toBlob.getPayload().openStream();
                InputStream expected = BYTE_SOURCE.openStream()) {
            assertThat(actual).hasContentEqualTo(expected);
        }
        ContentMetadata contentMetadata =
                toBlob.getMetadata().getContentMetadata();
        assertThat(contentMetadata.getContentDisposition()).isEqualTo(
                contentDisposition);
        assertThat(contentMetadata.getContentEncoding()).isEqualTo(
                contentEncoding);
        if (!SWIFT_BLOBSTORES.contains(blobStoreType)) {
            assertThat(contentMetadata.getContentLanguage()).isEqualTo(
                    contentLanguage);
        }
        assertThat(contentMetadata.getContentType()).isEqualTo(
                contentType);
        // TODO: expires
        assertThat(toBlob.getMetadata().getUserMetadata()).isEqualTo(
                userMetadata);
    }

    @Test
    public void testCopyObjectReplaceMetadata() throws Exception {
        String fromName = "from-name";
        String toName = "to-name";
        Blob fromBlob = s3BlobStore.blobBuilder(fromName)
                .payload(BYTE_SOURCE)
                .contentLength(BYTE_SOURCE.size())
                .contentDisposition("attachment; filename=old.jpg")
                .contentEncoding("compress")
                .contentLanguage("en")
                .contentType("audio/ogg")
                // TODO: expires
                .userMetadata(ImmutableMap.of(
                        "key1", "value1",
                        "key2", "value2"))
                .build();
        s3BlobStore.putBlob(containerName, fromBlob);

        String contentDisposition = "attachment; filename=new.jpg";
        String contentEncoding = "gzip";
        String contentLanguage = "fr";
        String contentType = "audio/mp4";
        ContentMetadata contentMetadata = ContentMetadataBuilder.create()
                .contentDisposition(contentDisposition)
                .contentEncoding(contentEncoding)
                .contentLanguage(contentLanguage)
                .contentType(contentType)
                // TODO: expires
                .build();
        Map<String, String> userMetadata = ImmutableMap.of(
                "key3", "value3",
                "key4", "value4");
        s3BlobStore.copyBlob(containerName, fromName, containerName, toName,
                CopyOptions.builder()
                        .contentMetadata(contentMetadata)
                        .userMetadata(userMetadata)
                        .build());

        Blob toBlob = s3BlobStore.getBlob(containerName, toName);
        try (InputStream actual = toBlob.getPayload().openStream();
                InputStream expected = BYTE_SOURCE.openStream()) {
            assertThat(actual).hasContentEqualTo(expected);
        }
        ContentMetadata toContentMetadata =
                toBlob.getMetadata().getContentMetadata();
        assertThat(toContentMetadata.getContentDisposition()).isEqualTo(
                contentDisposition);
        assertThat(toContentMetadata.getContentEncoding()).isEqualTo(
                contentEncoding);
        if (!SWIFT_BLOBSTORES.contains(blobStoreType)) {
            assertThat(toContentMetadata.getContentLanguage()).isEqualTo(
                    contentLanguage);
        }
        assertThat(toContentMetadata.getContentType()).isEqualTo(
                contentType);
        // TODO: expires
        assertThat(toBlob.getMetadata().getUserMetadata()).isEqualTo(
                userMetadata);
    }

    @Test
    public void testConditionalGet() throws Exception {
        String blobName = "blob-name";
        Blob putBlob = s3BlobStore.blobBuilder(blobName)
                .payload(BYTE_SOURCE)
                .contentLength(BYTE_SOURCE.size())
                .build();
        String eTag = s3BlobStore.putBlob(containerName, putBlob);

        Blob getBlob = s3BlobStore.getBlob(containerName, blobName,
                new GetOptions().ifETagMatches(eTag));
        assertThat(getBlob.getPayload()).isNotNull();

        try {
            s3BlobStore.getBlob(containerName, blobName,
                    new GetOptions().ifETagDoesntMatch(eTag));
            Fail.failBecauseExceptionWasNotThrown(HttpResponseException.class);
        } catch (HttpResponseException hre) {
            assertThat(hre.getResponse().getStatusCode()).isEqualTo(
                    HttpServletResponse.SC_NOT_MODIFIED);
        }
    }

    @Test
    public void testUnknownParameter() throws Exception {
        final S3Client s3Client = s3Context.unwrapApi(S3Client.class);

        try {
            s3Client.disableBucketLogging(containerName);
            Fail.failBecauseExceptionWasNotThrown(AWSResponseException.class);
        } catch (AWSResponseException e) {
            assertThat(e.getError().getCode()).isEqualTo("NotImplemented");
        }
    }

    private static String createRandomContainerName() {
        return "s3proxy-" + new Random().nextInt(Integer.MAX_VALUE);
    }
}
