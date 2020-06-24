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
import static org.junit.Assume.assumeTrue;

import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import javax.annotation.Nullable;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import com.amazonaws.ClientConfiguration;
import com.amazonaws.HttpMethod;
import com.amazonaws.SDKGlobalConfiguration;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.client.builder.AwsClientBuilder.EndpointConfiguration;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.internal.SkipMd5CheckStrategy;
import com.amazonaws.services.s3.model.AbortMultipartUploadRequest;
import com.amazonaws.services.s3.model.AccessControlList;
import com.amazonaws.services.s3.model.AmazonS3Exception;
import com.amazonaws.services.s3.model.Bucket;
import com.amazonaws.services.s3.model.BucketLoggingConfiguration;
import com.amazonaws.services.s3.model.CannedAccessControlList;
import com.amazonaws.services.s3.model.CompleteMultipartUploadRequest;
import com.amazonaws.services.s3.model.CopyObjectRequest;
import com.amazonaws.services.s3.model.CopyPartRequest;
import com.amazonaws.services.s3.model.CopyPartResult;
import com.amazonaws.services.s3.model.DeleteObjectsRequest;
import com.amazonaws.services.s3.model.DeleteObjectsResult;
import com.amazonaws.services.s3.model.GeneratePresignedUrlRequest;
import com.amazonaws.services.s3.model.GetObjectRequest;
import com.amazonaws.services.s3.model.GroupGrantee;
import com.amazonaws.services.s3.model.HeadBucketRequest;
import com.amazonaws.services.s3.model.InitiateMultipartUploadRequest;
import com.amazonaws.services.s3.model.InitiateMultipartUploadResult;
import com.amazonaws.services.s3.model.ListMultipartUploadsRequest;
import com.amazonaws.services.s3.model.ListObjectsRequest;
import com.amazonaws.services.s3.model.ListObjectsV2Request;
import com.amazonaws.services.s3.model.ListObjectsV2Result;
import com.amazonaws.services.s3.model.ListPartsRequest;
import com.amazonaws.services.s3.model.MultipartUploadListing;
import com.amazonaws.services.s3.model.ObjectListing;
import com.amazonaws.services.s3.model.ObjectMetadata;
import com.amazonaws.services.s3.model.ObjectTagging;
import com.amazonaws.services.s3.model.PartETag;
import com.amazonaws.services.s3.model.PartListing;
import com.amazonaws.services.s3.model.Permission;
import com.amazonaws.services.s3.model.PutObjectRequest;
import com.amazonaws.services.s3.model.PutObjectResult;
import com.amazonaws.services.s3.model.ResponseHeaderOverrides;
import com.amazonaws.services.s3.model.S3Object;
import com.amazonaws.services.s3.model.S3ObjectSummary;
import com.amazonaws.services.s3.model.SetBucketLoggingConfigurationRequest;
import com.amazonaws.services.s3.model.Tag;
import com.amazonaws.services.s3.model.UploadPartRequest;
import com.amazonaws.services.s3.model.UploadPartResult;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Maps;
import com.google.common.io.ByteSource;
import com.google.common.io.ByteStreams;

import org.assertj.core.api.Fail;

import org.jclouds.ContextBuilder;
import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.BlobStoreContext;
import org.jclouds.rest.HttpClient;

import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

public final class AwsSdkTest {
    static {
        System.setProperty(
                SDKGlobalConfiguration.DISABLE_CERT_CHECKING_SYSTEM_PROPERTY,
                "true");
        disableSslVerification();
    }

    private static final ByteSource BYTE_SOURCE = ByteSource.wrap(new byte[1]);
    private static final ClientConfiguration V2_SIGNER_CONFIG =
            new ClientConfiguration().withSignerOverride("S3SignerType");
    private static final long MINIMUM_MULTIPART_SIZE = 5 * 1024 * 1024;

    private URI s3Endpoint;
    private EndpointConfiguration s3EndpointConfig;
    private S3Proxy s3Proxy;
    private BlobStoreContext context;
    private String blobStoreType;
    private String containerName;
    private AWSCredentials awsCreds;
    private AmazonS3 client;
    private String servicePath;

    @Before
    public void setUp() throws Exception {
        TestUtils.S3ProxyLaunchInfo info = TestUtils.startS3Proxy(
                "s3proxy.conf");
        awsCreds = new BasicAWSCredentials(info.getS3Identity(),
                info.getS3Credential());
        context = info.getBlobStore().getContext();
        s3Proxy = info.getS3Proxy();
        s3Endpoint = info.getSecureEndpoint();
        servicePath = info.getServicePath();
        s3EndpointConfig = new EndpointConfiguration(
                s3Endpoint.toString() + servicePath, "us-east-1");
        client = AmazonS3ClientBuilder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(awsCreds))
                .withEndpointConfiguration(s3EndpointConfig)
                .build();

        containerName = createRandomContainerName();
        info.getBlobStore().createContainerInLocation(null, containerName);

        blobStoreType = context.unwrap().getProviderMetadata().getId();
        if (Quirks.OPAQUE_ETAG.contains(blobStoreType)) {
            System.setProperty(
                    SkipMd5CheckStrategy
                            .DISABLE_GET_OBJECT_MD5_VALIDATION_PROPERTY,
                    "true");
            System.setProperty(
                    SkipMd5CheckStrategy
                            .DISABLE_PUT_OBJECT_MD5_VALIDATION_PROPERTY,
                    "true");
        }
    }

    @After
    public void tearDown() throws Exception {
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
        if (context != null) {
            context.getBlobStore().deleteContainer(containerName);
            context.close();
        }
    }

    @Test
    public void testAwsV2Signature() throws Exception {
        client = AmazonS3ClientBuilder.standard()
                .withClientConfiguration(V2_SIGNER_CONFIG)
                .withCredentials(new AWSStaticCredentialsProvider(awsCreds))
                .withEndpointConfiguration(s3EndpointConfig)
                .build();

        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentLength(BYTE_SOURCE.size());
        client.putObject(containerName, "foo", BYTE_SOURCE.openStream(),
                metadata);

        S3Object object = client.getObject(containerName, "foo");
        assertThat(object.getObjectMetadata().getContentLength()).isEqualTo(
                BYTE_SOURCE.size());
        try (InputStream actual = object.getObjectContent();
                InputStream expected = BYTE_SOURCE.openStream()) {
            assertThat(actual).hasContentEqualTo(expected);
        }
    }

    @Test
    public void testAwsV2SignatureWithOverrideParameters() throws Exception {
        client = AmazonS3ClientBuilder.standard()
                .withClientConfiguration(V2_SIGNER_CONFIG)
                .withCredentials(new AWSStaticCredentialsProvider(awsCreds))
                .withEndpointConfiguration(s3EndpointConfig).build();

        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentLength(BYTE_SOURCE.size());
        client.putObject(containerName, "foo", BYTE_SOURCE.openStream(),
                metadata);

        String blobName = "foo";

        ResponseHeaderOverrides headerOverride = new ResponseHeaderOverrides();

        String expectedContentDisposition = "attachment; " + blobName;
        headerOverride.setContentDisposition(expectedContentDisposition);

        String expectedContentType = "text/plain";
        headerOverride.setContentType(expectedContentType);

        GetObjectRequest request = new GetObjectRequest(containerName,
                blobName);
        request.setResponseHeaders(headerOverride);

        S3Object object = client.getObject(request);
        assertThat(object.getObjectMetadata().getContentLength()).isEqualTo(
                BYTE_SOURCE.size());
        assertThat(object.getObjectMetadata().getContentDisposition())
                .isEqualTo(expectedContentDisposition);
        assertThat(object.getObjectMetadata().getContentType()).isEqualTo(
                expectedContentType);
        try (InputStream actual = object.getObjectContent();
             InputStream expected = BYTE_SOURCE.openStream()) {
            assertThat(actual).hasContentEqualTo(expected);
        }
    }

    @Test
    public void testAwsV4Signature() throws Exception {
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentLength(BYTE_SOURCE.size());
        client.putObject(containerName, "foo",
                BYTE_SOURCE.openStream(), metadata);

        S3Object object = client.getObject(containerName, "foo");
        assertThat(object.getObjectMetadata().getContentLength()).isEqualTo(
                BYTE_SOURCE.size());
        try (InputStream actual = object.getObjectContent();
                InputStream expected = BYTE_SOURCE.openStream()) {
            assertThat(actual).hasContentEqualTo(expected);
        }
    }

    @Test
    public void testAwsV4SignatureNonChunked() throws Exception {
        client = AmazonS3ClientBuilder.standard()
                .withChunkedEncodingDisabled(true)
                .withCredentials(new AWSStaticCredentialsProvider(awsCreds))
                .withEndpointConfiguration(s3EndpointConfig)
                .build();

        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentLength(BYTE_SOURCE.size());
        client.putObject(containerName, "foo",
                BYTE_SOURCE.openStream(), metadata);

        S3Object object = client.getObject(containerName, "foo");
        assertThat(object.getObjectMetadata().getContentLength()).isEqualTo(
                BYTE_SOURCE.size());
        try (InputStream actual = object.getObjectContent();
                InputStream expected = BYTE_SOURCE.openStream()) {
            assertThat(actual).hasContentEqualTo(expected);
        }
    }

    @Test
    public void testAwsV4SignaturePayloadUnsigned() throws Exception {
        client = AmazonS3ClientBuilder.standard()
                .withChunkedEncodingDisabled(true)
                .withPayloadSigningEnabled(false)
                .withCredentials(new AWSStaticCredentialsProvider(awsCreds))
                .withEndpointConfiguration(s3EndpointConfig)
                .build();

        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentLength(BYTE_SOURCE.size());
        client.putObject(containerName, "foo",
                BYTE_SOURCE.openStream(), metadata);

        S3Object object = client.getObject(containerName, "foo");
        assertThat(object.getObjectMetadata().getContentLength()).isEqualTo(
                BYTE_SOURCE.size());
        try (InputStream actual = object.getObjectContent();
                InputStream expected = BYTE_SOURCE.openStream()) {
            assertThat(actual).hasContentEqualTo(expected);
        }
    }

    @Test
    public void testAwsV4SignatureBadIdentity() throws Exception {
        client = AmazonS3ClientBuilder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(
                        new BasicAWSCredentials(
                                "bad-access-key", awsCreds.getAWSSecretKey())))
                .withEndpointConfiguration(s3EndpointConfig)
                .build();

        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentLength(BYTE_SOURCE.size());

        try {
            client.putObject(containerName, "foo",
                    BYTE_SOURCE.openStream(), metadata);
            Fail.failBecauseExceptionWasNotThrown(AmazonS3Exception.class);
        } catch (AmazonS3Exception e) {
            assertThat(e.getErrorCode()).isEqualTo("InvalidAccessKeyId");
        }
    }

    @Test
    public void testAwsV4SignatureBadCredential() throws Exception {
        client = AmazonS3ClientBuilder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(
                        new BasicAWSCredentials(
                                awsCreds.getAWSAccessKeyId(),
                                "bad-secret-key")))
                .withEndpointConfiguration(s3EndpointConfig)
                .build();

        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentLength(BYTE_SOURCE.size());

        try {
            client.putObject(containerName, "foo",
                    BYTE_SOURCE.openStream(), metadata);
            Fail.failBecauseExceptionWasNotThrown(AmazonS3Exception.class);
        } catch (AmazonS3Exception e) {
            assertThat(e.getErrorCode()).isEqualTo("SignatureDoesNotMatch");
        }
    }

    @Test
    public void testAwsV2UrlSigning() throws Exception {
        client = AmazonS3ClientBuilder.standard()
                .withClientConfiguration(V2_SIGNER_CONFIG)
                .withCredentials(new AWSStaticCredentialsProvider(awsCreds))
                .withEndpointConfiguration(s3EndpointConfig)
                .build();

        String blobName = "foo";
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentLength(BYTE_SOURCE.size());
        client.putObject(containerName, blobName, BYTE_SOURCE.openStream(),
                metadata);

        Date expiration = new Date(System.currentTimeMillis() +
                TimeUnit.HOURS.toMillis(1));
        URL url = client.generatePresignedUrl(containerName, blobName,
                expiration, HttpMethod.GET);
        try (InputStream actual = url.openStream();
                InputStream expected = BYTE_SOURCE.openStream()) {
            assertThat(actual).hasContentEqualTo(expected);
        }
    }

    @Test
    public void testAwsV2UrlSigningWithOverrideParameters() throws Exception {
        client = AmazonS3ClientBuilder.standard()
                .withClientConfiguration(V2_SIGNER_CONFIG)
                .withCredentials(new AWSStaticCredentialsProvider(awsCreds))
                .withEndpointConfiguration(s3EndpointConfig).build();

        String blobName = "foo";
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentLength(BYTE_SOURCE.size());
        client.putObject(containerName, blobName, BYTE_SOURCE.openStream(),
                metadata);

        GeneratePresignedUrlRequest generatePresignedUrlRequest =
                new GeneratePresignedUrlRequest(containerName, blobName);
        generatePresignedUrlRequest.setMethod(HttpMethod.GET);

        ResponseHeaderOverrides headerOverride = new ResponseHeaderOverrides();

        headerOverride.setContentDisposition("attachment; " + blobName);
        headerOverride.setContentType("text/plain");
        generatePresignedUrlRequest.setResponseHeaders(headerOverride);

        Date expiration = new Date(System.currentTimeMillis() +
                TimeUnit.HOURS.toMillis(1));
        generatePresignedUrlRequest.setExpiration(expiration);

        URL url = client.generatePresignedUrl(generatePresignedUrlRequest);
        URLConnection connection =  url.openConnection();
        try (InputStream actual = connection.getInputStream();
             InputStream expected = BYTE_SOURCE.openStream()) {

            String value = connection.getHeaderField("Content-Disposition");
            assertThat(value).isEqualTo(headerOverride.getContentDisposition());

            value = connection.getHeaderField("Content-Type");
            assertThat(value).isEqualTo(headerOverride.getContentType());

            assertThat(actual).hasContentEqualTo(expected);
        }
    }

    @Test
    public void testAwsV4UrlSigning() throws Exception {
        String blobName = "foo";
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentLength(BYTE_SOURCE.size());
        client.putObject(containerName, blobName, BYTE_SOURCE.openStream(),
                metadata);

        Date expiration = new Date(System.currentTimeMillis() +
                TimeUnit.HOURS.toMillis(1));
        URL url = client.generatePresignedUrl(containerName, blobName,
                expiration, HttpMethod.GET);
        try (InputStream actual = url.openStream();
                InputStream expected = BYTE_SOURCE.openStream()) {
            assertThat(actual).hasContentEqualTo(expected);
        }
    }

    @Test
    public void testMultipartCopy() throws Exception {
        // B2 requires two parts to issue an MPU
        assumeTrue(!blobStoreType.equals("b2"));

        String sourceBlobName = "testMultipartCopy-source";
        String targetBlobName = "testMultipartCopy-target";

        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentLength(BYTE_SOURCE.size());
        client.putObject(containerName, sourceBlobName,
                BYTE_SOURCE.openStream(), metadata);

        InitiateMultipartUploadRequest initiateRequest =
                new InitiateMultipartUploadRequest(containerName,
                        targetBlobName);
        InitiateMultipartUploadResult initResult =
                client.initiateMultipartUpload(initiateRequest);
        String uploadId = initResult.getUploadId();

        CopyPartRequest copyRequest = new CopyPartRequest()
                .withDestinationBucketName(containerName)
                .withDestinationKey(targetBlobName)
                .withSourceBucketName(containerName)
                .withSourceKey(sourceBlobName)
                .withUploadId(uploadId)
                .withFirstByte(0L)
                .withLastByte(BYTE_SOURCE.size() - 1)
                .withPartNumber(1);
        CopyPartResult copyPartResult = client.copyPart(copyRequest);

        CompleteMultipartUploadRequest completeRequest =
                new CompleteMultipartUploadRequest(
                        containerName, targetBlobName, uploadId,
                        ImmutableList.of(copyPartResult.getPartETag()));
        client.completeMultipartUpload(completeRequest);

        S3Object object = client.getObject(containerName, targetBlobName);
        assertThat(object.getObjectMetadata().getContentLength()).isEqualTo(
                BYTE_SOURCE.size());
        try (InputStream actual = object.getObjectContent();
                InputStream expected = BYTE_SOURCE.openStream()) {
            assertThat(actual).hasContentEqualTo(expected);
        }
    }

    @Test
    public void testBigMultipartUpload() throws Exception {
        String key = "multipart-upload";
        long partSize = MINIMUM_MULTIPART_SIZE;
        long size = partSize + 1;
        ByteSource byteSource = TestUtils.randomByteSource().slice(0, size);

        InitiateMultipartUploadRequest initRequest =
                new InitiateMultipartUploadRequest(containerName, key);
        InitiateMultipartUploadResult initResponse =
                client.initiateMultipartUpload(initRequest);
        String uploadId = initResponse.getUploadId();

        ByteSource byteSource1 = byteSource.slice(0, partSize);
        UploadPartRequest uploadRequest1 = new UploadPartRequest()
                .withBucketName(containerName)
                .withKey(key)
                .withUploadId(uploadId)
                .withPartNumber(1)
                .withInputStream(byteSource1.openStream())
                .withPartSize(byteSource1.size());
        uploadRequest1.getRequestClientOptions().setReadLimit(
                (int) byteSource1.size());
        UploadPartResult uploadPartResult1 = client.uploadPart(uploadRequest1);

        ByteSource byteSource2 = byteSource.slice(partSize, size - partSize);
        UploadPartRequest uploadRequest2 = new UploadPartRequest()
                .withBucketName(containerName)
                .withKey(key)
                .withUploadId(uploadId)
                .withPartNumber(2)
                .withInputStream(byteSource2.openStream())
                .withPartSize(byteSource2.size());
        uploadRequest2.getRequestClientOptions().setReadLimit(
                (int) byteSource2.size());
        UploadPartResult uploadPartResult2 = client.uploadPart(uploadRequest2);

        CompleteMultipartUploadRequest completeRequest =
                new CompleteMultipartUploadRequest(
                        containerName, key, uploadId,
                        ImmutableList.of(
                                uploadPartResult1.getPartETag(),
                                uploadPartResult2.getPartETag()));
        client.completeMultipartUpload(completeRequest);

        S3Object object = client.getObject(containerName, key);
        assertThat(object.getObjectMetadata().getContentLength()).isEqualTo(
                size);
        try (InputStream actual = object.getObjectContent();
                InputStream expected = byteSource.openStream()) {
            assertThat(actual).hasContentEqualTo(expected);
        }
    }

    // TODO: testMultipartUploadConditionalCopy

    @Test
    public void testUpdateBlobXmlAcls() throws Exception {
        assumeTrue(!Quirks.NO_BLOB_ACCESS_CONTROL.contains(blobStoreType));
        String blobName = "testUpdateBlobXmlAcls-blob";
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentLength(BYTE_SOURCE.size());
        client.putObject(containerName, blobName, BYTE_SOURCE.openStream(),
                metadata);
        AccessControlList acl = client.getObjectAcl(containerName, blobName);

        acl.grantPermission(GroupGrantee.AllUsers, Permission.Read);
        client.setObjectAcl(containerName, blobName, acl);
        assertThat(client.getObjectAcl(containerName, blobName)).isEqualTo(acl);

        acl.revokeAllPermissions(GroupGrantee.AllUsers);
        client.setObjectAcl(containerName, blobName, acl);
        assertThat(client.getObjectAcl(containerName, blobName)).isEqualTo(acl);

        acl.grantPermission(GroupGrantee.AllUsers, Permission.Write);
        try {
            client.setObjectAcl(containerName, blobName, acl);
            Fail.failBecauseExceptionWasNotThrown(AmazonS3Exception.class);
        } catch (AmazonS3Exception e) {
            assertThat(e.getErrorCode()).isEqualTo("NotImplemented");
        }
    }

    @Test
    public void testUnicodeObject() throws Exception {
        String blobName = "ŪņЇЌœđЗ/☺ unicode € rocks ™";
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentLength(BYTE_SOURCE.size());
        client.putObject(containerName, blobName, BYTE_SOURCE.openStream(),
                metadata);

        metadata = client.getObjectMetadata(containerName, blobName);
        assertThat(metadata).isNotNull();

        ObjectListing listing = client.listObjects(containerName);
        List<S3ObjectSummary> summaries = listing.getObjectSummaries();
        assertThat(summaries).hasSize(1);
        S3ObjectSummary summary = summaries.iterator().next();
        assertThat(summary.getKey()).isEqualTo(blobName);
    }

    @Test
    public void testSpecialCharacters() throws Exception {
        String prefix = "special !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
        if (blobStoreType.equals("azureblob") || blobStoreType.equals("b2")) {
            prefix = prefix.replace("\\", "");
        }
        if (blobStoreType.equals("azureblob")) {
            // Avoid blob names that end with a dot (.), a forward slash (/), or
            // a sequence or combination of the two.
            prefix = prefix.replace("./", "/") + ".";
        }
        String blobName = prefix + "foo";
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentLength(BYTE_SOURCE.size());
        client.putObject(containerName, blobName, BYTE_SOURCE.openStream(),
                metadata);

        ObjectListing listing = client.listObjects(new ListObjectsRequest()
                .withBucketName(containerName)
                .withPrefix(prefix));
        List<S3ObjectSummary> summaries = listing.getObjectSummaries();
        assertThat(summaries).hasSize(1);
        S3ObjectSummary summary = summaries.iterator().next();
        assertThat(summary.getKey()).isEqualTo(blobName);
    }

    @Test
    public void testAtomicMpuAbort() throws Exception {
        String key = "testAtomicMpuAbort";
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentLength(BYTE_SOURCE.size());
        client.putObject(containerName, key, BYTE_SOURCE.openStream(),
                metadata);

        InitiateMultipartUploadRequest initRequest =
                new InitiateMultipartUploadRequest(containerName, key);
        InitiateMultipartUploadResult initResponse =
                client.initiateMultipartUpload(initRequest);
        String uploadId = initResponse.getUploadId();

        client.abortMultipartUpload(new AbortMultipartUploadRequest(
                    containerName, key, uploadId));

        S3Object object = client.getObject(containerName, key);
        assertThat(object.getObjectMetadata().getContentLength()).isEqualTo(
                BYTE_SOURCE.size());
        try (InputStream actual = object.getObjectContent();
                InputStream expected = BYTE_SOURCE.openStream()) {
            assertThat(actual).hasContentEqualTo(expected);
        }
    }

    @Test
    public void testOverrideResponseHeader() throws Exception {
        String blobName = "foo";
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentLength(BYTE_SOURCE.size());
        client.putObject(containerName, blobName, BYTE_SOURCE.openStream(),
                metadata);

        String cacheControl = "no-cache";
        String contentDisposition = "attachment; filename=foo.html";
        String contentEncoding = "gzip";
        String contentLanguage = "en";
        String contentType = "text/html; charset=UTF-8";
        String expires = "Wed, 13 Jul 2016 21:23:51 GMT";
        long expiresTime = 1468445031000L;

        GetObjectRequest getObjectRequest = new GetObjectRequest(containerName,
                blobName);
        getObjectRequest.setResponseHeaders(
                new ResponseHeaderOverrides()
                    .withCacheControl(cacheControl)
                    .withContentDisposition(contentDisposition)
                    .withContentEncoding(contentEncoding)
                    .withContentLanguage(contentLanguage)
                    .withContentType(contentType)
                    .withExpires(expires));
        S3Object object = client.getObject(getObjectRequest);
        try (InputStream is = object.getObjectContent()) {
            assertThat(is).isNotNull();
            ByteStreams.copy(is, ByteStreams.nullOutputStream());
        }

        ObjectMetadata reponseMetadata = object.getObjectMetadata();
        assertThat(reponseMetadata.getCacheControl()).isEqualTo(
                cacheControl);
        assertThat(reponseMetadata.getContentDisposition()).isEqualTo(
                contentDisposition);
        assertThat(reponseMetadata.getContentEncoding()).isEqualTo(
                contentEncoding);
        assertThat(reponseMetadata.getContentLanguage()).isEqualTo(
                contentLanguage);
        assertThat(reponseMetadata.getContentType()).isEqualTo(
                contentType);
        assertThat(reponseMetadata.getHttpExpiresDate().getTime())
            .isEqualTo(expiresTime);
    }

    @Test
    public void testDeleteMultipleObjectsEmpty() throws Exception {
        DeleteObjectsRequest request = new DeleteObjectsRequest(containerName)
                .withKeys();

        try {
            client.deleteObjects(request);
            Fail.failBecauseExceptionWasNotThrown(AmazonS3Exception.class);
        } catch (AmazonS3Exception e) {
            assertThat(e.getErrorCode()).isEqualTo("MalformedXML");
        }
    }

    @Test
    public void testDeleteMultipleObjects() throws Exception {
        String blobName = "foo";
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentLength(BYTE_SOURCE.size());

        DeleteObjectsRequest request = new DeleteObjectsRequest(containerName)
                .withKeys(blobName);

        // without quiet
        client.putObject(containerName, blobName, BYTE_SOURCE.openStream(),
                metadata);

        DeleteObjectsResult result = client.deleteObjects(request);
        assertThat(result.getDeletedObjects()).hasSize(1);
        assertThat(result.getDeletedObjects().iterator().next().getKey())
                .isEqualTo(blobName);

        // with quiet
        client.putObject(containerName, blobName, BYTE_SOURCE.openStream(),
                metadata);

        result = client.deleteObjects(request.withQuiet(true));
        assertThat(result.getDeletedObjects()).isEmpty();
    }

    @Test
    public void testPartNumberMarker() throws Exception {
        String blobName = "foo";
        InitiateMultipartUploadResult result = client.initiateMultipartUpload(
                new InitiateMultipartUploadRequest(containerName, blobName));
        ListPartsRequest request = new ListPartsRequest(containerName,
                blobName, result.getUploadId());

        client.listParts(request.withPartNumberMarker(0));

        try {
            client.listParts(request.withPartNumberMarker(1));
            Fail.failBecauseExceptionWasNotThrown(AmazonS3Exception.class);
        } catch (AmazonS3Exception e) {
            assertThat(e.getErrorCode()).isEqualTo("NotImplemented");
        }
    }

    @Test
    public void testHttpClient() throws Exception {
        String blobName = "blob-name";
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentLength(BYTE_SOURCE.size());
        client.putObject(containerName, blobName, BYTE_SOURCE.openStream(),
                metadata);

        if (Quirks.NO_BLOB_ACCESS_CONTROL.contains(blobStoreType)) {
            client.setBucketAcl(containerName,
                    CannedAccessControlList.PublicRead);
        } else {
            client.setObjectAcl(containerName, blobName,
                    CannedAccessControlList.PublicRead);
        }

        HttpClient httpClient = context.utils().http();
        URI uri = new URI(s3Endpoint.getScheme(), s3Endpoint.getUserInfo(),
                s3Endpoint.getHost(), s3Proxy.getSecurePort(),
                servicePath + "/" + containerName + "/" + blobName,
                /*query=*/ null, /*fragment=*/ null);
        try (InputStream actual = httpClient.get(uri);
             InputStream expected = BYTE_SOURCE.openStream()) {
            assertThat(actual).hasContentEqualTo(expected);
        }
    }

    @Test
    public void testListBuckets() throws Exception {
        ImmutableList.Builder<String> builder = ImmutableList.builder();
        for (Bucket bucket : client.listBuckets()) {
            builder.add(bucket.getName());
        }
        assertThat(builder.build()).contains(containerName);
    }

    @Test
    public void testContainerExists() throws Exception {
        client.headBucket(new HeadBucketRequest(containerName));
        try {
            client.headBucket(new HeadBucketRequest(
                    createRandomContainerName()));
            Fail.failBecauseExceptionWasNotThrown(AmazonS3Exception.class);
        } catch (AmazonS3Exception e) {
            assertThat(e.getErrorCode()).isEqualTo("404 Not Found");
        }
    }

    @Test
    public void testContainerCreateDelete() throws Exception {
        String containerName2 = createRandomContainerName();
        client.createBucket(containerName2);
        try {
            client.createBucket(containerName2);
            client.deleteBucket(containerName2);
            Fail.failBecauseExceptionWasNotThrown(AmazonS3Exception.class);
        } catch (AmazonS3Exception e) {
            assertThat(e.getErrorCode()).isEqualTo("BucketAlreadyOwnedByYou");
        }
    }

    @Test
    public void testContainerDelete() throws Exception {
        client.headBucket(new HeadBucketRequest(containerName));
        client.deleteBucket(containerName);
        try {
            client.headBucket(new HeadBucketRequest(containerName));
            Fail.failBecauseExceptionWasNotThrown(AmazonS3Exception.class);
        } catch (AmazonS3Exception e) {
            assertThat(e.getErrorCode()).isEqualTo("404 Not Found");
        }
    }

    private void putBlobAndCheckIt(String blobName) throws Exception {
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentLength(BYTE_SOURCE.size());

        client.putObject(containerName, blobName, BYTE_SOURCE.openStream(),
                metadata);

        S3Object object = client.getObject(containerName, blobName);
        try (InputStream actual = object.getObjectContent();
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
        ObjectListing listing = client.listObjects(containerName);
        assertThat(listing.getObjectSummaries()).isEmpty();

        putBlobAndCheckIt("blob%");

        listing = client.listObjects(containerName);
        assertThat(listing.getObjectSummaries()).hasSize(1);
        assertThat(listing.getObjectSummaries().iterator().next().getKey())
                .isEqualTo("blob%");
    }

    @Test
    public void testBlobList() throws Exception {
        ObjectListing listing = client.listObjects(containerName);
        assertThat(listing.getObjectSummaries()).isEmpty();

        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentLength(BYTE_SOURCE.size());

        ImmutableList.Builder<String> builder = ImmutableList.builder();
        client.putObject(containerName, "blob1", BYTE_SOURCE.openStream(),
                metadata);
        listing = client.listObjects(containerName);
        for (S3ObjectSummary summary : listing.getObjectSummaries()) {
            builder.add(summary.getKey());
        }
        assertThat(builder.build()).containsOnly("blob1");

        builder = ImmutableList.builder();
        client.putObject(containerName, "blob2", BYTE_SOURCE.openStream(),
                metadata);
        listing = client.listObjects(containerName);
        for (S3ObjectSummary summary : listing.getObjectSummaries()) {
            builder.add(summary.getKey());
        }
        assertThat(builder.build()).containsOnly("blob1", "blob2");
    }

    @Test
    public void testBlobListRecursive() throws Exception {
        ObjectListing listing = client.listObjects(containerName);
        assertThat(listing.getObjectSummaries()).isEmpty();

        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentLength(BYTE_SOURCE.size());
        client.putObject(containerName, "prefix/blob1",
                BYTE_SOURCE.openStream(), metadata);
        client.putObject(containerName, "prefix/blob2",
                BYTE_SOURCE.openStream(), metadata);

        ImmutableList.Builder<String> builder = ImmutableList.builder();
        listing = client.listObjects(new ListObjectsRequest()
                .withBucketName(containerName)
                .withDelimiter("/"));
        assertThat(listing.getObjectSummaries()).isEmpty();
        for (String prefix : listing.getCommonPrefixes()) {
            builder.add(prefix);
        }
        assertThat(builder.build()).containsOnly("prefix/");

        builder = ImmutableList.builder();
        listing = client.listObjects(containerName);
        for (S3ObjectSummary summary : listing.getObjectSummaries()) {
            builder.add(summary.getKey());
        }
        assertThat(builder.build()).containsOnly("prefix/blob1",
                "prefix/blob2");
        assertThat(listing.getCommonPrefixes()).isEmpty();
    }

    @Test
    public void testBlobListRecursiveImplicitMarker() throws Exception {
        ObjectListing listing = client.listObjects(containerName);
        assertThat(listing.getObjectSummaries()).isEmpty();

        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentLength(BYTE_SOURCE.size());
        client.putObject(containerName, "blob1", BYTE_SOURCE.openStream(),
                metadata);
        client.putObject(containerName, "blob2", BYTE_SOURCE.openStream(),
                metadata);

        listing = client.listObjects(new ListObjectsRequest()
                .withBucketName(containerName)
                .withMaxKeys(1));
        assertThat(listing.getObjectSummaries()).hasSize(1);
        assertThat(listing.getObjectSummaries().iterator().next().getKey())
                .isEqualTo("blob1");

        listing = client.listObjects(new ListObjectsRequest()
                .withBucketName(containerName)
                .withMaxKeys(1)
                .withMarker("blob1"));
        assertThat(listing.getObjectSummaries()).hasSize(1);
        assertThat(listing.getObjectSummaries().iterator().next().getKey())
                .isEqualTo("blob2");
    }

    @Test
    public void testBlobListV2() throws Exception {
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentLength(BYTE_SOURCE.size());
        for (int i = 1; i < 5; ++i) {
            client.putObject(containerName, String.valueOf(i),
                    BYTE_SOURCE.openStream(), metadata);
        }

        ListObjectsV2Result result = client.listObjectsV2(
                new ListObjectsV2Request()
                .withBucketName(containerName)
                .withMaxKeys(1)
                .withStartAfter("1"));
        assertThat(result.getContinuationToken()).isEmpty();
        assertThat(result.getStartAfter()).isEqualTo("1");
        assertThat(result.getNextContinuationToken()).isEqualTo("2");
        assertThat(result.isTruncated()).isTrue();
        assertThat(result.getObjectSummaries()).hasSize(1);
        assertThat(result.getObjectSummaries().get(0).getKey()).isEqualTo("2");

        result = client.listObjectsV2(
                new ListObjectsV2Request()
                .withBucketName(containerName)
                .withMaxKeys(1)
                .withContinuationToken(result.getNextContinuationToken()));
        assertThat(result.getContinuationToken()).isEqualTo("2");
        assertThat(result.getStartAfter()).isEmpty();
        assertThat(result.getNextContinuationToken()).isEqualTo("3");
        assertThat(result.isTruncated()).isTrue();
        assertThat(result.getObjectSummaries()).hasSize(1);
        assertThat(result.getObjectSummaries().get(0).getKey()).isEqualTo("3");

        result = client.listObjectsV2(
                new ListObjectsV2Request()
                .withBucketName(containerName)
                .withMaxKeys(1)
                .withContinuationToken(result.getNextContinuationToken()));
        assertThat(result.getContinuationToken()).isEqualTo("3");
        assertThat(result.getStartAfter()).isEmpty();
        assertThat(result.getNextContinuationToken()).isNull();
        assertThat(result.isTruncated()).isFalse();
        assertThat(result.getObjectSummaries()).hasSize(1);
        assertThat(result.getObjectSummaries().get(0).getKey()).isEqualTo("4");
    }

    @Test
    public void testBlobMetadata() throws Exception {
        String blobName = "blob";
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentLength(BYTE_SOURCE.size());
        client.putObject(containerName, blobName, BYTE_SOURCE.openStream(),
                metadata);

        ObjectMetadata newMetadata = client.getObjectMetadata(containerName,
                blobName);
        assertThat(newMetadata.getContentLength())
                .isEqualTo(BYTE_SOURCE.size());
    }

    @Test
    public void testBlobRemove() throws Exception {
        String blobName = "blob";
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentLength(BYTE_SOURCE.size());
        client.putObject(containerName, blobName, BYTE_SOURCE.openStream(),
                metadata);
        assertThat(client.getObjectMetadata(containerName, blobName))
                .isNotNull();

        client.deleteObject(containerName, blobName);
        try {
            client.getObjectMetadata(containerName, blobName);
            Fail.failBecauseExceptionWasNotThrown(AmazonS3Exception.class);
        } catch (AmazonS3Exception e) {
            assertThat(e.getErrorCode()).isEqualTo("404 Not Found");
        }

        client.deleteObject(containerName, blobName);
    }

    @Test
    public void testSinglepartUpload() throws Exception {
        String blobName = "singlepart-upload";
        String cacheControl = "max-age=3600";
        String contentDisposition = "attachment; filename=new.jpg";
        String contentEncoding = "gzip";
        String contentLanguage = "fr";
        String contentType = "audio/mp4";
        Map<String, String> userMetadata = ImmutableMap.of(
                "key1", "value1",
                "key2", "value2");
        ObjectMetadata metadata = new ObjectMetadata();
        if (!Quirks.NO_CACHE_CONTROL_SUPPORT.contains(blobStoreType)) {
            metadata.setCacheControl(cacheControl);
        }
        if (!Quirks.NO_CONTENT_DISPOSITION.contains(blobStoreType)) {
            metadata.setContentDisposition(contentDisposition);
        }
        if (!Quirks.NO_CONTENT_ENCODING.contains(blobStoreType)) {
            metadata.setContentEncoding(contentEncoding);
        }
        if (!Quirks.NO_CONTENT_LANGUAGE.contains(blobStoreType)) {
            metadata.setContentLanguage(contentLanguage);
        }
        metadata.setContentLength(BYTE_SOURCE.size());
        metadata.setContentType(contentType);
        // TODO: expires
        metadata.setUserMetadata(userMetadata);

        client.putObject(containerName, blobName, BYTE_SOURCE.openStream(),
                metadata);

        S3Object object = client.getObject(containerName, blobName);
        try (InputStream actual = object.getObjectContent();
                InputStream expected = BYTE_SOURCE.openStream()) {
            assertThat(actual).hasContentEqualTo(expected);
        }
        ObjectMetadata newContentMetadata = object.getObjectMetadata();
        if (!Quirks.NO_CACHE_CONTROL_SUPPORT.contains(blobStoreType)) {
            assertThat(newContentMetadata.getCacheControl()).isEqualTo(
                    cacheControl);
        }
        if (!Quirks.NO_CONTENT_DISPOSITION.contains(blobStoreType)) {
            assertThat(newContentMetadata.getContentDisposition()).isEqualTo(
                    contentDisposition);
        }
        if (!Quirks.NO_CONTENT_ENCODING.contains(blobStoreType)) {
            assertThat(newContentMetadata.getContentEncoding()).isEqualTo(
                    contentEncoding);
        }
        if (!Quirks.NO_CONTENT_LANGUAGE.contains(blobStoreType)) {
            assertThat(newContentMetadata.getContentLanguage()).isEqualTo(
                    contentLanguage);
        }
        assertThat(newContentMetadata.getContentType()).isEqualTo(
                contentType);
        // TODO: expires
        assertThat(newContentMetadata.getUserMetadata()).isEqualTo(
                userMetadata);
    }

    // TODO: fails for GCS (jclouds not implemented)
    @Test
    public void testMultipartUpload() throws Exception {
        String blobName = "multipart-upload";
        String cacheControl = "max-age=3600";
        String contentDisposition = "attachment; filename=new.jpg";
        String contentEncoding = "gzip";
        String contentLanguage = "fr";
        String contentType = "audio/mp4";
        Map<String, String> userMetadata = ImmutableMap.of(
                "key1", "value1",
                "key2", "value2");
        ObjectMetadata metadata = new ObjectMetadata();
        if (!Quirks.NO_CACHE_CONTROL_SUPPORT.contains(blobStoreType)) {
            metadata.setCacheControl(cacheControl);
        }
        if (!Quirks.NO_CONTENT_DISPOSITION.contains(blobStoreType)) {
            metadata.setContentDisposition(contentDisposition);
        }
        if (!Quirks.NO_CONTENT_ENCODING.contains(blobStoreType)) {
            metadata.setContentEncoding(contentEncoding);
        }
        if (!Quirks.NO_CONTENT_LANGUAGE.contains(blobStoreType)) {
            metadata.setContentLanguage(contentLanguage);
        }
        metadata.setContentType(contentType);
        // TODO: expires
        metadata.setUserMetadata(userMetadata);
        InitiateMultipartUploadResult result = client.initiateMultipartUpload(
                new InitiateMultipartUploadRequest(containerName, blobName,
                        metadata));

        ByteSource byteSource = TestUtils.randomByteSource().slice(
                0, MINIMUM_MULTIPART_SIZE + 1);
        ByteSource byteSource1 = byteSource.slice(0, MINIMUM_MULTIPART_SIZE);
        ByteSource byteSource2 = byteSource.slice(MINIMUM_MULTIPART_SIZE, 1);
        UploadPartResult part1 = client.uploadPart(new UploadPartRequest()
                .withBucketName(containerName)
                .withKey(blobName)
                .withUploadId(result.getUploadId())
                .withPartNumber(1)
                .withPartSize(byteSource1.size())
                .withInputStream(byteSource1.openStream()));
        UploadPartResult part2 = client.uploadPart(new UploadPartRequest()
                .withBucketName(containerName)
                .withKey(blobName)
                .withUploadId(result.getUploadId())
                .withPartNumber(2)
                .withPartSize(byteSource2.size())
                .withInputStream(byteSource2.openStream()));

        client.completeMultipartUpload(new CompleteMultipartUploadRequest(
                containerName, blobName, result.getUploadId(),
                ImmutableList.of(part1.getPartETag(), part2.getPartETag())));
        ObjectListing listing = client.listObjects(containerName);
        assertThat(listing.getObjectSummaries()).hasSize(1);

        S3Object object = client.getObject(containerName, blobName);
        try (InputStream actual = object.getObjectContent();
                InputStream expected = byteSource.openStream()) {
            assertThat(actual).hasContentEqualTo(expected);
        }
        ObjectMetadata newContentMetadata = object.getObjectMetadata();
        if (!Quirks.NO_CACHE_CONTROL_SUPPORT.contains(blobStoreType)) {
            assertThat(newContentMetadata.getCacheControl()).isEqualTo(
                    cacheControl);
        }
        if (!Quirks.NO_CONTENT_DISPOSITION.contains(blobStoreType)) {
            assertThat(newContentMetadata.getContentDisposition()).isEqualTo(
                    contentDisposition);
        }
        if (!Quirks.NO_CONTENT_ENCODING.contains(blobStoreType)) {
            assertThat(newContentMetadata.getContentEncoding()).isEqualTo(
                    contentEncoding);
        }
        if (!Quirks.NO_CONTENT_LANGUAGE.contains(blobStoreType)) {
            assertThat(newContentMetadata.getContentLanguage()).isEqualTo(
                    contentLanguage);
        }
        assertThat(newContentMetadata.getContentType()).isEqualTo(
                contentType);
        // TODO: expires
        assertThat(newContentMetadata.getUserMetadata()).isEqualTo(
                userMetadata);
    }

    // this test runs for several minutes
    @Ignore
    @Test
    public void testMaximumMultipartUpload() throws Exception {
        // skip with remote blobstores to avoid excessive run-times
        assumeTrue(blobStoreType.equals("filesystem") ||
                blobStoreType.equals("transient"));

        String blobName = "multipart-upload";
        int numParts = 10_000;
        ByteSource byteSource = TestUtils.randomByteSource().slice(0, numParts);

        InitiateMultipartUploadResult result = client.initiateMultipartUpload(
                new InitiateMultipartUploadRequest(containerName, blobName));
        ImmutableList.Builder<PartETag> parts = ImmutableList.builder();

        for (int i = 0; i < numParts; ++i) {
            ByteSource partByteSource = byteSource.slice(i, 1);
            UploadPartResult partResult = client.uploadPart(
                    new UploadPartRequest()
                    .withBucketName(containerName)
                    .withKey(blobName)
                    .withUploadId(result.getUploadId())
                    .withPartNumber(i + 1)
                    .withPartSize(partByteSource.size())
                    .withInputStream(partByteSource.openStream()));
            parts.add(partResult.getPartETag());
        }

        client.completeMultipartUpload(new CompleteMultipartUploadRequest(
                containerName, blobName, result.getUploadId(), parts.build()));
        ObjectListing listing = client.listObjects(containerName);
        assertThat(listing.getObjectSummaries()).hasSize(1);

        S3Object object = client.getObject(containerName, blobName);

        try (InputStream actual = object.getObjectContent();
                InputStream expected = byteSource.openStream()) {
            assertThat(actual).hasContentEqualTo(expected);
        }
    }

    @Test
    public void testMultipartUploadAbort() throws Exception {
        String blobName = "multipart-upload-abort";
        ByteSource byteSource = TestUtils.randomByteSource().slice(
                0, MINIMUM_MULTIPART_SIZE);

        InitiateMultipartUploadResult result = client.initiateMultipartUpload(
                new InitiateMultipartUploadRequest(containerName, blobName));

        // TODO: google-cloud-storage and openstack-swift cannot list multipart
        // uploads
        MultipartUploadListing multipartListing = client.listMultipartUploads(
                new ListMultipartUploadsRequest(containerName));
        if (blobStoreType.equals("azureblob")) {
            // Azure does not create a manifest during initiate multi-part
            // upload.  Instead the first part creates this.
            assertThat(multipartListing.getMultipartUploads()).isEmpty();
        } else {
            assertThat(multipartListing.getMultipartUploads()).hasSize(1);
        }

        PartListing partListing = client.listParts(new ListPartsRequest(
                containerName, blobName, result.getUploadId()));
        assertThat(partListing.getParts()).isEmpty();

        client.uploadPart(new UploadPartRequest()
                .withBucketName(containerName)
                .withKey(blobName)
                .withUploadId(result.getUploadId())
                .withPartNumber(1)
                .withPartSize(byteSource.size())
                .withInputStream(byteSource.openStream()));

        multipartListing = client.listMultipartUploads(
                new ListMultipartUploadsRequest(containerName));
        assertThat(multipartListing.getMultipartUploads()).hasSize(1);

        partListing = client.listParts(new ListPartsRequest(
                containerName, blobName, result.getUploadId()));
        assertThat(partListing.getParts()).hasSize(1);

        client.abortMultipartUpload(new AbortMultipartUploadRequest(
                containerName, blobName, result.getUploadId()));

        multipartListing = client.listMultipartUploads(
                new ListMultipartUploadsRequest(containerName));
        if (blobStoreType.equals("azureblob")) {
            // Azure does not support explicit abort.  It automatically
            // removes incomplete multi-part uploads after 7 days.
            assertThat(multipartListing.getMultipartUploads()).hasSize(1);
        } else {
            assertThat(multipartListing.getMultipartUploads()).isEmpty();
        }

        ObjectListing listing = client.listObjects(containerName);
        assertThat(listing.getObjectSummaries()).isEmpty();
    }

    // TODO: Fails since B2 returns the Cache-Control header on reads but does
    // not accept it on writes.
    @Test
    public void testCopyObjectPreserveMetadata() throws Exception {
        String fromName = "from-name";
        String toName = "to-name";
        String cacheControl = "max-age=3600";
        String contentDisposition = "attachment; filename=old.jpg";
        String contentEncoding = "gzip";
        String contentLanguage = "en";
        String contentType = "audio/ogg";
        Map<String, String> userMetadata = ImmutableMap.of(
                "key1", "value1",
                "key2", "value2");
        ObjectMetadata metadata = new ObjectMetadata();
        if (!Quirks.NO_CACHE_CONTROL_SUPPORT.contains(blobStoreType)) {
            metadata.setCacheControl(cacheControl);
        }
        metadata.setContentLength(BYTE_SOURCE.size());
        if (!Quirks.NO_CONTENT_DISPOSITION.contains(blobStoreType)) {
            metadata.setContentDisposition(contentDisposition);
        }
        if (!Quirks.NO_CONTENT_ENCODING.contains(blobStoreType)) {
            metadata.setContentEncoding(contentEncoding);
        }
        if (!Quirks.NO_CONTENT_LANGUAGE.contains(blobStoreType)) {
            metadata.setContentLanguage(contentLanguage);
        }
        metadata.setContentType(contentType);
        // TODO: expires
        metadata.setUserMetadata(userMetadata);
        client.putObject(containerName, fromName, BYTE_SOURCE.openStream(),
                metadata);

        client.copyObject(containerName, fromName, containerName, toName);

        S3Object object = client.getObject(containerName, toName);

        try (InputStream actual = object.getObjectContent();
                InputStream expected = BYTE_SOURCE.openStream()) {
            assertThat(actual).hasContentEqualTo(expected);
        }

        ObjectMetadata contentMetadata = object.getObjectMetadata();
        assertThat(contentMetadata.getContentLength()).isEqualTo(
                BYTE_SOURCE.size());
        if (!Quirks.NO_CACHE_CONTROL_SUPPORT.contains(blobStoreType)) {
            assertThat(contentMetadata.getCacheControl()).isEqualTo(
                    cacheControl);
        }
        if (!Quirks.NO_CONTENT_DISPOSITION.contains(blobStoreType)) {
            assertThat(contentMetadata.getContentDisposition()).isEqualTo(
                    contentDisposition);
        }
        if (!Quirks.NO_CONTENT_ENCODING.contains(blobStoreType)) {
            assertThat(contentMetadata.getContentEncoding()).isEqualTo(
                    contentEncoding);
        }
        if (!Quirks.NO_CONTENT_LANGUAGE.contains(blobStoreType)) {
            assertThat(contentMetadata.getContentLanguage()).isEqualTo(
                    contentLanguage);
        }
        assertThat(contentMetadata.getContentType()).isEqualTo(
                contentType);
        // TODO: expires
        assertThat(contentMetadata.getUserMetadata()).isEqualTo(
                userMetadata);
    }

    @Test
    public void testCopyObjectReplaceMetadata() throws Exception {
        String fromName = "from-name";
        String toName = "to-name";
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentLength(BYTE_SOURCE.size());
        if (!Quirks.NO_CACHE_CONTROL_SUPPORT.contains(blobStoreType)) {
            metadata.setCacheControl("max-age=3600");
        }
        if (!Quirks.NO_CONTENT_DISPOSITION.contains(blobStoreType)) {
            metadata.setContentDisposition("attachment; filename=old.jpg");
        }
        if (!Quirks.NO_CONTENT_ENCODING.contains(blobStoreType)) {
            metadata.setContentEncoding("compress");
        }
        if (!Quirks.NO_CONTENT_LANGUAGE.contains(blobStoreType)) {
            metadata.setContentLanguage("en");
        }
        metadata.setContentType("audio/ogg");
        // TODO: expires
        metadata.setUserMetadata(ImmutableMap.of(
                        "key1", "value1",
                        "key2", "value2"));
        client.putObject(containerName, fromName, BYTE_SOURCE.openStream(),
                metadata);

        String cacheControl = "max-age=1800";
        String contentDisposition = "attachment; filename=new.jpg";
        String contentEncoding = "gzip";
        String contentLanguage = "fr";
        String contentType = "audio/mp4";
        ObjectMetadata contentMetadata = new ObjectMetadata();
        if (!Quirks.NO_CACHE_CONTROL_SUPPORT.contains(blobStoreType)) {
            contentMetadata.setCacheControl(cacheControl);
        }
        if (!Quirks.NO_CONTENT_DISPOSITION.contains(blobStoreType)) {
            contentMetadata.setContentDisposition(contentDisposition);
        }
        if (!Quirks.NO_CONTENT_ENCODING.contains(blobStoreType)) {
            contentMetadata.setContentEncoding(contentEncoding);
        }
        if (!Quirks.NO_CONTENT_LANGUAGE.contains(blobStoreType)) {
            contentMetadata.setContentLanguage(contentLanguage);
        }
        contentMetadata.setContentType(contentType);
        // TODO: expires
        Map<String, String> userMetadata = ImmutableMap.of(
                "key3", "value3",
                "key4", "value4");
        contentMetadata.setUserMetadata(userMetadata);
        client.copyObject(new CopyObjectRequest(
                    containerName, fromName, containerName, toName)
                            .withNewObjectMetadata(contentMetadata));

        S3Object object = client.getObject(containerName, toName);

        try (InputStream actual = object.getObjectContent();
                InputStream expected = BYTE_SOURCE.openStream()) {
            assertThat(actual).hasContentEqualTo(expected);
        }

        ObjectMetadata toContentMetadata = object.getObjectMetadata();
        if (!Quirks.NO_CACHE_CONTROL_SUPPORT.contains(blobStoreType)) {
            assertThat(contentMetadata.getCacheControl()).isEqualTo(
                    cacheControl);
        }
        if (!Quirks.NO_CONTENT_DISPOSITION.contains(blobStoreType)) {
            assertThat(toContentMetadata.getContentDisposition()).isEqualTo(
                    contentDisposition);
        }
        if (!Quirks.NO_CONTENT_ENCODING.contains(blobStoreType)) {
            assertThat(toContentMetadata.getContentEncoding()).isEqualTo(
                    contentEncoding);
        }
        if (!Quirks.NO_CONTENT_LANGUAGE.contains(blobStoreType)) {
            assertThat(toContentMetadata.getContentLanguage()).isEqualTo(
                    contentLanguage);
        }
        assertThat(toContentMetadata.getContentType()).isEqualTo(
                contentType);
        // TODO: expires
        assertThat(toContentMetadata.getUserMetadata()).isEqualTo(
                userMetadata);
    }

    @Test
    public void testConditionalGet() throws Exception {
        assumeTrue(!blobStoreType.equals("b2"));

        String blobName = "blob-name";
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentLength(BYTE_SOURCE.size());
        PutObjectResult result = client.putObject(containerName, blobName,
                BYTE_SOURCE.openStream(), metadata);

        S3Object object = client.getObject(
                new GetObjectRequest(containerName, blobName)
                        .withMatchingETagConstraint(result.getETag()));
        try (InputStream is = object.getObjectContent()) {
            assertThat(is).isNotNull();
            ByteStreams.copy(is, ByteStreams.nullOutputStream());
        }

        object = client.getObject(
                new GetObjectRequest(containerName, blobName)
                        .withNonmatchingETagConstraint(result.getETag()));
        assertThat(object).isNull();
    }

    @Test
    public void testStorageClass() throws Exception {
        String blobName = "test-storage-class";
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentLength(BYTE_SOURCE.size());
        PutObjectRequest request = new PutObjectRequest(
                containerName, blobName, BYTE_SOURCE.openStream(), metadata)
                .withStorageClass("STANDARD_IA");
        client.putObject(request);
        metadata = client.getObjectMetadata(containerName, blobName);
        assertThat(metadata.getStorageClass()).isEqualTo("STANDARD_IA");
    }

    @Test
    public void testUnknownHeader() throws Exception {
        String blobName = "test-unknown-header";
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentLength(BYTE_SOURCE.size());
        PutObjectRequest request = new PutObjectRequest(
                containerName, blobName, BYTE_SOURCE.openStream(), metadata)
                .withTagging(new ObjectTagging(ImmutableList.<Tag>of()));
        try {
            client.putObject(request);
            Fail.failBecauseExceptionWasNotThrown(AmazonS3Exception.class);
        } catch (AmazonS3Exception e) {
            assertThat(e.getErrorCode()).isEqualTo("NotImplemented");
        }
    }

    @Test
    public void testGetBucketPolicy() throws Exception {
        try {
            client.getBucketPolicy(containerName);
            Fail.failBecauseExceptionWasNotThrown(AmazonS3Exception.class);
        } catch (AmazonS3Exception e) {
            assertThat(e.getErrorCode()).isEqualTo("NoSuchPolicy");
        }
    }

    @Test
    public void testUnknownParameter() throws Exception {
        try {
            client.setBucketLoggingConfiguration(
                    new SetBucketLoggingConfigurationRequest(
                            containerName, new BucketLoggingConfiguration()));
            Fail.failBecauseExceptionWasNotThrown(AmazonS3Exception.class);
        } catch (AmazonS3Exception e) {
            assertThat(e.getErrorCode()).isEqualTo("NotImplemented");
        }
    }

    @Test
    public void testBlobStoreLocator() throws Exception {
        final BlobStore blobStore1 = context.getBlobStore();
        final BlobStore blobStore2 = ContextBuilder
                .newBuilder(blobStoreType)
                .credentials("other-identity", "credential")
                .build(BlobStoreContext.class)
                .getBlobStore();
        s3Proxy.setBlobStoreLocator(new BlobStoreLocator() {
            @Nullable
            @Override
            public Map.Entry<String, BlobStore> locateBlobStore(
                    String identity, String container, String blob) {
                if (identity.equals(awsCreds.getAWSAccessKeyId())) {
                    return Maps.immutableEntry(awsCreds.getAWSSecretKey(),
                            blobStore1);
                } else if (identity.equals("other-identity")) {
                    return Maps.immutableEntry("credential", blobStore2);
                } else {
                    return null;
                }
            }
        });

        // check first access key
        List<Bucket> buckets = client.listBuckets();
        assertThat(buckets).hasSize(1);
        assertThat(buckets.get(0).getName()).isEqualTo(containerName);

        // check second access key
        client = AmazonS3ClientBuilder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(
                        new BasicAWSCredentials("other-identity",
                                "credential")))
                .withEndpointConfiguration(s3EndpointConfig)
                .build();
        buckets = client.listBuckets();
        assertThat(buckets).isEmpty();

        // check invalid access key
        client = AmazonS3ClientBuilder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(
                        new BasicAWSCredentials("bad-identity", "credential")))
                .withEndpointConfiguration(s3EndpointConfig)
                .build();
        try {
            client.listBuckets();
            Fail.failBecauseExceptionWasNotThrown(AmazonS3Exception.class);
        } catch (AmazonS3Exception e) {
            assertThat(e.getErrorCode()).isEqualTo("InvalidAccessKeyId");
        }
    }

    private static final class NullX509TrustManager
            implements X509TrustManager {
        @Override
        @Nullable
        public X509Certificate[] getAcceptedIssuers() {
            return null;
        }

        @Override
        public void checkClientTrusted(X509Certificate[] certs,
                String authType) {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] certs,
                String authType) {
        }
    }

    static void disableSslVerification() {
        try {
            // Create a trust manager that does not validate certificate chains
            TrustManager[] trustAllCerts = new TrustManager[] {
                new NullX509TrustManager() };

            // Install the all-trusting trust manager
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(
                    sc.getSocketFactory());

            // Create all-trusting host name verifier
            HostnameVerifier allHostsValid = new HostnameVerifier() {
                @Override
                public boolean verify(String hostname, SSLSession session) {
                    return true;
                }
            };

            // Install the all-trusting host verifier
            HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
        } catch (KeyManagementException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static String createRandomContainerName() {
        return "s3proxy-" + new Random().nextInt(Integer.MAX_VALUE);
    }
}
