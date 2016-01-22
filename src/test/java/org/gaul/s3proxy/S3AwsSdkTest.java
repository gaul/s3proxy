/*
 * Copyright 2014-2016 Andrew Gaul <andrew@gaul.org>
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

import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import com.amazonaws.ClientConfiguration;
import com.amazonaws.HttpMethod;
import com.amazonaws.SDKGlobalConfiguration;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.S3ClientOptions;
import com.amazonaws.services.s3.model.AbortMultipartUploadRequest;
import com.amazonaws.services.s3.model.AccessControlList;
import com.amazonaws.services.s3.model.AmazonS3Exception;
import com.amazonaws.services.s3.model.CompleteMultipartUploadRequest;
import com.amazonaws.services.s3.model.CompleteMultipartUploadResult;
import com.amazonaws.services.s3.model.CopyPartRequest;
import com.amazonaws.services.s3.model.CopyPartResult;
import com.amazonaws.services.s3.model.GeneratePresignedUrlRequest;
import com.amazonaws.services.s3.model.GetObjectRequest;
import com.amazonaws.services.s3.model.GroupGrantee;
import com.amazonaws.services.s3.model.InitiateMultipartUploadRequest;
import com.amazonaws.services.s3.model.InitiateMultipartUploadResult;
import com.amazonaws.services.s3.model.ObjectListing;
import com.amazonaws.services.s3.model.ObjectMetadata;
import com.amazonaws.services.s3.model.Permission;
import com.amazonaws.services.s3.model.S3Object;
import com.amazonaws.services.s3.model.S3ObjectSummary;
import com.amazonaws.services.s3.model.UploadPartRequest;
import com.amazonaws.services.s3.model.UploadPartResult;
import com.google.common.base.Throwables;
import com.google.common.collect.ImmutableList;
import com.google.common.io.ByteSource;

import org.assertj.core.api.Fail;

import org.jclouds.blobstore.BlobStoreContext;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public final class S3AwsSdkTest {
    static {
        System.setProperty(
                SDKGlobalConfiguration.DISABLE_CERT_CHECKING_SYSTEM_PROPERTY,
                "true");
        System.setProperty(
                SDKGlobalConfiguration.ENFORCE_S3_SIGV4_SYSTEM_PROPERTY,
                "true");
        disableSslVerification();
    }

    private static final ByteSource BYTE_SOURCE = ByteSource.wrap(new byte[1]);

    private URI s3Endpoint;
    private S3Proxy s3Proxy;
    private BlobStoreContext context;
    private String containerName;
    private BasicAWSCredentials awsCreds;
    private AmazonS3 client;

    @Before
    public void setUp() throws Exception {
        TestUtils.S3ProxyLaunchInfo info = TestUtils.startS3Proxy();
        awsCreds = new BasicAWSCredentials(info.getS3Identity(),
                info.getS3Credential());
        context = info.getBlobStore().getContext();
        s3Proxy = info.getS3Proxy();
        s3Endpoint = info.getEndpoint();
        client = new AmazonS3Client(awsCreds,
                new ClientConfiguration());
        client.setEndpoint(s3Endpoint.toString());

        containerName = createRandomContainerName();
        info.getBlobStore().createContainerInLocation(null, containerName);

        String blobStoreType = context.unwrap().getProviderMetadata().getId();
        if (Quirks.OPAQUE_ETAG.contains(blobStoreType)) {
            // AWK SDK checks that ETag matches Content-MD5 during PUT
            System.setProperty(
                    "com.amazonaws.services.s3.disablePutObjectMD5Validation",
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
        client = new AmazonS3Client(awsCreds,
                new ClientConfiguration().withSignerOverride("S3SignerType"));
        client.setEndpoint(s3Endpoint.toString());
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentLength(BYTE_SOURCE.size());
        client.putObject(containerName, "foo", BYTE_SOURCE.openStream(),
                metadata);

        S3Object object = client.getObject(new GetObjectRequest(containerName,
                "foo"));
        assertThat(object.getObjectMetadata().getContentLength()).isEqualTo(
                BYTE_SOURCE.size());
        try (InputStream actual = object.getObjectContent();
                InputStream expected = BYTE_SOURCE.openStream()) {
            assertThat(actual).hasContentEqualTo(expected);
        }
    }

    @Test
    public void testAwsV4Signature() throws Exception {
        client = new AmazonS3Client(awsCreds);
        client.setEndpoint(s3Endpoint.toString());

        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentLength(BYTE_SOURCE.size());
        client.putObject(containerName, "foo",
                BYTE_SOURCE.openStream(), metadata);

        S3Object object = client.getObject(new GetObjectRequest(containerName,
                "foo"));
        assertThat(object.getObjectMetadata().getContentLength()).isEqualTo(
                BYTE_SOURCE.size());
        try (InputStream actual = object.getObjectContent();
                InputStream expected = BYTE_SOURCE.openStream()) {
            assertThat(actual).hasContentEqualTo(expected);
        }
    }

    @Test
    public void testAwsV4SignatureNonChunked() throws Exception {
        client = new AmazonS3Client(awsCreds);
        client.setEndpoint(s3Endpoint.toString());
        client.setS3ClientOptions(
                new S3ClientOptions().disableChunkedEncoding());

        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentLength(BYTE_SOURCE.size());
        client.putObject(containerName, "foo",
                BYTE_SOURCE.openStream(), metadata);

        S3Object object = client.getObject(new GetObjectRequest(containerName,
                "foo"));
        assertThat(object.getObjectMetadata().getContentLength()).isEqualTo(
                BYTE_SOURCE.size());
        try (InputStream actual = object.getObjectContent();
                InputStream expected = BYTE_SOURCE.openStream()) {
            assertThat(actual).hasContentEqualTo(expected);
        }
    }

    @Test
    public void testAwsV4SignatureBadIdentity() throws Exception {
        client = new AmazonS3Client(new BasicAWSCredentials(
                "bad-identity", awsCreds.getAWSSecretKey()));
        client.setEndpoint(s3Endpoint.toString());
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
        client = new AmazonS3Client(new BasicAWSCredentials(
                awsCreds.getAWSAccessKeyId(), "bad-credential"));
        client.setEndpoint(s3Endpoint.toString());
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

    // TODO: cannot test with jclouds since S3BlobRequestSigner does not
    // implement the same logic as
    // AWSS3BlobRequestSigner.signForTemporaryAccess.
    @Test
    public void testAwsV2UrlSigning() throws Exception {
        client = new AmazonS3Client(awsCreds,
                new ClientConfiguration().withSignerOverride("S3SignerType"));
        client.setEndpoint(s3Endpoint.toString());

        String blobName = "foo";
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentLength(BYTE_SOURCE.size());
        client.putObject(containerName, blobName, BYTE_SOURCE.openStream(),
                metadata);

        Date expiration = new Date(System.currentTimeMillis() +
                TimeUnit.HOURS.toMillis(1));
        GeneratePresignedUrlRequest request = new GeneratePresignedUrlRequest(
                containerName, blobName);
        request.setMethod(HttpMethod.GET);
        request.setExpiration(expiration);

        URL url = client.generatePresignedUrl(request);
        try (InputStream actual = url.openStream();
                InputStream expected = BYTE_SOURCE.openStream()) {
            assertThat(actual).hasContentEqualTo(expected);
        }
    }

    // TODO: testAwsV4UrlSigning()

    // TODO: jclouds lacks support for multipart copy
    @Test
    public void testMultipartCopy() throws Exception {
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
        CompleteMultipartUploadResult completeUploadResponse =
                client.completeMultipartUpload(completeRequest);

        S3Object object = client.getObject(new GetObjectRequest(containerName,
                targetBlobName));
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
        int size = 10_000_000;
        int partSize = 5 * 1024 * 1024;
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

        S3Object object = client.getObject(new GetObjectRequest(containerName,
                key));
        assertThat(object.getObjectMetadata().getContentLength()).isEqualTo(
                size);
        try (InputStream actual = object.getObjectContent();
                InputStream expected = byteSource.openStream()) {
            assertThat(actual).hasContentEqualTo(expected);
        }
    }

    @Test
    public void testUpdateBlobXmlAcls() throws Exception {
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

        S3Object object = client.getObject(new GetObjectRequest(containerName,
                key));
        assertThat(object.getObjectMetadata().getContentLength()).isEqualTo(
                BYTE_SOURCE.size());
        try (InputStream actual = object.getObjectContent();
                InputStream expected = BYTE_SOURCE.openStream()) {
            assertThat(actual).hasContentEqualTo(expected);
        }
    }

    private static final class NullX509TrustManager
            implements X509TrustManager {
        @Override
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

    private static void disableSslVerification() {
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
            throw Throwables.propagate(e);
        }
    }

    private static String createRandomContainerName() {
        return "s3proxy-" + new Random().nextInt(Integer.MAX_VALUE);
    }
}
