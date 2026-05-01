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

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.common.file.virtualfs.VirtualFileSystemFactory;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.sftp.server.SftpSubsystemFactory;
import org.gaul.s3proxy.sftp.SftpBlobStoreApiMetadata;
import org.jclouds.Constants;
import org.jclouds.ContextBuilder;
import org.jclouds.blobstore.BlobStoreContext;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.async.AsyncRequestBody;
import software.amazon.awssdk.core.async.AsyncResponseTransformer;
import software.amazon.awssdk.core.checksums.RequestChecksumCalculation;
import software.amazon.awssdk.core.checksums.ResponseChecksumValidation;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.S3Configuration;

public final class S3BackupSftpBridgeTest {
    private static final String SFTP_USER = "sftp-user";
    private static final String SFTP_PASSWORD = "sftp-password";
    private static final String S3_IDENTITY = "local-identity";
    private static final String S3_CREDENTIAL = "local-credential";

    private SshServer sshServer;
    private BlobStoreContext context;
    private S3Proxy s3Proxy;
    private S3AsyncClient s3Client;
    private Path sftpRoot;

    @Before
    public void setUp() throws Exception {
        sftpRoot = Files.createTempDirectory("s3proxy-sftp-root");
        sshServer = SshServer.setUpDefaultServer();
        sshServer.setHost("127.0.0.1");
        sshServer.setPort(0);
        sshServer.setKeyPairProvider(new SimpleGeneratorHostKeyProvider(
                Files.createTempFile("s3proxy-sftp-hostkey", ".ser")));
        sshServer.setPasswordAuthenticator((username, password, session) ->
                SFTP_USER.equals(username) && SFTP_PASSWORD.equals(password));
        sshServer.setFileSystemFactory(new VirtualFileSystemFactory(sftpRoot));
        sshServer.setSubsystemFactories(List.of(
                new SftpSubsystemFactory.Builder().build()));
        sshServer.start();

        var properties = new Properties();
        properties.setProperty(Constants.PROPERTY_ENDPOINT,
                "sftp://127.0.0.1:" + sshServer.getPort() + "/");
        properties.setProperty(SftpBlobStoreApiMetadata.BASEDIR, "/");
        context = ContextBuilder.newBuilder("sftp")
                .credentials(SFTP_USER, SFTP_PASSWORD)
                .overrides(properties)
                .build(BlobStoreContext.class);

        s3Proxy = S3Proxy.builder()
                .endpoint(URI.create("http://127.0.0.1:0"))
                .awsAuthentication(AuthenticationType.AWS_V2_OR_V4,
                        S3_IDENTITY, S3_CREDENTIAL)
                .blobStore(context.getBlobStore())
                .ignoreUnknownHeaders(true)
                .build();
        s3Proxy.start();

        s3Client = S3AsyncClient.builder()
                .multipartEnabled(true)
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create(S3_IDENTITY, S3_CREDENTIAL)))
                .region(Region.US_EAST_1)
                .endpointOverride(
                        URI.create("http://127.0.0.1:" + s3Proxy.getPort()))
                .requestChecksumCalculation(
                        RequestChecksumCalculation.WHEN_REQUIRED)
                .responseChecksumValidation(
                        ResponseChecksumValidation.WHEN_REQUIRED)
                .serviceConfiguration(S3Configuration.builder()
                        .pathStyleAccessEnabled(true)
                        .chunkedEncodingEnabled(false)
                        .build())
                .build();
    }

    @After
    public void tearDown() throws Exception {
        if (s3Client != null) {
            s3Client.close();
        }
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
        if (context != null) {
            context.close();
        }
        if (sshServer != null) {
            sshServer.stop();
        }
    }

    @Test
    public void testS3BackupOperationProfile() throws Exception {
        var bucket = "s3-backup";
        var snapshotPayload = "backups/snapshot/100/snapshot.zip";
        var snapshotEntry = "backups/snapshot/100/entry.txt";
        var appPayload = "backups/app/1000/db_dump.zip";
        var appEntry = "backups/app/1000/entry.txt";

        get(s3Client.createBucket(request -> request.bucket(bucket)));
        putObject(bucket, snapshotPayload, bytes(1024 * 1024));
        putObject(bucket, snapshotEntry, "snapshot-entry".getBytes(
                StandardCharsets.UTF_8));
        putObject(bucket, appPayload, bytes(2 * 1024 * 1024));
        putObject(bucket, appEntry, "app-entry".getBytes(StandardCharsets.UTF_8));

        assertThat(get(s3Client.headObject(request -> request.bucket(bucket)
                .key(snapshotPayload))).contentLength()).isEqualTo(1024 * 1024);
        assertThat(get(s3Client.getObject(request -> request.bucket(bucket)
                .key(snapshotEntry), AsyncResponseTransformer.toBytes()))
                .asUtf8String()).isEqualTo("snapshot-entry");
        assertThat(get(s3Client.getObject(request -> request.bucket(bucket)
                .key(appEntry), AsyncResponseTransformer.toBytes()))
                .asUtf8String()).isEqualTo("app-entry");
        assertThat(Files.exists(sftpRoot.resolve(bucket).resolve(snapshotPayload)))
                .isTrue();
        assertThat(Files.exists(sftpRoot.resolve(bucket).resolve(snapshotEntry)))
                .isTrue();
        assertThat(Files.exists(sftpRoot.resolve(bucket).resolve(appPayload)))
                .isTrue();
        assertThat(Files.exists(sftpRoot.resolve(bucket).resolve(appEntry)))
                .isTrue();

        var snapshotKeys = get(s3Client.listObjectsV2(request -> request
                .bucket(bucket)
                .prefix("backups/snapshot/"))).contents();
        assertThat(snapshotKeys).extracting(object -> object.key())
                .containsExactlyInAnyOrder(snapshotPayload, snapshotEntry);

        get(s3Client.deleteObject(request -> request.bucket(bucket)
                .key(snapshotEntry)));
        get(s3Client.deleteObject(request -> request.bucket(bucket)
                .key(snapshotPayload)));
        get(s3Client.deleteObject(request -> request.bucket(bucket)
                .key(appEntry)));
        get(s3Client.deleteObject(request -> request.bucket(bucket)
                .key(appPayload)));
        get(s3Client.deleteBucket(request -> request.bucket(bucket)));
    }

    private void putObject(String bucket, String key, byte[] content)
            throws Exception {
        get(s3Client.putObject(request -> request.bucket(bucket).key(key),
                AsyncRequestBody.fromBytes(content)));
    }

    private static <T> T get(CompletableFuture<T> future) throws Exception {
        return future.get(30, TimeUnit.SECONDS);
    }

    private static byte[] bytes(int size) {
        var bytes = new byte[size];
        for (int i = 0; i < size; i++) {
            bytes[i] = (byte) (i & 0xff);
        }
        return bytes;
    }
}
