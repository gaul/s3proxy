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

package org.gaul.s3proxy.sftp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;

import com.google.common.base.Suppliers;
import com.google.common.io.ByteSource;

import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.file.virtualfs.VirtualFileSystemFactory;
import org.apache.sshd.common.keyprovider.KeyIdentityProvider;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.sftp.server.SftpSubsystemFactory;
import org.assertj.core.api.Assertions;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.gaul.s3proxy.blobstore.Credentials;
import org.gaul.s3proxy.blobstore.S3Exceptions;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.CompletedMultipartUpload;
import software.amazon.awssdk.services.s3.model.CompletedPart;
import software.amazon.awssdk.services.s3.model.CopyObjectRequest;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.services.s3.model.UploadPartRequest;

public final class SftpBlobStoreTest {
    private static final String SFTP_USER = "sftp-user";
    private static final String SFTP_PASSWORD = "sftp:p@ss/word#%";
    private static final String BASEDIR = "/s3proxy-test";

    private SshServer sshServer;

    @TempDir
    private Path sftpRoot;
    @TempDir
    private Path tempDir;

    @AfterEach
    public void tearDown() throws Exception {
        if (sshServer != null) {
            sshServer.stop();
        }
    }

    @Test
    public void testDefaultPort() {
        assertThat(SftpBlobStore.endpointPort(URI.create("sftp://example.com/")))
                .isEqualTo(22);
        assertThat(SftpBlobStore.endpointPort(
                URI.create("sftp://example.com:2022/"))).isEqualTo(2022);
    }

    @Test
    public void testProviderRegistrationWithSpecialCharacterPassword()
            throws Exception {
        var hostKeyProvider = startSftpServer();

        try (var blobStore = buildBlobStore(hostKeyFingerprint(
                hostKeyProvider))) {
            var bucket = "bucket";
            var key = "object.txt";
            blobStore.createContainer(bucket);
            var payload = ByteSource.wrap("value".getBytes(
                    StandardCharsets.UTF_8));
            blobStore.putBlob(PutObjectRequest.builder()
                    .bucket(bucket)
                    .key(key)
                    .contentLength(payload.size())
                    .build(), payload.openStream());

            try (InputStream input = blobStore.getBlob(bucket, key)) {
                assertThat(new String(input.readAllBytes(),
                        StandardCharsets.UTF_8)).isEqualTo("value");
            }
        }
    }

    /**
     * The server may run on Windows, which reads a backslash as a path
     * separator where SFTP, and so every check made on this side, sees part
     * of a name: {@code ..\other\object.txt} is another bucket's object
     * there.  A key or prefix holding one is refused whatever the server.
     */
    @Test
    public void testBackslashInKeyIsRefused() throws Exception {
        var hostKeyProvider = startSftpServer();

        try (var blobStore = buildBlobStore(hostKeyFingerprint(
                hostKeyProvider))) {
            var bucket = "bucket";
            var key = "..\\other\\object.txt";
            blobStore.createContainer(bucket);
            var payload = ByteSource.wrap("value".getBytes(
                    StandardCharsets.UTF_8));

            assertRefused(() -> blobStore.putBlob(PutObjectRequest.builder()
                    .bucket(bucket)
                    .key(key)
                    .contentLength(payload.size())
                    .build(), payload.openStream()));
            assertRefused(() -> blobStore.getBlob(bucket, key));
            assertRefused(() -> blobStore.removeBlob(bucket, key));
            assertRefused(() -> blobStore.list(ListObjectsV2Request.builder()
                    .bucket(bucket)
                    .prefix("..\\other/")
                    .build()));
            assertThat(sftpRoot.resolve(BASEDIR.substring(1)).resolve(bucket))
                    .isEmptyDirectory();
        }
    }

    /**
     * A bucket name reaches the store unchecked as the source of a copy, and
     * {@code bucket\..\other} is the bucket other on such a server.
     */
    @Test
    public void testBackslashInBucketIsRefused() throws Exception {
        var hostKeyProvider = startSftpServer();

        try (var blobStore = buildBlobStore(hostKeyFingerprint(
                hostKeyProvider))) {
            var bucket = "bucket";
            var source = "bucket\\..\\other";
            blobStore.createContainer(bucket);

            assertRefused(() -> blobStore.createContainer(source));
            assertRefused(() -> blobStore.getBlob(source, "object.txt"));
            assertRefused(() -> blobStore.copyBlob(CopyObjectRequest.builder()
                    .sourceBucket(source)
                    .sourceKey("object.txt")
                    .destinationBucket(bucket)
                    .destinationKey("copy.txt")
                    .build()));
            assertThat(sftpRoot.resolve(BASEDIR.substring(1)).resolve(source))
                    .doesNotExist();
        }
    }

    private static void assertRefused(ThrowingCallable callable) {
        assertThatThrownBy(callable)
                .isInstanceOf(S3Exception.class)
                .matches(e -> S3Exceptions.errorCode((S3Exception) e)
                        .equals("InvalidArgument"))
                .hasMessageContaining("path separator");
    }

    @Test
    public void testRejectsMismatchedHostKey() throws Exception {
        startSftpServer();

        Assertions.assertThatThrownBy(() -> buildBlobStore(
                "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
                .hasStackTraceContaining("Server key did not validate");
    }

    @Test
    public void testRejectsMd5Fingerprint() throws Exception {
        startSftpServer();

        // A legacy MD5 fingerprint (colon-separated hex) is refused before
        // the client connects: only the SHA-256 form is pinned.
        Assertions.assertThatThrownBy(() -> buildBlobStore(
                "16:27:ac:a5:76:28:2d:36:63:1b:56:4d:eb:df:a6:48"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("SHA-256");
    }

    /**
     * MINA reports a directory that still holds entries as a generic SFTP
     * failure rather than DirectoryNotEmptyException.  A delete removes the
     * directories it leaves empty and has to stop at one that is not.
     */
    @Test
    public void testDeleteLeavesDirectoryInUse() throws Exception {
        var hostKeyProvider = startSftpServer();

        try (var blobStore = buildBlobStore(hostKeyFingerprint(
                hostKeyProvider))) {
            var bucket = "bucket";
            blobStore.createContainer(bucket);
            for (var key : List.of("dir/sub/one", "dir/sub/two")) {
                blobStore.putBlob(PutObjectRequest.builder()
                        .bucket(bucket).key(key).contentLength(0L).build(),
                        new ByteArrayInputStream(new byte[0]));
            }

            blobStore.removeBlob(bucket, "dir/sub/one");
            assertThat(blobStore.blobExists(bucket, "dir/sub/two")).isTrue();

            blobStore.removeBlob(bucket, "dir/sub/two");
            assertThat(sftpRoot.resolve(BASEDIR.substring(1)).resolve(bucket))
                    .isEmptyDirectory();
        }
    }

    /**
     * The parts of an upload to a key in a directory lie beside its stub in
     * a directory of their own, so removing the first part meets a directory
     * still in use.  Failing there left the upload open after its object was
     * stored, to take parts and be completed again, and kept an abort from
     * removing it.
     */
    @Test
    public void testMultipartUploadOfKeyInDirectoryEnds() throws Exception {
        var hostKeyProvider = startSftpServer();

        try (var blobStore = buildBlobStore(hostKeyFingerprint(
                hostKeyProvider))) {
            var bucket = "bucket";
            var key = "dir/object.txt";
            blobStore.createContainer(bucket);
            var create = CreateMultipartUploadRequest.builder()
                    .bucket(bucket).key(key).build();

            var completed = blobStore.initiateMultipartUpload(create);
            uploadPart(blobStore, completed);
            blobStore.completeMultipartUpload(completed,
                    CompleteMultipartUploadRequest.builder()
                            .bucket(bucket).key(key)
                            .multipartUpload(CompletedMultipartUpload.builder()
                                    .parts(CompletedPart.builder()
                                            .partNumber(1).build())
                                    .build())
                            .build());
            assertThat(blobStore.blobExists(bucket, key)).isTrue();
            assertThat(blobStore.listMultipartUploads(bucket)).isEmpty();

            var aborted = blobStore.initiateMultipartUpload(create);
            uploadPart(blobStore, aborted);
            blobStore.abortMultipartUpload(aborted);
            assertThat(blobStore.listMultipartUploads(bucket)).isEmpty();
        }
    }

    private static void uploadPart(SftpBlobStore blobStore,
            MultipartUpload mpu) {
        blobStore.uploadMultipartPart(mpu, UploadPartRequest.builder()
                .bucket(mpu.containerName()).key(mpu.blobName())
                .uploadId(mpu.id()).partNumber(1).contentLength(4L).build(),
                new ByteArrayInputStream(new byte[4]));
    }

    private SftpBlobStore buildBlobStore(String hostKey) {
        var creds = Suppliers.ofInstance(new Credentials(
                SFTP_USER, SFTP_PASSWORD));
        var endpoint = "sftp://127.0.0.1:" + sshServer.getPort() + "/";
        return new SftpBlobStore(creds, endpoint, BASEDIR, hostKey);
    }

    private KeyIdentityProvider startSftpServer() throws Exception {
        sshServer = SshServer.setUpDefaultServer();
        sshServer.setHost("127.0.0.1");
        sshServer.setPort(0);
        var hostKeyProvider = new SimpleGeneratorHostKeyProvider(
                tempDir.resolve("hostkey.ser"));
        sshServer.setKeyPairProvider(hostKeyProvider);
        sshServer.setPasswordAuthenticator((username, password, session) ->
                SFTP_USER.equals(username) && SFTP_PASSWORD.equals(password));
        sshServer.setFileSystemFactory(new VirtualFileSystemFactory(sftpRoot));
        sshServer.setSubsystemFactories(List.of(
                new SftpSubsystemFactory.Builder().build()));
        sshServer.start();
        return hostKeyProvider;
    }

    private static String hostKeyFingerprint(KeyIdentityProvider provider)
            throws Exception {
        return KeyUtils.getFingerPrint(provider.loadKeys(null).iterator()
                .next().getPublic());
    }
}
