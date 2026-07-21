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
import org.gaul.s3proxy.blobstore.Credentials;
import org.gaul.s3proxy.blobstore.domain.Blob;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

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
            blobStore.putBlob(bucket, Blob.builder(key)
                    .payload(payload)
                    .contentLength(payload.size())
                    .build());

            try (InputStream input = blobStore.getBlob(bucket, key)
                    .getPayload()) {
                assertThat(new String(input.readAllBytes(),
                        StandardCharsets.UTF_8)).isEqualTo("value");
            }
        }
    }

    @Test
    public void testRejectsMismatchedHostKey() throws Exception {
        startSftpServer();

        Assertions.assertThatThrownBy(() -> buildBlobStore(
                "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
                .hasStackTraceContaining("Server key did not validate");
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
