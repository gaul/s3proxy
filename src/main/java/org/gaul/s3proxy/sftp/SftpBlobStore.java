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

import java.io.Closeable;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.util.Map;

import com.google.common.base.Supplier;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.sftp.client.fs.SftpFileSystemProvider;
import org.gaul.s3proxy.blobstore.Credentials;
import org.gaul.s3proxy.nio2blob.AbstractNio2BlobStore;
import org.jspecify.annotations.Nullable;

public final class SftpBlobStore extends AbstractNio2BlobStore {
    public static final String PROPERTY_BASEDIR = "s3proxy.sftp.basedir";
    public static final String PROPERTY_HOST_KEY = "s3proxy.sftp.host-key";

    private final SshClient client;
    private final FileSystem fileSystem;

    public SftpBlobStore(Supplier<Credentials> creds, String endpoint,
            String baseDir, String hostKey) {
        this(createRoot(creds.get(), URI.create(endpoint), baseDir, hostKey));
    }

    private SftpBlobStore(Root root) {
        super(root.path);
        this.client = root.client;
        this.fileSystem = root.fileSystem;
    }

    @Override
    public void close() {
        try {
            try {
                fileSystem.close();
            } finally {
                client.close();
            }
        } catch (IOException ioe) {
            throw new UncheckedIOException(ioe);
        }
    }

    static int endpointPort(URI endpoint) {
        int port = endpoint.getPort();
        return port < 0 ? 22 : port;
    }

    private static Root createRoot(Credentials creds, URI endpoint,
            String baseDir, String hostKey) {
        int port = endpointPort(endpoint);
        var uri = createFileSystemUri(endpoint.getHost(), port, creds);
        SshClient client = null;
        FileSystem fs = null;
        try {
            client = createClient(hostKey, creds);
            fs = new SftpFileSystemProvider(client).newFileSystem(uri,
                    Map.of());
            var root = fs.getPath(baseDir).normalize();
            createDirectories(root);
            return new Root(client, fs, root);
        } catch (IOException ioe) {
            closeQuietly(fs, ioe);
            closeQuietly(client, ioe);
            throw new UncheckedIOException(
                    "Failed to initialize SFTP backend", ioe);
        } catch (RuntimeException re) {
            closeQuietly(fs, re);
            closeQuietly(client, re);
            throw re;
        }
    }

    private static SshClient createClient(String expectedHostKey,
            Credentials creds) {
        var fingerprint = expectedHostKey == null ? "" :
                expectedHostKey.trim();
        if (fingerprint.isEmpty()) {
            throw new IllegalArgumentException(
                    "Missing required SFTP host key fingerprint property: " +
                    PROPERTY_HOST_KEY);
        }
        // Pin only a strong fingerprint: KeyUtils.checkFingerPrint infers the
        // digest from the string it is given, so a legacy MD5 fingerprint
        // (colon-separated hex) would let a broken hash make the trust
        // decision.  Require the SHA-256 form the docs prescribe.
        if (!fingerprint.startsWith("SHA256:")) {
            throw new IllegalArgumentException(
                    "SFTP host key fingerprint must be a SHA-256 fingerprint " +
                    "(SHA256:...): " + PROPERTY_HOST_KEY);
        }
        var client = SshClient.setUpDefaultClient();
        try {
            client.setServerKeyVerifier((session, remoteAddress, serverKey) ->
                    verifyHostKey(fingerprint, serverKey));
            // Register the password on the client rather than embedding it in
            // the filesystem URI, so the secret never rides in a URI that a
            // MINA exception or the filesystem cache could surface.
            if (creds.credential() != null) {
                client.addPasswordIdentity(creds.credential());
            }
            client.start();
        } catch (RuntimeException re) {
            closeQuietly(client, re);
            throw re;
        }
        return client;
    }

    // A missing or mismatched key is a refusal, not an error: answer false so
    // the handshake is rejected cleanly rather than letting a null server key
    // raise an exception from inside the verifier.
    private static boolean verifyHostKey(String fingerprint,
            PublicKey serverKey) {
        if (serverKey == null) {
            return false;
        }
        var match = KeyUtils.checkFingerPrint(fingerprint, serverKey);
        return match != null && Boolean.TRUE.equals(match.getKey());
    }

    private static URI createFileSystemUri(String host, int port,
            Credentials creds) {
        if (creds.identity() == null || creds.identity().isBlank()) {
            throw new IllegalArgumentException(
                    "Missing required SFTP identity");
        }
        try {
            // Only the identity goes in the URI; the credential is registered
            // as a password identity on the SshClient (see createClient).
            return new URI("sftp", creds.identity(), host, port, "/", null,
                    null);
        } catch (URISyntaxException use) {
            throw new IllegalArgumentException(
                    "Failed to create SFTP filesystem URI", use);
        }
    }

    private static void createDirectories(Path root) throws IOException {
        if (Files.exists(root)) {
            return;
        }
        try {
            Files.createDirectories(root);
        } catch (FileAlreadyExistsException faee) {
            // The target may appear between exists() and createDirectories().
        }
    }

    private static void closeQuietly(@Nullable Closeable closeable,
            Throwable throwable) {
        if (closeable == null) {
            return;
        }
        try {
            closeable.close();
        } catch (IOException closeException) {
            throwable.addSuppressed(closeException);
        }
    }

    private static final class Root {
        private final SshClient client;
        private final FileSystem fileSystem;
        private final Path path;

        private Root(SshClient client, FileSystem fileSystem, Path path) {
            this.client = client;
            this.fileSystem = fileSystem;
            this.path = path;
        }
    }
}
