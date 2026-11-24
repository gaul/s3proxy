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
import java.nio.file.CopyOption;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.PublicKey;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import com.google.common.base.Supplier;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.client.extensions.openssh.OpenSSHPosixRenameExtension;
import org.apache.sshd.sftp.client.fs.SftpFileSystemProvider;
import org.apache.sshd.sftp.client.fs.SftpPath;
import org.apache.sshd.sftp.common.SftpConstants;
import org.apache.sshd.sftp.common.SftpException;
import org.gaul.s3proxy.blobstore.Credentials;
import org.gaul.s3proxy.nio2blob.AbstractNio2BlobStore;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class SftpBlobStore extends AbstractNio2BlobStore {
    public static final String PROPERTY_BASEDIR = "s3proxy.sftp.basedir";
    public static final String PROPERTY_HOST_KEY = "s3proxy.sftp.host-key";

    private static final Logger logger = LoggerFactory.getLogger(
            SftpBlobStore.class);

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

    /**
     * SFTP spells every path with "/" whatever the server runs on, so the
     * separator of the filesystem on this side says nothing about the host
     * that resolves the path.  A server on Windows reads a backslash as a
     * separator too: the key {@code ..\other-bucket\key} would pass every
     * check here as a single name and reach another bucket, or a file
     * outside the base directory, there.  Nothing in the protocol says which
     * kind of server this is, so a backslash is taken for a separator on all
     * of them and a bucket, key or prefix holding one is refused.
     */
    @Override
    protected String nativeSeparator() {
        return "\\";
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
            fs = new ReplacingMoveProvider(client).newFileSystem(uri,
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

    private static SshClient createClient(@Nullable String expectedHostKey,
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
            client.addPasswordIdentity(creds.credential());
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
            @Nullable PublicKey serverKey) {
        if (serverKey == null) {
            return false;
        }
        var match = KeyUtils.checkFingerPrint(fingerprint, serverKey);
        return match != null && Boolean.TRUE.equals(match.getKey());
    }

    private static URI createFileSystemUri(@Nullable String host, int port,
            Credentials creds) {
        if (host == null) {
            throw new IllegalArgumentException(
                    "Missing required SFTP host");
        }
        if (creds.identity().isBlank()) {
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

    /**
     * Replaces the target of a move in one step.  AbstractNio2BlobStore
     * publishes an object by moving a finished file onto the key's path
     * with ATOMIC_MOVE and REPLACE_EXISTING and relies on what rename(2)
     * gives a local filesystem: the key holds the old object or the new one
     * at every moment, and the old one when the move fails.  The stock
     * provider ignores ATOMIC_MOVE and carries out REPLACE_EXISTING as a
     * delete of the target followed by a plain rename, so an object being
     * overwritten does not exist in between and is lost with the new one
     * when that rename fails.
     */
    private static final class ReplacingMoveProvider
            extends SftpFileSystemProvider {
        private final AtomicBoolean warned = new AtomicBoolean();

        private ReplacingMoveProvider(SshClient client) {
            super(client);
        }

        @Override
        public void move(Path source, Path target, CopyOption... options)
                throws IOException {
            var requested = List.of(options);
            if (requested.contains(StandardCopyOption.ATOMIC_MOVE) &&
                    requested.contains(StandardCopyOption.REPLACE_EXISTING)) {
                boolean renamed;
                try {
                    renamed = renameOver(toSftpPath(source),
                            toSftpPath(target));
                } catch (SftpException se) {
                    // The publish retries a parent directory that another
                    // write's cleanup took away, which it knows by this.
                    if (se.getStatus() == SftpConstants.SSH_FX_NO_SUCH_FILE) {
                        var nsfe = new NoSuchFileException(source.toString(),
                                target.toString(), se.getMessage());
                        nsfe.initCause(se);
                        throw nsfe;
                    }
                    throw se;
                }
                if (renamed) {
                    return;
                }
                // Each overwrite would say the same, so say it once, where
                // an operator will see it.
                if (warned.compareAndSet(false, true)) {
                    logger.warn("The SFTP server offers neither the" +
                            " posix-rename@openssh.com extension nor the" +
                            " rename flags of SFTP version 5, so an" +
                            " overwrite deletes the old object before it" +
                            " renames the new one into place: a reader may" +
                            " find neither in between, and a rename that" +
                            " fails leaves neither");
                }
            }
            super.move(source, target, options);
        }

        /**
         * Asks the server for a rename that replaces: rename(2) where it
         * offers OpenSSH's posix-rename extension, and otherwise the flags
         * that SSH_FXP_RENAME has from SFTP version 5 on.
         *
         * @return false when the server has neither, which leaves only the
         *         delete followed by a rename
         */
        private static boolean renameOver(SftpPath source, SftpPath target)
                throws IOException {
            var from = source.toString();
            var to = target.toString();
            try (var sftp = source.getFileSystem().getClient()) {
                var posixRename = sftp.getExtension(
                        OpenSSHPosixRenameExtension.class);
                if (posixRename != null && posixRename.isSupported()) {
                    posixRename.posixRename(from, to);
                    return true;
                }
                if (sftp.getVersion() < SftpConstants.SFTP_V5) {
                    return false;
                }
                try {
                    sftp.rename(from, to, SftpClient.CopyMode.Atomic,
                            SftpClient.CopyMode.Overwrite);
                    return true;
                } catch (SftpException se) {
                    if (se.getStatus() !=
                            SftpConstants.SSH_FX_OP_UNSUPPORTED) {
                        throw se;
                    }
                    return false;
                }
            }
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
