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
import java.util.Map;
import java.util.Set;

import com.google.common.base.Supplier;

import jakarta.inject.Inject;
import jakarta.inject.Named;
import jakarta.inject.Singleton;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.sftp.client.fs.SftpFileSystemProvider;
import org.gaul.s3proxy.nio2blob.AbstractNio2BlobStore;
import org.jclouds.blobstore.BlobStoreContext;
import org.jclouds.blobstore.util.BlobUtils;
import org.jclouds.collect.Memoized;
import org.jclouds.domain.Credentials;
import org.jclouds.domain.Location;
import org.jclouds.io.PayloadSlicer;
import org.jclouds.lifecycle.Closer;
import org.jclouds.providers.ProviderMetadata;

@Singleton
public final class SftpBlobStore extends AbstractNio2BlobStore {
    private final SshClient client;
    private final FileSystem fileSystem;

    @Inject
    SftpBlobStore(BlobStoreContext context, BlobUtils blobUtils,
            Supplier<Location> defaultLocation,
            @Memoized Supplier<Set<? extends Location>> locations,
            PayloadSlicer slicer,
            @org.jclouds.location.Provider Supplier<Credentials> creds,
            ProviderMetadata provider,
            Closer closer,
            @Named(SftpBlobStoreApiMetadata.BASEDIR) String baseDir,
            @Named(SftpBlobStoreApiMetadata.HOST_KEY) String hostKey) {
        this(context, blobUtils, defaultLocation, locations, slicer, creds,
                createRoot(provider, creds.get(), baseDir, hostKey));
        closer.addToClose(client);
        closer.addToClose(fileSystem);
    }

    private SftpBlobStore(BlobStoreContext context, BlobUtils blobUtils,
            Supplier<Location> defaultLocation,
            @Memoized Supplier<Set<? extends Location>> locations,
            PayloadSlicer slicer,
            Supplier<Credentials> creds,
            Root root) {
        super(context, blobUtils, defaultLocation, locations, slicer, creds,
                root.path);
        this.client = root.client;
        this.fileSystem = root.fileSystem;
    }

    static int endpointPort(URI endpoint) {
        int port = endpoint.getPort();
        return port < 0 ? 22 : port;
    }

    private static Root createRoot(ProviderMetadata provider, Credentials creds,
            String baseDir, String hostKey) {
        var endpoint = URI.create(provider.getEndpoint());
        int port = endpointPort(endpoint);
        var uri = createFileSystemUri(endpoint.getHost(), port, creds);
        SshClient client = null;
        FileSystem fs = null;
        try {
            client = createClient(hostKey);
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

    private static SshClient createClient(String expectedHostKey) {
        var fingerprint = expectedHostKey == null ? "" :
                expectedHostKey.trim();
        if (fingerprint.isEmpty()) {
            throw new IllegalArgumentException(
                    "Missing required SFTP host key fingerprint property: " +
                    SftpBlobStoreApiMetadata.HOST_KEY);
        }
        var client = SshClient.setUpDefaultClient();
        try {
            client.setServerKeyVerifier((session, remoteAddress, serverKey) ->
                    Boolean.TRUE.equals(KeyUtils.checkFingerPrint(fingerprint,
                            serverKey).getKey()));
            client.start();
        } catch (RuntimeException re) {
            closeQuietly(client, re);
            throw re;
        }
        return client;
    }

    private static URI createFileSystemUri(String host, int port,
            Credentials creds) {
        if (creds.identity == null || creds.identity.isBlank()) {
            throw new IllegalArgumentException(
                    "Missing required SFTP identity");
        }
        var userInfo = creds.credential == null ? creds.identity :
                creds.identity + ":" + creds.credential;
        try {
            return new URI("sftp", userInfo, host, port, "/", null, null);
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

    private static void closeQuietly(Closeable closeable, Throwable throwable) {
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
