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

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Set;

import com.google.common.base.Supplier;

import jakarta.inject.Inject;
import jakarta.inject.Named;
import jakarta.inject.Singleton;

import org.apache.sshd.sftp.client.fs.SftpFileSystemProvider;
import org.gaul.s3proxy.nio2blob.AbstractNio2BlobStore;
import org.jclouds.blobstore.BlobStoreContext;
import org.jclouds.blobstore.util.BlobUtils;
import org.jclouds.collect.Memoized;
import org.jclouds.domain.Credentials;
import org.jclouds.domain.Location;
import org.jclouds.io.PayloadSlicer;
import org.jclouds.providers.ProviderMetadata;

@Singleton
public final class SftpBlobStore extends AbstractNio2BlobStore {
    @Inject
    SftpBlobStore(BlobStoreContext context, BlobUtils blobUtils,
            Supplier<Location> defaultLocation,
            @Memoized Supplier<Set<? extends Location>> locations,
            PayloadSlicer slicer,
            @org.jclouds.location.Provider Supplier<Credentials> creds,
            ProviderMetadata provider,
            @Named(SftpBlobStoreApiMetadata.BASEDIR) String baseDir) {
        super(context, blobUtils, defaultLocation, locations, slicer, creds,
                createRoot(provider, creds.get(), baseDir));
    }

    private static Path createRoot(ProviderMetadata provider, Credentials creds,
            String baseDir) {
        var endpoint = URI.create(provider.getEndpoint());
        int port = endpoint.getPort();
        var uri = SftpFileSystemProvider.createFileSystemURI(
                endpoint.getHost(), port, creds.identity, creds.credential);
        try {
            var fs = new SftpFileSystemProvider().newFileSystem(uri, Map.of());
            var root = fs.getPath(baseDir).normalize();
            Files.createDirectories(root);
            return root;
        } catch (IOException ioe) {
            throw new RuntimeException("Failed to initialize SFTP backend", ioe);
        }
    }
}
