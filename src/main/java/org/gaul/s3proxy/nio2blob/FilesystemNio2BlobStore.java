/*
 * Copyright 2014-2025 Andrew Gaul <andrew@gaul.org>
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

package org.gaul.s3proxy.nio2blob;

import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.util.Set;

import com.google.common.base.Supplier;

import jakarta.inject.Inject;
import jakarta.inject.Named;
import jakarta.inject.Singleton;

import org.jclouds.blobstore.BlobStoreContext;
import org.jclouds.blobstore.util.BlobUtils;
import org.jclouds.collect.Memoized;
import org.jclouds.domain.Credentials;
import org.jclouds.domain.Location;
import org.jclouds.filesystem.reference.FilesystemConstants;
import org.jclouds.io.PayloadSlicer;

@Singleton
public final class FilesystemNio2BlobStore extends AbstractNio2BlobStore {
    @Inject
    FilesystemNio2BlobStore(BlobStoreContext context, BlobUtils blobUtils,
            Supplier<Location> defaultLocation,
            @Memoized Supplier<Set<? extends Location>> locations,
            PayloadSlicer slicer,
            @org.jclouds.location.Provider Supplier<Credentials> creds,
            @Named(FilesystemConstants.PROPERTY_BASEDIR) String baseDir) {
        super(context, blobUtils, defaultLocation, locations, slicer, creds,
                // cannot be closed
                FileSystems.getDefault().getPath(baseDir));
        if (!Files.exists(getRoot())) {
            throw new RuntimeException(new NoSuchFileException(getRoot().toString()));
        }
    }
}
