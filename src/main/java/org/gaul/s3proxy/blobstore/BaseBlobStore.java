/*
 * Copyright 2009-2025 The Apache Software Foundation
 * Copyright 2026 Andrew Gaul <andrew@gaul.org>
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

package org.gaul.s3proxy.blobstore;

import org.gaul.s3proxy.blobstore.domain.PageSet;
import org.gaul.s3proxy.blobstore.domain.StorageMetadata;
import org.gaul.s3proxy.blobstore.options.ListContainerOptions;

public abstract class BaseBlobStore implements BlobStore {

    @Override
    public void removeBlobs(String container, Iterable<String> names) {
        for (String name : names) {
            removeBlob(container, name);
        }
    }

    @Override
    public void clearContainer(String containerName,
            ListContainerOptions options) {
        ListContainerOptions opts = options;
        while (true) {
            PageSet<? extends StorageMetadata> page = list(containerName, opts);
            for (StorageMetadata sm : page) {
                String name = sm.name();
                if (name != null) {
                    removeBlob(containerName, name);
                }
            }
            String marker = page.getNextMarker();
            if (marker == null) {
                return;
            }
            opts = options.toBuilder().afterMarker(marker).build();
        }
    }

    @Override
    public void deleteContainer(String container) {
        try {
            clearContainer(container,
                    ListContainerOptions.builder().recursive().build());
        } catch (ContainerNotFoundException e) {
            return;
        }
        deleteContainerIfEmpty(container);
    }
}
