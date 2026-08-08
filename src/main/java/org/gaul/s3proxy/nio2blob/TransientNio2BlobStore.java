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

package org.gaul.s3proxy.nio2blob;

import java.nio.file.FileSystem;

import com.google.common.jimfs.Configuration;
import com.google.common.jimfs.Jimfs;

public final class TransientNio2BlobStore extends AbstractNio2BlobStore {

    public TransientNio2BlobStore() {
        this(Jimfs.newFileSystem(Configuration.unix().toBuilder()
                .setAttributeViews("posix", "user")
                .setWorkingDirectory("/")
                .build()));
    }

    // Helper to create Path
    private TransientNio2BlobStore(FileSystem fs) {
        // TODO: close fs?
        // Use Jimfs's actual root rather than the empty path: Path.startsWith
        // against the empty path returns false in Jimfs, which would defeat
        // the path-traversal check in AbstractNio2BlobStore.
        super(fs.getPath("/"));
    }

    /**
     * Versioning is answered here and refused by the filesystem store, whose
     * versions would have to survive a restart: where this one keeps them is
     * a detail of a filesystem that lives and dies with the process, while
     * anything written to a real disk is a format S3Proxy would owe its users
     * from then on.  See issue #74.
     */
    @Override
    public boolean supportsVersioning() {
        return true;
    }
}
