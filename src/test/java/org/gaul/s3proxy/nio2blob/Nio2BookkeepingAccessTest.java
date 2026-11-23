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

import static org.assertj.core.api.Assertions.assertThat;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import com.google.common.io.ByteSource;
import com.google.common.jimfs.Configuration;
import com.google.common.jimfs.Jimfs;

import org.gaul.s3proxy.TestUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.BucketVersioningStatus;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.ObjectCannedACL;

/**
 * Others-read is how the nio2 stores record public-read, and a file created
 * without permissions of its own usually carries it: 0644 under the common
 * umask, and always on Jimfs.  The files the store makes for itself -- the
 * one a write is assembled in, a delete marker -- were created that way, so
 * each was a public object under its reserved name: an anonymous client read
 * a private object's body while it was still being uploaded.
 */
public final class Nio2BookkeepingAccessTest {
    private static final String CONTAINER = "container";
    private static final ByteSource CONTENT = ByteSource.wrap(
            "hello world".getBytes(StandardCharsets.UTF_8));

    private FileSystem fileSystem;
    private Path containerPath;
    private AbstractNio2BlobStore store;

    /** A versioning store over a filesystem the test can look into. */
    private static final class Nio2Store extends AbstractNio2BlobStore {
        Nio2Store(Path root) {
            super(root);
        }

        @Override
        public boolean supportsVersioning() {
            return true;
        }
    }

    @BeforeEach
    public void setUp() {
        fileSystem = Jimfs.newFileSystem(Configuration.unix().toBuilder()
                .setAttributeViews("posix", "user")
                .setWorkingDirectory("/")
                .build());
        store = new Nio2Store(fileSystem.getPath("/"));
        store.createContainer(CONTAINER);
        containerPath = fileSystem.getPath("/", CONTAINER);
    }

    @AfterEach
    public void tearDown() throws IOException {
        fileSystem.close();
    }

    /** Whatever access a write asks for applies once its file is whole. */
    @Test
    public void testWriteInFlightIsPrivate() throws IOException {
        for (var access : List.of(ObjectCannedACL.PRIVATE,
                ObjectCannedACL.PUBLIC_READ)) {
            var during = new ArrayList<Set<PosixFilePermission>>();
            InputStream payload = new FilterInputStream(CONTENT.openStream()) {
                @Override
                public int read(byte[] b, int off, int len)
                        throws IOException {
                    int count = super.read(b, off, len);
                    if (count == -1) {
                        // everything before this is in the file
                        during.addAll(permissions(".s3proxy-tmp"));
                    }
                    return count;
                }
            };

            store.putBlob(TestUtils.putRequest(CONTAINER, "key", CONTENT)
                    .toBuilder().acl(access).build(), payload);

            assertThat(during).hasSize(1);
            assertThat(during.get(0))
                    .doesNotContain(PosixFilePermission.OTHERS_READ);
            assertThat(store.getBlobAccess(CONTAINER, "key"))
                    .isEqualTo(access);
        }
    }

    /** A delete marker is not an object, let alone a public one. */
    @Test
    public void testDeleteMarkerIsPrivate() throws IOException {
        store.putBucketVersioning(CONTAINER, BucketVersioningStatus.ENABLED);
        store.putBlob(TestUtils.putRequest(CONTAINER, "key", CONTENT),
                CONTENT.openStream());
        var deleted = store.removeBlob(DeleteObjectRequest.builder()
                .bucket(CONTAINER).key("key").build());
        assertThat(deleted.deleteMarker()).isTrue();

        // the private version and the marker over it
        assertThat(permissions(".s3proxy-versions")).hasSize(2)
                .allSatisfy(permissions -> assertThat(permissions)
                        .doesNotContain(PosixFilePermission.OTHERS_READ));
    }

    private List<Set<PosixFilePermission>> permissions(String directory)
            throws IOException {
        var permissions = new ArrayList<Set<PosixFilePermission>>();
        try (var stream = Files.newDirectoryStream(
                containerPath.resolve(directory))) {
            for (var path : stream) {
                permissions.add(Files.getPosixFilePermissions(path));
            }
        }
        return permissions;
    }
}
