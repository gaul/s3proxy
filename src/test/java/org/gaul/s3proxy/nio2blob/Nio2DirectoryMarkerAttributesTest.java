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
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.UserDefinedFileAttributeView;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import software.amazon.awssdk.services.s3.model.PutObjectRequest;

/**
 * A directory marker is the directory itself, which stays when the marker
 * is deleted while keys lie below it.  What the marker carried must go with
 * it rather than wait on the directory for the next marker written there.
 */
public final class Nio2DirectoryMarkerAttributesTest {
    private static final String CONTAINER = "container";

    @TempDir
    private Path root;

    @Test
    public void testDeletedMarkerLeavesNothingOnItsDirectory()
            throws Exception {
        assumeTrue(supportsUserAttributes(root),
                "the filesystem keeps no user attributes");
        var blobStore = new FilesystemNio2BlobStore(root.toString());
        blobStore.createContainer(CONTAINER);
        blobStore.putBlob(PutObjectRequest.builder()
                .bucket(CONTAINER).key("dir/blob")
                .contentLength(0L).build(),
                new ByteArrayInputStream(new byte[0]));
        Path dir = root.resolve(CONTAINER).resolve("dir");
        List<String> before = attributes(dir);

        blobStore.putBlob(PutObjectRequest.builder()
                .bucket(CONTAINER).key("dir/")
                .contentLength(0L)
                .contentDisposition("attachment; filename=report.pdf")
                .metadata(Map.of("patient", "Jane Roe"))
                .build(), new ByteArrayInputStream(new byte[0]));
        assertThat(attributes(dir)).hasSizeGreaterThan(before.size());

        blobStore.removeBlob(CONTAINER, "dir/");

        assertThat(blobStore.blobExists(CONTAINER, "dir/")).isFalse();
        assertThat(blobStore.blobExists(CONTAINER, "dir/blob")).isTrue();
        assertThat(attributes(dir)).isEqualTo(before);
    }

    private static boolean supportsUserAttributes(Path path) {
        var view = Files.getFileAttributeView(path,
                UserDefinedFileAttributeView.class);
        if (view == null) {
            return false;
        }
        try {
            view.write("probe", ByteBuffer.wrap(new byte[] {1}));
            view.delete("probe");
            return true;
        } catch (IOException | UnsupportedOperationException e) {
            return false;
        }
    }

    private static List<String> attributes(Path path) throws IOException {
        return Files.getFileAttributeView(path,
                UserDefinedFileAttributeView.class).list().stream()
                .sorted().toList();
    }
}
