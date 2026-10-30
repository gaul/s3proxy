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

import java.io.IOException;

import com.google.common.jimfs.Configuration;
import com.google.common.jimfs.Jimfs;

import org.junit.jupiter.api.Test;

/**
 * The filesystem store keeps everything about an object but its bytes in
 * user extended attributes, which some filesystems do not have: NFSv3, vfat,
 * some container bind mounts.  See issue #1210.  Jimfs configured without the
 * "user" view stands in for one of those.
 */
public final class Nio2UserAttributesTest {
    /** Whether the store's filesystem keeps them is asked of the mount. */
    @Test
    public void testSupportFollowsTheFilesystem() throws IOException {
        try (var with = Jimfs.newFileSystem(Configuration.unix().toBuilder()
                .setAttributeViews("posix", "user")
                .build());
             var without = Jimfs.newFileSystem(
                     Configuration.unix().toBuilder()
                             .setAttributeViews("posix")
                             .build())) {
            assertThat(AbstractNio2BlobStore.supportsUserAttributes(
                    with.getPath("/"))).isTrue();
            assertThat(AbstractNio2BlobStore.supportsUserAttributes(
                    without.getPath("/"))).isFalse();
        }
    }
}
