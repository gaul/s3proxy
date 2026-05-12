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

import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;

import com.google.common.io.ByteSource;

/** An immutable, repeatable, ByteSource-backed Payload. */
public final class ByteSourcePayload implements Payload {
    private final ByteSource content;
    private final ContentMetadata contentMetadata;

    public ByteSourcePayload(ByteSource content) {
        this(content, defaultContentMetadata(content));
    }

    public ByteSourcePayload(ByteSource content,
            ContentMetadata contentMetadata) {
        this.content = Objects.requireNonNull(content, "content");
        this.contentMetadata = Objects.requireNonNull(contentMetadata,
                "contentMetadata");
    }

    private static ContentMetadata defaultContentMetadata(ByteSource content) {
        var builder = ContentMetadata.builder();
        Long size = content.sizeIfKnown().orNull();
        if (size != null) {
            builder.contentLength(size);
        }
        return builder.build();
    }

    @Override
    public InputStream openStream() throws IOException {
        return content.openStream();
    }

    @Override
    public ContentMetadata getContentMetadata() {
        return contentMetadata;
    }

    @Override
    public Payload withContentMetadata(ContentMetadata contentMetadata) {
        return new ByteSourcePayload(content, contentMetadata);
    }
}
