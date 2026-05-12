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

import java.io.InputStream;
import java.util.Objects;

public final class InputStreamPayload implements Payload {
    private final InputStream content;
    private final ContentMetadata contentMetadata;

    public InputStreamPayload(InputStream content) {
        this(content, ContentMetadata.builder().build());
    }

    public InputStreamPayload(InputStream content,
            ContentMetadata contentMetadata) {
        this.content = Objects.requireNonNull(content, "content");
        this.contentMetadata = Objects.requireNonNull(contentMetadata,
                "contentMetadata");
    }

    @Override
    public InputStream openStream() {
        return content;
    }

    @Override
    public ContentMetadata getContentMetadata() {
        return contentMetadata;
    }

    @Override
    public Payload withContentMetadata(ContentMetadata contentMetadata) {
        return new InputStreamPayload(content, contentMetadata);
    }
}
