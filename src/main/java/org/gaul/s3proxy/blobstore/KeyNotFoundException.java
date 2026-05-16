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

/** Thrown when a blob cannot be located in the container. */
public final class KeyNotFoundException extends RuntimeException {

    private final String container;
    private final String key;

    public KeyNotFoundException(String container, String key, String message) {
        super(String.format("%s not found in container %s: %s", key, container,
                message));
        this.container = container;
        this.key = key;
    }

    public String getContainer() {
        return container;
    }

    public String getKey() {
        return key;
    }
}
