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

package org.gaul.s3proxy.blobstore.domain;

import org.jspecify.annotations.Nullable;

/**
 * A bucket's versioning state.  A bucket that has never been versioned has
 * no state at all -- S3 answers GetBucketVersioning with an empty
 * configuration -- which callers model as null rather than as a constant
 * here, since suspending is only reachable from enabled.
 */
public enum VersioningStatus {
    ENABLED("Enabled"),
    SUSPENDED("Suspended");

    private final String value;

    VersioningStatus(String value) {
        this.value = value;
    }

    /** The Status element value in VersioningConfiguration XML. */
    public String value() {
        return value;
    }

    /** Parses a Status element value, or null when it names no status. */
    @Nullable
    public static VersioningStatus fromValue(String value) {
        for (var status : values()) {
            if (status.value.equals(value)) {
                return status;
            }
        }
        return null;
    }
}
