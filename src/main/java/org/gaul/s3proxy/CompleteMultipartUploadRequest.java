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

package org.gaul.s3proxy;

import java.util.Collection;

import com.fasterxml.jackson.annotation.JsonProperty;

import org.jspecify.annotations.Nullable;

import tools.jackson.dataformat.xml.annotation.JacksonXmlElementWrapper;
import tools.jackson.dataformat.xml.annotation.JacksonXmlProperty;

public record CompleteMultipartUploadRequest(
        @JacksonXmlProperty(localName = "Part")
        @JacksonXmlElementWrapper(useWrapping = false)
        @Nullable Collection<Part> parts) {

    public record Part(
            // Required, so that a Part without one is refused as
            // MalformedXML, as S3 does, rather than bound to zero.
            @JsonProperty(required = true)
            @JacksonXmlProperty(localName = "PartNumber") int partNumber,
            @JacksonXmlProperty(localName = "ETag") @Nullable String eTag,
            // Per-part flexible checksums, enforced in
            // handleCompleteMultipartUpload to form the composite checksum.
            @JacksonXmlProperty(localName = "ChecksumCRC32")
            @Nullable String checksumCRC32,
            @JacksonXmlProperty(localName = "ChecksumCRC32C")
            @Nullable String checksumCRC32C,
            @JacksonXmlProperty(localName = "ChecksumCRC64NVME")
            @Nullable String checksumCRC64NVME,
            @JacksonXmlProperty(localName = "ChecksumSHA1")
            @Nullable String checksumSHA1,
            @JacksonXmlProperty(localName = "ChecksumSHA256")
            @Nullable String checksumSHA256) {
    }
}
