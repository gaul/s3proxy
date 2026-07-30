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

import tools.jackson.dataformat.xml.annotation.JacksonXmlElementWrapper;
import tools.jackson.dataformat.xml.annotation.JacksonXmlProperty;

record DeleteMultipleObjectsRequest(
        @JacksonXmlProperty(localName = "Quiet") boolean quiet,
        @JacksonXmlProperty(localName = "Object")
        @JacksonXmlElementWrapper(useWrapping = false)
        Collection<S3Object> objects) {

    record S3Object(
            @JacksonXmlProperty(localName = "Key") String key,
            // Parsed so handleMultiBlobRemove can reject a version-scoped
            // delete instead of removing the current object; the value itself
            // is never used.  The element is VersionId, not VersionID: the
            // mapper matches case sensitively, so the latter never bound and
            // every version named here was silently ignored.
            @JacksonXmlProperty(localName = "VersionId") String versionId,
            // Delete conditions that only directory buckets honor.  Parsed
            // so handleMultiBlobRemove can reject them instead of deleting
            // unconditionally; the values themselves are never used.
            @JacksonXmlProperty(localName = "ETag") String eTag,
            @JacksonXmlProperty(localName = "LastModifiedTime")
            String lastModifiedTime,
            @JacksonXmlProperty(localName = "Size") String size) {

        boolean hasCondition() {
            return eTag != null || lastModifiedTime != null || size != null;
        }

        /** "null" names the current object in an unversioned bucket. */
        boolean hasVersion() {
            return versionId != null && !versionId.equals("null");
        }
    }
}
