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

import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Collection;

import org.jspecify.annotations.Nullable;

import tools.jackson.dataformat.xml.annotation.JacksonXmlElementWrapper;
import tools.jackson.dataformat.xml.annotation.JacksonXmlProperty;

record DeleteMultipleObjectsRequest(
        @JacksonXmlProperty(localName = "Quiet") boolean quiet,
        @JacksonXmlProperty(localName = "Object")
        @JacksonXmlElementWrapper(useWrapping = false)
        Collection<S3Object> objects) {

    record S3Object(
            @JacksonXmlProperty(localName = "Key") String key,
            // The element is VersionId, not VersionID: the mapper matches
            // case sensitively, so the latter never bound and every version
            // named here was silently ignored.
            @JacksonXmlProperty(localName = "VersionId") String versionId,
            // Delete conditions, evaluated per object.
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

        /** The Size condition as a number, or null when absent. */
        @Nullable
        Long parsedSize() {
            if (size == null) {
                return null;
            }
            try {
                return Long.valueOf(size);
            } catch (NumberFormatException nfe) {
                throw new S3ProxyException(S3ErrorCode.MALFORMED_X_M_L, nfe);
            }
        }

        /**
         * The LastModifiedTime condition as an instant, or null when
         * absent.  The service model formats this element as rfc822 like
         * its header twin, not as the ISO 8601 of most XML timestamps.
         */
        @Nullable
        Instant parsedLastModifiedTime() {
            if (lastModifiedTime == null) {
                return null;
            }
            try {
                return ZonedDateTime.parse(lastModifiedTime,
                        DateTimeFormatter.RFC_1123_DATE_TIME).toInstant();
            } catch (DateTimeParseException dtpe) {
                throw new S3ProxyException(S3ErrorCode.MALFORMED_X_M_L, dtpe);
            }
        }
    }
}
