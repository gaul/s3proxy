/*
 * Copyright 2014-2020 Andrew Gaul <andrew@gaul.org>
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

import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlElementWrapper;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;

// CHECKSTYLE:OFF
final class DeleteMultipleObjectsRequest {
    @JacksonXmlProperty(localName = "Quiet")
    boolean quiet;

    @JacksonXmlProperty(localName = "Object")
    @JacksonXmlElementWrapper(useWrapping = false)
    Collection<S3Object> objects;

    static final class S3Object {
        @JacksonXmlProperty(localName = "Key")
        String key;
        @JacksonXmlProperty(localName = "VersionID")
        String versionId;
    }
}
// CHECKSTYLE:ON
