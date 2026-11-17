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

import org.jspecify.annotations.Nullable;

import tools.jackson.dataformat.xml.annotation.JacksonXmlElementWrapper;
import tools.jackson.dataformat.xml.annotation.JacksonXmlProperty;

/** Represent an Amazon AccessControlPolicy for a container or object. */
record AccessControlPolicy(
        @JacksonXmlProperty(localName = "Owner") @Nullable Owner owner,
        @JacksonXmlProperty(localName = "AccessControlList")
        @Nullable AccessControlList aclList) {

    record Owner(
            @JacksonXmlProperty(localName = "ID") @Nullable String id,
            @JacksonXmlProperty(localName = "DisplayName")
            @Nullable String displayName) {
    }

    record AccessControlList(
            @JacksonXmlProperty(localName = "Grant")
            @JacksonXmlElementWrapper(useWrapping = false)
            @Nullable Collection<Grant> grants) {

        record Grant(
                @JacksonXmlProperty(localName = "Grantee")
                @Nullable Grantee grantee,
                @JacksonXmlProperty(localName = "Permission")
                @Nullable String permission) {

            record Grantee(
                    @JacksonXmlProperty(
                            namespace = "http://www.w3.org/2001/XMLSchema-instance",
                            localName = "type", isAttribute = true)
                    @Nullable String type,
                    @JacksonXmlProperty(localName = "ID") @Nullable String id,
                    @JacksonXmlProperty(localName = "DisplayName")
                    @Nullable String displayName,
                    @JacksonXmlProperty(localName = "EmailAddress")
                    @Nullable String emailAddress,
                    @JacksonXmlProperty(localName = "URI")
                    @Nullable String uri) {
            }
        }
    }
}
