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
import com.google.common.base.MoreObjects;

/** Represent an Amazon AccessControlPolicy for a container or object. */
// CHECKSTYLE:OFF
final class AccessControlPolicy {
    @JacksonXmlProperty(localName = "Owner")
    Owner owner;
    @JacksonXmlProperty(localName = "AccessControlList")
    AccessControlList aclList;

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(AccessControlList.class)
                .add("owner", owner)
                .add("aclList", aclList)
                .toString();
    }

    static final class Owner {
        @JacksonXmlProperty(localName = "ID")
        String id;
        @JacksonXmlProperty(localName = "DisplayName")
        String displayName;

        @Override
        public String toString() {
            return MoreObjects.toStringHelper(Owner.class)
                    .add("id", id)
                    .add("displayName", displayName)
                    .toString();
        }
    }

    static final class AccessControlList {
        @JacksonXmlProperty(localName = "Grant")
        @JacksonXmlElementWrapper(useWrapping = false)
        Collection<Grant> grants;

        @Override
        public String toString() {
            return MoreObjects.toStringHelper(AccessControlList.class)
                    .add("grants", grants)
                    .toString();
        }

        static final class Grant {
            @JacksonXmlProperty(localName = "Grantee")
            Grantee grantee;
            @JacksonXmlProperty(localName = "Permission")
            String permission;

            @Override
            public String toString() {
                return MoreObjects.toStringHelper(Grant.class)
                        .add("grantee", grantee)
                        .add("permission", permission)
                        .toString();
            }

            static final class Grantee {
                @JacksonXmlProperty(namespace = "xsi", localName = "type",
                        isAttribute = true)
                String type;
                @JacksonXmlProperty(localName = "ID")
                String id;
                @JacksonXmlProperty(localName = "DisplayName")
                String displayName;
                @JacksonXmlProperty(localName = "EmailAddress")
                String emailAddress;
                @JacksonXmlProperty(localName = "URI")
                String uri;

                @Override
                public String toString() {
                    return MoreObjects.toStringHelper(Grantee.class)
                            .add("type", type)
                            .add("id", id)
                            .add("displayName", displayName)
                            .add("emailAddress", emailAddress)
                            .add("uri", uri)
                            .toString();
                }
            }
        }
    }
}
// CHECKSTYLE:ON
