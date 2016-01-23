/*
 * Copyright 2014-2016 Andrew Gaul <andrew@gaul.org>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
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

/** Represent an Amazon AccessControlPolicy for a container or object. */
// CHECKSTYLE:OFF
final class AccessControlPolicy {
    @JacksonXmlProperty(localName = "Owner")
    Owner owner;
    @JacksonXmlProperty(localName = "AccessControlList")
    AccessControlList aclList;

    static final class Owner {
        @JacksonXmlProperty(localName = "ID")
        String id;
        @JacksonXmlProperty(localName = "DisplayName")
        String displayName;
    }

    static final class AccessControlList {
        @JacksonXmlProperty(localName = "Grant")
        @JacksonXmlElementWrapper(useWrapping = false)
        Collection<Grant> grants;

        static final class Grant {
            @JacksonXmlProperty(localName = "Grantee")
            Grantee grantee;
            @JacksonXmlProperty(localName = "Permission")
            String permission;

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
            }
        }
    }
}
// CHECKSTYLE:ON
