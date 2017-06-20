/*
 * Copyright 2014-2017 Andrew Gaul <andrew@gaul.org>
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

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;

public final class XMLUtils {
    private static final String FAKE_INITIATOR_ID =
            "arn:aws:iam::111122223333:" +
                    "user/some-user-11116a31-17b5-4fb7-9df5-b288870f11xx";
    private static final String FAKE_INITIATOR_DISPLAY_NAME =
            "umat-user-11116a31-17b5-4fb7-9df5-b288870f11xx";
    private static final String FAKE_OWNER_ID =
            "75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a";
    private static final String FAKE_OWNER_DISPLAY_NAME =
            "CustomersName@amazon.com";

    private XMLUtils() { }

    // TODO: bogus values
    public static void writeInitiatorStanza(XMLStreamWriter xml)
            throws XMLStreamException {
        xml.writeStartElement("Initiator");

        writeSimpleElement(xml, "ID", FAKE_INITIATOR_ID);
        writeSimpleElement(xml, "DisplayName",
                FAKE_INITIATOR_DISPLAY_NAME);

        xml.writeEndElement();
    }

    // TODO: bogus values
    public static void writeOwnerStanza(XMLStreamWriter xml)
            throws XMLStreamException {
        xml.writeStartElement("Owner");

        writeSimpleElement(xml, "ID", FAKE_OWNER_ID);
        writeSimpleElement(xml, "DisplayName", FAKE_OWNER_DISPLAY_NAME);

        xml.writeEndElement();
    }

    public static void writeSimpleElement(XMLStreamWriter xml,
                                          String elementName, String characters)
            throws XMLStreamException {
        xml.writeStartElement(elementName);
        xml.writeCharacters(characters);
        xml.writeEndElement();
    }
}
