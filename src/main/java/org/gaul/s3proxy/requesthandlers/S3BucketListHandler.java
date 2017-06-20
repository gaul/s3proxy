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

package org.gaul.s3proxy.requesthandlers;

import java.io.IOException;
import java.io.Writer;
import java.util.Date;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;

import org.gaul.s3proxy.S3Exception;
import org.gaul.s3proxy.XMLUtils;
import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.domain.PageSet;
import org.jclouds.blobstore.domain.StorageMetadata;

public final class S3BucketListHandler extends AbstractS3BucketHandler {
    public S3BucketListHandler(HttpServletRequest request,
                        HttpServletResponse response,
                        BlobStore blobStore) {
        super(request, response, blobStore);
    }

    @Override
    public void executeRequest() throws IOException, S3Exception {
        PageSet<? extends StorageMetadata> buckets = this.getBlobStore().list();
        try (Writer writer = this.getResponse().getWriter()) {
            XMLStreamWriter xml = xmlOutputFactory.createXMLStreamWriter(
                    writer);
            xml.writeStartDocument();
            xml.writeStartElement("ListAllMyBucketsResult");
            xml.writeDefaultNamespace(AWS_XMLNS);

            XMLUtils.writeOwnerStanza(xml);

            xml.writeStartElement("Buckets");
            for (StorageMetadata metadata : buckets) {
                xml.writeStartElement("Bucket");

                XMLUtils.writeSimpleElement(xml, "Name", metadata.getName());

                Date creationDate = metadata.getCreationDate();
                if (creationDate == null) {
                    // Some providers, e.g., Swift, do not provide container
                    // creation date.  Emit a bogus one to satisfy clients like
                    // s3cmd which require one.
                    creationDate = new Date(0);
                }
                XMLUtils.writeSimpleElement(xml, "CreationDate",
                        this.getBlobStore().getContext().utils().date()
                                .iso8601DateFormat(creationDate).trim());

                xml.writeEndElement();
            }
            xml.writeEndElement();

            xml.writeEndElement();
            xml.flush();
        } catch (XMLStreamException xse) {
            throw new IOException(xse);
        }
    }
}
