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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.stream.XMLOutputFactory;

import org.gaul.s3proxy.S3Exception;
import org.jclouds.blobstore.BlobStore;

abstract class AbstractRequestHandler {

    protected static final String AWS_XMLNS =
            "http://s3.amazonaws.com/doc/2006-03-01/";
    protected final XMLOutputFactory xmlOutputFactory =
            XMLOutputFactory.newInstance();

    private HttpServletRequest request;
    private HttpServletResponse response;
    private BlobStore blobStore;

    AbstractRequestHandler(HttpServletRequest request,
                                  HttpServletResponse response,
                                  BlobStore blobStore) {
        this.request = request;
        this.response = response;
        this.blobStore = blobStore;
    }

    public HttpServletRequest getRequest() {
        return request;
    }

    public HttpServletResponse getResponse() {
        return response;
    }

    public BlobStore getBlobStore() {
        return blobStore;
    }

    String getBlobStoreType() {
        return blobStore.getContext().unwrap().getProviderMetadata().getId();
    }

    abstract void executeRequest() throws IOException, S3Exception;
}
