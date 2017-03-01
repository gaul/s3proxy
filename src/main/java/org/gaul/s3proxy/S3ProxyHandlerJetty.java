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

import java.io.IOException;
import java.io.InputStream;
import java.util.Optional;
import java.util.concurrent.TimeoutException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.google.common.collect.ImmutableMap;

import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.ContainerNotFoundException;
import org.jclouds.blobstore.KeyNotFoundException;
import org.jclouds.http.HttpResponse;
import org.jclouds.http.HttpResponseException;
import org.jclouds.rest.AuthorizationException;
import org.jclouds.util.Throwables2;

/** Jetty-specific handler for S3 requests. */
final class S3ProxyHandlerJetty extends AbstractHandler {
    private final S3ProxyHandler handler;

    S3ProxyHandlerJetty(final BlobStore blobStore,
            AuthenticationType authenticationType, final String identity,
            final String credential, Optional<String> virtualHost,
            long v4MaxNonChunkedRequestSize, boolean ignoreUnknownHeaders,
            boolean ignoreUnknownParameters, boolean corsAllowAll) {
        handler = new S3ProxyHandler(blobStore, authenticationType, identity,
                credential, virtualHost, v4MaxNonChunkedRequestSize,
                ignoreUnknownHeaders, ignoreUnknownParameters, corsAllowAll);
    }

    @Override
    public void handle(String target, Request baseRequest,
            HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        try (InputStream is = request.getInputStream()) {

            // Set query encoding
            baseRequest.setAttribute(S3ProxyConstants.ATTRIBUTE_QUERY_ENCODING,
                    baseRequest.getQueryEncoding());

            handler.doHandle(baseRequest, request, response, is);
            baseRequest.setHandled(true);
        } catch (ContainerNotFoundException cnfe) {
            S3ErrorCode code = S3ErrorCode.NO_SUCH_BUCKET;
            handler.sendSimpleErrorResponse(request, response, code,
                    code.getMessage(), ImmutableMap.<String, String>of());
            baseRequest.setHandled(true);
            return;
        } catch (HttpResponseException hre) {
            HttpResponse httpResponse = hre.getResponse();
            response.sendError(httpResponse == null ?
                    HttpServletResponse.SC_INTERNAL_SERVER_ERROR :
                    httpResponse.getStatusCode());
            baseRequest.setHandled(true);
            return;
        } catch (IllegalArgumentException iae) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST);
            baseRequest.setHandled(true);
            return;
        } catch (KeyNotFoundException knfe) {
            S3ErrorCode code = S3ErrorCode.NO_SUCH_KEY;
            handler.sendSimpleErrorResponse(request, response, code,
                    code.getMessage(), ImmutableMap.<String, String>of());
            baseRequest.setHandled(true);
            return;
        } catch (S3Exception se) {
            handler.sendSimpleErrorResponse(request, response,
                    se.getError(), se.getMessage(), se.getElements());
            baseRequest.setHandled(true);
            return;
        } catch (UnsupportedOperationException uoe) {
            response.sendError(HttpServletResponse.SC_NOT_IMPLEMENTED);
            baseRequest.setHandled(true);
            return;
        } catch (Throwable throwable) {
            if (Throwables2.getFirstThrowableOfType(throwable,
                    AuthorizationException.class) != null) {
                S3ErrorCode code = S3ErrorCode.ACCESS_DENIED;
                handler.sendSimpleErrorResponse(request, response, code,
                        code.getMessage(), ImmutableMap.<String, String>of());
                baseRequest.setHandled(true);
                return;
            } else if (Throwables2.getFirstThrowableOfType(throwable,
                    TimeoutException.class) != null) {
                S3ErrorCode code = S3ErrorCode.REQUEST_TIMEOUT;
                handler.sendSimpleErrorResponse(request, response, code,
                        code.getMessage(), ImmutableMap.<String, String>of());
                baseRequest.setHandled(true);
                return;
            } else {
                throw throwable;
            }
        }
    }

    public S3ProxyHandler getHandler() {
        return this.handler;
    }
}
