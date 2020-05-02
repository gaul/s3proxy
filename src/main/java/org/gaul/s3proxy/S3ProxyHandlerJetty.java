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

import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.TimeoutException;

import javax.annotation.Nullable;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Jetty-specific handler for S3 requests. */
final class S3ProxyHandlerJetty extends AbstractHandler {
    private static final Logger logger = LoggerFactory.getLogger(
            S3ProxyHandlerJetty.class);

    private final S3ProxyHandler handler;

    S3ProxyHandlerJetty(final BlobStore blobStore,
            AuthenticationType authenticationType, final String identity,
            final String credential, @Nullable String virtualHost,
            long v4MaxNonChunkedRequestSize, boolean ignoreUnknownHeaders,
            CrossOriginResourceSharing corsRules, String servicePath,
            int maximumTimeSkew) {
        handler = new S3ProxyHandler(blobStore, authenticationType, identity,
                credential, virtualHost, v4MaxNonChunkedRequestSize,
                ignoreUnknownHeaders, corsRules, servicePath, maximumTimeSkew);
    }

    private void sendS3Exception(HttpServletRequest request,
            HttpServletResponse response, S3Exception se)
            throws IOException {
        handler.sendSimpleErrorResponse(request, response,
                se.getError(), se.getMessage(), se.getElements());
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
            HttpResponse hr = hre.getResponse();
            if (hr == null) {
                logger.debug("HttpResponseException without HttpResponse:",
                        hre);
                response.sendError(
                        HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                        hre.getMessage());
                return;
            }
            int status = hr.getStatusCode();
            switch (status) {
            case 412:
                sendS3Exception(request, response,
                        new S3Exception(S3ErrorCode.PRECONDITION_FAILED));
                break;
            case 416:
                sendS3Exception(request, response,
                        new S3Exception(S3ErrorCode.INVALID_RANGE));
                break;
            case HttpServletResponse.SC_BAD_REQUEST:
            case 422:  // Swift returns 422 Unprocessable Entity
                sendS3Exception(request, response,
                    new S3Exception(S3ErrorCode.BAD_DIGEST));
                break;
            default:
                response.sendError(status, hre.getContent());
                break;
            }
            baseRequest.setHandled(true);
            return;
        } catch (IllegalArgumentException iae) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                    iae.getMessage());
            baseRequest.setHandled(true);
            return;
        } catch (KeyNotFoundException knfe) {
            S3ErrorCode code = S3ErrorCode.NO_SUCH_KEY;
            handler.sendSimpleErrorResponse(request, response, code,
                    code.getMessage(), ImmutableMap.<String, String>of());
            baseRequest.setHandled(true);
            return;
        } catch (S3Exception se) {
            sendS3Exception(request, response, se);
            baseRequest.setHandled(true);
            return;
        } catch (UnsupportedOperationException uoe) {
            response.sendError(HttpServletResponse.SC_NOT_IMPLEMENTED,
                    uoe.getMessage());
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
                logger.debug("Unknown exception:", throwable);
                throw throwable;
            }
        }
    }

    public S3ProxyHandler getHandler() {
        return this.handler;
    }
}
