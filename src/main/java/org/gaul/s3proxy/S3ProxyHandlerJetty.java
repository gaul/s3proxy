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

import java.io.IOException;
import java.io.InputStream;
import java.util.Map;
import java.util.concurrent.TimeoutException;

import com.google.common.net.HttpHeaders;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.ContainerNotFoundException;
import org.jclouds.blobstore.KeyNotFoundException;
import org.jclouds.http.HttpResponse;
import org.jclouds.http.HttpResponseException;
import org.jclouds.rest.AuthorizationException;
import org.jclouds.util.Throwables2;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Jetty-specific handler for S3 requests. */
final class S3ProxyHandlerJetty extends HttpServlet {
    private static final Logger logger = LoggerFactory.getLogger(
            S3ProxyHandlerJetty.class);

    private final S3ProxyHandler handler;
    private final S3ProxyMetrics metrics;

    S3ProxyHandlerJetty(final BlobStore blobStore,
            AuthenticationType authenticationType, final String identity,
            final String credential, @Nullable String virtualHost,
            long maxSinglePartObjectSize, long v4MaxNonChunkedRequestSize,
            int v4MaxChunkSize,
            boolean ignoreUnknownHeaders, CrossOriginResourceSharing corsRules,
            String servicePath, int maximumTimeSkew,
            @Nullable S3ProxyMetrics metrics) {
        handler = new S3ProxyHandler(blobStore, authenticationType, identity,
                credential, virtualHost, maxSinglePartObjectSize,
                v4MaxNonChunkedRequestSize, v4MaxChunkSize,
                ignoreUnknownHeaders, corsRules,
                servicePath, maximumTimeSkew);
        this.metrics = metrics;
    }

    private void sendS3Exception(HttpServletRequest request,
            HttpServletResponse response, S3Exception se)
            throws IOException {
        handler.sendSimpleErrorResponse(request, response,
                se.getError(), se.getMessage(), se.getElements());
    }

    @Override
    protected void service(HttpServletRequest request,
            HttpServletResponse response)
            throws IOException {
        long startNanos = System.nanoTime();
        var ctx = new S3ProxyHandler.RequestContext();

        try (InputStream is = request.getInputStream()) {

            handler.doHandle(request, request, response, is, ctx);
        } catch (ContainerNotFoundException cnfe) {
            S3ErrorCode code = S3ErrorCode.NO_SUCH_BUCKET;
            handler.sendSimpleErrorResponse(request, response, code,
                    code.getMessage(), Map.of());
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

            String eTag = hr.getFirstHeaderOrNull(HttpHeaders.ETAG);
            if (eTag != null) {
                response.setHeader(HttpHeaders.ETAG, eTag);
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
                logger.debug("HttpResponseException:", hre);
                response.setStatus(status);
                break;
            }
            return;
        } catch (IllegalArgumentException iae) {
            logger.debug("IllegalArgumentException:", iae);
            response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                    iae.getMessage());
            return;
        } catch (IllegalStateException ise) {
            // google-cloud-storage uses a different exception
            if (ise.getMessage().startsWith("PreconditionFailed")) {
                sendS3Exception(request, response,
                        new S3Exception(S3ErrorCode.PRECONDITION_FAILED));
                return;
            }
            logger.debug("IllegalStateException:", ise);
            response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                    ise.getMessage());
            return;
        } catch (IOException ioe) {
            var cause = Throwables2.getFirstThrowableOfType(ioe,
                    S3Exception.class);
            if (cause != null) {
                sendS3Exception(request, response, cause);
                return;
            }
            throw ioe;
        } catch (KeyNotFoundException knfe) {
            S3ErrorCode code = S3ErrorCode.NO_SUCH_KEY;
            handler.sendSimpleErrorResponse(request, response, code,
                    code.getMessage(), Map.of());
            return;
        } catch (S3Exception se) {
            sendS3Exception(request, response, se);
            return;
        } catch (UnsupportedOperationException uoe) {
            logger.debug("UnsupportedOperationException:", uoe);
            response.sendError(HttpServletResponse.SC_NOT_IMPLEMENTED,
                    uoe.getMessage());
            return;
        } catch (Throwable throwable) {
            if (Throwables2.getFirstThrowableOfType(throwable,
                    AuthorizationException.class) != null) {
                S3ErrorCode code = S3ErrorCode.ACCESS_DENIED;
                handler.sendSimpleErrorResponse(request, response, code,
                        code.getMessage(), Map.of());
                return;
            } else if (Throwables2.getFirstThrowableOfType(throwable,
                    TimeoutException.class) != null) {
                S3ErrorCode code = S3ErrorCode.REQUEST_TIMEOUT;
                handler.sendSimpleErrorResponse(request, response, code,
                        code.getMessage(), Map.of());
                return;
            } else {
                logger.debug("Unknown exception:", throwable);
                throw throwable;
            }
        } finally {
            recordMetrics(request, response, ctx, startNanos);
        }
    }

    private void recordMetrics(HttpServletRequest request,
            HttpServletResponse response, S3ProxyHandler.RequestContext ctx,
            long startNanos) {
        if (metrics == null || ctx.getOperation() == null) {
            return;
        }
        long durationNanos = System.nanoTime() - startNanos;
        metrics.recordRequest(
                request.getMethod(),
                request.getScheme(),
                response.getStatus(),
                ctx.getOperation(),
                ctx.getBucket(),
                durationNanos);
    }

    public S3ProxyHandler getHandler() {
        return this.handler;
    }
}
