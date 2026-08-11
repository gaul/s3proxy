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
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeoutException;

import com.google.common.base.Throwables;
import com.google.common.net.HttpHeaders;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.gaul.s3proxy.auth.AuthenticationType;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.S3Exceptions;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import software.amazon.awssdk.awscore.exception.AwsServiceException;

/** Jetty-specific handler for S3 requests. */
final class S3ProxyHandlerJetty extends HttpServlet {
    private static final Logger logger = LoggerFactory.getLogger(
            S3ProxyHandlerJetty.class);

    private final S3ProxyHandler handler;
    @Nullable private final S3ProxyMetrics metrics;

    S3ProxyHandlerJetty(final BlobStore blobStore,
            AuthenticationType authenticationType,
            @Nullable final String identity,
            @Nullable final String credential, @Nullable String virtualHost,
            long maxSinglePartObjectSize, long v4MaxNonChunkedRequestSize,
            int v4MaxChunkSize,
            boolean ignoreUnknownHeaders,
            @Nullable CrossOriginResourceSharing corsRules,
            @Nullable String servicePath, int maximumTimeSkew,
            @Nullable S3ProxyMetrics metrics) {
        handler = new S3ProxyHandler(blobStore, authenticationType, identity,
                credential, virtualHost, maxSinglePartObjectSize,
                v4MaxNonChunkedRequestSize, v4MaxChunkSize,
                ignoreUnknownHeaders, corsRules,
                servicePath, maximumTimeSkew);
        this.metrics = metrics;
    }

    private void sendErrorResponse(HttpServletRequest request,
            HttpServletResponse response, S3ErrorCode code)
            throws IOException {
        handler.sendSimpleErrorResponse(request, response, code,
                code.getMessage(), Map.of());
    }

    @Override
    protected void service(HttpServletRequest request,
            HttpServletResponse response)
            throws IOException {
        long startNanos = System.nanoTime();
        var ctx = new S3ProxyHandler.RequestContext();

        try (InputStream is = request.getInputStream()) {

            handler.doHandle(request, request, response, is, ctx);
        } catch (IllegalArgumentException iae) {
            logger.debug("IllegalArgumentException:", iae);
            response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                    iae.getMessage());
            return;
        } catch (IllegalStateException ise) {
            // google-cloud-storage uses a different exception
            String message = ise.getMessage();
            if (message != null && message.startsWith("PreconditionFailed")) {
                sendErrorResponse(request, response,
                        S3ErrorCode.PRECONDITION_FAILED);
                return;
            }
            logger.debug("IllegalStateException:", ise);
            response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                    ise.getMessage());
            return;
        } catch (IOException ioe) {
            var cause = Throwables.getCausalChain(ioe).stream()
                    .filter(AwsServiceException.class::isInstance)
                    .map(AwsServiceException.class::cast)
                    .findFirst()
                    .orElse(null);
            if (cause != null) {
                handleAwsServiceException(request, response, cause);
                return;
            }
            throw ioe;
        } catch (AwsServiceException ase) {
            handleAwsServiceException(request, response, ase);
            return;
        } catch (UnsupportedOperationException uoe) {
            logger.debug("UnsupportedOperationException:", uoe);
            response.sendError(HttpServletResponse.SC_NOT_IMPLEMENTED,
                    uoe.getMessage());
            return;
        } catch (Throwable throwable) {
            var causes = Throwables.getCausalChain(throwable);
            // A body-validation error, e.g. BadDigest from a checksum
            // mismatch thrown while reading the payload, may arrive wrapped
            // in an unchecked exception; surface the original error code.
            var s3 = causes.stream()
                    .filter(AwsServiceException.class::isInstance)
                    .map(AwsServiceException.class::cast)
                    .findFirst()
                    .orElse(null);
            if (s3 != null) {
                handleAwsServiceException(request, response, s3);
                return;
            }
            if (causes.stream().anyMatch(
                    TimeoutException.class::isInstance)) {
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

    /**
     * Renders a backend error.  These arrive as AWS SDK exceptions: the
     * aws-s3-sdk backend rethrows its service's errors verbatim while the
     * other backends fabricate S3-shaped ones via {@link S3Exceptions}.
     * The S3 error code the exception carries renders as-is; one carrying
     * none, only a status, maps to an error document by status.
     */
    private void handleAwsServiceException(HttpServletRequest request,
            HttpServletResponse response, AwsServiceException ase)
            throws IOException {
        // e.g. the ETag a 304 Not Modified echoes, or x-amz-delete-marker
        // and x-amz-version-id riding on a versioned backend's refusal to
        // read a delete marker
        var backendResponse = S3Exceptions.httpResponse(ase);
        if (backendResponse != null) {
            for (String header : List.of(HttpHeaders.ETAG,
                    AwsHttpHeaders.DELETE_MARKER, AwsHttpHeaders.VERSION_ID,
                    HttpHeaders.ALLOW)) {
                backendResponse.firstMatchingHeader(header).ifPresent(
                        value -> response.setHeader(header, value));
            }
        }

        String code = S3Exceptions.errorCode(ase);
        if (code != null) {
            String message = ase.awsErrorDetails().errorMessage();
            // the ordered elements some error documents carry beside Code
            // and Message, e.g. StringToSign on SignatureDoesNotMatch
            Map<String, String> elements =
                    ase instanceof S3ProxyException pe ?
                            pe.getElements() : Map.of();
            handler.sendSimpleErrorResponse(request, response, code,
                    ase.statusCode(), message == null ? "" : message,
                    elements);
            return;
        }

        int status = ase.statusCode();
        switch (status) {
        case 412 -> {
            // Backends report any conditional-header failure as 412.
            // Per the S3/HTTP spec, GET/HEAD with If-None-Match (or
            // If-Modified-Since) failing maps to 304 Not Modified, not
            // 412.  Disambiguate by inspecting the original request.
            String method = request.getMethod();
            boolean notModified =
                    ("GET".equals(method) || "HEAD".equals(method)) &&
                    request.getHeader(HttpHeaders.IF_MATCH) == null &&
                    request.getDateHeader(
                            HttpHeaders.IF_UNMODIFIED_SINCE) == -1 &&
                    (request.getHeader(HttpHeaders.IF_NONE_MATCH) != null ||
                     request.getDateHeader(
                             HttpHeaders.IF_MODIFIED_SINCE) != -1);
            if (notModified) {
                response.setStatus(HttpServletResponse.SC_NOT_MODIFIED);
            } else {
                sendErrorResponse(request, response,
                        S3ErrorCode.PRECONDITION_FAILED);
            }
        }
        case 416 -> sendErrorResponse(request, response,
                S3ErrorCode.INVALID_RANGE);
        case HttpServletResponse.SC_METHOD_NOT_ALLOWED ->
            sendErrorResponse(request, response,
                    S3ErrorCode.METHOD_NOT_ALLOWED);
        // Swift returns 422 Unprocessable Entity
        case HttpServletResponse.SC_BAD_REQUEST, 422 -> sendErrorResponse(
                request, response, S3ErrorCode.BAD_DIGEST);
        // Backends report authorization failures as 403; surface a proper
        // AccessDenied error document rather than a bare 403 status.
        case HttpServletResponse.SC_FORBIDDEN -> sendErrorResponse(
                request, response, S3ErrorCode.ACCESS_DENIED);
        default -> {
            logger.debug("AwsServiceException:", ase);
            response.setStatus(status);
        }
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
