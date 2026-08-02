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
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import jakarta.servlet.http.HttpServletResponse;

import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.http.UriCompliance;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.server.handler.ErrorHandler;
import org.eclipse.jetty.util.Callback;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Renders the errors Jetty answers on its own as the XML document an S3 client
 * expects.  A request whose request line or headers the parser rejects never
 * reaches S3ProxyHandler, so without this Jetty replies with its HTML error
 * page or with no body at all, and a client reports an unparseable response
 * instead of the error.
 */
final class S3ErrorHandler extends ErrorHandler {
    private static final Logger logger = LoggerFactory.getLogger(
            S3ErrorHandler.class);

    /**
     * The method Jetty gives the request it synthesizes when the parser
     * failed before reading a request line, i.e., when the URI itself is what
     * it could not read.  See HttpConnection.badMessage.
     */
    private static final String BAD_MESSAGE_METHOD = "BAD";

    /**
     * Jetty writes an error page only for the methods a browser follows one
     * with, which leaves a rejected PUT or DELETE -- most of the S3 API --
     * answering a status and nothing else.  Every method gets the document
     * here since an S3 client parses one whatever it asked for.
     */
    @Override
    public boolean errorPageForMethod(String method) {
        return true;
    }

    @Override
    protected void generateResponse(Request request, Response response,
            int code, @Nullable String message, @Nullable Throwable cause,
            Callback callback) throws IOException {
        S3ErrorCode errorCode = errorCode(request, code);
        logger.debug("rendering Jetty error {} {} as {}", code, message,
                errorCode, cause);

        // Deliberately writes S3ErrorCode's own message rather than Jetty's,
        // which quotes the offending bytes and names Jetty internals.
        String requestId = S3ProxyHandler.generateRequestId();
        byte[] xml = ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
                "<Error><Code>" + errorCode.getErrorCode() +
                "</Code><Message>" + errorCode.getMessage() +
                "</Message><RequestId>" + requestId +
                "</RequestId></Error>").getBytes(StandardCharsets.UTF_8);

        response.getHeaders().put(HttpHeader.CONTENT_TYPE,
                "application/xml;charset=utf-8");
        response.getHeaders().put(AwsHttpHeaders.REQUEST_ID, requestId);
        // Jetty suppresses the body of a HEAD response when generating it.
        response.write(/*last=*/ true, ByteBuffer.wrap(xml), callback);
    }

    /**
     * Names the failure with the closest S3 error code.  The status stays
     * whatever Jetty chose since HTTP mandates some of them, e.g., 417 for an
     * Expect it cannot meet, so a code whose usual status differs does not
     * change the response.
     */
    private static S3ErrorCode errorCode(Request request, int code) {
        if (code == HttpServletResponse.SC_REQUEST_URI_TOO_LONG ||
                (code == HttpServletResponse.SC_BAD_REQUEST &&
                        isUriFailure(request))) {
            return S3ErrorCode.INVALID_U_R_I;
        }
        return switch (code) {
        case HttpServletResponse.SC_METHOD_NOT_ALLOWED ->
            S3ErrorCode.METHOD_NOT_ALLOWED;
        case HttpServletResponse.SC_LENGTH_REQUIRED ->
            S3ErrorCode.MISSING_CONTENT_LENGTH;
        case HttpServletResponse.SC_NOT_IMPLEMENTED ->
            S3ErrorCode.NOT_IMPLEMENTED;
        default -> code >= HttpServletResponse.SC_INTERNAL_SERVER_ERROR ?
            S3ErrorCode.INTERNAL_ERROR : S3ErrorCode.INVALID_REQUEST;
        };
    }

    /**
     * Whether the URI is what Jetty refused.  Two ways it can be: the parser
     * gave up before reading a request line, leaving the synthesized method,
     * or the URI parsed but broke a rule the configured UriCompliance does
     * not waive, which is what Jetty itself tests before rejecting it.  Asking
     * the request rather than reading Jetty's message keeps this working when
     * the message is only a status phrase.
     */
    private static boolean isUriFailure(Request request) {
        if (BAD_MESSAGE_METHOD.equals(request.getMethod())) {
            return true;
        }
        UriCompliance compliance = request.getConnectionMetaData()
                .getHttpConfiguration().getUriCompliance();
        for (var violation : request.getHttpURI().getViolations()) {
            if (!compliance.allows(violation)) {
                return true;
            }
        }
        return false;
    }
}
