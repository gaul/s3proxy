package org.gaul.s3proxy;

import org.eclipse.jetty.server.Request;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public final class S3ProxyAccessLogger implements AccessLogger {
    @Override
    public void logRequest(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response) {
        return;
    }

    @Override
    public void logResponse(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response) {
        return;
    }
}
