package org.gaul.s3proxy;

import org.eclipse.jetty.server.Request;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public interface AccessLogger {

    void logRequest(String target, Request baseRequest,
               HttpServletRequest request, HttpServletResponse response);

    void logResponse(String target, Request baseRequest,
                     HttpServletRequest request, HttpServletResponse response);
}
