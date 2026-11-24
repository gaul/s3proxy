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

import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

import com.google.common.net.HostAndPort;
import com.google.common.net.InetAddresses;

import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.http.HttpStatus;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.util.Callback;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Refuses a request whose Host is not a name this proxy goes by.
 *
 * A browser keeps web pages away from a proxy that only it can reach, e.g.,
 * one bound to localhost with anonymous authorization, by comparing origins,
 * and an origin is a name, not an address.  A page whose name server answers
 * with the proxy's address the second time it is asked (DNS rebinding) is
 * same-origin with the proxy: no preflight, no Access-Control-Allow-Origin.
 * Its requests differ from the owner's in one thing that a script cannot
 * set, the Host, which is the page's name.  A name that can be pointed at the
 * proxy is never an IP address literal and never under localhost, which
 * browsers resolve themselves, so those are always served, as is a request
 * without any Host, which no browser sends.
 */
final class AllowedHostsHandler extends Handler.Wrapper {
    private static final Logger logger = LoggerFactory.getLogger(
            AllowedHostsHandler.class);
    private static final String LOCALHOST = "localhost";

    private final Set<String> allowedHosts = new HashSet<>();
    /** Names under this one address buckets and are served too. */
    @Nullable private final String virtualHostSuffix;

    AllowedHostsHandler(Handler handler, Iterable<String> allowedHosts,
            @Nullable String virtualHost) {
        super(handler);
        for (String host : allowedHosts) {
            this.allowedHosts.add(host.toLowerCase(Locale.ROOT));
        }
        if (virtualHost != null) {
            virtualHost = virtualHost.toLowerCase(Locale.ROOT);
            this.allowedHosts.add(virtualHost);
            this.virtualHostSuffix = "." + virtualHost;
        } else {
            this.virtualHostSuffix = null;
        }
        logger.info("Refusing requests whose Host is not an IP address, " +
                "localhost or one of {}; {} allows more", this.allowedHosts,
                S3ProxyConstants.PROPERTY_ALLOWED_HOSTS);
    }

    @Override
    public boolean handle(Request request, Response response,
            Callback callback) throws Exception {
        for (String hostHeader : request.getHeaders().getValuesList(
                HttpHeader.HOST)) {
            if (!isAllowed(hostHeader)) {
                logger.debug("refusing Host {}, which is neither this " +
                        "proxy's nor listed in {}", hostHeader,
                        S3ProxyConstants.PROPERTY_ALLOWED_HOSTS);
                Response.writeError(request, response, callback,
                        HttpStatus.FORBIDDEN_403);
                return true;
            }
        }
        return super.handle(request, response, callback);
    }

    private boolean isAllowed(String hostHeader) {
        if (hostHeader.isEmpty()) {
            return true;
        }
        String host;
        try {
            // strips the port and the brackets of an IPv6 literal
            host = HostAndPort.fromString(hostHeader).getHost();
        } catch (IllegalArgumentException iae) {
            return false;
        }
        host = host.toLowerCase(Locale.ROOT);
        return InetAddresses.isInetAddress(host) ||
                host.equals(LOCALHOST) || host.endsWith("." + LOCALHOST) ||
                allowedHosts.contains(host) ||
                (virtualHostSuffix != null &&
                        host.endsWith(virtualHostSuffix));
    }
}
