/*
 * Copyright 2014-2025 Andrew Gaul <andrew@gaul.org>
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
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.google.common.base.Joiner;
import com.google.common.base.Splitter;
import com.google.common.base.Strings;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class CrossOriginResourceSharing {
    protected static final List<String> SUPPORTED_METHODS =
            List.of("GET", "HEAD", "PUT", "POST", "DELETE");

    private static final String HEADER_VALUE_SEPARATOR = ", ";
    private static final String ALLOW_ANY_ORIGIN = "*";
    private static final String ALLOW_ANY_HEADER = "*";
    private static final String EXPOSE_ALL_HEADERS = "*";
    private static final String ALLOW_CREDENTIALS = "true";

    private static final Logger logger = LoggerFactory.getLogger(
            CrossOriginResourceSharing.class);

    private final String allowedMethodsRaw;
    private final String allowedHeadersRaw;
    private final String exposedHeadersRaw;
    private final boolean anyOriginAllowed;
    // Enforce ordering of values
    private final List<Pattern> allowedOrigins;
    private final List<String> allowedMethods;
    private final List<String> allowedHeaders;
    private final List<String> exposedHeaders;
    private final String allowCredentials;

    public CrossOriginResourceSharing() {
        // CORS Allow all
        this(List.of(ALLOW_ANY_ORIGIN), SUPPORTED_METHODS,
            List.of(ALLOW_ANY_HEADER),
            List.of(EXPOSE_ALL_HEADERS), "");
    }

    public CrossOriginResourceSharing(List<String> allowedOrigins,
            List<String> allowedMethods,
            List<String> allowedHeaders,
            List<String> exposedHeaders,
            String allowCredentials) {
        Set<Pattern> allowedPattern = new HashSet<Pattern>();
        boolean anyOriginAllowed = false;

        if (allowedOrigins != null) {
            if (allowedOrigins.contains(ALLOW_ANY_ORIGIN)) {
                anyOriginAllowed = true;
            } else {
                for (String origin : allowedOrigins) {
                    allowedPattern.add(Pattern.compile(
                        origin, Pattern.CASE_INSENSITIVE));
                }
            }
        }
        this.anyOriginAllowed = anyOriginAllowed;
        this.allowedOrigins = List.copyOf(allowedPattern);

        if (allowedMethods == null) {
            this.allowedMethods = List.of();
        } else {
            this.allowedMethods = List.copyOf(allowedMethods);
        }
        this.allowedMethodsRaw = Joiner.on(HEADER_VALUE_SEPARATOR).join(
                this.allowedMethods);

        if (allowedHeaders == null) {
            this.allowedHeaders = List.of();
        } else {
            this.allowedHeaders = List.copyOf(allowedHeaders);
        }
        this.allowedHeadersRaw = Joiner.on(HEADER_VALUE_SEPARATOR).join(
                this.allowedHeaders);

        if (exposedHeaders == null) {
            this.exposedHeaders = List.of();
        } else {
            this.exposedHeaders = List.copyOf(exposedHeaders);
        }
        this.exposedHeadersRaw = Joiner.on(HEADER_VALUE_SEPARATOR).join(
                this.exposedHeaders);

        this.allowCredentials = allowCredentials;

        logger.info("CORS allowed origins: {}", allowedOrigins);
        logger.info("CORS allowed methods: {}", allowedMethods);
        logger.info("CORS allowed headers: {}", allowedHeaders);
        logger.info("CORS exposed headers: {}", exposedHeaders);
        logger.info("CORS allow credentials: {}", allowCredentials);
    }

    public String getAllowedMethods() {
        return this.allowedMethodsRaw;
    }

    public String getExposedHeaders() {
        return this.exposedHeadersRaw;
    }

    public String getAllowedOrigin(String origin) {
        if (this.anyOriginAllowed) {
            return ALLOW_ANY_ORIGIN;
        } else {
            return origin;
        }
    }

    public boolean isOriginAllowed(String origin) {
        if (!Strings.isNullOrEmpty(origin)) {
            if (this.anyOriginAllowed) {
                logger.debug("CORS origin allowed: {}", origin);
                return true;
            } else {
                for (Pattern pattern : this.allowedOrigins) {
                    Matcher matcher = pattern.matcher(origin);
                    if (matcher.matches()) {
                        logger.debug("CORS origin allowed: {}", origin);
                        return true;
                    }
                }
            }
        }
        logger.debug("CORS origin not allowed: {}", origin);
        return false;
    }

    public boolean isMethodAllowed(String method) {
        if (!Strings.isNullOrEmpty(method)) {
            if (this.allowedMethods.contains(method)) {
                logger.debug("CORS method allowed: {}", method);
                return true;
            }
        }
        logger.debug("CORS method not allowed: {}", method);
        return false;
    }

    public boolean isEveryHeaderAllowed(String headers) {
        boolean result = false;

        if (!Strings.isNullOrEmpty(headers)) {
            if (this.allowedHeadersRaw.equals(ALLOW_ANY_HEADER)) {
                result = true;
            } else {
                for (String header : Splitter.on(HEADER_VALUE_SEPARATOR).split(
                        headers)) {
                    result = this.allowedHeaders.contains(header);
                    if (!result) {
                        // First not matching header breaks
                        break;
                    }
                }
            }
        }

        if (result) {
            logger.debug("CORS headers allowed: {}", headers);
        } else {
            logger.debug("CORS headers not allowed: {}", headers);
        }

        return result;
    }

    public boolean isAllowCredentials() {
        return ALLOW_CREDENTIALS.equals(allowCredentials);
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) {
            return true;
        }
        if (object == null || !(object instanceof CrossOriginResourceSharing)) {
            return false;
        }

        CrossOriginResourceSharing that = (CrossOriginResourceSharing) object;
        return this.allowedOrigins.equals(that.allowedOrigins) &&
                this.allowedMethodsRaw.equals(that.allowedMethodsRaw) &&
                this.allowedHeadersRaw.equals(that.allowedHeadersRaw);
    }

    @Override
    public int hashCode() {
        return Objects.hash(this.allowedOrigins, this.allowedMethodsRaw,
                this.allowedHeadersRaw);
    }
}
