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

import java.util.Collection;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.google.common.base.Joiner;
import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Lists;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

final class CrossOriginResourceSharing {
    private static final String HEADER_VALUE_SEPARATOR = ", ";
    private static final String ALLOW_ANY_HEADER = "*";

    private static final Logger logger = LoggerFactory.getLogger(
            CrossOriginResourceSharing.class);

    private final String allowedMethodsRaw;
    private final String allowedHeadersRaw;
    private final Set<Pattern> allowedOrigins;
    private final Set<String> allowedMethods;
    private final Set<String> allowedHeaders;

    protected CrossOriginResourceSharing() {
        // CORS Allow all
        this(Lists.newArrayList(".*"), Lists.newArrayList("GET", "PUT", "POST"),
                Lists.newArrayList(ALLOW_ANY_HEADER));
    }

    protected CrossOriginResourceSharing(Collection<String> allowedOrigins,
            Collection<String> allowedMethods,
            Collection<String> allowedHeaders) {
        Set<Pattern> allowedPattern = new HashSet<Pattern>();
        if (allowedOrigins != null) {
            for (String origin : allowedOrigins) {
                allowedPattern.add(Pattern.compile(
                        origin, Pattern.CASE_INSENSITIVE));
            }
        }
        this.allowedOrigins = ImmutableSet.copyOf(allowedPattern);

        if (allowedMethods == null) {
            this.allowedMethods = ImmutableSet.of();
        } else {
            this.allowedMethods = ImmutableSet.copyOf(allowedMethods);
        }
        this.allowedMethodsRaw = Joiner.on(HEADER_VALUE_SEPARATOR).join(
                this.allowedMethods);

        if (allowedHeaders == null) {
            this.allowedHeaders = ImmutableSet.of();
        } else {
            this.allowedHeaders = ImmutableSet.copyOf(allowedHeaders);
        }
        this.allowedHeadersRaw = Joiner.on(HEADER_VALUE_SEPARATOR).join(
                this.allowedHeaders);

        logger.info("CORS allowed origins: {}", allowedOrigins);
        logger.info("CORS allowed methods: {}", allowedMethods);
        logger.info("CORS allowed headers: {}", allowedHeaders);
    }

    public String getAllowedMethods() {
        return this.allowedMethodsRaw;
    }

    public boolean isOriginAllowed(String origin) {
        if (!Strings.isNullOrEmpty(origin)) {
            for (Pattern pattern : this.allowedOrigins) {
                Matcher matcher = pattern.matcher(origin);
                if (matcher.matches()) {
                    logger.debug("CORS origin allowed: {}", origin);
                    return true;
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
