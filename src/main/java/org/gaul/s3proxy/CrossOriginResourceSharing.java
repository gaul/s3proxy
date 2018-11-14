/*
 * Copyright 2014-2018 Andrew Gaul <andrew@gaul.org>
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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.google.common.base.Joiner;
import com.google.common.base.Strings;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class CrossOriginResourceSharing {
    private static final String VALUE_SEPARATOR = " ";
    private static final String HEADER_VALUE_SEPARATOR = ", ";
    private static final String ALLOW_ANY_HEADER = "*";

    private static final Logger logger = LoggerFactory.getLogger(
            CrossOriginResourceSharing.class);

    private String allowedMethodsRaw;
    private String allowedHeadersRaw;
    private List<Pattern> allowedOrigins;
    private List<String> allowedMethods;
    private List<String> allowedHeaders;

    protected CrossOriginResourceSharing() {
        // CORS Allow all
        this(".+", "GET PUT POST", ALLOW_ANY_HEADER);
    }

    protected CrossOriginResourceSharing(String allowedOrigins,
            String allowedMethods, String allowedHeaders) {
        this.allowedOrigins = new ArrayList<Pattern>();
        for (String origin: allowedOrigins.split(VALUE_SEPARATOR)) {
            this.allowedOrigins.add(
                    Pattern.compile(origin, Pattern.CASE_INSENSITIVE));
        }
        this.allowedMethods = Arrays.asList(allowedMethods.split(
                VALUE_SEPARATOR));
        this.allowedHeaders = Arrays.asList(allowedHeaders.split(
                VALUE_SEPARATOR));

        this.allowedMethodsRaw = Joiner.on(HEADER_VALUE_SEPARATOR).join(
                this.allowedMethods);
        this.allowedHeadersRaw = allowedHeaders;
    }

    public String getAllowedMethods() {
        return this.allowedMethodsRaw;
    }

    public boolean isOriginAllowed(String origin) {
        if (!Strings.isNullOrEmpty(origin)) {
            for (Pattern pattern: this.allowedOrigins) {
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
        if (!this.allowedHeadersRaw.equals(ALLOW_ANY_HEADER)) {
            for (String header: headers.split(HEADER_VALUE_SEPARATOR)) {
                if (!this.allowedHeaders.contains(header)) {
                    logger.debug("CORS headers not allowed: {}", headers);
                    return false;
                }
            }
        }
        logger.debug("CORS headers allowed: {}", headers);
        return true;
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) {
            return true;
        }
        if (object == null || getClass() != object.getClass()) {
            return false;
        }

        CrossOriginResourceSharing that = (CrossOriginResourceSharing) object;
        return this.allowedOrigins.equals(that.allowedOrigins) &&
                this.allowedMethodsRaw.equals(that.allowedMethodsRaw) &&
                this.allowedHeadersRaw.equals(that.allowedHeadersRaw);
    }

    @Override
    public int hashCode() {
        return Objects.hash(this.allowedOrigins.hashCode(),
                this.allowedMethodsRaw, this.allowedHeadersRaw);
    }
}
