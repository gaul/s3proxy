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

public final class S3ProxyConstants {
    public static final String PROPERTY_ENDPOINT =
            "s3proxy.endpoint";
    public static final String PROPERTY_SECURE_ENDPOINT =
            "s3proxy.secure-endpoint";
    public static final String PROPERTY_AUTHORIZATION =
            "s3proxy.authorization";
    public static final String PROPERTY_IDENTITY =
            "s3proxy.identity";
    /**
     * Path to prepend to all requests, e.g.,
     * https://endpoint/service-path/object.
     */
    public static final String PROPERTY_SERVICE_PATH =
            "s3proxy.service-path";
    /** When true, include "Access-Control-Allow-Origin: *" in all responses. */
    public static final String PROPERTY_CORS_ALLOW_ALL =
            "s3proxy.cors-allow-all";
    public static final String PROPERTY_CORS_ALLOW_ORIGINS =
            "s3proxy.cors-allow-origins";
    public static final String PROPERTY_CORS_ALLOW_METHODS =
            "s3proxy.cors-allow-methods";
    public static final String PROPERTY_CORS_ALLOW_HEADERS =
            "s3proxy.cors-allow-headers";
    public static final String PROPERTY_CREDENTIAL =
            "s3proxy.credential";
    public static final String PROPERTY_IGNORE_UNKNOWN_HEADERS =
            "s3proxy.ignore-unknown-headers";
    public static final String PROPERTY_KEYSTORE_PATH =
            "s3proxy.keystore-path";
    public static final String PROPERTY_KEYSTORE_PASSWORD =
            "s3proxy.keystore-password";
    public static final String PROPERTY_JETTY_MAX_THREADS =
            "s3proxy.jetty.max-threads";

    /** Request attributes. */
    public static final String ATTRIBUTE_QUERY_ENCODING = "queryEncoding";

    /**
     * Configure servicing of virtual host buckets.  Setting to localhost:8080
     * allows bucket-in-hostname requests, e.g., bucketname.localhost:8080.
     * This mode requires configuring DNS to forward all requests to the
     * S3Proxy host.
     */
    public static final String PROPERTY_VIRTUAL_HOST =
            "s3proxy.virtual-host";
    public static final String PROPERTY_V4_MAX_NON_CHUNKED_REQUEST_SIZE =
            "s3proxy.v4-max-non-chunked-request-size";
    /** When true, model eventual consistency using two storage backends. */
    public static final String PROPERTY_EVENTUAL_CONSISTENCY =
            "s3proxy.eventual-consistency";
    /**
     * Minimum delay, in seconds, when propagating modifications from the
     * write backend to the read backend.
     */
    public static final String PROPERTY_EVENTUAL_CONSISTENCY_DELAY =
            "s3proxy.eventual-consistency.delay";
    /** Probability of eventual consistency, between 0.0 and 1.0. */
    public static final String PROPERTY_EVENTUAL_CONSISTENCY_PROBABILITY =
            "s3proxy.eventual-consistency.probability";
    /** Discard object data. */
    public static final String PROPERTY_NULL_BLOBSTORE =
            "s3proxy.null-blobstore";
    /** Prevent mutations. */
    public static final String PROPERTY_READ_ONLY_BLOBSTORE =
            "s3proxy.read-only-blobstore";

    /** Maximum time skew allowed in signed requests. */
    public static final String PROPERTY_MAXIMUM_TIME_SKEW =
            "s3proxy.maximum-timeskew";

    static final String PROPERTY_ALT_JCLOUDS_PREFIX = "alt.";

    private S3ProxyConstants() {
        throw new AssertionError("Cannot instantiate utility constructor");
    }
}
