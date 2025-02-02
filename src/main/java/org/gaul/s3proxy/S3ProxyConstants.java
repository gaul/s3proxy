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
    public static final String PROPERTY_CORS_EXPOSED_HEADERS =
            "s3proxy.cors-exposed-headers";
    public static final String PROPERTY_CORS_ALLOW_CREDENTIAL =
            "s3proxy.cors-allow-credential";
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
    public static final String PROPERTY_MAX_SINGLE_PART_OBJECT_SIZE =
            "s3proxy.max-single-part-object-size";
    public static final String PROPERTY_V4_MAX_NON_CHUNKED_REQUEST_SIZE =
            "s3proxy.v4-max-non-chunked-request-size";
    /** Used to locate blobstores by specified bucket names. Each property
     * file should contain a list of buckets associated with it, e.g.
     *     s3proxy.bucket-locator.1 = data
     *     s3proxy.bucket-locator.2 = metadata
     *     s3proxy.bucket-locator.3 = other
     * When a request is made for the specified bucket, the backend defined
     * in that properties file is used. This allows using the same
     * credentials in multiple properties file and select the backend based
     * on the bucket names.
     */
    public static final String PROPERTY_BUCKET_LOCATOR =
            "s3proxy.bucket-locator";
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
    /** Alias a backend bucket to an alternate name. */
    public static final String PROPERTY_ALIAS_BLOBSTORE =
            "s3proxy.alias-blobstore";
    /** Alias a backend bucket to an alternate name. */
    public static final String PROPERTY_REGEX_BLOBSTORE =
            "s3proxy.regex-blobstore";
    public static final String PROPERTY_REGEX_BLOBSTORE_MATCH =
            "match";
    public static final String PROPERTY_REGEX_BLOBSTORE_REPLACE =
            "replace";
    /** Discard object data. */
    public static final String PROPERTY_NULL_BLOBSTORE =
            "s3proxy.null-blobstore";
    /** Prevent mutations. */
    public static final String PROPERTY_READ_ONLY_BLOBSTORE =
            "s3proxy.read-only-blobstore";
    /** Shard objects across a specified number of buckets. */
    public static final String PROPERTY_SHARDED_BLOBSTORE =
            "s3proxy.sharded-blobstore";
    /** Override tier when creating blobs. */
    public static final String PROPERTY_STORAGE_CLASS_BLOBSTORE =
            "s3proxy.storage-class-blobstore";

    /** Maximum time skew allowed in signed requests. */
    public static final String PROPERTY_MAXIMUM_TIME_SKEW =
            "s3proxy.maximum-timeskew";

    public static final String PROPERTY_ENCRYPTED_BLOBSTORE =
            "s3proxy.encrypted-blobstore";
    public static final String PROPERTY_ENCRYPTED_BLOBSTORE_PASSWORD =
            "s3proxy.encrypted-blobstore-password";
    public static final String PROPERTY_ENCRYPTED_BLOBSTORE_SALT =
            "s3proxy.encrypted-blobstore-salt";

    public static final String PROPERTY_USER_METADATA_REPLACER =
            "s3proxy.user-metadata-replacer-blobstore";
    public static final String PROPERTY_USER_METADATA_REPLACER_FROM_CHARS =
            "s3proxy.user-metadata-replacer-blobstore.from-chars";
    public static final String PROPERTY_USER_METADATA_REPLACER_TO_CHARS =
            "s3proxy.user-metadata-replacer-blobstore.to-chars";

    static final String PROPERTY_ALT_JCLOUDS_PREFIX = "alt.";

    private S3ProxyConstants() {
        throw new AssertionError("Cannot instantiate utility constructor");
    }
}
