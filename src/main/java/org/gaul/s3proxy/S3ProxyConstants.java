/*
 * Copyright 2014 Andrew Gaul <andrew@gaul.org>
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

public final class S3ProxyConstants {
    public static final String PROPERTY_ENDPOINT =
            "s3proxy.endpoint";
    public static final String PROPERTY_AUTHORIZATION =
            "s3proxy.authorization";
    public static final String PROPERTY_IDENTITY =
            "s3proxy.identity";
    public static final String PROPERTY_CREDENTIAL =
            "s3proxy.credential";
    public static final String PROPERTY_KEYSTORE_PATH =
            "s3proxy.keystore-path";
    public static final String PROPERTY_KEYSTORE_PASSWORD =
            "s3proxy.keystore-password";
    /** Force all proxy-server put objects to use multi-part upload. */
    public static final String PROPERTY_FORCE_MULTI_PART_UPLOAD =
            "s3proxy.force-multi-part-upload";

    private S3ProxyConstants() {
        throw new AssertionError("Cannot instantiate utility constructor");
    }
}
