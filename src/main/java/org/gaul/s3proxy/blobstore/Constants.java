/*
 * Copyright 2009-2025 The Apache Software Foundation
 * Copyright 2026 Andrew Gaul <andrew@gaul.org>
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

package org.gaul.s3proxy.blobstore;

public final class Constants {

    public static final String PROPERTY_PROVIDER = "jclouds.provider";
    public static final String PROPERTY_ENDPOINT = "jclouds.endpoint";
    public static final String PROPERTY_IDENTITY = "jclouds.identity";
    public static final String PROPERTY_CREDENTIAL = "jclouds.credential";
    public static final String PROPERTY_REGION = "jclouds.region";

    // TODO: fake owner
    /** The account S3Proxy claims owns everything a store without one holds. */
    public static final String OWNER_ID =
            "75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a";
    public static final String OWNER_DISPLAY_NAME = "CustomersName@amazon.com";

    /** The group naming everyone, which is how S3 spells a public grant. */
    public static final String ALL_USERS_URI =
            "http://acs.amazonaws.com/groups/global/AllUsers";

    private Constants() {
    }
}
