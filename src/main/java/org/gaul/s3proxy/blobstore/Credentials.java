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

import org.jspecify.annotations.Nullable;

/**
 * What a store authenticates to its backend with.  Every store takes these
 * from a {@link com.google.common.base.Supplier} and asks it again for each
 * request it signs rather than keeping the first answer, so a supplier that
 * hands out credentials which expire -- an STS AssumeRole session, a shared
 * access signature, an OAuth token -- keeps working past the first expiry.
 *
 * @param identity the enduring half of the credential: an AWS access key id,
 *     an Azure storage account, a Google Cloud project, or a Swift or SFTP
 *     user name.
 * @param credential its secret: an AWS secret access key, an Azure account
 *     key, a Google service account key in JSON, or a Swift or SFTP password.
 * @param sessionToken the expiring half, where the backend has one: an AWS
 *     session token, an Azure shared access signature, a Google OAuth 2.0
 *     access token, or a Keystone token.  Null or empty when the credential
 *     above names no session, which is what a store built from a durable key
 *     alone sees.
 */
public record Credentials(String identity, String credential,
        @Nullable String sessionToken) {

    /** Credentials naming no session, and so nothing that expires. */
    public Credentials(String identity, String credential) {
        this(identity, credential, /*sessionToken=*/ null);
    }
}
