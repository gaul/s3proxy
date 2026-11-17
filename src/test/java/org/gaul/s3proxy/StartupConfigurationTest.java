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

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import java.util.HashMap;
import java.util.Properties;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.middleware.Middlewares;
import org.junit.jupiter.api.Test;

/**
 * A setting left out is a configuration error and is reported as one.
 * These were NullPointerExceptions, which Main does not catch: the operator
 * got a stack trace naming S3Proxy's internals for a missing property.
 */
public final class StartupConfigurationTest {
    @Test
    public void testSecureEndpointWithoutKeyStore() throws Exception {
        BlobStore blobStore = TestUtils.createTransientBlobStore();
        assertThatThrownBy(() -> S3Proxy.builder()
                .blobStore(blobStore)
                .secureEndpoint(URI.create("https://127.0.0.1:0"))
                .build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("keyStorePath");
    }

    @Test
    public void testOneIdentityWithTwoCredentials() {
        var credentials = new HashMap<String, String>();
        Main.checkSameCredential(credentials, "identity", "credential");
        // the same pair again is two backends behind one account
        Main.checkSameCredential(credentials, "identity", "credential");
        Main.checkSameCredential(credentials, "other", "another");
        assertThatThrownBy(() -> Main.checkSameCredential(credentials,
                "identity", "another"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("identity");
    }

    @Test
    public void testUserMetadataReplacerWithoutCharacters() throws Exception {
        BlobStore blobStore = TestUtils.createTransientBlobStore();
        var properties = new Properties();
        properties.setProperty(
                S3ProxyConstants.PROPERTY_USER_METADATA_REPLACER, "true");
        assertThatThrownBy(() -> Middlewares.wrap(blobStore, properties,
                unused -> blobStore))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining(S3ProxyConstants
                        .PROPERTY_USER_METADATA_REPLACER_FROM_CHARS);
    }
}
