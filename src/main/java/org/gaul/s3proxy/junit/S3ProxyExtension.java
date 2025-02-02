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

package org.gaul.s3proxy.junit;

import java.net.URI;

import org.gaul.s3proxy.AuthenticationType;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

/**
 * A JUnit 5 Extension that manages an S3Proxy instance which tests
 * can use as an S3 API endpoint.
 */
public final class S3ProxyExtension
        implements AfterEachCallback, BeforeEachCallback {

    private final S3ProxyJunitCore core;

    public static final class Builder {

        private final S3ProxyJunitCore.Builder builder;

        private Builder() {
            builder = new S3ProxyJunitCore.Builder();
        }

        public Builder withCredentials(AuthenticationType authType,
                                       String accessKey, String secretKey) {
            builder.withCredentials(authType, accessKey, secretKey);
            return this;
        }

        public Builder withCredentials(String accessKey, String secretKey) {
            builder.withCredentials(accessKey, secretKey);
            return this;
        }

        public Builder withSecretStore(String path, String password) {
            builder.withSecretStore(path, password);
            return this;
        }

        public Builder withPort(int port) {
            builder.withPort(port);
            return this;
        }

        public Builder withBlobStoreProvider(String blobStoreProvider) {
            builder.withBlobStoreProvider(blobStoreProvider);
            return this;
        }

        public Builder ignoreUnknownHeaders() {
            builder.ignoreUnknownHeaders();
            return this;
        }

        public S3ProxyExtension build() {
            return new S3ProxyExtension(this);
        }
    }

    private S3ProxyExtension(Builder builder) {
        core = new S3ProxyJunitCore(builder.builder);
    }

    public static Builder builder() {
        return new Builder();
    }

    @Override
    public void beforeEach(ExtensionContext extensionContext) throws Exception {
        core.beforeEach();
    }

    @Override
    public void afterEach(ExtensionContext extensionContext) {
        core.afterEach();
    }

    public URI getUri() {
        return core.getUri();
    }

    public String getAccessKey() {
        return core.getAccessKey();
    }

    public String getSecretKey() {
        return core.getSecretKey();
    }
}
