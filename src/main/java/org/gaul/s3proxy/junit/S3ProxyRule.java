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

package org.gaul.s3proxy.junit;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.util.Properties;

import com.google.common.annotations.Beta;

import org.apache.commons.io.FileUtils;
import org.eclipse.jetty.util.component.AbstractLifeCycle;
import org.gaul.s3proxy.AuthenticationType;
import org.gaul.s3proxy.S3Proxy;
import org.jclouds.ContextBuilder;
import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.BlobStoreContext;
import org.jclouds.blobstore.domain.StorageMetadata;
import org.junit.rules.ExternalResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A JUnit Rule that manages an S3Proxy instance which tests can use as an S3
 * API endpoint.
 */
@Beta
public final class S3ProxyRule extends ExternalResource {
    private static final Logger logger = LoggerFactory.getLogger(
        S3ProxyRule.class);

    private static final String LOCALHOST = "127.0.0.1";

    private final String accessKey;
    private final String secretKey;
    private final String endpointFormat;
    private final S3Proxy s3Proxy;

    private final BlobStoreContext blobStoreContext;
    private URI endpointUri;
    private final File blobStoreLocation;

    public static final class Builder {
        private AuthenticationType authType = AuthenticationType.NONE;
        private String accessKey;
        private String secretKey;
        private String secretStorePath;
        private String secretStorePassword;
        private int port = -1;
        private boolean ignoreUnknownHeaders;
        private String blobStoreProvider = "filesystem";

        private Builder() { }

        public Builder withCredentials(AuthenticationType authType,
                String accessKey, String secretKey) {
            this.authType = authType;
            this.accessKey = accessKey;
            this.secretKey = secretKey;
            return this;
        }

        public Builder withCredentials(String accessKey, String secretKey) {
            return withCredentials(AuthenticationType.AWS_V2_OR_V4, accessKey,
                secretKey);
        }

        public Builder withSecretStore(String path, String password) {
            secretStorePath = path;
            secretStorePassword = password;
            return this;
        }

        public Builder withPort(int port) {
            this.port = port;
            return this;
        }

        public Builder withBlobStoreProvider(String blobStoreProvider) {
            this.blobStoreProvider = blobStoreProvider;
            return this;
        }

        public Builder ignoreUnknownHeaders() {
            ignoreUnknownHeaders = true;
            return this;
        }

        public S3ProxyRule build() {
            return new S3ProxyRule(this);
        }
    }

    private S3ProxyRule(Builder builder) {
        accessKey = builder.accessKey;
        secretKey = builder.secretKey;

        Properties properties = new Properties();
        try {
            blobStoreLocation = Files.createTempDirectory("S3ProxyRule")
                    .toFile();
            properties.setProperty("jclouds.filesystem.basedir",
                blobStoreLocation.getCanonicalPath());
        } catch (IOException e) {
            throw new RuntimeException("Unable to initialize Blob Store", e);
        }

        blobStoreContext = ContextBuilder.newBuilder(
                    builder.blobStoreProvider)
                .credentials(accessKey, secretKey)
                .overrides(properties).build(BlobStoreContext.class);

        S3Proxy.Builder s3ProxyBuilder = S3Proxy.builder()
            .blobStore(blobStoreContext.getBlobStore())
            .awsAuthentication(builder.authType, accessKey, secretKey)
            .ignoreUnknownHeaders(builder.ignoreUnknownHeaders);

        if (builder.secretStorePath != null ||
                builder.secretStorePassword != null) {
            s3ProxyBuilder.keyStore(builder.secretStorePath,
                builder.secretStorePassword);
        }

        int port = builder.port < 0 ? 0 : builder.port;
        endpointFormat = "http://%s:%d";
        String endpoint = String.format(endpointFormat, LOCALHOST, port);
        s3ProxyBuilder.endpoint(URI.create(endpoint));

        s3Proxy = s3ProxyBuilder.build();
    }

    public static Builder builder() {
        return new Builder();
    }

    @Override
    protected void before() throws Throwable {
        logger.debug("S3 proxy is starting");
        s3Proxy.start();
        while (!s3Proxy.getState().equals(AbstractLifeCycle.STARTED)) {
            Thread.sleep(10);
        }
        endpointUri = URI.create(String.format(endpointFormat, LOCALHOST,
                s3Proxy.getPort()));
        logger.debug("S3 proxy is running");
    }

    @Override
    protected void after() {
        logger.debug("S3 proxy is stopping");
        try {
            s3Proxy.stop();
            BlobStore blobStore = blobStoreContext.getBlobStore();
            for (StorageMetadata metadata : blobStore.list()) {
                blobStore.deleteContainer(metadata.getName());
            }
            blobStoreContext.close();
        } catch (Exception e) {
            throw new RuntimeException("Unable to stop S3 proxy", e);
        }
        FileUtils.deleteQuietly(blobStoreLocation);
        logger.debug("S3 proxy has stopped");
    }

    public URI getUri() {
        return endpointUri;
    }

    public String getAccessKey() {
        return accessKey;
    }

    public String getSecretKey() {
        return secretKey;
    }

}
