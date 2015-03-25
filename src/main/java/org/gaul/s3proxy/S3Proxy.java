/*
 * Copyright 2014-2015 Andrew Gaul <andrew@gaul.org>
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

import static java.util.Objects.requireNonNull;

import static com.google.common.base.Preconditions.checkArgument;

import java.net.URI;

import com.google.common.base.Optional;
import com.google.common.base.Strings;

import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.jclouds.blobstore.BlobStore;

/**
 * S3Proxy translates S3 HTTP operations into jclouds provider-agnostic
 * operations.  This allows applications using the S3 API to interface with any
 * provider that jclouds supports, e.g., EMC Atmos, Microsoft Azure,
 * OpenStack Swift.
 */
public final class S3Proxy {
    private final Server server;
    private final S3ProxyHandler handler;

    static {
        // Prevent Jetty from rewriting headers:
        // https://bugs.eclipse.org/bugs/show_bug.cgi?id=414449
        System.setProperty("org.eclipse.jetty.http.HttpParser.STRICT", "true");
    }

    S3Proxy(BlobStore blobStore, URI endpoint, String identity,
            String credential, String keyStorePath, String keyStorePassword,
            Optional<String> virtualHost) {
        requireNonNull(blobStore);
        requireNonNull(endpoint);
        // TODO: allow service paths?
        checkArgument(endpoint.getPath().isEmpty(),
                "endpoint path must be empty, was: %s", endpoint.getPath());
        checkArgument(Strings.isNullOrEmpty(identity) ^
                !Strings.isNullOrEmpty(credential),
                "Must provide both identity and credential");
        if (endpoint.getScheme().equals("https:")) {
            requireNonNull(keyStorePath,
                    "Must provide keyStorePath with HTTPS endpoint");
            requireNonNull(keyStorePassword,
                    "Must provide keyStorePassword with HTTPS endpoint");
        }
        requireNonNull(virtualHost);

        server = new Server();
        HttpConnectionFactory httpConnectionFactory =
                new HttpConnectionFactory();
        ServerConnector connector;
        if (endpoint.getScheme().equals("https")) {
            SslContextFactory sslContextFactory = new SslContextFactory();
            sslContextFactory.setKeyStorePath(keyStorePath);
            sslContextFactory.setKeyStorePassword(keyStorePassword);
            connector = new ServerConnector(server, sslContextFactory,
                    httpConnectionFactory);
        } else {
            connector = new ServerConnector(server, httpConnectionFactory);
        }
        connector.setHost(endpoint.getHost());
        connector.setPort(endpoint.getPort());
        server.addConnector(connector);
        handler = new S3ProxyHandler(blobStore, identity, credential,
                virtualHost);
        server.setHandler(handler);
    }

    public static final class Builder {
        private BlobStore blobStore;
        private URI endpoint;
        private String identity;
        private String credential;
        private String keyStorePath;
        private String keyStorePassword;
        private String virtualHost;

        Builder() {
        }

        public S3Proxy build() {
            return new S3Proxy(blobStore, endpoint, identity, credential,
                    keyStorePath, keyStorePassword,
                    Optional.fromNullable(virtualHost));
        }

        public Builder blobStore(BlobStore blobStore) {
            this.blobStore = requireNonNull(blobStore);
            return this;
        }

        public Builder endpoint(URI endpoint) {
            this.endpoint = requireNonNull(endpoint);
            return this;
        }

        public Builder awsAuthentication(String identity, String credential) {
            this.identity = requireNonNull(identity);
            this.credential = requireNonNull(credential);
            return this;
        }

        public Builder keyStore(String keyStorePath, String keyStorePassword) {
            this.keyStorePath = requireNonNull(keyStorePath);
            this.keyStorePassword = requireNonNull(keyStorePassword);
            return this;
        }

        public Builder virtualHost(String virtualHost) {
            this.virtualHost = requireNonNull(virtualHost);
            return this;
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    public void start() throws Exception {
        server.start();
    }

    public void stop() throws Exception {
        server.stop();
    }

    public int getPort() {
        return ((ServerConnector) server.getConnectors()[0]).getLocalPort();
    }

    public String getState() {
        return server.getState();
    }

    public void setBlobStoreLocator(BlobStoreLocator lookup) {
        handler.setBlobStoreLocator(lookup);
    }

}
