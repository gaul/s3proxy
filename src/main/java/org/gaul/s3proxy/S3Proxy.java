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

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.URI;
import java.util.Properties;

import com.google.common.base.Optional;
import com.google.common.base.Preconditions;
import com.google.common.base.Strings;

import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.jclouds.Constants;
import org.jclouds.ContextBuilder;
import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.BlobStoreContext;

/**
 * S3Proxy translates S3 HTTP operations into jclouds provider-agnostic
 * operations.  This allows applications using the S3 API to interface with any
 * provider that jclouds supports, e.g., EMC Atmos, Microsoft Azure,
 * OpenStack Swift.
 */
public final class S3Proxy {
    private final Server server;

    static {
        // Prevent Jetty from rewriting headers:
        // https://bugs.eclipse.org/bugs/show_bug.cgi?id=414449
        System.setProperty("org.eclipse.jetty.http.HttpParser.STRICT", "true");
    }

    S3Proxy(BlobStore blobStore, URI endpoint, String identity,
            String credential, String keyStorePath, String keyStorePassword,
            boolean forceMultiPartUpload, Optional<String> virtualHost) {
        Preconditions.checkNotNull(blobStore);
        Preconditions.checkNotNull(endpoint);
        // TODO: allow service paths?
        Preconditions.checkArgument(endpoint.getPath().isEmpty(),
                "endpoint path must be empty, was: " + endpoint.getPath());

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
        server.setHandler(new S3ProxyHandler(blobStore, identity, credential,
                forceMultiPartUpload, virtualHost));
    }

    public void start() throws Exception {
        server.start();
    }

    public void stop() throws Exception {
        server.stop();
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 1 && args[0].equals("--version")) {
            System.err.println(
                    S3Proxy.class.getPackage().getImplementationVersion());
            System.exit(0);
        } else if (args.length != 2) {
            System.err.println("Usage: s3proxy --properties FILE");
            System.exit(1);
        }
        Properties properties = new Properties();
        try (InputStream is = new FileInputStream(new File(args[1]))) {
            properties.load(is);
        }

        String provider = properties.getProperty(Constants.PROPERTY_PROVIDER);
        String identity = properties.getProperty(Constants.PROPERTY_IDENTITY);
        String credential = properties.getProperty(
                Constants.PROPERTY_CREDENTIAL);
        String endpoint = properties.getProperty(Constants.PROPERTY_ENDPOINT);
        String s3ProxyEndpointString = properties.getProperty(
                S3ProxyConstants.PROPERTY_ENDPOINT);
        String s3ProxyAuthorization = properties.getProperty(
                S3ProxyConstants.PROPERTY_AUTHORIZATION);
        if (provider == null || identity == null || credential == null
                || s3ProxyEndpointString == null
                || s3ProxyAuthorization == null) {
            System.err.println("Properties file must contain:\n" +
                    Constants.PROPERTY_PROVIDER + "\n" +
                    Constants.PROPERTY_IDENTITY + "\n" +
                    Constants.PROPERTY_CREDENTIAL + "\n" +
                    S3ProxyConstants.PROPERTY_ENDPOINT + "\n" +
                    S3ProxyConstants.PROPERTY_AUTHORIZATION);
            System.exit(1);
        }

        String localIdentity = null;
        String localCredential = null;
        if (s3ProxyAuthorization.equalsIgnoreCase("aws-v2")) {
            localIdentity = properties.getProperty(
                    S3ProxyConstants.PROPERTY_IDENTITY);
            localCredential = properties.getProperty(
                    S3ProxyConstants.PROPERTY_CREDENTIAL);
            if (localIdentity == null || localCredential == null) {
                System.err.println(
                        "Both " + S3ProxyConstants.PROPERTY_IDENTITY +
                        " and " + S3ProxyConstants.PROPERTY_CREDENTIAL +
                        " must be set");
                System.exit(1);
            }
        } else if (!s3ProxyAuthorization.equalsIgnoreCase("none")) {
            System.err.println(S3ProxyConstants.PROPERTY_AUTHORIZATION +
                    " must be aws-v2 or none, was: " + s3ProxyAuthorization);
            System.exit(1);
        }

        String keyStorePath = properties.getProperty(
                S3ProxyConstants.PROPERTY_KEYSTORE_PATH);
        String keyStorePassword = properties.getProperty(
                S3ProxyConstants.PROPERTY_KEYSTORE_PASSWORD);
        if (s3ProxyEndpointString.startsWith("https")) {
            if (Strings.isNullOrEmpty(keyStorePath) ||
                    Strings.isNullOrEmpty(keyStorePassword)) {
                System.err.println(
                        "Both " + S3ProxyConstants.PROPERTY_KEYSTORE_PATH +
                        " and " + S3ProxyConstants.PROPERTY_KEYSTORE_PASSWORD +
                        " must be set with an HTTP endpoint");
                System.exit(1);
            }
        }

        String forceMultiPartUpload = properties.getProperty(
                S3ProxyConstants.PROPERTY_FORCE_MULTI_PART_UPLOAD);
        Optional<String> virtualHost = Optional.fromNullable(
                properties.getProperty(
                        S3ProxyConstants.PROPERTY_VIRTUAL_HOST));

        ContextBuilder builder = ContextBuilder
                .newBuilder(provider)
                .credentials(identity, credential)
                .overrides(properties);
        if (endpoint != null) {
            builder = builder.endpoint(endpoint);
        }
        BlobStoreContext context = builder.build(BlobStoreContext.class);
        URI s3ProxyEndpoint = new URI(s3ProxyEndpointString);
        S3Proxy s3Proxy = new S3Proxy(context.getBlobStore(), s3ProxyEndpoint,
                localIdentity, localCredential, keyStorePath,
                keyStorePassword,
                "true".equalsIgnoreCase(forceMultiPartUpload), virtualHost);
        s3Proxy.start();
    }
}
