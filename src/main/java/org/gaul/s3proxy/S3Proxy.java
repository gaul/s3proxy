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

import com.google.common.base.Preconditions;

import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
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
    static final String PROPERTY_S3PROXY_ENDPOINT = "s3proxy.endpoint";
    private static final String PROPERTY_S3PROXY_AUTHORIZATION =
            "s3proxy.authorization";
    static final String PROPERTY_S3PROXY_IDENTITY = "s3proxy.identity";
    static final String PROPERTY_S3PROXY_CREDENTIAL = "s3proxy.credential";

    private final Server server;

    static {
        // Prevent Jetty from rewriting headers:
        // https://bugs.eclipse.org/bugs/show_bug.cgi?id=414449
        System.setProperty("org.eclipse.jetty.http.HttpParser.STRICT", "true");
    }

    public S3Proxy(BlobStore blobStore, URI endpoint, String identity,
            String credential) {
        Preconditions.checkNotNull(blobStore);
        Preconditions.checkNotNull(endpoint);
        // TODO: allow service paths?
        Preconditions.checkArgument(endpoint.getPath().isEmpty(),
                "endpoint path must be empty, was: " + endpoint.getPath());

        server = new Server();
        HttpConnectionFactory httpConnectionFactory =
                new HttpConnectionFactory();
        ServerConnector connector = new ServerConnector(server,
                httpConnectionFactory);
        connector.setHost(endpoint.getHost());
        connector.setPort(endpoint.getPort());
        server.addConnector(connector);
        server.setHandler(new S3ProxyHandler(blobStore, identity, credential));
    }

    public void start() throws Exception {
        server.start();
    }

    public void stop() throws Exception {
        server.stop();
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
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
                PROPERTY_S3PROXY_ENDPOINT);
        String s3ProxyAuthorization = properties.getProperty(
                PROPERTY_S3PROXY_AUTHORIZATION);
        if (provider == null || identity == null || credential == null
                || s3ProxyEndpointString == null
                || s3ProxyAuthorization == null) {
            System.err.println("Properties file must contain:\n" +
                    Constants.PROPERTY_PROVIDER + "\n" +
                    Constants.PROPERTY_IDENTITY + "\n" +
                    Constants.PROPERTY_CREDENTIAL + "\n" +
                    PROPERTY_S3PROXY_ENDPOINT + "\n" +
                    PROPERTY_S3PROXY_AUTHORIZATION);
            System.exit(1);
        }

        String localIdentity = null;
        String localCredential = null;
        if (s3ProxyAuthorization.equalsIgnoreCase("aws-v2")) {
            localIdentity = properties.getProperty(PROPERTY_S3PROXY_IDENTITY);
            localCredential = properties.getProperty(
                    PROPERTY_S3PROXY_CREDENTIAL);
            if (localIdentity == null || localCredential == null) {
                System.err.println("Both " + PROPERTY_S3PROXY_IDENTITY +
                        " and " + PROPERTY_S3PROXY_CREDENTIAL +
                        " must be set");
                System.exit(1);
            }
        } else if (!s3ProxyAuthorization.equalsIgnoreCase("none")) {
            System.err.println(PROPERTY_S3PROXY_AUTHORIZATION +
                    " must be aws-v2 or none, was: " + s3ProxyAuthorization);
            System.exit(1);
        }

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
                localIdentity, localCredential);
        s3Proxy.start();
    }
}
