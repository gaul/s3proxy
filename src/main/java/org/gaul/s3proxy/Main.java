/*
 * Copyright 2014-2016 Andrew Gaul <andrew@gaul.org>
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
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.jclouds.blobstore.BlobStore;
import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;
import org.kohsuke.args4j.Option;

public final class Main {
    private Main() {
        throw new AssertionError("intentionally not implemented");
    }

    private static final class Options {
        @Option(name = "--properties",
                usage = "S3Proxy configuration (required)")
        private File propertiesFile;

        @Option(name = "--version", usage = "display version")
        private boolean version;
    }

    public static void main(String[] args) throws Exception {
        Options options = new Options();
        CmdLineParser parser = new CmdLineParser(options);
        try {
            parser.parseArgument(args);
        } catch (CmdLineException cle) {
            usage(parser);
        }

        if (options.version) {
            System.err.println(
                    Main.class.getPackage().getImplementationVersion());
            System.exit(0);
        } else if (options.propertiesFile == null) {
            usage(parser);
        }

        Properties properties = new Properties();
        try (InputStream is = new FileInputStream(options.propertiesFile)) {
            properties.load(is);
        }
        properties.putAll(System.getProperties());

        String s3ProxyEndpointString = properties.getProperty(
                S3ProxyConstants.PROPERTY_ENDPOINT);
        String secureEndpoint = properties.getProperty(
                S3ProxyConstants.PROPERTY_SECURE_ENDPOINT);
        String s3ProxyAuthorization = properties.getProperty(
                S3ProxyConstants.PROPERTY_AUTHORIZATION);
        if ((s3ProxyEndpointString == null && secureEndpoint == null) ||
                s3ProxyAuthorization == null) {
            System.err.println("Properties file must contain:\n" +
                    S3ProxyConstants.PROPERTY_AUTHORIZATION + "\n" +
                    "and one of\n" +
                    S3ProxyConstants.PROPERTY_ENDPOINT + "\n" +
                    S3ProxyConstants.PROPERTY_SECURE_ENDPOINT);
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
                System.err.println("Must specify both " +
                        S3ProxyConstants.PROPERTY_IDENTITY + " and " +
                        S3ProxyConstants.PROPERTY_CREDENTIAL +
                        " when using aws-v2 authentication");
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
        String virtualHost = properties.getProperty(
                S3ProxyConstants.PROPERTY_VIRTUAL_HOST);
        String v4MaxNonChunkedRequestSize = properties.getProperty(
                S3ProxyConstants.PROPERTY_V4_MAX_NON_CHUNKED_REQUEST_SIZE);
        String ignoreUnknownHeaders = properties.getProperty(
                S3ProxyConstants.PROPERTY_IGNORE_UNKNOWN_HEADERS);
        String corsAllowAll = properties.getProperty(
                S3ProxyConstants.PROPERTY_CORS_ALLOW_ALL);

        BlobStore blobStore = S3ProxyHandler.createBlobStore(properties);

        Properties altProperties = new Properties();
        for (Map.Entry<Object, Object> entry : properties.entrySet()) {
            String key = (String) entry.getKey();
            if (key.startsWith(S3ProxyConstants.PROPERTY_ALT_JCLOUDS_PREFIX)) {
                key = key.substring(
                        S3ProxyConstants.PROPERTY_ALT_JCLOUDS_PREFIX.length());
                altProperties.put(key, (String) entry.getValue());
            }
        }

        String eventualConsistency = properties.getProperty(
                S3ProxyConstants.PROPERTY_EVENTUAL_CONSISTENCY);
        if ("true".equalsIgnoreCase(eventualConsistency)) {
            BlobStore altBlobStore = S3ProxyHandler
                    .createBlobStore(altProperties);
            int delay = Integer.parseInt(properties.getProperty(
                    S3ProxyConstants.PROPERTY_EVENTUAL_CONSISTENCY_DELAY,
                    "5"));
            double probability = Double.parseDouble(properties.getProperty(
                    S3ProxyConstants.PROPERTY_EVENTUAL_CONSISTENCY_PROBABILITY,
                    "1.0"));
            System.err.println("Emulating eventual consistency with delay " +
                    delay + " seconds and probability " + (probability * 100) +
                    "%");
            blobStore = EventualBlobStore.newEventualBlobStore(
                    blobStore, altBlobStore,
                    Executors.newScheduledThreadPool(1),
                    delay, TimeUnit.SECONDS, probability);
        }

        S3Proxy s3Proxy;
        try {
            S3Proxy.Builder s3ProxyBuilder = S3Proxy.builder()
                    .blobStore(blobStore);
            if (s3ProxyEndpointString != null) {
                s3ProxyBuilder.endpoint(new URI(s3ProxyEndpointString));
            }
            if (secureEndpoint != null) {
                s3ProxyBuilder.secureEndpoint(new URI(secureEndpoint));
            }
            if (localIdentity != null || localCredential != null) {
                s3ProxyBuilder.awsAuthentication(localIdentity,
                        localCredential);
            }
            if (keyStorePath != null || keyStorePassword != null) {
                s3ProxyBuilder.keyStore(keyStorePath, keyStorePassword);
            }
            if (virtualHost != null) {
                s3ProxyBuilder.virtualHost(virtualHost);
            }
            if (v4MaxNonChunkedRequestSize != null) {
                s3ProxyBuilder.v4MaxNonChunkedRequestSize(Long.parseLong(
                        v4MaxNonChunkedRequestSize));
            }
            if (ignoreUnknownHeaders != null) {
                s3ProxyBuilder.ignoreUnknownHeaders(Boolean.parseBoolean(
                        ignoreUnknownHeaders));
            }
            if (corsAllowAll != null) {
                s3ProxyBuilder.corsAllowAll(Boolean.parseBoolean(
                        corsAllowAll));
            }
            s3Proxy = s3ProxyBuilder.build();
        } catch (IllegalArgumentException | IllegalStateException e) {
            System.err.println(e.getMessage());
            System.exit(1);
            throw e;
        }
        try {
            s3Proxy.start();
        } catch (Exception e) {
            System.err.println(e.getMessage());
            System.exit(1);
        }
    }



    private static void usage(CmdLineParser parser) {
        System.err.println("Usage: s3proxy [options...]");
        parser.printUsage(System.err);
        System.exit(1);
    }
}
