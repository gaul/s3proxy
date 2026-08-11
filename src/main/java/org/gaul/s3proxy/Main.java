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

import static java.util.Objects.requireNonNull;

import java.io.Console;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableMap;

import org.gaul.s3proxy.auth.AuthenticationType;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.Constants;
import org.gaul.s3proxy.middleware.GlobBlobStoreLocator;
import org.gaul.s3proxy.middleware.Middlewares;
import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;
import org.kohsuke.args4j.Option;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class Main {
    private static final Logger logger = LoggerFactory.getLogger(Main.class);
    private Main() {
        throw new AssertionError("intentionally not implemented");
    }

    private static final class Options {
        @Option(name = "--properties",
                usage = "S3Proxy configuration (required, multiple allowed)")
        private List<Path> properties = new ArrayList<>();

        @Option(name = "--version", usage = "display version")
        private boolean version;
    }

    @SuppressWarnings({"EqualsIncompatibleType", "SystemConsoleNull"})
    public static void main(String[] args) throws Exception {
        Console console = System.console();
        if (console == null) {
            System.setErr(createLoggerErrorPrintStream());
        }

        var options = new Options();
        var parser = new CmdLineParser(options);
        try {
            parser.parseArgument(args);
        } catch (CmdLineException cle) {
            usage(parser);
        }

        if (options.version) {
            System.err.println(
                    Main.class.getPackage().getImplementationVersion());
            System.exit(0);
        } else if (options.properties.isEmpty()) {
            usage(parser);
        }

        S3Proxy.Builder s3ProxyBuilder = null;
        var locators = ImmutableMap.<String, AccessGrant>builder();
        var globLocators = ImmutableMap
                .<PathMatcher, GlobBlobStoreLocator.GlobTarget>builder();
        Set<String> locatorGlobs = new HashSet<>();
        Set<String> parsedIdentities = new HashSet<>();
        for (var path : options.properties) {
            var properties = new Properties();
            try (var is = Files.newInputStream(path)) {
                properties.load(is);
            }
            properties.putAll(System.getProperties());

            BlobStore blobStore;
            try {
                blobStore = createBlobStore(properties);
            } catch (IllegalArgumentException e) {
                System.err.println(e.getMessage());
                System.exit(1);
                throw e;
            }

            blobStore = Middlewares.wrap(blobStore, properties,
                    Main::createBlobStore);

            String s3ProxyAuthorizationString = properties.getProperty(
                    S3ProxyConstants.PROPERTY_AUTHORIZATION);

            String localIdentity = null;
            if (AuthenticationType.fromString(s3ProxyAuthorizationString) !=
                    AuthenticationType.NONE) {
                localIdentity = properties.getProperty(
                        S3ProxyConstants.PROPERTY_IDENTITY);
                String localCredential = properties.getProperty(
                        S3ProxyConstants.PROPERTY_CREDENTIAL);
                if (parsedIdentities.add(localIdentity)) {
                    locators.put(localIdentity,
                            new AccessGrant(localCredential, blobStore));
                }
            }
            for (String key : properties.stringPropertyNames()) {
                if (key.startsWith(S3ProxyConstants.PROPERTY_BUCKET_LOCATOR)) {
                    String bucketLocator = properties.getProperty(key);
                    if (locatorGlobs.add(bucketLocator)) {
                        globLocators.put(
                                FileSystems.getDefault().getPathMatcher(
                                        "glob:" + bucketLocator),
                                new GlobBlobStoreLocator.GlobTarget(
                                        Optional.ofNullable(localIdentity),
                                        blobStore));
                    } else {
                        System.err.println("Multiple definitions of the " +
                                "bucket locator: " + bucketLocator);
                        System.exit(1);
                    }
                }
            }

            S3Proxy.Builder s3ProxyBuilder2 = S3Proxy.Builder
                    .fromProperties(properties)
                    .blobStore(blobStore);

            if (s3ProxyBuilder != null &&
                    !s3ProxyBuilder.equals(s3ProxyBuilder2)) {
                System.err.println("Multiple configurations require" +
                        " identical s3proxy properties");
                System.exit(1);
            }
            s3ProxyBuilder = s3ProxyBuilder2;
        }

        S3Proxy s3Proxy;
        try {
            s3Proxy = requireNonNull(s3ProxyBuilder).build();
        } catch (IllegalArgumentException | IllegalStateException e) {
            System.err.println(e.getMessage());
            System.exit(1);
            throw e;
        }

        var locator = locators.build();
        var globLocator = globLocators.build();
        if (!locator.isEmpty() || !globLocator.isEmpty()) {
            s3Proxy.setBlobStoreLocator(
                    new GlobBlobStoreLocator(locator, globLocator));
        }

        try {
            s3Proxy.start();
        } catch (Exception e) {
            System.err.println(e.getMessage());
            System.exit(1);
        }

        // Drain in-flight requests on SIGTERM, e.g., docker stop or
        // Kubernetes pod eviction.
        S3Proxy finalS3Proxy = s3Proxy;
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try {
                finalS3Proxy.stop();
            } catch (Exception e) {
                System.err.println("Error during shutdown: " +
                        e.getMessage());
            }
        }, "s3proxy-shutdown"));
    }


    private static PrintStream createLoggerErrorPrintStream() {
        return new PrintStream(System.err) {
            private final StringBuilder builder = new StringBuilder();

            @Override
            @edu.umd.cs.findbugs.annotations.SuppressFBWarnings(
                    "SLF4J_SIGN_ONLY_FORMAT")
            public void print(final String string) {
                logger.error("{}", string);
            }

            @Override
            public void write(byte[] buf, int off, int len) {
                for (int i = off; i < len; ++i) {
                    char ch = (char) buf[i];
                    if (ch == '\n') {
                        if (builder.length() != 0) {
                            print(builder.toString());
                            builder.setLength(0);
                        }
                    } else {
                        builder.append(ch);
                    }
                }
            }
        };
    }

    private static BlobStore createBlobStore(Properties properties)
            throws IOException {
        String provider = properties.getProperty(Constants.PROPERTY_PROVIDER);
        String identity = properties.getProperty(Constants.PROPERTY_IDENTITY);
        String credential = properties.getProperty(
                Constants.PROPERTY_CREDENTIAL);

        if (provider == null) {
            System.err.println(
                    "Properties file must contain: " +
                    Constants.PROPERTY_PROVIDER);
            System.exit(1);
        }

        // Resolve here as well as in BlobStores.create so that the branches
        // below, and anything reading the property afterwards, see the name
        // the store will actually be created under.
        provider = BlobStores.resolveProviderAlias(provider);
        properties.setProperty(Constants.PROPERTY_PROVIDER, provider);

        if (provider.equals("filesystem") ||
                provider.equals("transient")) {
            identity = Strings.nullToEmpty(identity);
            credential = Strings.nullToEmpty(credential);
        } else if (provider.equals("google-cloud-storage")) {
            if (credential != null && !credential.isEmpty()) {
                var path = FileSystems.getDefault().getPath(credential);
                if (Files.exists(path)) {
                    credential = Files.readString(path);
                }
            }
            identity = Strings.nullToEmpty(identity);
            credential = Strings.nullToEmpty(credential);
            properties.remove(Constants.PROPERTY_CREDENTIAL);
            System.clearProperty(Constants.PROPERTY_CREDENTIAL);
        }

        if (identity == null || credential == null) {
            System.err.println(
                    "Properties file must contain: " +
                    Constants.PROPERTY_IDENTITY + " and " +
                    Constants.PROPERTY_CREDENTIAL);
            System.exit(1);
        }

        properties.setProperty(Constants.PROPERTY_IDENTITY, identity);
        properties.setProperty(Constants.PROPERTY_CREDENTIAL, credential);

        return BlobStores.create(provider, properties);
    }

    private static void usage(CmdLineParser parser) {
        System.err.println("Usage: s3proxy [options...]");
        parser.printUsage(System.err);
        System.exit(1);
    }
}
