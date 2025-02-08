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

package org.gaul.s3proxy;

import java.io.Console;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.AWSSessionCredentials;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.google.common.base.Strings;
import com.google.common.base.Supplier;
import com.google.common.collect.ImmutableBiMap;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Maps;
import com.google.common.io.MoreFiles;
import com.google.common.util.concurrent.ThreadFactoryBuilder;

import org.gaul.modernizer_maven_annotations.SuppressModernizer;
import org.jclouds.Constants;
import org.jclouds.ContextBuilder;
import org.jclouds.JcloudsVersion;
import org.jclouds.aws.domain.SessionCredentials;
import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.BlobStoreContext;
import org.jclouds.concurrent.DynamicExecutors;
import org.jclouds.concurrent.config.ExecutorServiceModule;
import org.jclouds.domain.Credentials;
import org.jclouds.location.reference.LocationConstants;
import org.jclouds.logging.slf4j.config.SLF4JLoggingModule;
import org.jclouds.openstack.swift.v1.blobstore.RegionScopedBlobStoreContext;
import org.jclouds.s3.domain.ObjectMetadata.StorageClass;
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

    @SuppressWarnings("EqualsIncompatibleType")
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
        var factory = new ThreadFactoryBuilder()
                .setNameFormat("user thread %d")
                .setThreadFactory(Executors.defaultThreadFactory())
                .build();
        ExecutorService executorService = DynamicExecutors.newScalingThreadPool(
                1, 20, 60 * 1000, factory);
        var locators = ImmutableMap
                .<String, Map.Entry<String, BlobStore>>builder();
        var globLocators = ImmutableMap
                .<PathMatcher, Map.Entry<String, BlobStore>>builder();
        Set<String> locatorGlobs = new HashSet<>();
        Set<String> parsedIdentities = new HashSet<>();
        for (var path : options.properties) {
            var properties = new Properties();
            try (var is = Files.newInputStream(path)) {
                properties.load(is);
            }
            properties.putAll(System.getProperties());

            BlobStore blobStore = createBlobStore(properties, executorService);
            if (blobStore.getContext().unwrap().getProviderMetadata().getId().equals("filesystem")) {
                logger.warn("filesystem storage backend deprecated -- please use filesystem-nio2 instead");
            }

            blobStore = parseMiddlewareProperties(blobStore, executorService,
                    properties);

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
                            Map.entry(localCredential, blobStore));
                }
            }
            for (String key : properties.stringPropertyNames()) {
                if (key.startsWith(S3ProxyConstants.PROPERTY_BUCKET_LOCATOR)) {
                    String bucketLocator = properties.getProperty(key);
                    if (locatorGlobs.add(bucketLocator)) {
                        globLocators.put(
                                FileSystems.getDefault().getPathMatcher(
                                        "glob:" + bucketLocator),
                                Maps.immutableEntry(localIdentity, blobStore));
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
            s3Proxy = s3ProxyBuilder.build();
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
    }

    private static BlobStore parseMiddlewareProperties(BlobStore blobStore,
            ExecutorService executorService, Properties properties)
            throws IOException {
        var altProperties = new Properties();
        for (var entry : properties.entrySet()) {
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
            BlobStore altBlobStore = createBlobStore(altProperties,
                    executorService);
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

        String nullBlobStore = properties.getProperty(
                S3ProxyConstants.PROPERTY_NULL_BLOBSTORE);
        if ("true".equalsIgnoreCase(nullBlobStore)) {
            System.err.println("Using null storage backend");
            blobStore = NullBlobStore.newNullBlobStore(blobStore);
        }

        String readOnlyBlobStore = properties.getProperty(
                S3ProxyConstants.PROPERTY_READ_ONLY_BLOBSTORE);
        if ("true".equalsIgnoreCase(readOnlyBlobStore)) {
            System.err.println("Using read-only storage backend");
            blobStore = ReadOnlyBlobStore.newReadOnlyBlobStore(blobStore);
        }

        ImmutableBiMap<String, String> aliases = AliasBlobStore.parseAliases(
                properties);
        if (!aliases.isEmpty()) {
            System.err.println("Using alias backend");
            blobStore = AliasBlobStore.newAliasBlobStore(blobStore, aliases);
        }

        List<Map.Entry<Pattern, String>> regexs =
                RegexBlobStore.parseRegexs(properties);
        if (!regexs.isEmpty()) {
            System.err.println("Using regex backend");
            blobStore = RegexBlobStore.newRegexBlobStore(blobStore, regexs);
        }

        Map<String, Integer> shards =
                ShardedBlobStore.parseBucketShards(properties);
        Map<String, String> prefixes =
                ShardedBlobStore.parsePrefixes(properties);
        if (!shards.isEmpty()) {
            System.err.println("Using sharded buckets backend");
            blobStore = ShardedBlobStore.newShardedBlobStore(blobStore,
                    shards, prefixes);
        }

        String encryptedBlobStore = properties.getProperty(
            S3ProxyConstants.PROPERTY_ENCRYPTED_BLOBSTORE);
        if ("true".equalsIgnoreCase(encryptedBlobStore)) {
            System.err.println("Using encrypted storage backend");
            blobStore = EncryptedBlobStore.newEncryptedBlobStore(blobStore,
                properties);
        }

        var storageClass = properties.getProperty(
                S3ProxyConstants.PROPERTY_STORAGE_CLASS_BLOBSTORE);
        if (!Strings.isNullOrEmpty(storageClass)) {
            System.err.println("Using storage class override backend");
            var storageClassBlobStore =
                    StorageClassBlobStore.newStorageClassBlobStore(
                            blobStore, storageClass);
            blobStore = storageClassBlobStore;
            System.err.println("Configuration storage class: " + storageClass);
            // TODO: This only makes sense for S3 backends.
            System.err.println("Mapping storage storage class to: " +
                    StorageClass.fromTier(storageClassBlobStore.getTier()));
        }

        String userMetadataReplacerBlobStore = properties.getProperty(
                S3ProxyConstants.PROPERTY_USER_METADATA_REPLACER);
        if ("true".equalsIgnoreCase(userMetadataReplacerBlobStore)) {
            System.err.println("Using user metadata replacers storage backend");
            String fromChars = properties.getProperty(S3ProxyConstants
                    .PROPERTY_USER_METADATA_REPLACER_FROM_CHARS);
            String toChars = properties.getProperty(S3ProxyConstants
                    .PROPERTY_USER_METADATA_REPLACER_TO_CHARS);
            blobStore = UserMetadataReplacerBlobStore
                    .newUserMetadataReplacerBlobStore(
                            blobStore, fromChars, toChars);
        }

        return blobStore;
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

    private static BlobStore createBlobStore(Properties properties,
            ExecutorService executorService) throws IOException {
        String provider = properties.getProperty(Constants.PROPERTY_PROVIDER);
        String identity = properties.getProperty(Constants.PROPERTY_IDENTITY);
        String credential = properties.getProperty(
                Constants.PROPERTY_CREDENTIAL);
        String endpoint = properties.getProperty(Constants.PROPERTY_ENDPOINT);
        properties.remove(Constants.PROPERTY_ENDPOINT);
        String region = properties.getProperty(
                LocationConstants.PROPERTY_REGION);

        if (provider == null) {
            System.err.println(
                    "Properties file must contain: " +
                    Constants.PROPERTY_PROVIDER);
            System.exit(1);
        }

        if (provider.equals("filesystem") || provider.equals("transient")) {
            // local blobstores do not require credentials
            identity = Strings.nullToEmpty(identity);
            credential = Strings.nullToEmpty(credential);
        } else if (provider.equals("google-cloud-storage")) {
            var path = FileSystems.getDefault().getPath(credential);
            if (Files.exists(path)) {
                credential = MoreFiles.asCharSource(path,
                        StandardCharsets.UTF_8).read();
            }
            properties.remove(Constants.PROPERTY_CREDENTIAL);
            // We also need to clear the system property, otherwise the
            // credential will be overridden by the system property.
            System.clearProperty(Constants.PROPERTY_CREDENTIAL);
        }

        if (identity == null || credential == null) {
            System.err.println(
                    "Properties file must contain: " +
                    Constants.PROPERTY_IDENTITY + " and " +
                    Constants.PROPERTY_CREDENTIAL);
            System.exit(1);
        }

        properties.setProperty(Constants.PROPERTY_USER_AGENT,
                String.format("s3proxy/%s jclouds/%s java/%s",
                        Main.class.getPackage().getImplementationVersion(),
                        JcloudsVersion.get(),
                        System.getProperty("java.version")));

        ContextBuilder builder = ContextBuilder
                .newBuilder(provider)
                .modules(List.of(
                        new SLF4JLoggingModule(),
                        new ExecutorServiceModule(executorService)))
                .overrides(properties);
        if (!Strings.isNullOrEmpty(endpoint)) {
            builder = builder.endpoint(endpoint);
        }

        if ((identity.isEmpty() || credential.isEmpty()) && provider.equals("aws-s3")) {
            @SuppressModernizer
            Supplier<Credentials> credentialsSupplier = new Supplier<Credentials>() {
                @Override
                public Credentials get() {
                    AWSCredentialsProvider authChain = DefaultAWSCredentialsProviderChain.getInstance();
                    AWSCredentials newCreds = authChain.getCredentials();
                    Credentials jcloudCred = null;

                    if (newCreds instanceof AWSSessionCredentials) {
                        jcloudCred = SessionCredentials.builder()
                                .accessKeyId(newCreds.getAWSAccessKeyId())
                                .secretAccessKey(newCreds.getAWSSecretKey())
                                .sessionToken(((AWSSessionCredentials) newCreds).getSessionToken())
                                .build();
                    } else {
                        jcloudCred = new Credentials(
                                newCreds.getAWSAccessKeyId(), newCreds.getAWSSecretKey()
                        );
                    }

                    return jcloudCred;
                }
            };
            builder = builder.credentialsSupplier(credentialsSupplier);
        } else {
            builder = builder.credentials(identity, credential);
        }

        BlobStoreContext context = builder.build(BlobStoreContext.class);
        BlobStore blobStore;
        if (context instanceof RegionScopedBlobStoreContext &&
                region != null) {
            blobStore = ((RegionScopedBlobStoreContext) context)
                    .getBlobStore(region);
        } else {
            blobStore = context.getBlobStore();
        }
        return blobStore;
    }

    private static void usage(CmdLineParser parser) {
        System.err.println("Usage: s3proxy [options...]");
        parser.printUsage(System.err);
        System.exit(1);
    }
}
