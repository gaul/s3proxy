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

package org.gaul.s3proxy.middleware;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableBiMap;

import org.gaul.s3proxy.S3ProxyConstants;
import org.gaul.s3proxy.blobstore.BlobStore;

/**
 * The wiring for this package: wraps a backend in each middleware its
 * properties configure, so that the middlewares themselves stay behind the
 * property surface they are documented by.
 */
public final class Middlewares {
    private Middlewares() {
        throw new AssertionError("intentionally not implemented");
    }

    /**
     * Creates a backend from its properties.  The eventual-consistency
     * middleware stands a second backend beside the one it wraps, and
     * creating one -- provider resolution, credential handling -- belongs
     * to the caller.
     */
    @FunctionalInterface
    public interface BackendFactory {
        BlobStore create(Properties properties) throws IOException;
    }

    /**
     * Wraps {@code blobStore} in each middleware which {@code properties}
     * configures, the earlier-configured ones innermost.
     */
    public static BlobStore wrap(BlobStore blobStore, Properties properties,
            BackendFactory backendFactory) throws IOException {
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
            BlobStore altBlobStore = backendFactory.create(altProperties);
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

        Map<String, String> prefixMap = PrefixBlobStore.parsePrefixes(properties);
        if (!prefixMap.isEmpty()) {
            System.err.println("Using prefix backend");
            blobStore = PrefixBlobStore.newPrefixBlobStore(blobStore,
                    prefixMap);
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
                    storageClassBlobStore.getStorageClass());
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

        Map<String, Long> latencies = LatencyBlobStore.parseLatencies(properties);
        Map<String, Long> speeds = LatencyBlobStore.parseSpeeds(properties);
        if (!latencies.isEmpty() || !speeds.isEmpty()) {
            System.err.println("Using latency storage backend");
            blobStore = LatencyBlobStore.newLatencyBlobStore(blobStore, latencies, speeds);
        }

        String noCacheBlobStore = properties.getProperty(
              S3ProxyConstants.PROPERTY_NO_CACHE_BLOBSTORE);
        if  ("true".equalsIgnoreCase(noCacheBlobStore)) {
            System.err.println("Using no-cache storage backend middleware");
            blobStore = NoCacheBlobStore
                    .newNoCacheBlobStore(blobStore);
        }

        return blobStore;
    }
}
