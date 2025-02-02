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

import static com.google.common.base.Preconditions.checkArgument;

import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Sets;
import com.google.common.hash.HashCode;
import com.google.common.hash.HashFunction;
import com.google.common.hash.Hashing;

import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.ContainerNotFoundException;
import org.jclouds.blobstore.domain.Blob;
import org.jclouds.blobstore.domain.BlobAccess;
import org.jclouds.blobstore.domain.BlobMetadata;
import org.jclouds.blobstore.domain.ContainerAccess;
import org.jclouds.blobstore.domain.MultipartPart;
import org.jclouds.blobstore.domain.MultipartUpload;
import org.jclouds.blobstore.domain.MutableStorageMetadata;
import org.jclouds.blobstore.domain.PageSet;
import org.jclouds.blobstore.domain.StorageMetadata;
import org.jclouds.blobstore.domain.internal.MutableStorageMetadataImpl;
import org.jclouds.blobstore.domain.internal.PageSetImpl;
import org.jclouds.blobstore.options.CopyOptions;
import org.jclouds.blobstore.options.CreateContainerOptions;
import org.jclouds.blobstore.options.GetOptions;
import org.jclouds.blobstore.options.ListContainerOptions;
import org.jclouds.blobstore.options.PutOptions;
import org.jclouds.blobstore.util.ForwardingBlobStore;
import org.jclouds.domain.Location;
import org.jclouds.io.Payload;

/**
 * This class implements the ability to split objects destined for specified
 * buckets across multiple backend buckets. The sharding is only applied to
 * the configured buckets. Each sharded bucket must specify the number of
 * shards in the form:
 *   s3proxy.sharded-blobstore.&lt;bucket name&gt;.shards=&lt;integer&gt;.
 * The number of shards is limited to 1000. An optional prefix can be
 * specified to use for shard names, like so:
 *   s3proxy.sharded-blobstore.&lt;bucket name&gt;.prefix=&lt;string&gt;.
 * The shards are named as follows: &lt;prefix&gt;-&lt;integer&gt;,
 * corresponding to the shards from 0 to the specified number. If a
 * &lt;prefix&gt; is not specified, the name of the bucket is used instead.
 *
 * Requests for all other buckets are passed through unchanged. Shards must
 * be pre-created either out of band or by issuing the CreateBucket API with
 * the sharded bucket name. The sharded bucket itself will not be
 * instantiated on the backend.
 */
final class ShardedBlobStore extends ForwardingBlobStore {
    public static final Pattern PROPERTIES_PREFIX_RE = Pattern.compile(
            S3ProxyConstants.PROPERTY_SHARDED_BLOBSTORE +
                    "\\.(?<bucket>.*)\\.prefix$");
    private static final Pattern PROPERTIES_SHARDS_RE = Pattern.compile(
            S3ProxyConstants.PROPERTY_SHARDED_BLOBSTORE +
            "\\.(?<bucket>.*)\\.shards$");
    private static final Pattern SHARD_RE = Pattern.compile(
            "(?<prefix>.*)-(?<shard>[0-9]+)$");
    private static final HashFunction SHARD_HASH = Hashing.murmur3_128();
    private static final int MAX_SHARD_THREADS = 10;
    private static final String SUPERBLOCK_VERSION = "1.0";
    private static final String SUPERBLOCK_BLOB_NAME =
            ".s3proxy-sharded-superblock";
    private static final int MAX_SHARDS = 1000;
    private final Map<String, ShardedBucket> buckets;
    private final Map<String, String> prefixMap;

    private static final class ShardedBucket {
        private final String prefix;
        private final int shards;

        private ShardedBucket(String name, int shards) {
            this.prefix = Objects.requireNonNull(name);
            this.shards = shards;
        }
    }

    private ShardedBlobStore(BlobStore blobStore,
                             Map<String, Integer> shards,
                             Map<String, String> prefixes) {
        super(blobStore);
        Set<String> missingShards = Sets.difference(
                prefixes.keySet(), shards.keySet());
        if (!missingShards.isEmpty()) {
            String allMissingShards = missingShards.stream().collect(
                    Collectors.joining(", "));
            throw new IllegalArgumentException(
                    String.format(
                            "Number of shards unset for sharded buckets: %s",
                            allMissingShards));
        }
        var bucketsBuilder = new ImmutableMap.Builder<String, ShardedBucket>();
        for (String bucket : shards.keySet()) {
            String prefix = prefixes.get(bucket);
            if (prefix == null) {
                prefix = bucket;
            }
            bucketsBuilder.put(bucket, new ShardedBucket(prefix,
                    shards.get(bucket)));
        }
        this.buckets = bucketsBuilder.build();

        this.prefixMap = buckets.keySet().stream().collect(Collectors.toMap(
                virtualBucket -> buckets.get(virtualBucket).prefix,
                virtualBucket -> virtualBucket));
    }

    public static Map<String, Integer> parseBucketShards(
            Properties properties) {
        var shardsMap = new ImmutableMap.Builder<String, Integer>();
        for (String key : properties.stringPropertyNames()) {
            Matcher matcher = PROPERTIES_SHARDS_RE.matcher(key);
            if (!matcher.matches()) {
                continue;
            }
            String bucket = matcher.group("bucket");
            int shards = Integer.parseInt(properties.getProperty(key));
            checkArgument(shards > 0 && shards < MAX_SHARDS,
                    "number of shards must be between 1 and 1000 for %s",
                        bucket);
            shardsMap.put(bucket, shards);
        }
        return shardsMap.build();
    }

    public static Map<String, String> parsePrefixes(Properties properties) {
        var prefixesMap = new ImmutableMap.Builder<String, String>();
        for (String key : properties.stringPropertyNames()) {
            Matcher matcher = PROPERTIES_PREFIX_RE.matcher(key);
            if (!matcher.matches()) {
                continue;
            }
            prefixesMap.put(matcher.group("bucket"),
                    properties.getProperty(key));
        }
        return prefixesMap.build();
    }

    static ShardedBlobStore newShardedBlobStore(
            BlobStore blobStore,
            Map<String, Integer> shards,
            Map<String, String> prefixes) {
        return new ShardedBlobStore(blobStore, shards, prefixes);
    }

    private Map<String, String> createSuperblockMeta(ShardedBucket bucket) {
        return Map.of(
                "s3proxy-sharded-superblock-version", SUPERBLOCK_VERSION,
                "s3proxy-sharded-superblock-prefix", bucket.prefix,
                "s3proxy-sharded-superblock-shards",
                Integer.toString(bucket.shards));
    }

    private static String getShardContainer(ShardedBucket bucket, int shard) {
        return String.format("%s-%d", bucket.prefix, shard);
    }

    private String getShard(String containerName, String blob) {
        ShardedBucket bucket = buckets.get(containerName);
        if (bucket == null) {
            return containerName;
        }
        HashCode hash = SHARD_HASH.hashString(blob, StandardCharsets.UTF_8);
        return ShardedBlobStore.getShardContainer(
                bucket, Hashing.consistentHash(hash, bucket.shards));
    }

    private void checkSuperBlock(Blob blob, Map<String, String> expectedMeta,
                                 String container) {
        Map<String, String> currentSuperblockMeta =
                blob.getMetadata().getUserMetadata();
        for (var entry : expectedMeta.entrySet()) {
            String current = currentSuperblockMeta.get(entry.getKey());
            String expected = entry.getValue();
            if (!expected.equalsIgnoreCase(current)) {
                throw new RuntimeException(String.format(
                        "Superblock block for %s does not match: %s, %s",
                        container, expected, current));
            }
        }
    }

    private boolean createShards(ShardedBucket bucket, Location location,
                                 CreateContainerOptions options) {
        var futuresBuilder = new ImmutableList.Builder<Future<Boolean>>();
        ExecutorService executor = Executors.newFixedThreadPool(
                Math.min(bucket.shards, MAX_SHARD_THREADS));
        BlobStore blobStore = this.delegate();
        for (int n = 0; n < bucket.shards; ++n) {
            String shardContainer = ShardedBlobStore.getShardContainer(
                    bucket, n);
            futuresBuilder.add(executor.submit(
                () -> blobStore.createContainerInLocation(
                        location, shardContainer, options)));
        }
        var futures = futuresBuilder.build();
        executor.shutdown();
        boolean ret = true;
        for (Future<Boolean> future : futures) {
            try {
                ret &= future.get();
            } catch (InterruptedException | ExecutionException e) {
                throw new RuntimeException("Failed to create some shards", e);
            }
        }

        return ret;
    }

    @Override
    public boolean createContainerInLocation(Location location,
                                             String container) {
        return createContainerInLocation(
                location, container, CreateContainerOptions.NONE);
    }

    @SuppressWarnings("EmptyCatch")
    @Override
    public boolean createContainerInLocation(
            Location location, String container,
            CreateContainerOptions createContainerOptions) {

        ShardedBucket bucket = this.buckets.get(container);
        if (bucket == null) {
            return this.delegate().createContainerInLocation(
                    location, container, createContainerOptions);
        }

        Map<String, String> superblockMeta = this.createSuperblockMeta(bucket);
        Blob superblockBlob = null;
        try {
            superblockBlob = this.delegate().getBlob(
                    ShardedBlobStore.getShardContainer(bucket, 0),
                    SUPERBLOCK_BLOB_NAME);
        } catch (ContainerNotFoundException ignored) {
        }
        if (superblockBlob != null) {
            checkSuperBlock(superblockBlob, superblockMeta, container);
        }

        boolean ret = createShards(bucket, location, createContainerOptions);

        // Upload the superblock
        if (superblockBlob == null) {
            superblockBlob = this.delegate().blobBuilder(SUPERBLOCK_BLOB_NAME)
                    .payload("")
                    .userMetadata(superblockMeta)
                    .build();
            this.delegate().putBlob(ShardedBlobStore.getShardContainer(
                    bucket, 0), superblockBlob);
        }

        return ret;
    }

    @Override
    public PageSet<? extends StorageMetadata> list() {
        PageSet<? extends StorageMetadata> upstream = this.delegate().list();
        var results = new ImmutableList.Builder<StorageMetadata>();
        Set<String> virtualBuckets = new HashSet<>();
        for (StorageMetadata sm : upstream) {
            Matcher matcher = SHARD_RE.matcher(sm.getName());
            if (!matcher.matches()) {
                results.add(sm);
                continue;
            }
            String prefix = matcher.group("prefix");
            String virtualBucketName = this.prefixMap.get(prefix);
            if (virtualBucketName == null) {
                results.add(sm);
                continue;
            }
            if (!virtualBuckets.contains(prefix)) {
                virtualBuckets.add(prefix);
                MutableStorageMetadata virtualBucket =
                        new MutableStorageMetadataImpl();
                virtualBucket.setCreationDate(sm.getCreationDate());
                virtualBucket.setETag(sm.getETag());
                virtualBucket.setId(sm.getProviderId());
                virtualBucket.setLastModified(sm.getLastModified());
                virtualBucket.setLocation(sm.getLocation());
                virtualBucket.setName(virtualBucketName);
                virtualBucket.setSize(sm.getSize());
                virtualBucket.setTier(sm.getTier());
                virtualBucket.setType(sm.getType());
                virtualBucket.setUri(sm.getUri());
                // copy the user metadata from the first shard as part
                // of the response
                virtualBucket.setUserMetadata(sm.getUserMetadata());
                results.add(virtualBucket);
            }
        }
        return new PageSetImpl<>(results.build(), upstream.getNextMarker());
    }

    @Override
    public PageSet<? extends StorageMetadata> list(String container) {
        if (!this.buckets.containsKey(container)) {
            return this.delegate().list(container);
        }
        // TODO: implement listing a sharded container
        throw new UnsupportedOperationException("sharded bucket");
    }

    @Override
    public PageSet<? extends StorageMetadata> list(
            String container,
            ListContainerOptions options) {
        if (!this.buckets.containsKey(container)) {
            return this.delegate().list(container, options);
        }
        // TODO: implement listing a sharded container
        throw new UnsupportedOperationException("sharded bucket");
    }

    @Override
    public boolean containerExists(String container) {
        if (!this.buckets.containsKey(container)) {
            return this.delegate().containerExists(container);
        }
        return true;
    }

    @Override
    public ContainerAccess getContainerAccess(String container) {
        if (!this.buckets.containsKey(container)) {
            return this.delegate().getContainerAccess(container);
        }
        throw new UnsupportedOperationException("sharded bucket");
    }

    @Override
    public void setContainerAccess(String container,
                                   ContainerAccess containerAccess) {
        if (!this.buckets.containsKey(container)) {
            this.delegate().setContainerAccess(container, containerAccess);
        }
        throw new UnsupportedOperationException("sharded bucket");
    }

    @Override
    public void clearContainer(String container) {
        clearContainer(container, new ListContainerOptions());
    }

    @Override
    public void clearContainer(String container, ListContainerOptions options) {
        throw new UnsupportedOperationException("sharded bucket");
    }

    @Override
    public void deleteContainer(String container) {
        throw new UnsupportedOperationException("sharded bucket");
    }

    private boolean deleteShards(ShardedBucket bucket) {
        var futuresBuilder = new ImmutableList.Builder<Future<Boolean>>();
        ExecutorService executor = Executors.newFixedThreadPool(
                Math.min(bucket.shards, MAX_SHARD_THREADS));
        for (int n = 0; n < bucket.shards; ++n) {
            String shard = ShardedBlobStore.getShardContainer(bucket, n);
            futuresBuilder.add(executor.submit(
                () -> this.delegate().deleteContainerIfEmpty(shard)));
        }
        executor.shutdown();
        var futures = futuresBuilder.build();
        boolean ret = true;
        for (Future<Boolean> future : futures) {
            try {
                ret &= future.get();
            } catch (InterruptedException | ExecutionException e) {
                throw new RuntimeException("Failed to delete shards", e);
            }
        }

        return ret;
    }

    @Override
    public boolean deleteContainerIfEmpty(String container) {
        ShardedBucket bucket = this.buckets.get(container);
        if (bucket == null) {
            return this.delegate().deleteContainerIfEmpty(container);
        }

        String zeroShardContainer = ShardedBlobStore.getShardContainer(
                bucket, 0);
        PageSet<? extends StorageMetadata> listing = this.delegate().list(
                zeroShardContainer);
        if (listing.size() > 1) {
            return false;
        }
        StorageMetadata sm = listing.iterator().next();
        if (!sm.getName().equals(SUPERBLOCK_BLOB_NAME)) {
            return false;
        }
        // Remove the superblock
        this.delegate().removeBlob(zeroShardContainer, SUPERBLOCK_BLOB_NAME);
        return this.deleteShards(bucket);
    }

    @Override
    public boolean directoryExists(String container, String directory) {
        throw new UnsupportedOperationException("sharded bucket");
    }

    @Override
    public void createDirectory(String container, String directory) {
        throw new UnsupportedOperationException("sharded bucket");
    }

    @Override
    public void deleteDirectory(String container, String directory) {
        throw new UnsupportedOperationException("sharded bucket");
    }

    @Override
    public boolean blobExists(String container, String name) {
        return this.delegate().blobExists(this.getShard(container, name), name);
    }

    @Override
    public String putBlob(String containerName, Blob blob) {
        return this.delegate().putBlob(this.getShard(containerName,
                blob.getMetadata().getName()), blob);
    }

    @Override
    public String putBlob(final String containerName, Blob blob,
                          final PutOptions putOptions) {
        return this.delegate().putBlob(
                this.getShard(containerName, blob.getMetadata().getName()),
                blob, putOptions);
    }

    @Override
    public String copyBlob(String fromContainer, String fromName,
                           String toContainer, String toName,
                           CopyOptions options) {
        String srcShard = this.getShard(fromContainer, fromName);
        String dstShard = this.getShard(toContainer, toName);
        return this.delegate().copyBlob(srcShard, fromName,
                dstShard, toName, options);
    }

    @Override
    public BlobMetadata blobMetadata(String container, String name) {
        return this.delegate().blobMetadata(this.getShard(container, name),
                name);
    }

    @Override
    public Blob getBlob(String containerName, String blobName) {
        return this.delegate().getBlob(this.getShard(containerName, blobName),
                blobName);
    }

    @Override
    public Blob getBlob(String containerName, String blobName,
                        GetOptions getOptions) {
        return this.delegate()
                .getBlob(this.getShard(containerName, blobName), blobName,
                        getOptions);
    }

    @Override
    public void removeBlob(String container, String name) {
        this.delegate().removeBlob(this.getShard(container, name), name);
    }

    @Override
    public void removeBlobs(String container, Iterable<String> iterable) {
        if (!this.buckets.containsKey(container)) {
            this.delegate().removeBlobs(container, iterable);
        }

        Map<String, List<String>> shardMap = new HashMap<>();
        for (String blob : iterable) {
            List<String> shardBlobs =
                    shardMap.computeIfAbsent(this.getShard(container, blob),
                        k -> new ArrayList<>());
            shardBlobs.add(blob);
        }

        for (var entry : shardMap.entrySet()) {
            this.delegate().removeBlobs(entry.getKey(), entry.getValue());
        }
    }

    @Override
    public BlobAccess getBlobAccess(String container, String name) {
        return this.delegate()
                .getBlobAccess(this.getShard(container, name), name);
    }

    @Override
    public void setBlobAccess(String container, String name,
                              BlobAccess access) {
        this.delegate()
                .setBlobAccess(this.getShard(container, name), name, access);
    }

    @Override
    public long countBlobs(String container) {
        if (!this.buckets.containsKey(container)) {
            return this.delegate().countBlobs(container);
        }
        throw new UnsupportedOperationException("sharded bucket");
    }

    @Override
    public long countBlobs(String container, ListContainerOptions options) {
        if (!this.buckets.containsKey(container)) {
            return this.delegate().countBlobs(container, options);
        }
        throw new UnsupportedOperationException("sharded bucket");
    }

    @Override
    public MultipartUpload initiateMultipartUpload(String container,
                                                   BlobMetadata blobMetadata,
                                                   PutOptions options) {
        if (!this.buckets.containsKey(container)) {
            return this.delegate()
                    .initiateMultipartUpload(container, blobMetadata, options);
        }
        throw new UnsupportedOperationException("sharded bucket");
    }

    @Override
    public void abortMultipartUpload(MultipartUpload mpu) {
        if (!this.buckets.containsKey(mpu.containerName())) {
            this.delegate().abortMultipartUpload(mpu);
        }
        throw new UnsupportedOperationException("sharded bucket");
    }

    @Override
    public String completeMultipartUpload(MultipartUpload mpu,
                                          List<MultipartPart> parts) {
        if (!this.buckets.containsKey(mpu.containerName())) {
            return this.delegate().completeMultipartUpload(mpu, parts);
        }
        throw new UnsupportedOperationException("sharded bucket");
    }

    @Override
    public MultipartPart uploadMultipartPart(MultipartUpload mpu,
                                             int partNumber, Payload payload) {
        if (!this.buckets.containsKey(mpu.containerName())) {
            return this.delegate()
                    .uploadMultipartPart(mpu, partNumber, payload);
        }
        throw new UnsupportedOperationException("sharded bucket");
    }

    @Override
    public List<MultipartPart> listMultipartUpload(MultipartUpload mpu) {
        if (!this.buckets.containsKey(mpu.containerName())) {
            return this.delegate().listMultipartUpload(mpu);
        }
        throw new UnsupportedOperationException("sharded bucket");
    }

    @Override
    public List<MultipartUpload> listMultipartUploads(String container) {
        if (!this.buckets.containsKey(container)) {
            return this.delegate().listMultipartUploads(container);
        }
        throw new UnsupportedOperationException("sharded bucket");
    }

    @Override
    public void downloadBlob(String container, String name, File destination) {
        this.delegate().downloadBlob(this.getShard(container, name), name,
                destination);
    }

    @Override
    public void downloadBlob(String container, String name, File destination,
                             ExecutorService executor) {
        this.delegate()
                .downloadBlob(this.getShard(container, name), name, destination,
                        executor);
    }

    @Override
    public InputStream streamBlob(String container, String name) {
        return this.delegate().streamBlob(this.getShard(container, name), name);
    }

    @Override
    public InputStream streamBlob(String container, String name,
                                  ExecutorService executor) {
        return this.delegate()
                .streamBlob(this.getShard(container, name), name, executor);
    }
}
