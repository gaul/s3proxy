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

import static com.google.common.base.Preconditions.checkArgument;
import static java.util.Objects.requireNonNull;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
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

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.ForwardingBlobStore;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.jspecify.annotations.Nullable;

import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.services.s3.model.Bucket;
import software.amazon.awssdk.services.s3.model.BucketCannedACL;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.CopyObjectRequest;
import software.amazon.awssdk.services.s3.model.CopyObjectResponse;
import software.amazon.awssdk.services.s3.model.CreateBucketRequest;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.DeleteObjectResponse;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.HeadObjectRequest;
import software.amazon.awssdk.services.s3.model.HeadObjectResponse;
import software.amazon.awssdk.services.s3.model.ListBucketsResponse;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Response;
import software.amazon.awssdk.services.s3.model.NoSuchBucketException;
import software.amazon.awssdk.services.s3.model.ObjectCannedACL;
import software.amazon.awssdk.services.s3.model.Part;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.awssdk.services.s3.model.S3Object;
import software.amazon.awssdk.services.s3.model.UploadPartResponse;

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
                    "Number of shards unset for sharded buckets: %s"
                            .formatted(allMissingShards));
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
                virtualBucket -> requireNonNull(
                        buckets.get(virtualBucket)).prefix,
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
        return "%s-%d".formatted(bucket.prefix, shard);
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

    private void checkSuperBlock(HeadObjectResponse blob,
                                 Map<String, String> expectedMeta,
                                 String container) {
        Map<String, String> currentSuperblockMeta =
                blob.metadata();
        for (var entry : expectedMeta.entrySet()) {
            String current = currentSuperblockMeta.get(entry.getKey());
            String expected = entry.getValue();
            if (!expected.equalsIgnoreCase(current)) {
                throw new RuntimeException(
                        "Superblock block for %s does not match: %s, %s".formatted(
                        container, expected, current));
            }
        }
    }

    private boolean createShards(ShardedBucket bucket,
                                 CreateBucketRequest request) {
        var futuresBuilder = new ImmutableList.Builder<Future<Boolean>>();
        ExecutorService executor = Executors.newFixedThreadPool(
                Math.min(bucket.shards, MAX_SHARD_THREADS));
        BlobStore blobStore = this.delegate();
        for (int n = 0; n < bucket.shards; ++n) {
            String shardContainer = ShardedBlobStore.getShardContainer(
                    bucket, n);
            futuresBuilder.add(executor.submit(
                () -> blobStore.createContainer(request.toBuilder()
                        .bucket(shardContainer)
                        .build())));
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

    @SuppressWarnings("EmptyCatch")
    @Override
    public boolean createContainer(CreateBucketRequest request) {
        String container = request.bucket();
        ShardedBucket bucket = this.buckets.get(container);
        if (bucket == null) {
            return this.delegate().createContainer(request);
        }

        Map<String, String> superblockMeta = this.createSuperblockMeta(bucket);
        // Fetch only the superblock metadata: getBlob would open a payload
        // stream that checkSuperBlock never reads, leaking the connection.
        HeadObjectResponse existingSuperblock = null;
        try {
            existingSuperblock = this.delegate().blobMetadata(
                    ShardedBlobStore.getShardContainer(bucket, 0),
                    SUPERBLOCK_BLOB_NAME);
        } catch (NoSuchBucketException ignored) {
        }
        if (existingSuperblock != null) {
            checkSuperBlock(existingSuperblock, superblockMeta, container);
        }

        boolean ret = createShards(bucket, request);

        // Upload the superblock
        if (existingSuperblock == null) {
            this.delegate().putBlob(PutObjectRequest.builder()
                    .bucket(ShardedBlobStore.getShardContainer(bucket, 0))
                    .key(SUPERBLOCK_BLOB_NAME)
                    .contentLength(0L)
                    .metadata(superblockMeta)
                    .build(), new ByteArrayInputStream(new byte[0]));
        }

        return ret;
    }

    @Override
    public ListBucketsResponse list() {
        ListBucketsResponse upstream = this.delegate().list();
        var results = new ImmutableList.Builder<Bucket>();
        Set<String> virtualBuckets = new HashSet<>();
        for (Bucket bucket : upstream.buckets()) {
            Matcher matcher = SHARD_RE.matcher(bucket.name());
            if (!matcher.matches()) {
                results.add(bucket);
                continue;
            }
            String prefix = matcher.group("prefix");
            String virtualBucketName = this.prefixMap.get(prefix);
            if (virtualBucketName == null) {
                results.add(bucket);
                continue;
            }
            if (!virtualBuckets.contains(prefix)) {
                virtualBuckets.add(prefix);
                results.add(bucket.toBuilder()
                        .name(virtualBucketName)
                        .build());
            }
        }
        return upstream.toBuilder().buckets(results.build()).build();
    }

    @Override
    public ListObjectsV2Response list(ListObjectsV2Request request) {
        if (!this.buckets.containsKey(request.bucket())) {
            return this.delegate().list(request);
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
    public BucketCannedACL getContainerAccess(String container) {
        if (!this.buckets.containsKey(container)) {
            return this.delegate().getContainerAccess(container);
        }
        throw new UnsupportedOperationException("sharded bucket");
    }

    @Override
    public void setContainerAccess(String container,
                                   BucketCannedACL containerAccess) {
        if (!this.buckets.containsKey(container)) {
            this.delegate().setContainerAccess(container, containerAccess);
            return;
        }
        throw new UnsupportedOperationException("sharded bucket");
    }

    @Override
    public void clearContainer(ListObjectsV2Request request) {
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

    private boolean shardsAreEmpty(ShardedBucket bucket) {
        // Shard 0 is inspected separately for the superblock; only shards
        // 1..N-1 need to be empty here.
        if (bucket.shards <= 1) {
            return true;
        }
        var futuresBuilder = new ImmutableList.Builder<Future<Boolean>>();
        ExecutorService executor = Executors.newFixedThreadPool(
                Math.min(bucket.shards - 1, MAX_SHARD_THREADS));
        BlobStore blobStore = this.delegate();
        for (int n = 1; n < bucket.shards; ++n) {
            String shard = ShardedBlobStore.getShardContainer(bucket, n);
            futuresBuilder.add(executor.submit(() -> {
                try {
                    return blobStore.list(shard).contents().isEmpty();
                } catch (NoSuchBucketException nsbe) {
                    return true;
                }
            }));
        }
        executor.shutdown();
        boolean empty = true;
        for (Future<Boolean> future : futuresBuilder.build()) {
            try {
                empty &= future.get();
            } catch (InterruptedException | ExecutionException e) {
                throw new RuntimeException("Failed to list shards", e);
            }
        }
        return empty;
    }

    @Override
    public boolean deleteContainerIfEmpty(String container) {
        ShardedBucket bucket = this.buckets.get(container);
        if (bucket == null) {
            return this.delegate().deleteContainerIfEmpty(container);
        }

        // A sharded bucket is empty only when shard 0 holds nothing but the
        // superblock and every other shard is empty.  Verify all shards
        // before deleting anything; otherwise removing the superblock and the
        // empty shards would corrupt a bucket whose objects hash to other
        // shards.
        String zeroShardContainer = ShardedBlobStore.getShardContainer(
                bucket, 0);
        boolean superblockPresent = false;
        for (S3Object sm : this.delegate().list(zeroShardContainer)
                .contents()) {
            if (sm.key().equals(SUPERBLOCK_BLOB_NAME)) {
                superblockPresent = true;
            } else {
                return false;
            }
        }
        if (!this.shardsAreEmpty(bucket)) {
            return false;
        }

        if (superblockPresent) {
            this.delegate().removeBlob(zeroShardContainer,
                    SUPERBLOCK_BLOB_NAME);
        }
        return this.deleteShards(bucket);
    }

    @Override
    public boolean blobExists(String container, String name) {
        return this.delegate().blobExists(this.getShard(container, name), name);
    }

    @Override
    public PutObjectResponse putBlob(PutObjectRequest request,
            InputStream payload) {
        return this.delegate().putBlob(request.toBuilder()
                .bucket(this.getShard(request.bucket(), request.key()))
                .build(), payload);
    }

    @Override
    public CopyObjectResponse copyBlob(CopyObjectRequest request) {
        return this.delegate().copyBlob(request.toBuilder()
                .sourceBucket(this.getShard(request.sourceBucket(),
                        request.sourceKey()))
                .destinationBucket(this.getShard(request.destinationBucket(),
                        request.destinationKey()))
                .build());
    }

    @Override
    @Nullable
    public HeadObjectResponse blobMetadata(HeadObjectRequest request) {
        return this.delegate().blobMetadata(request.toBuilder()
                .bucket(this.getShard(request.bucket(), request.key()))
                .build());
    }

    @Override
    @Nullable
    public ResponseInputStream<GetObjectResponse> getBlob(
            GetObjectRequest request) {
        return this.delegate().getBlob(request.toBuilder()
                .bucket(this.getShard(request.bucket(), request.key()))
                .build());
    }

    @Override
    public void removeBlob(String container, String name) {
        this.delegate().removeBlob(this.getShard(container, name), name);
    }

    @Override
    public DeleteObjectResponse removeBlob(DeleteObjectRequest request) {
        return this.delegate().removeBlob(request.toBuilder()
                .bucket(this.getShard(request.bucket(), request.key()))
                .build());
    }

    @Override
    public ObjectCannedACL getBlobAccess(String container, String name) {
        return this.delegate()
                .getBlobAccess(this.getShard(container, name), name);
    }

    @Override
    public void setBlobAccess(String container, String name,
                              ObjectCannedACL access) {
        this.delegate()
                .setBlobAccess(this.getShard(container, name), name, access);
    }

    @Override
    public MultipartUpload initiateMultipartUpload(
            CreateMultipartUploadRequest request) {
        if (!this.buckets.containsKey(request.bucket())) {
            return this.delegate().initiateMultipartUpload(request);
        }
        throw new UnsupportedOperationException("sharded bucket");
    }

    @Override
    public void abortMultipartUpload(MultipartUpload mpu) {
        if (!this.buckets.containsKey(mpu.containerName())) {
            this.delegate().abortMultipartUpload(mpu);
            return;
        }
        throw new UnsupportedOperationException("sharded bucket");
    }

    @Override
    public CompleteMultipartUploadResponse completeMultipartUpload(
            MultipartUpload mpu, CompleteMultipartUploadRequest request) {
        if (!this.buckets.containsKey(mpu.containerName())) {
            return this.delegate().completeMultipartUpload(mpu, request);
        }
        throw new UnsupportedOperationException("sharded bucket");
    }

    @Override
    public UploadPartResponse uploadMultipartPart(MultipartUpload mpu,
            int partNumber, InputStream is, long contentLength,
            @Nullable HashCode contentMD5) {
        if (!this.buckets.containsKey(mpu.containerName())) {
            return this.delegate()
                    .uploadMultipartPart(mpu, partNumber, is, contentLength,
                            contentMD5);
        }
        throw new UnsupportedOperationException("sharded bucket");
    }

    @Override
    public List<Part> listMultipartUpload(MultipartUpload mpu) {
        if (!this.buckets.containsKey(mpu.containerName())) {
            return this.delegate().listMultipartUpload(mpu);
        }
        throw new UnsupportedOperationException("sharded bucket");
    }

    @Override
    public List<software.amazon.awssdk.services.s3.model.MultipartUpload>
            listMultipartUploads(String container) {
        if (!this.buckets.containsKey(container)) {
            return this.delegate().listMultipartUploads(container);
        }
        throw new UnsupportedOperationException("sharded bucket");
    }
    // Disable versioning: the shard mapping does not extend to the
    // versioned operations.
    @Override
    public boolean supportsVersioning() {
        return false;
    }

}
