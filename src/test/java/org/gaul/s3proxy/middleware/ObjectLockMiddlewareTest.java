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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.regex.Pattern;

import com.google.common.collect.ImmutableBiMap;

import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.gaul.s3proxy.S3ProxyConstants;
import org.gaul.s3proxy.TestUtils;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.ForwardingBlobStore;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.GetObjectLegalHoldRequest;
import software.amazon.awssdk.services.s3.model.GetObjectLegalHoldResponse;
import software.amazon.awssdk.services.s3.model.GetObjectLockConfigurationRequest;
import software.amazon.awssdk.services.s3.model.GetObjectLockConfigurationResponse;
import software.amazon.awssdk.services.s3.model.GetObjectRetentionRequest;
import software.amazon.awssdk.services.s3.model.GetObjectRetentionResponse;
import software.amazon.awssdk.services.s3.model.PutObjectLegalHoldRequest;
import software.amazon.awssdk.services.s3.model.PutObjectLegalHoldResponse;
import software.amazon.awssdk.services.s3.model.PutObjectLockConfigurationRequest;
import software.amazon.awssdk.services.s3.model.PutObjectLockConfigurationResponse;
import software.amazon.awssdk.services.s3.model.PutObjectRetentionRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRetentionResponse;

/**
 * A lock protects versions, and the middlewares that rename buckets or
 * rewrite keys turn versioning off, so they report no object lock and the
 * frontend refuses every object-lock request before it reaches them.  They
 * forward the six object-lock calls untranslated, though, so one made
 * anyway, by an embedder, would act on another bucket's or another key's
 * lock.  They refuse such a call themselves.
 */
public final class ObjectLockMiddlewareTest {
    private static final String BUCKET = "bucket";
    private static final String KEY = "key";

    /** A store that keeps object locks, recording every lock call. */
    private static final class LockingStore extends ForwardingBlobStore {
        private final List<String> calls =
                Collections.synchronizedList(new ArrayList<>());

        LockingStore(BlobStore delegate) {
            super(delegate);
        }

        @Override
        public boolean supportsVersioning() {
            return true;
        }

        @Override
        public boolean supportsObjectLock() {
            return true;
        }

        @Override
        public GetObjectLockConfigurationResponse getObjectLockConfiguration(
                GetObjectLockConfigurationRequest request) {
            calls.add("getObjectLockConfiguration " + request.bucket());
            return GetObjectLockConfigurationResponse.builder().build();
        }

        @Override
        public PutObjectLockConfigurationResponse putObjectLockConfiguration(
                PutObjectLockConfigurationRequest request) {
            calls.add("putObjectLockConfiguration " + request.bucket());
            return PutObjectLockConfigurationResponse.builder().build();
        }

        @Override
        public GetObjectRetentionResponse getObjectRetention(
                GetObjectRetentionRequest request) {
            calls.add("getObjectRetention " + request.key());
            return GetObjectRetentionResponse.builder().build();
        }

        @Override
        public PutObjectRetentionResponse putObjectRetention(
                PutObjectRetentionRequest request) {
            calls.add("putObjectRetention " + request.key());
            return PutObjectRetentionResponse.builder().build();
        }

        @Override
        public GetObjectLegalHoldResponse getObjectLegalHold(
                GetObjectLegalHoldRequest request) {
            calls.add("getObjectLegalHold " + request.key());
            return GetObjectLegalHoldResponse.builder().build();
        }

        @Override
        public PutObjectLegalHoldResponse putObjectLegalHold(
                PutObjectLegalHoldRequest request) {
            calls.add("putObjectLegalHold " + request.key());
            return PutObjectLegalHoldResponse.builder().build();
        }
    }

    @Test
    public void testRenamingMiddlewaresRefuseObjectLock() throws Exception {
        var locking = new LockingStore(TestUtils.createTransientBlobStore());

        var encryption = new Properties();
        encryption.setProperty(
                S3ProxyConstants.PROPERTY_ENCRYPTED_BLOBSTORE_PASSWORD,
                "password");
        encryption.setProperty(
                S3ProxyConstants.PROPERTY_ENCRYPTED_BLOBSTORE_SALT, "salt");
        Map<String, BlobStore> wrappers = Map.of(
                "alias", AliasBlobStore.newAliasBlobStore(locking,
                        ImmutableBiMap.of(BUCKET, "backend")),
                "sharded", ShardedBlobStore.newShardedBlobStore(locking,
                        Map.of(BUCKET, 4), Map.of()),
                "regex", RegexBlobStore.newRegexBlobStore(locking, List.of(
                        new SimpleEntry<>(Pattern.compile("^key$"), "other"))),
                "encrypted", EncryptedBlobStore.newEncryptedBlobStore(
                        locking, encryption),
                "prefix", PrefixBlobStore.newPrefixBlobStore(locking,
                        Map.of(BUCKET, "tenant/")),
                "user-metadata-replacer", UserMetadataReplacerBlobStore
                        .newUserMetadataReplacerBlobStore(locking, "_", "-"));

        assertThat(locking.supportsObjectLock()).isTrue();
        for (var entry : wrappers.entrySet()) {
            BlobStore wrapper = entry.getValue();
            assertThat(wrapper.supportsObjectLock()).as(entry.getKey())
                    .isFalse();
            assertRefused(() -> wrapper.getObjectLockConfiguration(
                    GetObjectLockConfigurationRequest.builder()
                            .bucket(BUCKET).build()));
            assertRefused(() -> wrapper.putObjectLockConfiguration(
                    PutObjectLockConfigurationRequest.builder()
                            .bucket(BUCKET).build()));
            assertRefused(() -> wrapper.getObjectRetention(
                    GetObjectRetentionRequest.builder()
                            .bucket(BUCKET).key(KEY).build()));
            assertRefused(() -> wrapper.putObjectRetention(
                    PutObjectRetentionRequest.builder()
                            .bucket(BUCKET).key(KEY).build()));
            assertRefused(() -> wrapper.getObjectLegalHold(
                    GetObjectLegalHoldRequest.builder()
                            .bucket(BUCKET).key(KEY).build()));
            assertRefused(() -> wrapper.putObjectLegalHold(
                    PutObjectLegalHoldRequest.builder()
                            .bucket(BUCKET).key(KEY).build()));
        }
        assertThat(locking.calls).isEmpty();
    }

    /** A wrapper that keeps versioning passes the calls on as before. */
    @Test
    public void testReadOnlyMiddlewarePassesObjectLockReads() {
        var locking = new LockingStore(TestUtils.createTransientBlobStore());
        BlobStore readOnly = ReadOnlyBlobStore.newReadOnlyBlobStore(locking);

        assertThat(readOnly.supportsObjectLock()).isTrue();
        readOnly.getObjectRetention(GetObjectRetentionRequest.builder()
                .bucket(BUCKET).key(KEY).build());
        assertThat(locking.calls).containsExactly("getObjectRetention key");
    }

    private static void assertRefused(ThrowingCallable call) {
        assertThatThrownBy(call)
                .isInstanceOf(UnsupportedOperationException.class);
    }
}
