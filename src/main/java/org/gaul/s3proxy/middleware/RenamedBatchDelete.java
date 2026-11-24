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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Supplier;
import java.util.function.UnaryOperator;

import com.google.common.collect.ImmutableList;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.jspecify.annotations.Nullable;

import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.services.s3.model.DeleteObjectsRequest;
import software.amazon.awssdk.services.s3.model.DeleteObjectsResponse;
import software.amazon.awssdk.services.s3.model.DeletedObject;
import software.amazon.awssdk.services.s3.model.ObjectIdentifier;
import software.amazon.awssdk.services.s3.model.S3Error;

/**
 * A batch delete handed down whole by a wrapper that renames buckets, keys
 * or both, rather than one delete a key through its removeBlob: a
 * DeleteObjects of a thousand keys is then one request to a backend with a
 * bulk delete of its own, not a thousand.
 */
final class RenamedBatchDelete {
    private RenamedBatchDelete() {
        throw new AssertionError("intentionally unimplemented");
    }

    /**
     * Sends {@code delegate} one batch delete for each of its buckets the
     * keys land in, and reports each key's outcome under the name the
     * caller gave it.  {@code bucketOfKey} names the delegate's bucket for
     * each of the caller's keys, and {@code renameKey} the delegate's key.
     *
     * <p>Two keys renamed onto one object, or a key the wrapper refuses to
     * rename, send the whole request to {@code oneAtATime} instead -- the
     * interface's default, deleting through the wrapper's removeBlob.  The
     * delegate's answer could not say which of two such keys it was for,
     * and the default reports a refused key as that key's error.
     */
    static DeleteObjectsResponse removeBlobs(BlobStore delegate,
            DeleteObjectsRequest request, UnaryOperator<String> bucketOfKey,
            UnaryOperator<String> renameKey,
            Supplier<DeleteObjectsResponse> oneAtATime) {
        var objects = request.delete() == null ?
                List.<ObjectIdentifier>of() : request.delete().objects();
        if (objects.isEmpty()) {
            return DeleteObjectsResponse.builder().build();
        }

        // each delegate bucket's objects, and its names back to the caller's
        Map<String, List<ObjectIdentifier>> batches = new LinkedHashMap<>();
        Map<String, Map<String, String>> callerKeys = new HashMap<>();
        for (ObjectIdentifier object : objects) {
            String bucket;
            String key;
            try {
                bucket = bucketOfKey.apply(object.key());
                key = renameKey.apply(object.key());
            } catch (AwsServiceException ase) {
                return oneAtATime.get();
            }
            String previous = callerKeys.computeIfAbsent(bucket,
                    b -> new HashMap<>()).putIfAbsent(key, object.key());
            if (previous != null && !previous.equals(object.key())) {
                return oneAtATime.get();
            }
            batches.computeIfAbsent(bucket, b -> new ArrayList<>())
                    .add(object.toBuilder().key(key).build());
        }

        var deleted = new ImmutableList.Builder<DeletedObject>();
        var errors = new ImmutableList.Builder<S3Error>();
        for (var batch : batches.entrySet()) {
            Map<String, String> names = Objects.requireNonNull(
                    callerKeys.get(batch.getKey()));
            DeleteObjectsResponse response = delegate.removeBlobs(
                    request.toBuilder()
                            .bucket(batch.getKey())
                            .delete(request.delete().toBuilder()
                                    .objects(batch.getValue())
                                    .build())
                            .build());
            for (DeletedObject object : response.deleted()) {
                deleted.add(object.toBuilder()
                        .key(callerKey(names, object.key()))
                        .build());
            }
            for (S3Error error : response.errors()) {
                errors.add(error.toBuilder()
                        .key(callerKey(names, error.key()))
                        .build());
            }
        }
        return DeleteObjectsResponse.builder()
                .deleted(deleted.build())
                .errors(errors.build())
                .build();
    }

    private static @Nullable String callerKey(Map<String, String> names,
            @Nullable String delegateKey) {
        String name = delegateKey == null ? null : names.get(delegateKey);
        return name == null ? delegateKey : name;
    }
}
