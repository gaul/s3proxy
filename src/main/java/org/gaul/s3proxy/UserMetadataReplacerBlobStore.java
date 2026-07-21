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

import com.google.common.collect.ImmutableMap;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.ForwardingBlobStore;
import org.gaul.s3proxy.blobstore.domain.Blob;
import org.gaul.s3proxy.blobstore.domain.BlobMetadata;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.gaul.s3proxy.blobstore.options.CopyOptions;
import org.gaul.s3proxy.blobstore.options.GetOptions;
import org.gaul.s3proxy.blobstore.options.PutOptions;

/**
 * BlobStore which maps user metadata keys and values using character
 * replacement.  This is useful for some object stores like Azure which do not
 * allow characters like hyphens.  This munges keys and values during putBlob
 * and unmunges them on getBlob.
 */
final class UserMetadataReplacerBlobStore extends ForwardingBlobStore {
    private final String fromChars;
    private final String toChars;

    private UserMetadataReplacerBlobStore(
            BlobStore blobStore, String fromChars, String toChars) {
        super(blobStore);
        checkArgument(fromChars.length() == toChars.length());
        this.fromChars = fromChars;
        this.toChars = toChars;
    }

    public static BlobStore newUserMetadataReplacerBlobStore(
            BlobStore blobStore, String fromChars, String toChars) {
        return new UserMetadataReplacerBlobStore(blobStore, fromChars, toChars);
    }

    @Override
    public String putBlob(String containerName, Blob blob) {
        return putBlob(containerName, blob, PutOptions.NONE);
    }

    @Override
    public String putBlob(String containerName, Blob blob,
            PutOptions putOptions) {
        var metadata = ImmutableMap.<String, String>builder();
        for (var entry : blob.getMetadata().userMetadata().entrySet()) {
            metadata.put(replaceChars(entry.getKey(), fromChars, toChars),
                    replaceChars(entry.getValue(), fromChars, toChars));
        }
        return super.putBlob(containerName, blob.toBuilder()
                .userMetadata(metadata.build())
                .build(), putOptions);
    }

    @Override
    public BlobMetadata blobMetadata(String container, String name) {
        var blobMetadata = super.blobMetadata(container, name);
        if (blobMetadata == null) {
            return null;
        }

        var metadata = ImmutableMap.<String, String>builder();
        // TODO: duplication
        for (var entry : blobMetadata.userMetadata().entrySet()) {
            metadata.put(replaceChars(entry.getKey(), /*fromChars=*/ toChars, /*toChars=*/ fromChars),
                    replaceChars(entry.getValue(), /*fromChars=*/ toChars, /*toChars=*/ fromChars));
        }
        return blobMetadata.toBuilder().userMetadata(metadata.build()).build();
    }

    @Override
    public Blob getBlob(String containerName, String name) {
        return getBlob(containerName, name, GetOptions.NONE);
    }

    @Override
    public Blob getBlob(String containerName, String name,
            GetOptions getOptions) {
        var blob = super.getBlob(containerName, name, getOptions);
        if (blob == null) {
            return null;
        }

        var metadata = ImmutableMap.<String, String>builder();
        for (var entry : blob.getMetadata().userMetadata().entrySet()) {
            metadata.put(replaceChars(entry.getKey(), /*fromChars=*/ toChars, /*toChars=*/ fromChars),
                    replaceChars(entry.getValue(), /*fromChars=*/ toChars, /*toChars=*/ fromChars));
        }
        return blob.toBuilder()
                .userMetadata(metadata.build())
                .build();
    }

    @Override
    public String copyBlob(String fromContainer, String fromName,
            String toContainer, String toName, CopyOptions options) {
        var userMetadata = options.userMetadata();
        if (userMetadata != null) {
            // A copy that replaces user metadata must munge the new keys and
            // values the same way putBlob does, so the backend stores the
            // mapped form and getBlob reverses it.  A copy without replacement
            // metadata carries the source's already-munged metadata forward
            // untouched.
            var metadata = ImmutableMap.<String, String>builder();
            for (var entry : userMetadata.entrySet()) {
                metadata.put(replaceChars(entry.getKey(), fromChars, toChars),
                        replaceChars(entry.getValue(), fromChars, toChars));
            }
            var builder = CopyOptions.builder().userMetadata(metadata.build());
            if (options.contentMetadata() != null) {
                builder.contentMetadata(options.contentMetadata());
            }
            if (options.ifMatch() != null) {
                builder.ifMatch(options.ifMatch());
            }
            if (options.ifNoneMatch() != null) {
                builder.ifNoneMatch(options.ifNoneMatch());
            }
            if (options.ifModifiedSince() != null) {
                builder.ifModifiedSince(options.ifModifiedSince());
            }
            if (options.ifUnmodifiedSince() != null) {
                builder.ifUnmodifiedSince(options.ifUnmodifiedSince());
            }
            options = builder.build();
        }
        return super.copyBlob(fromContainer, fromName, toContainer, toName,
                options);
    }

    @Override
    public MultipartUpload initiateMultipartUpload(String container,
            BlobMetadata blobMetadata, PutOptions overrides) {
        var metadata = ImmutableMap.<String, String>builder();
        for (var entry : blobMetadata.userMetadata().entrySet()) {
            metadata.put(replaceChars(entry.getKey(), /*fromChars=*/ fromChars, /*toChars=*/ toChars),
                    replaceChars(entry.getValue(), /*fromChars=*/ fromChars, /*toChars=*/ toChars));
        }
        return super.initiateMultipartUpload(container,
                blobMetadata.toBuilder().userMetadata(metadata.build()).build(),
                overrides);
    }

    private static String replaceChars(String value, String fromChars,
            String toChars) {
        var builder = new StringBuilder(/*capacity=*/ value.length());
        for (int i = 0; i < value.length(); ++i) {
            char c = value.charAt(i);
            int idx = fromChars.indexOf(c);
            builder.append(idx < 0 ? c : toChars.charAt(idx));
        }
        return builder.toString();
    }
}
