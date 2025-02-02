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

import com.google.common.collect.ImmutableMap;

import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.domain.Blob;
import org.jclouds.blobstore.domain.BlobMetadata;
import org.jclouds.blobstore.domain.MultipartUpload;
import org.jclouds.blobstore.domain.MutableBlobMetadata;
import org.jclouds.blobstore.options.GetOptions;
import org.jclouds.blobstore.options.PutOptions;
import org.jclouds.blobstore.util.ForwardingBlobStore;

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
        return putBlob(containerName, blob, new PutOptions());
    }

    @Override
    public String putBlob(String containerName, Blob blob,
            PutOptions putOptions) {
        var metadata = ImmutableMap.<String, String>builder();
        for (var entry : blob.getMetadata().getUserMetadata().entrySet()) {
            metadata.put(replaceChars(entry.getKey(), fromChars, toChars),
                    replaceChars(entry.getValue(), fromChars, toChars));
        }
        // TODO: should this modify the parameter?
        blob.getMetadata().setUserMetadata(metadata.build());
        return super.putBlob(containerName, blob, putOptions);
    }

    @Override
    public BlobMetadata blobMetadata(String container, String name) {
        var blobMetadata = super.blobMetadata(container, name);
        if (blobMetadata == null) {
            return null;
        }

        var metadata = ImmutableMap.<String, String>builder();
        // TODO: duplication
        for (var entry : blobMetadata.getUserMetadata().entrySet()) {
            metadata.put(replaceChars(entry.getKey(), /*fromChars=*/ toChars, /*toChars=*/ fromChars),
                    replaceChars(entry.getValue(), /*fromChars=*/ toChars, /*toChars=*/ fromChars));
        }
        ((MutableBlobMetadata) blobMetadata).setUserMetadata(metadata.build());
        return blobMetadata;
    }

    @Override
    public Blob getBlob(String containerName, String name) {
        return getBlob(containerName, name, new GetOptions());
    }

    @Override
    public Blob getBlob(String containerName, String name,
            GetOptions getOptions) {
        var blob = super.getBlob(containerName, name, getOptions);
        if (blob == null) {
            return null;
        }

        var metadata = ImmutableMap.<String, String>builder();
        for (var entry : blob.getMetadata().getUserMetadata().entrySet()) {
            metadata.put(replaceChars(entry.getKey(), /*fromChars=*/ toChars, /*toChars=*/ fromChars),
                    replaceChars(entry.getValue(), /*fromChars=*/ toChars, /*toChars=*/ fromChars));
        }
        blob.getMetadata().setUserMetadata(metadata.build());
        return blob;
    }

    @Override
    public MultipartUpload initiateMultipartUpload(String container,
            BlobMetadata blobMetadata, PutOptions overrides) {
        var metadata = ImmutableMap.<String, String>builder();
        for (var entry : blobMetadata.getUserMetadata().entrySet()) {
            metadata.put(replaceChars(entry.getKey(), /*fromChars=*/ fromChars, /*toChars=*/ toChars),
                    replaceChars(entry.getValue(), /*fromChars=*/ fromChars, /*toChars=*/ toChars));
        }
        ((MutableBlobMetadata) blobMetadata).setUserMetadata(metadata.build());
        return super.initiateMultipartUpload(container, blobMetadata,
                overrides);
    }

    private static String replaceChars(String value, String fromChars,
            String toChars) {
        var builder = new StringBuilder(/*capacity=*/ value.length());
        for (int i = 0; i < value.length(); ++i) {
            for (int j = 0; j < fromChars.length(); ++j) {
                builder.append(value.charAt(i) == fromChars.charAt(j) ?
                        toChars.charAt(j) : value.charAt(i));
            }
        }
        return builder.toString();
    }
}
