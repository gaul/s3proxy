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

import java.io.InputStream;
import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.google.common.hash.HashCode;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.ForwardingBlobStore;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.CopyObjectRequest;
import software.amazon.awssdk.services.s3.model.CopyObjectResponse;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.HeadObjectRequest;
import software.amazon.awssdk.services.s3.model.HeadObjectResponse;
import software.amazon.awssdk.services.s3.model.ObjectCannedACL;
import software.amazon.awssdk.services.s3.model.Part;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.awssdk.services.s3.model.UploadPartResponse;

/**
 * This class implements a middleware to apply regex to blob names.
 * The regex are configured as:
 * s3proxy.regex-blobstore.match.&lt;regex name&gt; = &lt;regex match
 * expression&gt;
 * s3proxy.regex-blobstore.replace.&lt;regex name&gt; = &lt;regex replace
 * expression&gt;
 *
 * You can add multiple regex, they will be applied from the beginning to the
 * end,
 * stopping as soon as the first regex matches.
 */
public final class RegexBlobStore extends ForwardingBlobStore {
    private static final Logger logger = LoggerFactory.getLogger(
            RegexBlobStore.class);

    private final List<Entry<Pattern, String>> regexs;

    private RegexBlobStore(BlobStore blobStore,
            List<Entry<Pattern, String>> regexs) {
        super(blobStore);
        this.regexs = requireNonNull(regexs);
    }

    static BlobStore newRegexBlobStore(BlobStore delegate,
            List<Entry<Pattern, String>> regexs) {
        return new RegexBlobStore(delegate, regexs);
    }

    public static List<Map.Entry<Pattern, String>> parseRegexs(
            Properties properties) {
        List<Entry<String, String>> configRegex = new ArrayList<>();
        List<Entry<Pattern, String>> regexs = new ArrayList<>();

        for (String key : properties.stringPropertyNames()) {
            if (key.startsWith(S3ProxyConstants.PROPERTY_REGEX_BLOBSTORE)) {
                String propKey = key.substring(
                        S3ProxyConstants.PROPERTY_REGEX_BLOBSTORE.length() + 1);
                String value = properties.getProperty(key);

                configRegex.add(new SimpleEntry<>(propKey, value));
            }
        }

        for (Entry<String, String> entry : configRegex) {
            String key = entry.getKey();
            if (key.startsWith(
                    S3ProxyConstants.PROPERTY_REGEX_BLOBSTORE_MATCH)) {
                String regexName = key.substring(S3ProxyConstants
                        .PROPERTY_REGEX_BLOBSTORE_MATCH.length() + 1);
                String regex = entry.getValue();
                Pattern pattern = Pattern.compile(regex);

                String replace = properties.getProperty(String.join(
                        ".", S3ProxyConstants.PROPERTY_REGEX_BLOBSTORE,
                        S3ProxyConstants.PROPERTY_REGEX_BLOBSTORE_REPLACE,
                        regexName));

                checkArgument(
                        replace != null,
                        "Regex %s has no replace property associated",
                        regexName);

                logger.info(
                        "Adding new regex with name {} replaces with {} to {}",
                        regexName, regex, replace);

                regexs.add(new SimpleEntry<>(pattern, replace));
            }
        }

        return List.copyOf(regexs);
    }

    @Override
    public boolean blobExists(String container, String name) {
        return super.blobExists(container, replaceBlobName(name));
    }

    @Override
    public PutObjectResponse putBlob(PutObjectRequest request,
            InputStream payload) {
        String name = request.key();
        String newName = replaceBlobName(name);
        logger.debug("Renaming blob name from {} to {}", name, newName);

        return super.putBlob(request.toBuilder().key(newName).build(),
                payload);
    }

    @Override
    public CopyObjectResponse copyBlob(CopyObjectRequest request) {
        return super.copyBlob(request.toBuilder()
                .sourceKey(replaceBlobName(request.sourceKey()))
                .destinationKey(replaceBlobName(request.destinationKey()))
                .build());
    }

    @Override
    @Nullable
    public HeadObjectResponse blobMetadata(HeadObjectRequest request) {
        return super.blobMetadata(request.toBuilder()
                .key(replaceBlobName(request.key()))
                .build());
    }

    @Override
    @Nullable
    public ResponseInputStream<GetObjectResponse> getBlob(
            GetObjectRequest request) {
        return super.getBlob(request.toBuilder()
                .key(replaceBlobName(request.key()))
                .build());
    }

    @Override
    public void removeBlob(String container, String name) {
        super.removeBlob(container, replaceBlobName(name));
    }

    @Override
    public void removeBlobs(String container, Iterable<String> iterable) {
        List<String> blobs = new ArrayList<>();
        for (String name : iterable) {
            blobs.add(replaceBlobName(name));
        }
        super.removeBlobs(container, blobs);
    }

    @Override
    public ObjectCannedACL getBlobAccess(String container, String name) {
        return super.getBlobAccess(container, replaceBlobName(name));
    }

    @Override
    public void setBlobAccess(String container, String name,
            ObjectCannedACL access) {
        super.setBlobAccess(container, replaceBlobName(name), access);
    }

    @Override
    public MultipartUpload initiateMultipartUpload(
            CreateMultipartUploadRequest request) {
        return super.initiateMultipartUpload(request.toBuilder()
                .key(replaceBlobName(request.key()))
                .build());
    }

    @Override
    public void abortMultipartUpload(MultipartUpload mpu) {
        super.abortMultipartUpload(rewriteMultipartUpload(mpu));
    }

    @Override
    public CompleteMultipartUploadResponse completeMultipartUpload(MultipartUpload mpu,
            CompleteMultipartUploadRequest request) {
        return super.completeMultipartUpload(rewriteMultipartUpload(mpu),
                request.toBuilder()
                        .key(replaceBlobName(request.key()))
                        .build());
    }

    @Override
    public UploadPartResponse uploadMultipartPart(MultipartUpload mpu,
            int partNumber, InputStream is, long contentLength,
            @Nullable HashCode contentMD5) {
        return super.uploadMultipartPart(rewriteMultipartUpload(mpu),
                partNumber, is, contentLength, contentMD5);
    }

    @Override
    public List<Part> listMultipartUpload(MultipartUpload mpu) {
        return super.listMultipartUpload(rewriteMultipartUpload(mpu));
    }

    private MultipartUpload rewriteMultipartUpload(MultipartUpload mpu) {
        String name = mpu.blobName();
        String newName = replaceBlobName(name);
        if (name.equals(newName)) {
            return mpu;
        }
        return new MultipartUpload(mpu.id(), mpu.request().toBuilder()
                .key(newName)
                .build());
    }


    private String replaceBlobName(String name) {
        String newName = name;

        for (var entry : this.regexs) {
            Pattern pattern = entry.getKey();
            Matcher match = pattern.matcher(name);

            if (match.find()) {
                return match.replaceAll(entry.getValue());
            }

        }

        return newName;
    }
    // Disable versioning: the name rewrite does not extend to the
    // versioned operations.
    @Override
    public boolean supportsVersioning() {
        return false;
    }

}
