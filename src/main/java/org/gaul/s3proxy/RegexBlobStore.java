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

import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.ForwardingBlobStore;
import org.gaul.s3proxy.blobstore.Payload;
import org.gaul.s3proxy.blobstore.domain.Blob;
import org.gaul.s3proxy.blobstore.domain.BlobAccess;
import org.gaul.s3proxy.blobstore.domain.BlobMetadata;
import org.gaul.s3proxy.blobstore.domain.MultipartPart;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.gaul.s3proxy.blobstore.options.CopyOptions;
import org.gaul.s3proxy.blobstore.options.GetOptions;
import org.gaul.s3proxy.blobstore.options.PutOptions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
    public String putBlob(String containerName, Blob blob) {
        String name = blob.getMetadata().getName();
        String newName = replaceBlobName(name);
        logger.debug("Renaming blob name from {} to {}", name, newName);

        return super.putBlob(containerName,
                blob.toBuilder().name(newName).build());
    }

    @Override
    public String putBlob(String containerName, Blob blob,
            PutOptions putOptions) {
        String name = blob.getMetadata().getName();
        String newName = replaceBlobName(name);
        logger.debug("Renaming blob name from {} to {}", name, newName);

        return super.putBlob(containerName,
                blob.toBuilder().name(newName).build(), putOptions);
    }

    @Override
    public String copyBlob(String fromContainer, String fromName,
            String toContainer, String toName, CopyOptions options) {
        return super.copyBlob(fromContainer, replaceBlobName(fromName),
                toContainer, replaceBlobName(toName), options);
    }

    @Override
    public BlobMetadata blobMetadata(String container, String name) {
        return super.blobMetadata(container, replaceBlobName(name));
    }

    @Override
    public Blob getBlob(String containerName, String name) {
        return super.getBlob(containerName, replaceBlobName(name));
    }

    @Override
    public Blob getBlob(String containerName, String name,
            GetOptions getOptions) {
        return super.getBlob(containerName, replaceBlobName(name), getOptions);
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
    public BlobAccess getBlobAccess(String container, String name) {
        return super.getBlobAccess(container, replaceBlobName(name));
    }

    @Override
    public void setBlobAccess(String container, String name,
            BlobAccess access) {
        super.setBlobAccess(container, replaceBlobName(name), access);
    }

    @Override
    public MultipartUpload initiateMultipartUpload(String container,
            BlobMetadata blobMetadata, PutOptions options) {
        return super.initiateMultipartUpload(container,
                rewriteBlobMetadata(blobMetadata), options);
    }

    @Override
    public void abortMultipartUpload(MultipartUpload mpu) {
        super.abortMultipartUpload(rewriteMultipartUpload(mpu));
    }

    @Override
    public String completeMultipartUpload(MultipartUpload mpu,
            List<MultipartPart> parts) {
        return super.completeMultipartUpload(rewriteMultipartUpload(mpu), parts);
    }

    @Override
    public MultipartPart uploadMultipartPart(MultipartUpload mpu,
            int partNumber, Payload payload) {
        return super.uploadMultipartPart(rewriteMultipartUpload(mpu),
                partNumber, payload);
    }

    @Override
    public List<MultipartPart> listMultipartUpload(MultipartUpload mpu) {
        return super.listMultipartUpload(rewriteMultipartUpload(mpu));
    }

    private BlobMetadata rewriteBlobMetadata(BlobMetadata metadata) {
        String name = metadata.getName();
        String newName = replaceBlobName(name);
        if (name.equals(newName)) {
            return metadata;
        }
        return metadata.toBuilder().name(newName).build();
    }

    private MultipartUpload rewriteMultipartUpload(MultipartUpload mpu) {
        String name = mpu.blobName();
        String newName = replaceBlobName(name);
        if (name.equals(newName)) {
            return mpu;
        }
        BlobMetadata metadata = mpu.blobMetadata();
        if (metadata != null) {
            metadata = rewriteBlobMetadata(metadata);
        }
        return new MultipartUpload(mpu.containerName(), newName,
                mpu.id(), metadata, mpu.putOptions());
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
}
