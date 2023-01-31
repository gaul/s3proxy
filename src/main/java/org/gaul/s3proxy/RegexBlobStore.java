package org.gaul.s3proxy;

import static com.google.common.base.Preconditions.checkArgument;
import static java.util.Objects.requireNonNull;

import java.io.File;
import java.io.InputStream;
import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.concurrent.ExecutorService;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.domain.Blob;
import org.jclouds.blobstore.domain.BlobAccess;
import org.jclouds.blobstore.domain.BlobMetadata;
import org.jclouds.blobstore.options.CopyOptions;
import org.jclouds.blobstore.options.PutOptions;
import org.jclouds.blobstore.util.ForwardingBlobStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ImmutableList;

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
public class RegexBlobStore extends ForwardingBlobStore {
    private final ImmutableList<Entry<Pattern, String>> regexs;
    private static final Logger logger = LoggerFactory.getLogger(RegexBlobStore.class);

    static BlobStore newRegexBlobStore(BlobStore delegate, ImmutableList<Entry<Pattern, String>> regexs) {
        return new RegexBlobStore(delegate, regexs);
    }

    private RegexBlobStore(BlobStore blobStore, ImmutableList<Entry<Pattern, String>> regexs) {
        super(blobStore);
        this.regexs = requireNonNull(regexs);
    }

    public static ImmutableList<Map.Entry<Pattern, String>> parseRegexs(Properties properties) {

        List<Entry<String, String>> config_regex = new ArrayList<>();
        List<Entry<Pattern, String>> regexs = new ArrayList<>();

        for (String key : properties.stringPropertyNames()) {
            if (key.startsWith(S3ProxyConstants.PROPERTY_REGEX_BLOBSTORE)) {
                String prop_key = key.substring(S3ProxyConstants.PROPERTY_REGEX_BLOBSTORE.length() + 1);
                String value = properties.getProperty(key);

                config_regex.add(new SimpleEntry<>(prop_key, value));
            }
        }

        for (Entry<String, String> entry : config_regex) {
            String key = entry.getKey();
            if (key.startsWith(S3ProxyConstants.PROPERTY_REGEX_BLOBSTORE_MATCH)) {
                String regex_name = key.substring(S3ProxyConstants.PROPERTY_REGEX_BLOBSTORE_MATCH.length() + 1);
                String regex = entry.getValue();
                Pattern pattern = Pattern.compile(regex);

                String replace = properties.getProperty(
                        String.join(
                                ".",
                                S3ProxyConstants.PROPERTY_REGEX_BLOBSTORE,
                                S3ProxyConstants.PROPERTY_REGEX_BLOBSTORE_REPLACE,
                                regex_name));

                checkArgument(
                        replace != null,
                        "Regex %s has no replace property associated",
                        regex_name);

                logger.info("Adding new regex with name {} replaces with {} to {}", regex_name, regex, replace);

                regexs.add(new SimpleEntry<>(pattern, replace));
            }
        }

        return ImmutableList.copyOf(regexs);
    }

    @Override
    public boolean directoryExists(String container, String directory) {
        return super.directoryExists(container, replaceBlobName(directory));
    }

    @Override
    public void createDirectory(String container, String directory) {
        super.createDirectory(container, replaceBlobName(directory));
    }

    @Override
    public void deleteDirectory(String container, String directory) {
        super.deleteDirectory(container, replaceBlobName(directory));
    }

    @Override
    public boolean blobExists(String container, String name) {
        return super.blobExists(container, replaceBlobName(name));
    }

    @Override
    public String putBlob(String containerName, Blob blob) {
        String name = blob.getMetadata().getName();
        String newName = replaceBlobName(name);
        blob.getMetadata().setName(newName);

        logger.debug("Renaming blob name from {} to {}", name, newName);

        return super.putBlob(containerName, blob);
    }

    @Override
    public String putBlob(String containerName, Blob blob, PutOptions putOptions) {
        String name = blob.getMetadata().getName();
        String newName = replaceBlobName(name);
        blob.getMetadata().setName(newName);

        logger.debug("Renaming blob name from {} to {}", name, newName);

        return super.putBlob(containerName, blob, putOptions);
    }

    @Override
    public String copyBlob(String fromContainer, String fromName, String toContainer, String toName,
            CopyOptions options) {
        return super.copyBlob(fromContainer, replaceBlobName(fromName), toContainer, replaceBlobName(toName), options);
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
    public void setBlobAccess(String container, String name, BlobAccess access) {
        super.setBlobAccess(container, replaceBlobName(name), access);
    }

    @Override
    public void downloadBlob(String container, String name, File destination) {
        super.downloadBlob(container, replaceBlobName(name), destination);
    }

    @Override
    public void downloadBlob(String container, String name, File destination, ExecutorService executor) {
        super.downloadBlob(container, replaceBlobName(name), destination, executor);
    }

    @Override
    public InputStream streamBlob(String container, String name) {
        return super.streamBlob(container, replaceBlobName(name));
    }

    @Override
    public InputStream streamBlob(String container, String name, ExecutorService executor) {
        return super.streamBlob(container, replaceBlobName(name), executor);
    }

    private String replaceBlobName(String name) {
        String newName = name;

        for (Map.Entry<Pattern, String> entry : this.regexs) {
            Pattern pattern = entry.getKey();
            Matcher match = pattern.matcher(name);

            if (match.find()) {
                return match.replaceAll(entry.getValue());
            }

        }

        return newName;
    }
}
