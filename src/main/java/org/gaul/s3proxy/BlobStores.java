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

import java.util.Properties;

import com.google.common.base.Supplier;
import com.google.common.base.Suppliers;

import org.gaul.s3proxy.awssdk.AwsS3SdkBlobStore;
import org.gaul.s3proxy.azureblob.AzureBlobStore;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.Constants;
import org.gaul.s3proxy.blobstore.Credentials;
import org.gaul.s3proxy.gcloudsdk.GCloudBlobStore;
import org.gaul.s3proxy.nio2blob.FilesystemNio2BlobStore;
import org.gaul.s3proxy.nio2blob.TransientNio2BlobStore;
import org.gaul.s3proxy.openstackswift.OpenStackSwiftBlobStore;
import org.gaul.s3proxy.sftp.SftpBlobStore;

public final class BlobStores {

    private BlobStores() {
    }

    public static BlobStore create(String provider, Properties properties) {
        provider = resolveProviderAlias(provider);
        String identity = properties.getProperty(Constants.PROPERTY_IDENTITY,
                "");
        String credential = properties.getProperty(
                Constants.PROPERTY_CREDENTIAL, "");
        String endpoint = properties.getProperty(Constants.PROPERTY_ENDPOINT,
                "");
        String region = properties.getProperty(Constants.PROPERTY_REGION, "");

        Supplier<Credentials> creds = Suppliers.ofInstance(
                new Credentials(identity, credential));

        return switch (provider) {
        case "filesystem" -> {
            String baseDir = properties.getProperty(
                    "jclouds.filesystem.basedir");
            yield new FilesystemNio2BlobStore(baseDir);
        }
        case "transient" -> new TransientNio2BlobStore();
        case "aws-s3" -> {
            String conditionalWrites = properties.getProperty(
                    "s3proxy.aws-s3.conditional-writes", "native");
            String chunkedEncodingEnabled = properties.getProperty(
                    "s3proxy.aws-s3.chunked-encoding-enabled", "true");
            String stripETagQuotes = properties.getProperty(
                    "s3proxy.aws-s3.strip-etag-quotes", "false");
            yield new AwsS3SdkBlobStore(creds, endpoint,
                    region.isEmpty() ? "us-east-1" : region,
                    conditionalWrites, chunkedEncodingEnabled,
                    stripETagQuotes);
        }
        case "azureblob" -> {
            String eTagMode = properties.getProperty(
                    "s3proxy.azureblob.etag", "opaque");
            yield new AzureBlobStore(creds, endpoint, eTagMode);
        }
        case "google-cloud-storage" ->
            new GCloudBlobStore(creds, endpoint);
        case "openstack-swift" -> {
            String projectName = properties.getProperty(
                    OpenStackSwiftBlobStore.PROPERTY_PROJECT_NAME, "");
            String projectDomainName = properties.getProperty(
                    OpenStackSwiftBlobStore.PROPERTY_PROJECT_DOMAIN_NAME,
                    "Default");
            String userDomainName = properties.getProperty(
                    OpenStackSwiftBlobStore.PROPERTY_USER_DOMAIN_NAME,
                    "Default");
            String swiftRegion = properties.getProperty(
                    OpenStackSwiftBlobStore.PROPERTY_REGION, "");
            yield new OpenStackSwiftBlobStore(creds, endpoint, projectName,
                    projectDomainName, userDomainName, swiftRegion);
        }
        case "sftp" -> {
            String baseDir = properties.getProperty(
                    SftpBlobStore.PROPERTY_BASEDIR, "/s3proxy");
            String hostKey = properties.getProperty(
                    SftpBlobStore.PROPERTY_HOST_KEY, "");
            yield new SftpBlobStore(creds, endpoint, baseDir, hostKey);
        }
        default -> throw new IllegalArgumentException("Unknown provider: " +
                provider + ". Supported providers: filesystem, transient," +
                " aws-s3, azureblob, google-cloud-storage, openstack-swift," +
                " sftp");
        };
    }

    /**
     * Maps a retired provider name to its current one, so that a
     * configuration written for an earlier release keeps working.  The -sdk
     * and -nio2 suffixes distinguished these stores from the jclouds
     * implementations they grew up alongside; with jclouds gone the short
     * names are canonical.  Resolving here rather than in Main covers every
     * caller, including the JUnit rule and anything embedding S3Proxy as a
     * library.  A name that is already current, or that names nothing, is
     * returned unchanged for create to reject.
     */
    static String resolveProviderAlias(String provider) {
        return switch (provider) {
        case "transient-nio2" -> "transient";
        case "filesystem-nio2" -> "filesystem";
        case "aws-s3-sdk", "s3" -> "aws-s3";
        case "azureblob-sdk" -> "azureblob";
        case "google-cloud-storage-sdk" -> "google-cloud-storage";
        case "openstack-swift-sdk" -> "openstack-swift";
        default -> provider;
        };
    }
}
