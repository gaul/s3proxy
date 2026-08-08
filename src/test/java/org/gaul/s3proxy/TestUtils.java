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

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.util.Properties;
import java.util.Random;

import com.google.common.base.Strings;
import com.google.common.hash.HashFunction;
import com.google.common.hash.Hashing;
import com.google.common.io.ByteSource;
import com.google.common.io.MoreFiles;
import com.google.common.io.Resources;

import org.eclipse.jetty.util.component.AbstractLifeCycle;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.Constants;
import org.gaul.s3proxy.blobstore.ForwardingBlobStore;
import org.jspecify.annotations.Nullable;

import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.DeleteObjectResponse;

final class TestUtils {
    @SuppressWarnings("deprecation")
    static final HashFunction MD5 = Hashing.md5();

    private TestUtils() {
        throw new AssertionError("intentionally unimplemented");
    }

    /** The complete-request view of listed or uploaded parts. */
    static java.util.List<software.amazon.awssdk.services.s3.model
            .CompletedPart> completedParts(
            java.util.List<software.amazon.awssdk.services.s3.model
                    .Part> parts) {
        return parts.stream()
                .map(part -> software.amazon.awssdk.services.s3.model
                        .CompletedPart.builder()
                        .partNumber(part.partNumber())
                        .eTag(part.eTag())
                        .build())
                .toList();
    }

    static software.amazon.awssdk.services.s3.model.CompletedPart
            completedPart(int partNumber,
            software.amazon.awssdk.services.s3.model
                    .UploadPartResponse part) {
        return software.amazon.awssdk.services.s3.model.CompletedPart
                .builder()
                .partNumber(partNumber)
                .eTag(part.eTag())
                .build();
    }

    /** Stores {@code content} as one object without further options. */
    static software.amazon.awssdk.services.s3.model.PutObjectResponse putBlob(
            BlobStore blobStore, String containerName, String blobName,
            ByteSource content) throws IOException {
        return blobStore.putBlob(putRequest(containerName, blobName, content),
                content.openStream());
    }

    /** A bare write request sized to {@code content}. */
    static software.amazon.awssdk.services.s3.model.PutObjectRequest
            putRequest(String containerName, String blobName,
            ByteSource content) throws IOException {
        return software.amazon.awssdk.services.s3.model.PutObjectRequest
                .builder()
                .bucket(containerName)
                .key(blobName)
                .contentLength(content.size())
                .build();
    }

    /** A bare create-upload request. */
    static software.amazon.awssdk.services.s3.model
            .CreateMultipartUploadRequest createRequest(
            String containerName, String blobName) {
        return software.amazon.awssdk.services.s3.model
                .CreateMultipartUploadRequest.builder()
                .bucket(containerName)
                .key(blobName)
                .build();
    }

    /** The unconditional completion of {@code mpu} from listed parts. */
    static software.amazon.awssdk.services.s3.model
            .CompleteMultipartUploadRequest completeRequest(
            org.gaul.s3proxy.blobstore.domain.MultipartUpload mpu,
            java.util.List<software.amazon.awssdk.services.s3.model
                    .Part> parts) {
        return org.gaul.s3proxy.blobstore.SdkRequests.completeRequest(mpu,
                completedParts(parts));
    }

    static ByteSource randomByteSource() {
        return randomByteSource(0);
    }

    static ByteSource randomByteSource(long seed) {
        return new RandomByteSource(seed);
    }

    private static final class RandomByteSource extends ByteSource {
        private final long seed;

        RandomByteSource(long seed) {
            this.seed = seed;
        }

        @Override
        public InputStream openStream() {
            return new RandomInputStream(seed);
        }
    }

    private static final class RandomInputStream extends InputStream {
        private final Random random;
        private boolean closed;

        RandomInputStream(long seed) {
            this.random = new Random(seed);
        }

        @Override
        public synchronized int read() throws IOException {
            if (closed) {
                throw new IOException("Stream already closed");
            }
            // return value between 0 and 255
            return random.nextInt() & 0xff;
        }

        @Override
        public synchronized int read(byte[] b) throws IOException {
            return read(b, 0, b.length);
        }

        @Override
        public synchronized int read(byte[] b, int off, int len)
                throws IOException {
            if (closed) {
                throw new IOException("Stream already closed");
            }
            // Same byte sequence as read(), one nextInt per byte, without
            // dispatching each byte through it; this stream generates every
            // uploaded payload and was the suite's largest CPU consumer.
            for (int i = 0; i < len; ++i) {
                b[off + i] = (byte) (random.nextInt() & 0xff);
            }
            return len;
        }

        @Override
        public void close() throws IOException {
            super.close();
            closed = true;
        }
    }

    static final class S3ProxyLaunchInfo {
        private S3Proxy s3Proxy;
        private final Properties properties = new Properties();
        private String s3Identity;
        private String s3Credential;
        private BlobStore blobStore;
        private URI endpoint;
        private URI secureEndpoint;
        private String servicePath;

        S3Proxy getS3Proxy() {
            return s3Proxy;
        }

        Properties getProperties() {
            return properties;
        }

        String getS3Identity() {
            return s3Identity;
        }

        String getS3Credential() {
            return s3Credential;
        }

        String getServicePath() {
            return servicePath;
        }

        BlobStore getBlobStore() {
            return blobStore;
        }

        URI getEndpoint() {
            return endpoint;
        }

        URI getSecureEndpoint() {
            return secureEndpoint;
        }
    }

    /** Returns the provider which the s3proxy.test.conf system property
     * configures, resolved to its current name. */
    static String testBlobStoreProvider() throws IOException {
        var properties = new Properties();
        String configFile = System.getProperty("s3proxy.test.conf",
                "s3proxy.conf");
        try (InputStream is = Resources.asByteSource(Resources.getResource(
                configFile)).openStream()) {
            properties.load(is);
        }
        return BlobStores.resolveProviderAlias(
                properties.getProperty(Constants.PROPERTY_PROVIDER, ""));
    }

    /**
     * Creates the backend blobstore which the s3proxy.test.conf system
     * property configures, defaulting to transient.
     */
    static BlobStore createTestBlobStore() throws IOException {
        var properties = new Properties();
        String configFile = System.getProperty("s3proxy.test.conf",
                "s3proxy.conf");
        try (InputStream is = Resources.asByteSource(Resources.getResource(
                configFile)).openStream()) {
            properties.load(is);
        }
        return createBlobStore(properties);
    }

    private static BlobStore createBlobStore(Properties properties)
            throws IOException {
        String provider = BlobStores.resolveProviderAlias(
                properties.getProperty(Constants.PROPERTY_PROVIDER, ""));
        String identity = properties.getProperty(Constants.PROPERTY_IDENTITY);
        String credential = properties.getProperty(
                Constants.PROPERTY_CREDENTIAL);
        if (provider.equals("google-cloud-storage")) {
            if (credential != null && !credential.isEmpty()) {
                var path = FileSystems.getDefault().getPath(credential);
                if (Files.exists(path)) {
                    credential = MoreFiles.asCharSource(path,
                            StandardCharsets.UTF_8).read();
                }
            }
            identity = Strings.nullToEmpty(identity);
            credential = Strings.nullToEmpty(credential);
            properties.remove(Constants.PROPERTY_CREDENTIAL);
        }
        properties.setProperty(Constants.PROPERTY_IDENTITY,
                Strings.nullToEmpty(identity));
        properties.setProperty(Constants.PROPERTY_CREDENTIAL,
                Strings.nullToEmpty(credential));

        return BlobStores.create(provider, properties);
    }

    static S3ProxyLaunchInfo startS3Proxy(String configFile) throws Exception {
        var info = new S3ProxyLaunchInfo();

        try (InputStream is = Resources.asByteSource(Resources.getResource(
                configFile)).openStream()) {
            info.getProperties().load(is);
        }

        // When s3proxy.test.conf selects a backend and a test supplies its
        // own frontend configuration (anonymous, virtual-host, CORS, ...),
        // combine the two: the backend settings (jclouds.* plus the
        // backend-specific s3proxy.sftp.* namespace) come from the backend
        // configuration while the rest of the s3proxy.* namespace comes
        // from the test's configuration.  This lets the specialized tests
        // run against every backend lane instead of their hardcoded
        // transient provider.
        String backendConfigFile = System.getProperty("s3proxy.test.conf");
        if (backendConfigFile != null &&
                !backendConfigFile.equals(configFile)) {
            var backendProperties = new Properties();
            try (InputStream is = Resources.asByteSource(Resources.getResource(
                    backendConfigFile)).openStream()) {
                backendProperties.load(is);
            }
            for (String key : backendProperties.stringPropertyNames()) {
                if (!key.startsWith("s3proxy.") ||
                        key.startsWith("s3proxy.sftp.")) {
                    info.getProperties().setProperty(key,
                            backendProperties.getProperty(key));
                }
            }
        }

        // Resolve as Main does so that tests reading the property back
        // compare against the name the store was created under.
        info.getProperties().setProperty(Constants.PROPERTY_PROVIDER,
                BlobStores.resolveProviderAlias(info.getProperties()
                        .getProperty(Constants.PROPERTY_PROVIDER, "")));

        info.blobStore = createBlobStore(info.getProperties());

        String encrypted = info.getProperties().getProperty(
                S3ProxyConstants.PROPERTY_ENCRYPTED_BLOBSTORE);
        if (encrypted != null && encrypted.equals("true")) {
            info.blobStore =
                EncryptedBlobStore.newEncryptedBlobStore(info.blobStore,
                    info.getProperties());
        }

        S3Proxy.Builder s3ProxyBuilder = S3Proxy.Builder.fromProperties(
                info.getProperties());
        s3ProxyBuilder.blobStore(info.blobStore);
        // Tests' requests have completed by teardown, so skip the graceful
        // drain; it waits two seconds for any keep-alive connection the
        // test's client left open, once per test for the suites that start
        // a proxy in setUp.
        s3ProxyBuilder.stopTimeout(0);
        info.endpoint = s3ProxyBuilder.getEndpoint();
        info.secureEndpoint = s3ProxyBuilder.getSecureEndpoint();
        info.s3Identity = s3ProxyBuilder.getIdentity();
        info.s3Credential = s3ProxyBuilder.getCredential();
        info.servicePath = s3ProxyBuilder.getServicePath();

        // resolve relative path for tests
        String keyStorePath = info.getProperties().getProperty(
                S3ProxyConstants.PROPERTY_KEYSTORE_PATH);
        String keyStorePassword = info.getProperties().getProperty(
                S3ProxyConstants.PROPERTY_KEYSTORE_PASSWORD);
        if (keyStorePath != null || keyStorePassword != null) {
            s3ProxyBuilder.keyStore(
                    Resources.getResource(keyStorePath).toString(),
                    keyStorePassword);
        }
        info.s3Proxy = s3ProxyBuilder.build();
        info.s3Proxy.start();
        while (!info.s3Proxy.getState().equals(AbstractLifeCycle.STARTED)) {
            Thread.sleep(1);
        }

        // reset endpoint to handle zero port
        info.endpoint = new URI(info.endpoint.getScheme(),
                info.endpoint.getUserInfo(), info.endpoint.getHost(),
                info.s3Proxy.getPort(), info.endpoint.getPath(),
                info.endpoint.getQuery(), info.endpoint.getFragment());
        if (info.secureEndpoint != null) {
            info.secureEndpoint = new URI(info.secureEndpoint.getScheme(),
                    info.secureEndpoint.getUserInfo(),
                    info.secureEndpoint.getHost(),
                    info.s3Proxy.getSecurePort(),
                    info.secureEndpoint.getPath(),
                    info.secureEndpoint.getQuery(),
                    info.secureEndpoint.getFragment());
        }

        return info;
    }

    static BlobStore createTransientBlobStore() {
        var props = new Properties();
        props.setProperty(Constants.PROPERTY_IDENTITY, "identity");
        props.setProperty(Constants.PROPERTY_CREDENTIAL, "credential");
        return BlobStores.create("transient", props);
    }

    /**
     * A store standing in for a backend that judges the delete conditions
     * itself, which is what routes a request through
     * {@link BlobStore#removeBlob(DeleteObjectRequest)}.  The nio2 stores the
     * other tests build on implement only the unconditional overloads, so a
     * middleware forwarding the request one untranslated could not be caught
     * without this.  Records what it was asked to delete and deletes it.
     */
    static final class ConditionalDeleteRecorder extends ForwardingBlobStore {
        @Nullable private DeleteObjectRequest lastRequest;

        ConditionalDeleteRecorder(BlobStore blobStore) {
            super(blobStore);
        }

        @Override
        public DeleteObjectResponse removeBlob(DeleteObjectRequest request) {
            lastRequest = request;
            delegate().removeBlob(request.bucket(), request.key());
            return DeleteObjectResponse.builder().build();
        }

        @Nullable DeleteObjectRequest lastRequest() {
            return lastRequest;
        }
    }

    static String createRandomContainerName() {
        return "container-" + new Random().nextInt(Integer.MAX_VALUE);
    }

    static String createRandomBlobName() {
        return "blob-" + new Random().nextInt(Integer.MAX_VALUE);
    }
}
