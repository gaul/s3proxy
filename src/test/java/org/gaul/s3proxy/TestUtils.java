/*
 * Copyright 2014-2020 Andrew Gaul <andrew@gaul.org>
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

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Properties;
import java.util.Random;

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import com.google.common.hash.HashFunction;
import com.google.common.hash.Hashing;
import com.google.common.io.ByteSource;
import com.google.common.io.Files;
import com.google.common.io.Resources;
import com.google.inject.Module;

import org.eclipse.jetty.util.component.AbstractLifeCycle;

import org.jclouds.Constants;
import org.jclouds.ContextBuilder;
import org.jclouds.JcloudsVersion;
import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.BlobStoreContext;
import org.jclouds.logging.slf4j.config.SLF4JLoggingModule;

final class TestUtils {
    @SuppressWarnings("deprecation")
    static final HashFunction MD5 = Hashing.md5();

    private TestUtils() {
        throw new AssertionError("intentionally unimplemented");
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
            for (int i = 0; i < len; ++i) {
                b[off + i] = (byte) read();
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

    static S3ProxyLaunchInfo startS3Proxy(String configFile) throws Exception {
        S3ProxyLaunchInfo info = new S3ProxyLaunchInfo();

        try (InputStream is = Resources.asByteSource(Resources.getResource(
                configFile)).openStream()) {
            info.getProperties().load(is);
        }

        String provider = info.getProperties().getProperty(
                Constants.PROPERTY_PROVIDER);
        String identity = info.getProperties().getProperty(
                Constants.PROPERTY_IDENTITY);
        String credential = info.getProperties().getProperty(
                Constants.PROPERTY_CREDENTIAL);
        if (provider.equals("google-cloud-storage")) {
            File credentialFile = new File(credential);
            if (credentialFile.exists()) {
                credential = Files.asCharSource(credentialFile,
                        StandardCharsets.UTF_8).read();
            }
            info.getProperties().remove(Constants.PROPERTY_CREDENTIAL);
        }
        String endpoint = info.getProperties().getProperty(
                Constants.PROPERTY_ENDPOINT);

        ContextBuilder builder = ContextBuilder
                .newBuilder(provider)
                .credentials(identity, credential)
                .modules(ImmutableList.<Module>of(new SLF4JLoggingModule()))
                .overrides(info.getProperties());
        if (!Strings.isNullOrEmpty(endpoint)) {
            builder.endpoint(endpoint);
        }
        BlobStoreContext context = builder.build(BlobStoreContext.class);
        info.blobStore = context.getBlobStore();

        S3Proxy.Builder s3ProxyBuilder = S3Proxy.Builder.fromProperties(
                info.getProperties());
        s3ProxyBuilder.blobStore(info.blobStore);
        info.endpoint = s3ProxyBuilder.getEndpoint();
        info.secureEndpoint = s3ProxyBuilder.getSecureEndpoint();
        info.s3Identity = s3ProxyBuilder.getIdentity();
        info.s3Credential = s3ProxyBuilder.getCredential();
        info.servicePath = s3ProxyBuilder.getServicePath();
        info.getProperties().setProperty(Constants.PROPERTY_USER_AGENT,
                String.format("s3proxy/%s jclouds/%s java/%s",
                        TestUtils.class.getPackage().getImplementationVersion(),
                        JcloudsVersion.get(),
                        System.getProperty("java.version")));

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
}
