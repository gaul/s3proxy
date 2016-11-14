/*
 * Copyright 2014-2016 Andrew Gaul <andrew@gaul.org>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
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
import com.google.common.io.ByteSource;
import com.google.common.io.Files;
import com.google.common.io.Resources;
import com.google.inject.Module;

import org.eclipse.jetty.util.component.AbstractLifeCycle;

import org.jclouds.Constants;
import org.jclouds.ContextBuilder;
import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.BlobStoreContext;
import org.jclouds.logging.slf4j.config.SLF4JLoggingModule;

final class TestUtils {
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
        private Properties properties = new Properties();
        private String s3Identity;
        private String s3Credential;
        private BlobStore blobStore;
        private URI endpoint;

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

        BlobStore getBlobStore() {
            return blobStore;
        }

        URI getEndpoint() {
            return endpoint;
        }
    }

    static S3ProxyLaunchInfo startS3Proxy() throws Exception {
        S3ProxyLaunchInfo info = new S3ProxyLaunchInfo();

        try (InputStream is = Resources.asByteSource(Resources.getResource(
                "s3proxy.conf")).openStream()) {
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
                credential = Files.toString(credentialFile,
                        StandardCharsets.UTF_8);
            }
            info.getProperties().remove(Constants.PROPERTY_CREDENTIAL);
        }
        String endpoint = info.getProperties().getProperty(
                Constants.PROPERTY_ENDPOINT);
        String s3ProxyAuthorizationString = info.getProperties().getProperty(
                S3ProxyConstants.PROPERTY_AUTHORIZATION);
        AuthenticationType s3ProxyAuthorization =
                AuthenticationType.fromString(s3ProxyAuthorizationString);
        info.s3Identity = info.getProperties().getProperty(
                S3ProxyConstants.PROPERTY_IDENTITY);
        info.s3Credential = info.getProperties().getProperty(
                S3ProxyConstants.PROPERTY_CREDENTIAL);
        info.endpoint = new URI(info.getProperties().getProperty(
                S3ProxyConstants.PROPERTY_ENDPOINT));
        String secureEndpoint = info.getProperties().getProperty(
                S3ProxyConstants.PROPERTY_SECURE_ENDPOINT);
        String keyStorePath = info.getProperties().getProperty(
                S3ProxyConstants.PROPERTY_KEYSTORE_PATH);
        String keyStorePassword = info.getProperties().getProperty(
                S3ProxyConstants.PROPERTY_KEYSTORE_PASSWORD);
        String virtualHost = info.getProperties().getProperty(
                S3ProxyConstants.PROPERTY_VIRTUAL_HOST);

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

        S3Proxy.Builder s3ProxyBuilder = S3Proxy.builder()
                .blobStore(info.getBlobStore())
                .endpoint(info.getEndpoint());
        if (secureEndpoint != null) {
            s3ProxyBuilder.secureEndpoint(new URI(secureEndpoint));
        }
        if (info.getS3Identity() != null || info.getS3Credential() != null) {
            s3ProxyBuilder.awsAuthentication(s3ProxyAuthorization,
                    info.getS3Identity(), info.getS3Credential());
        }
        if (keyStorePath != null || keyStorePassword != null) {
            s3ProxyBuilder.keyStore(
                    Resources.getResource(keyStorePath).toString(),
                    keyStorePassword);
        }
        if (virtualHost != null) {
            s3ProxyBuilder.virtualHost(virtualHost);
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

        return info;
    }
}
