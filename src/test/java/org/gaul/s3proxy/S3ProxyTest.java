/*
 * Copyright 2014 Andrew Gaul <andrew@gaul.org>
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

import static org.assertj.core.api.Assertions.assertThat;

import java.io.InputStream;
import java.net.URI;
import java.util.Properties;

import javax.servlet.http.HttpServletResponse;

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.io.ByteSource;
import com.google.common.io.Resources;
import com.google.inject.Module;

import org.jclouds.Constants;
import org.jclouds.ContextBuilder;
import org.jclouds.blobstore.BlobRequestSigner;
import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.BlobStoreContext;
import org.jclouds.blobstore.domain.Blob;
import org.jclouds.blobstore.domain.BlobMetadata;
import org.jclouds.blobstore.domain.StorageMetadata;
import org.jclouds.blobstore.options.ListContainerOptions;
import org.jclouds.http.HttpRequest;
import org.jclouds.http.HttpResponse;
import org.jclouds.io.Payload;
import org.jclouds.io.payloads.ByteSourcePayload;
import org.jclouds.logging.slf4j.config.SLF4JLoggingModule;
import org.jclouds.rest.HttpClient;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

public final class S3ProxyTest {
    private URI s3Endpoint;
    private S3Proxy s3Proxy;
    private BlobStoreContext context;
    private BlobStoreContext s3Context;
    private BlobStore s3BlobStore;
    private static final String containerName = "container";

    @Before
    public void setUp() throws Exception {
        Properties s3ProxyProperties = new Properties();
        try (InputStream is = Resources.asByteSource(Resources.getResource(
                "s3proxy.conf")).openStream()) {
            s3ProxyProperties.load(is);
        }

        String provider = s3ProxyProperties.getProperty(
                Constants.PROPERTY_PROVIDER);
        String identity = s3ProxyProperties.getProperty(
                Constants.PROPERTY_IDENTITY);
        String credential = s3ProxyProperties.getProperty(
                Constants.PROPERTY_CREDENTIAL);
        String endpoint = s3ProxyProperties.getProperty(
                Constants.PROPERTY_ENDPOINT);
        String s3Identity = s3ProxyProperties.getProperty(
                S3ProxyConstants.PROPERTY_IDENTITY);
        String s3Credential = s3ProxyProperties.getProperty(
                S3ProxyConstants.PROPERTY_CREDENTIAL);
        s3Endpoint = new URI(s3ProxyProperties.getProperty(
                S3ProxyConstants.PROPERTY_ENDPOINT));
        String keyStorePath = s3ProxyProperties.getProperty(
                S3ProxyConstants.PROPERTY_KEYSTORE_PATH);
        String keyStorePassword = s3ProxyProperties.getProperty(
                S3ProxyConstants.PROPERTY_KEYSTORE_PASSWORD);
        String forceMultiPartUpload = s3ProxyProperties.getProperty(
                S3ProxyConstants.PROPERTY_FORCE_MULTI_PART_UPLOAD);

        Properties properties = new Properties();
        ContextBuilder builder = ContextBuilder
                .newBuilder(provider)
                .credentials(identity, credential)
                .modules(ImmutableList.<Module>of(new SLF4JLoggingModule()))
                .overrides(properties);
        if (!Strings.isNullOrEmpty(endpoint)) {
            builder.endpoint(endpoint);
        }
        context = builder.build(BlobStoreContext.class);
        BlobStore blobStore = context.getBlobStore();
        blobStore.createContainerInLocation(null, containerName);

        Properties s3Properties = new Properties();
        s3Properties.setProperty(Constants.PROPERTY_TRUST_ALL_CERTS, "true");
        s3Context = ContextBuilder
                .newBuilder("s3")
                .credentials(s3Identity, s3Credential)
                .endpoint(s3Endpoint.toString())
                .overrides(s3Properties)
                .build(BlobStoreContext.class);
        s3BlobStore = s3Context.getBlobStore();

        s3Proxy = new S3Proxy(blobStore, s3Endpoint, s3Identity, s3Credential,
                Resources.getResource(keyStorePath).toString(),
                keyStorePassword,
                "true".equalsIgnoreCase(forceMultiPartUpload));
        s3Proxy.start();
    }

    @After
    public void tearDown() throws Exception {
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
        if (s3Context != null) {
            s3Context.close();
        }
        if (context != null) {
            context.close();
        }
    }

    // TODO: why does this hang for 30 seconds?
    @Ignore
    @Test
    public void testHttpClient() throws Exception {
        HttpClient httpClient = context.utils().http();
        // TODO: how to interpret this?
        URI uri = URI.create(s3Endpoint + "/container/blob");
        ByteSource byteSource = ByteSource.wrap(new byte[1]);
        Payload payload = new ByteSourcePayload(byteSource);
        payload.getContentMetadata().setContentLength(byteSource.size());
        httpClient.put(uri, payload);
        try (InputStream actual = httpClient.get(uri);
             InputStream expected = byteSource.openStream()) {
            assertThat(actual).hasContentEqualTo(expected);
        }
    }

    @Test
    public void testJcloudsClient() throws Exception {
        ImmutableSet.Builder<String> builder = ImmutableSet.builder();
        for (StorageMetadata metadata : s3BlobStore.list()) {
            builder.add(metadata.getName());
        }
        assertThat(builder.build()).containsOnly(containerName);
    }

    @Test
    public void testContainerExists() throws Exception {
        assertThat(s3BlobStore.containerExists("fakecontainer")).isFalse();
        assertThat(s3BlobStore.containerExists(containerName)).isTrue();
    }

    @Test
    public void testContainerCreate() throws Exception {
        assertThat(s3BlobStore.createContainerInLocation(null,
                "newcontainer")).isTrue();
        assertThat(s3BlobStore.createContainerInLocation(null,
                "newcontainer")).isFalse();
    }

    @Test
    public void testContainerDelete() throws Exception {
        assertThat(s3BlobStore.containerExists(containerName)).isTrue();
        s3BlobStore.deleteContainerIfEmpty(containerName);
        assertThat(s3BlobStore.containerExists(containerName)).isFalse();
    }

    @Test
    public void testBlobPutGet() throws Exception {
        String blobName = "blob";
        ByteSource byteSource = ByteSource.wrap(new byte[42]);
        Blob blob = s3BlobStore.blobBuilder(blobName)
                .payload(byteSource)
                .contentLength(byteSource.size())
                .build();
        s3BlobStore.putBlob(containerName, blob);

        Blob blob2 = s3BlobStore.getBlob(containerName, blobName);
        try (InputStream actual = blob2.getPayload().openStream();
             InputStream expected = byteSource.openStream()) {
            assertThat(actual).hasContentEqualTo(expected);
        }
    }

    @Test
    public void testBlobList() throws Exception {
        assertThat(s3BlobStore.list(containerName)).isEmpty();

        // TODO: hang with zero length blobs?
        ByteSource byteSource = ByteSource.wrap(new byte[1]);
        ImmutableSet.Builder<String> builder = ImmutableSet.builder();
        Blob blob1 = s3BlobStore.blobBuilder("blob1")
                .payload(byteSource)
                .contentLength(byteSource.size())
                .build();
        s3BlobStore.putBlob(containerName, blob1);
        for (StorageMetadata metadata : s3BlobStore.list(containerName)) {
            builder.add(metadata.getName());
        }
        assertThat(builder.build()).containsOnly("blob1");

        builder = ImmutableSet.builder();
        Blob blob2 = s3BlobStore.blobBuilder("blob2")
                .payload(byteSource)
                .contentLength(byteSource.size())
                .build();
        s3BlobStore.putBlob(containerName, blob2);
        for (StorageMetadata metadata : s3BlobStore.list(containerName)) {
            builder.add(metadata.getName());
        }
        assertThat(builder.build()).containsOnly("blob1", "blob2");
    }

    @Test
    public void testBlobListRecursive() throws Exception {
        assertThat(s3BlobStore.list(containerName)).isEmpty();

        ByteSource byteSource = ByteSource.wrap(new byte[1]);
        Blob blob1 = s3BlobStore.blobBuilder("prefix/blob1")
                .payload(byteSource)
                .contentLength(byteSource.size())
                .build();
        s3BlobStore.putBlob(containerName, blob1);

        Blob blob2 = s3BlobStore.blobBuilder("prefix/blob2")
                .payload(byteSource)
                .contentLength(byteSource.size())
                .build();
        s3BlobStore.putBlob(containerName, blob2);

        ImmutableSet.Builder<String> builder = ImmutableSet.builder();
        for (StorageMetadata metadata : s3BlobStore.list(containerName)) {
            builder.add(metadata.getName());
        }
        assertThat(builder.build()).containsOnly("prefix");

        builder = ImmutableSet.builder();
        for (StorageMetadata metadata : s3BlobStore.list(containerName,
                new ListContainerOptions().recursive())) {
            builder.add(metadata.getName());
        }
        assertThat(builder.build()).containsOnly("prefix/blob1",
                "prefix/blob2");
    }

    @Test
    public void testBlobMetadata() throws Exception {
        String blobName = "blob";
        ByteSource byteSource = ByteSource.wrap(new byte[1]);
        Blob blob1 = s3BlobStore.blobBuilder(blobName)
                .payload(byteSource)
                .contentLength(byteSource.size())
                .build();
        s3BlobStore.putBlob(containerName, blob1);

        BlobMetadata metadata = s3BlobStore.blobMetadata(containerName,
                blobName);
        assertThat(metadata.getName()).isEqualTo(blobName);
        assertThat(metadata.getContentMetadata().getContentLength())
                .isEqualTo(byteSource.size());

        assertThat(s3BlobStore.blobMetadata(containerName,
                "fake-blob")).isNull();
    }

    @Test
    public void testBlobRemove() throws Exception {
        String blobName = "blob";
        ByteSource byteSource = ByteSource.wrap(new byte[1]);
        Blob blob = s3BlobStore.blobBuilder(blobName)
                .payload(byteSource)
                .contentLength(byteSource.size())
                .build();
        s3BlobStore.putBlob(containerName, blob);
        assertThat(s3BlobStore.blobExists(containerName, blobName)).isTrue();

        s3BlobStore.removeBlob(containerName, blobName);
        assertThat(s3BlobStore.blobExists(containerName, blobName)).isFalse();

        s3BlobStore.removeBlob(containerName, blobName);
    }

    // TODO: this test fails since S3BlobRequestSigner does not implement the
    // same logic as AWSS3BlobRequestSigner.signForTemporaryAccess.
    @Ignore
    @Test
    public void testUrlSigning() throws Exception {
        HttpClient httpClient = s3Context.utils().http();
        BlobRequestSigner signer = s3Context.getSigner();

        String blobName = "blob";
        ByteSource byteSource = ByteSource.wrap(new byte[1]);
        Blob blob = s3BlobStore.blobBuilder(blobName)
                .payload(byteSource)
                .contentLength(byteSource.size())
                .build();
        HttpRequest putRequest = signer.signPutBlob(containerName, blob, 10);
        HttpResponse putResponse = httpClient.invoke(putRequest);
        assertThat(putResponse.getStatusCode())
                .isEqualTo(HttpServletResponse.SC_OK);

        HttpRequest getRequest = signer.signGetBlob(containerName, blobName,
                10);
        HttpResponse getResponse = httpClient.invoke(getRequest);
        assertThat(getResponse.getStatusCode())
                .isEqualTo(HttpServletResponse.SC_OK);
    }
}
