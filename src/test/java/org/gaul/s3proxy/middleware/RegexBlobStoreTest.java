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

package org.gaul.s3proxy.middleware;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.AbstractMap.SimpleEntry;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Random;
import java.util.regex.Pattern;

import com.google.common.io.ByteSource;

import org.assertj.core.api.Assertions;
import org.gaul.s3proxy.S3Proxy;
import org.gaul.s3proxy.S3ProxyConstants;
import org.gaul.s3proxy.TestUtils;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.Constants;
import org.gaul.s3proxy.blobstore.MD5;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.model.CompletedMultipartUpload;
import software.amazon.awssdk.services.s3.model.CompletedPart;
import software.amazon.awssdk.services.s3.model.S3Exception;

public final class RegexBlobStoreTest {
    private BlobStore delegate;
    private String containerName;

    @BeforeEach
    public void setUp() throws Exception {
        containerName = createRandomContainerName();

        delegate = TestUtils.createTransientBlobStore();
        delegate.createContainer(containerName);

    }

    @AfterEach
    public void tearDown() throws Exception {
        if (delegate != null) {
            delegate.deleteContainer(containerName);
        }
    }

    @Test
    public void testRulesApplyInNameOrder() {
        var properties = new java.util.Properties();
        // every rule matches; the first by name must win
        for (String name : List.of("m", "c", "x", "a", "q", "f", "k", "b",
                "z", "d")) {
            properties.setProperty("s3proxy.regex-blobstore.match." + name,
                    ".*");
            properties.setProperty("s3proxy.regex-blobstore.replace." + name,
                    name);
        }
        var regexs = RegexBlobStore.parseRegexs(properties);
        assertThat(regexs).extracting(Map.Entry::getValue).containsExactly(
                "a", "b", "c", "d", "f", "k", "m", "q", "x", "z");
    }

    /** Numbered rules run as numbered, rule 10 after rule 2. */
    @Test
    public void testNumberedRulesApplyInNumberOrder() {
        var properties = new java.util.Properties();
        for (int i = 1; i <= 12; i++) {
            properties.setProperty("s3proxy.regex-blobstore.match." + i,
                    ".*");
            properties.setProperty("s3proxy.regex-blobstore.replace." + i,
                    Integer.toString(i));
        }
        var regexs = RegexBlobStore.parseRegexs(properties);
        assertThat(regexs).extracting(Map.Entry::getValue).containsExactly(
                "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11",
                "12");
    }

    @Test
    public void testRemoveSomeCharsFromName() throws IOException {
        var regexes = List.<Map.Entry<Pattern, String>>of(
                new SimpleEntry<Pattern, String>(
                        Pattern.compile("[^a-zA-Z0-9/_.]"), "_"));
        BlobStore regexBlobStore = RegexBlobStore.newRegexBlobStore(delegate,
                regexes);

        String initialBlobName = "test/remove:badchars-folder/blob.txt";
        String targetBlobName = "test/remove_badchars_folder/blob.txt";
        ByteSource content = TestUtils.randomByteSource().slice(0, 1024);
        String contentHash = HexFormat.of().formatHex(
                MD5.hash(content.read()));
        String eTag = TestUtils.putBlob(regexBlobStore, containerName,
                initialBlobName, content).eTag();
        assertThat(eTag).isEqualTo(contentHash);

        var blobMetadata = regexBlobStore.blobMetadata(
                containerName, targetBlobName);

        assertThat(blobMetadata.eTag()).isEqualTo(contentHash);
        var got1 = regexBlobStore.getBlob(containerName, targetBlobName);
        try (InputStream actual = got1;
             InputStream expected = content.openStream()) {
            assertThat(actual).hasSameContentAs(expected);
        }

        var got2 = regexBlobStore.getBlob(containerName, initialBlobName);
        try (InputStream actual = got2;
             InputStream expected = content.openStream()) {
            assertThat(actual).hasSameContentAs(expected);
        }
    }

    @Test
    public void testMultipartStubKeepsItsName() throws IOException {
        var regexes = List.<Map.Entry<Pattern, String>>of(
                new SimpleEntry<Pattern, String>(
                        Pattern.compile("[^a-zA-Z0-9/_.]"), "_"));
        BlobStore regexBlobStore = RegexBlobStore.newRegexBlobStore(delegate,
                regexes);

        // the handler names the stub itself, and reserves and hides it by
        // that name
        String stubName = Constants.MULTIPART_STUB_PREFIX +
                "01234567-89ab-cdef-0123-456789abcdef";
        TestUtils.putBlob(regexBlobStore, containerName, stubName,
                ByteSource.empty());

        assertThat(delegate.blobExists(containerName, stubName)).isTrue();
        assertThat(delegate.blobExists(containerName,
                stubName.replace('-', '_'))).isFalse();

        regexBlobStore.removeBlob(containerName, stubName);
        assertThat(delegate.blobExists(containerName, stubName)).isFalse();
    }

    @Test
    public void testNameMappedToMultipartStub() throws IOException {
        var regexes = List.<Map.Entry<Pattern, String>>of(
                new SimpleEntry<Pattern, String>(
                        Pattern.compile("^incoming/"), ""));
        BlobStore regexBlobStore = RegexBlobStore.newRegexBlobStore(delegate,
                regexes);

        String stubName = Constants.MULTIPART_STUB_PREFIX +
                "01234567-89ab-cdef-0123-456789abcdef";
        TestUtils.putBlob(delegate, containerName, stubName,
                ByteSource.empty());

        // a client's key must not reach the stub through the mapping
        String blobName = "incoming/" + stubName;
        assertThatThrownBy(() -> TestUtils.putBlob(regexBlobStore,
                containerName, blobName, ByteSource.empty()))
                .isInstanceOfSatisfying(S3Exception.class, e ->
                        assertThat(e.awsErrorDetails().errorCode())
                                .isEqualTo("InvalidArgument"));
        assertThatThrownBy(() -> regexBlobStore.removeBlob(containerName,
                blobName))
                .isInstanceOf(S3Exception.class);
        assertThat(delegate.blobExists(containerName, stubName)).isTrue();

        delegate.removeBlob(containerName, stubName);
    }

    @Test
    public void testMultipartStubIsNotAClientKey() throws Exception {
        var regexes = List.<Map.Entry<Pattern, String>>of(
                new SimpleEntry<Pattern, String>(
                        Pattern.compile("[^a-zA-Z0-9/_.]"), "_"));
        S3Proxy s3Proxy = S3Proxy.builder()
                .stopTimeout(0)
                .endpoint(URI.create("http://127.0.0.1:0"))
                .blobStore(RegexBlobStore.newRegexBlobStore(delegate,
                        regexes))
                .build();
        s3Proxy.start();
        try (S3Client client = S3Client.builder()
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create("identity", "credential")))
                .region(Region.US_EAST_1)
                .endpointOverride(URI.create(
                        "http://127.0.0.1:" + s3Proxy.getPort()))
                .serviceConfiguration(S3Configuration.builder()
                        .pathStyleAccessEnabled(true)
                        .build())
                .build()) {
            String key = "victim";
            String uploadId = client.createMultipartUpload(b -> b
                    .bucket(containerName).key(key)
                    .contentType("image/png")).uploadId();
            String eTag = client.uploadPart(b -> b
                    .bucket(containerName).key(key).uploadId(uploadId)
                    .partNumber(1), RequestBody.fromBytes(new byte[1]))
                    .eTag();

            // the stub is hidden under its reserved name and no other
            assertThat(client.listObjectsV2(b -> b.bucket(containerName))
                    .contents()).isEmpty();

            // upload ids are not secret, so any writer can spell the name
            // which the mapping would give the stub; this must be an
            // ordinary key and not the upload's metadata
            String mappedStubName = (Constants.MULTIPART_STUB_PREFIX +
                    uploadId).replace('-', '_');
            client.putObject(b -> b.bucket(containerName).key(mappedStubName)
                    .contentType("text/html"), RequestBody.empty());
            client.deleteObject(b -> b.bucket(containerName)
                    .key(mappedStubName));

            client.completeMultipartUpload(b -> b
                    .bucket(containerName).key(key).uploadId(uploadId)
                    .multipartUpload(CompletedMultipartUpload.builder()
                            .parts(CompletedPart.builder()
                                    .partNumber(1).eTag(eTag).build())
                            .build()));
            assertThat(client.headObject(b -> b.bucket(containerName)
                    .key(key)).contentType()).isEqualTo("image/png");
        } finally {
            s3Proxy.stop();
        }
    }

    @Test
    public void testParseMatchWithoutReplace() {
        var properties = new Properties();
        properties.put(
                "%s.%s.sample1".formatted(
                        S3ProxyConstants.PROPERTY_REGEX_BLOBSTORE,
                        S3ProxyConstants.PROPERTY_REGEX_BLOBSTORE_MATCH),
                "test");
        properties.put(
                "%s.%s.sample2".formatted(
                        S3ProxyConstants.PROPERTY_REGEX_BLOBSTORE,
                        S3ProxyConstants.PROPERTY_REGEX_BLOBSTORE_MATCH),
                "test");
        properties.put(
                "%s.%s.sample1".formatted(
                        S3ProxyConstants.PROPERTY_REGEX_BLOBSTORE,
                        S3ProxyConstants.PROPERTY_REGEX_BLOBSTORE_REPLACE),
                "test");

        try {
            RegexBlobStore.parseRegexs(properties);
            Assertions.failBecauseExceptionWasNotThrown(
                    IllegalArgumentException.class);
        } catch (IllegalArgumentException exc) {
            assertThat(exc.getMessage()).isEqualTo(
                    "Regex sample2 has no replace property associated");
        }
    }

    private static String createRandomContainerName() {
        return "container-" + new Random().nextInt(Integer.MAX_VALUE);
    }
}
