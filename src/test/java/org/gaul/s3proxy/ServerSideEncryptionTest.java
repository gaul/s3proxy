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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Base64;

import com.google.common.hash.Hashing;

import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.nio2blob.FilesystemNio2BlobStore;
import org.gaul.s3proxy.nio2blob.TransientNio2BlobStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.model.CompletedMultipartUpload;
import software.amazon.awssdk.services.s3.model.CompletedPart;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.services.s3.model.ServerSideEncryption;

/**
 * Server-side encryption end to end over the two nio2 stores, which share
 * the implementation and differ in whether they own up to it.  The transient
 * store answers the header family: what it holds never rests anywhere a
 * caller could read it, so an object's encryption is the family and nothing
 * else, which is all S3 lets a caller observe of SSE-S3 anyway.  The
 * filesystem store writes to a real disk, where reporting AES256 over
 * readable plaintext would be a claim S3Proxy has no business making, so it
 * refuses the family on every method -- as both stores did before these
 * headers were understood at all.
 */
public final class ServerSideEncryptionTest {
    private static final String KMS_KEY_ID =
            "arn:aws:kms:us-east-1:123456789012:key/test-key";
    private static final String KMS_CONTEXT = Base64.getEncoder()
            .encodeToString("{\"purpose\":\"testing\"}"
                    .getBytes(StandardCharsets.UTF_8));

    @TempDir
    private Path root;
    private S3Proxy s3Proxy;
    private S3Client client;
    private String containerName;

    private void start(BlobStore blobStore) throws Exception {
        containerName = TestUtils.createRandomContainerName();

        s3Proxy = S3Proxy.builder()
                .stopTimeout(0)
                .endpoint(URI.create("http://127.0.0.1:0"))
                .blobStore(blobStore)
                .build();
        s3Proxy.start();

        client = S3Client.builder()
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create("identity", "credential")))
                .region(Region.US_EAST_1)
                .endpointOverride(URI.create(
                        "http://127.0.0.1:" + s3Proxy.getPort()))
                .serviceConfiguration(S3Configuration.builder()
                        .pathStyleAccessEnabled(true)
                        .build())
                .build();

        client.createBucket(b -> b.bucket(containerName));
    }

    /** The store that encrypts, in front of the proxy. */
    private void startEncrypting() throws Exception {
        start(new TransientNio2BlobStore());
    }

    /** The store that refuses to, in front of the proxy. */
    private void startRefusing() throws Exception {
        start(new FilesystemNio2BlobStore(root.toString()));
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (client != null) {
            client.close();
        }
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
    }

    @Test
    public void testStoresDifferOverEncryption() {
        assertThat(new TransientNio2BlobStore()
                .supportsServerSideEncryption()).isTrue();
        assertThat(new FilesystemNio2BlobStore(root.toString())
                .supportsServerSideEncryption()).isFalse();
    }

    @Test
    public void testReportsDefaultEncryption() throws Exception {
        startEncrypting();

        // Ask for nothing and the object still rests under the default, the
        // way S3 encrypts what nobody asked it to.
        var put = client.putObject(b -> b.bucket(containerName).key("blob"),
                RequestBody.fromString("payload"));
        assertThat(put.serverSideEncryption())
                .isEqualTo(ServerSideEncryption.AES256);
        assertThat(put.ssekmsKeyId()).isNull();

        var head = client.headObject(b -> b.bucket(containerName).key("blob"));
        assertThat(head.serverSideEncryption())
                .isEqualTo(ServerSideEncryption.AES256);

        var get = client.getObjectAsBytes(
                b -> b.bucket(containerName).key("blob"));
        assertThat(get.response().serverSideEncryption())
                .isEqualTo(ServerSideEncryption.AES256);
        assertThat(get.asUtf8String()).isEqualTo("payload");
    }

    @Test
    public void testPutRestsUnderRequestedEncryption() throws Exception {
        startEncrypting();

        var put = client.putObject(b -> b.bucket(containerName).key("blob")
                        .serverSideEncryption(ServerSideEncryption.AWS_KMS)
                        .ssekmsKeyId(KMS_KEY_ID)
                        .ssekmsEncryptionContext(KMS_CONTEXT)
                        .bucketKeyEnabled(true),
                RequestBody.fromString("payload"));
        assertThat(put.serverSideEncryption())
                .isEqualTo(ServerSideEncryption.AWS_KMS);
        assertThat(put.ssekmsKeyId()).isEqualTo(KMS_KEY_ID);
        assertThat(put.ssekmsEncryptionContext()).isEqualTo(KMS_CONTEXT);
        assertThat(put.bucketKeyEnabled()).isTrue();

        // Reported from what the object rests under, not from the request
        // that wrote it: a later read has only the store to ask.
        var head = client.headObject(b -> b.bucket(containerName).key("blob"));
        assertThat(head.serverSideEncryption())
                .isEqualTo(ServerSideEncryption.AWS_KMS);
        assertThat(head.ssekmsKeyId()).isEqualTo(KMS_KEY_ID);
        assertThat(head.bucketKeyEnabled()).isTrue();

        var get = client.getObjectAsBytes(
                b -> b.bucket(containerName).key("blob"));
        assertThat(get.response().serverSideEncryption())
                .isEqualTo(ServerSideEncryption.AWS_KMS);
        assertThat(get.response().ssekmsKeyId()).isEqualTo(KMS_KEY_ID);
        assertThat(get.asUtf8String()).isEqualTo("payload");
    }

    @Test
    public void testCopyRestsUnderItsOwnEncryption() throws Exception {
        startEncrypting();
        client.putObject(b -> b.bucket(containerName).key("blob"),
                RequestBody.fromString("payload"));

        var copy = client.copyObject(b -> b
                .sourceBucket(containerName).sourceKey("blob")
                .destinationBucket(containerName).destinationKey("copy")
                .serverSideEncryption(ServerSideEncryption.AWS_KMS)
                .ssekmsKeyId(KMS_KEY_ID));
        assertThat(copy.serverSideEncryption())
                .isEqualTo(ServerSideEncryption.AWS_KMS);
        assertThat(copy.ssekmsKeyId()).isEqualTo(KMS_KEY_ID);

        var head = client.headObject(b -> b.bucket(containerName).key("copy"));
        assertThat(head.serverSideEncryption())
                .isEqualTo(ServerSideEncryption.AWS_KMS);
        assertThat(head.ssekmsKeyId()).isEqualTo(KMS_KEY_ID);

        // The source is a different object and keeps its own, which the copy
        // neither inherited nor disturbed.
        var source = client.headObject(
                b -> b.bucket(containerName).key("blob"));
        assertThat(source.serverSideEncryption())
                .isEqualTo(ServerSideEncryption.AES256);
        assertThat(source.ssekmsKeyId()).isNull();
    }

    @Test
    public void testMultipartRestsUnderTheUploadsEncryption() throws Exception {
        startEncrypting();

        var create = client.createMultipartUpload(
                b -> b.bucket(containerName).key("mpu")
                        .serverSideEncryption(ServerSideEncryption.AWS_KMS)
                        .ssekmsKeyId(KMS_KEY_ID));
        assertThat(create.serverSideEncryption())
                .isEqualTo(ServerSideEncryption.AWS_KMS);
        assertThat(create.ssekmsKeyId()).isEqualTo(KMS_KEY_ID);

        // The part and the completion name the encryption the upload was
        // created under, which only the upload itself still knows: the
        // requests carrying them name nothing but the bucket and key.
        var part = client.uploadPart(
                b -> b.bucket(containerName).key("mpu")
                        .uploadId(create.uploadId()).partNumber(1),
                RequestBody.fromString("payload"));
        assertThat(part.serverSideEncryption())
                .isEqualTo(ServerSideEncryption.AWS_KMS);
        assertThat(part.ssekmsKeyId()).isEqualTo(KMS_KEY_ID);

        var complete = client.completeMultipartUpload(
                b -> b.bucket(containerName).key("mpu")
                        .uploadId(create.uploadId())
                        .multipartUpload(CompletedMultipartUpload.builder()
                                .parts(CompletedPart.builder()
                                        .partNumber(1)
                                        .eTag(part.eTag())
                                        .build())
                                .build()));
        assertThat(complete.serverSideEncryption())
                .isEqualTo(ServerSideEncryption.AWS_KMS);
        assertThat(complete.ssekmsKeyId()).isEqualTo(KMS_KEY_ID);

        var head = client.headObject(b -> b.bucket(containerName).key("mpu"));
        assertThat(head.serverSideEncryption())
                .isEqualTo(ServerSideEncryption.AWS_KMS);
        assertThat(head.ssekmsKeyId()).isEqualTo(KMS_KEY_ID);

        var get = client.getObjectAsBytes(
                b -> b.bucket(containerName).key("mpu"));
        assertThat(get.asUtf8String()).isEqualTo("payload");
    }

    @Test
    public void testRefusesWhereBackendCannotEncrypt() throws Exception {
        startRefusing();

        // without the header everything still works
        client.putObject(b -> b.bucket(containerName).key("blob"),
                RequestBody.fromString("payload"));

        assertRefused(() -> client.putObject(
                b -> b.bucket(containerName).key("blob")
                        .serverSideEncryption(ServerSideEncryption.AES256),
                RequestBody.fromString("payload")));
        assertRefused(() -> client.putObject(
                b -> b.bucket(containerName).key("blob")
                        .serverSideEncryption(ServerSideEncryption.AWS_KMS)
                        .ssekmsKeyId(KMS_KEY_ID),
                RequestBody.fromString("payload")));
        assertRefused(() -> client.copyObject(b -> b
                .sourceBucket(containerName).sourceKey("blob")
                .destinationBucket(containerName).destinationKey("copy")
                .serverSideEncryption(ServerSideEncryption.AES256)));
        assertRefused(() -> client.createMultipartUpload(
                b -> b.bucket(containerName).key("mpu")
                        .serverSideEncryption(ServerSideEncryption.AES256)));
    }

    /**
     * A store that cannot encrypt reports nothing rather than the default:
     * the object rests as plaintext on a disk, and saying AES256 over it
     * would be the claim the refusal above exists to avoid.
     */
    @Test
    public void testReportsNoEncryptionWhereBackendCannot() throws Exception {
        startRefusing();
        client.putObject(b -> b.bucket(containerName).key("blob"),
                RequestBody.fromString("payload"));

        var head = client.headObject(b -> b.bucket(containerName).key("blob"));
        assertThat(head.serverSideEncryption()).isNull();

        var get = client.getObjectAsBytes(
                b -> b.bucket(containerName).key("blob"));
        assertThat(get.response().serverSideEncryption()).isNull();
    }

    @Test
    public void testRefusesReadCarryingEncryptionHeader() throws Exception {
        startRefusing();
        client.putObject(b -> b.bucket(containerName).key("blob"),
                RequestBody.fromString("payload"));

        // The header is refused on every method a store that cannot
        // encrypt sees, as before it was understood at all.
        var uri = URI.create("http://127.0.0.1:" + s3Proxy.getPort() + "/" +
                containerName + "/blob");
        var response = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(uri)
                        .header("x-amz-server-side-encryption", "AES256")
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(501);

        response = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(uri).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(200);
    }

    @Test
    @SuppressWarnings("deprecation")
    public void testCustomerKeysStayRefused() throws Exception {
        // SSE-C stays out even on a store that encrypts: dropping the
        // caller's key would claim an encryption nobody performed.
        startEncrypting();

        byte[] key = "0123456789abcdef0123456789abcdef"
                .getBytes(StandardCharsets.UTF_8);
        assertRefused(() -> client.putObject(
                b -> b.bucket(containerName).key("blob")
                        .sseCustomerAlgorithm("AES256")
                        .sseCustomerKey(Base64.getEncoder()
                                .encodeToString(key))
                        .sseCustomerKeyMD5(Base64.getEncoder().encodeToString(
                                Hashing.md5().hashBytes(key).asBytes())),
                RequestBody.fromString("payload")));
    }

    private static void assertRefused(ThrowingCallable callable) {
        assertThatThrownBy(callable)
                .isInstanceOfSatisfying(S3Exception.class,
                        e -> assertThat(e.statusCode()).isEqualTo(501));
    }
}
