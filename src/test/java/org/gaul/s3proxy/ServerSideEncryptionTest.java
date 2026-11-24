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
import java.util.HexFormat;

import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.MD5;
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
import software.amazon.awssdk.services.s3.model.ObjectAttributes;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.services.s3.model.ServerSideEncryption;
import software.amazon.awssdk.services.s3.model.ServerSideEncryptionByDefault;
import software.amazon.awssdk.services.s3.model.ServerSideEncryptionConfiguration;
import software.amazon.awssdk.services.s3.model.ServerSideEncryptionRule;

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
    /** Two customer keys, alike in everything but their bytes. */
    private static final byte[] KEY_A =
            "0123456789abcdef0123456789abcdef"
                    .getBytes(StandardCharsets.UTF_8);
    private static final byte[] KEY_B =
            "fedcba9876543210fedcba9876543210"
                    .getBytes(StandardCharsets.UTF_8);

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

    /**
     * A copy of an object onto itself is refused unless it changes something,
     * and naming the encryption is what S3 counts as a change: it is how a
     * caller re-encrypts an object in place.  Verified against AWS, which
     * accepts the copy even when it names the encryption the object has.
     */
    @Test
    public void testCopyOntoItselfNamingEncryption() throws Exception {
        startEncrypting();
        client.putObject(b -> b.bucket(containerName).key("blob"),
                RequestBody.fromString("payload"));

        assertThatThrownBy(() -> client.copyObject(b -> b
                .sourceBucket(containerName).sourceKey("blob")
                .destinationBucket(containerName).destinationKey("blob")))
                .isInstanceOf(S3Exception.class)
                .satisfies(thrown -> assertThat(
                        ((S3Exception) thrown).awsErrorDetails().errorCode())
                        .isEqualTo("InvalidRequest"));

        var copy = client.copyObject(b -> b
                .sourceBucket(containerName).sourceKey("blob")
                .destinationBucket(containerName).destinationKey("blob")
                .serverSideEncryption(ServerSideEncryption.AWS_KMS)
                .ssekmsKeyId(KMS_KEY_ID));
        assertThat(copy.serverSideEncryption())
                .isEqualTo(ServerSideEncryption.AWS_KMS);
        var head = client.headObject(b -> b.bucket(containerName).key("blob"));
        assertThat(head.serverSideEncryption())
                .isEqualTo(ServerSideEncryption.AWS_KMS);

        client.putObject(b -> b.bucket(containerName).key("customer")
                        .sseCustomerAlgorithm("AES256")
                        .sseCustomerKey(encodeKey(KEY_A))
                        .sseCustomerKeyMD5(keyMD5(KEY_A)),
                RequestBody.fromString("payload"));
        client.copyObject(b -> b
                .sourceBucket(containerName).sourceKey("customer")
                .destinationBucket(containerName).destinationKey("customer")
                .copySourceSSECustomerAlgorithm("AES256")
                .copySourceSSECustomerKey(encodeKey(KEY_A))
                .copySourceSSECustomerKeyMD5(keyMD5(KEY_A))
                .sseCustomerAlgorithm("AES256")
                .sseCustomerKey(encodeKey(KEY_A))
                .sseCustomerKeyMD5(keyMD5(KEY_A)));
        var get = client.getObjectAsBytes(b -> b.bucket(containerName)
                .key("customer")
                .sseCustomerAlgorithm("AES256")
                .sseCustomerKey(encodeKey(KEY_A))
                .sseCustomerKeyMD5(keyMD5(KEY_A)));
        assertThat(get.asUtf8String()).isEqualTo("payload");
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

        // The customer-key family is refused the same way: silently
        // dropping it would read around a key the caller presented.
        response = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(uri)
                        .header("x-amz-server-side-encryption-customer-" +
                                "algorithm", "AES256")
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
    public void testCustomerKeysRefusedWhereBackendCannot() throws Exception {
        startRefusing();

        assertRefused(() -> client.putObject(
                b -> b.bucket(containerName).key("blob")
                        .sseCustomerAlgorithm("AES256")
                        .sseCustomerKey(encodeKey(KEY_A))
                        .sseCustomerKeyMD5(keyMD5(KEY_A)),
                RequestBody.fromString("payload")));
    }

    @Test
    public void testCustomerKeyRoundTrip() throws Exception {
        startEncrypting();

        // The object rests under the caller's key and reports the key's
        // MD5 rather than an algorithm in x-amz-server-side-encryption:
        // SSE-C and SSE-S3 exclude each other on responses as on requests.
        var put = client.putObject(
                b -> b.bucket(containerName).key("blob")
                        .sseCustomerAlgorithm("AES256")
                        .sseCustomerKey(encodeKey(KEY_A))
                        .sseCustomerKeyMD5(keyMD5(KEY_A)),
                RequestBody.fromString("payload"));
        assertThat(put.serverSideEncryption()).isNull();
        assertThat(put.sseCustomerAlgorithm()).isEqualTo("AES256");
        assertThat(put.sseCustomerKeyMD5()).isEqualTo(keyMD5(KEY_A));

        var head = client.headObject(
                b -> b.bucket(containerName).key("blob")
                        .sseCustomerAlgorithm("AES256")
                        .sseCustomerKey(encodeKey(KEY_A))
                        .sseCustomerKeyMD5(keyMD5(KEY_A)));
        assertThat(head.serverSideEncryption()).isNull();
        assertThat(head.sseCustomerAlgorithm()).isEqualTo("AES256");
        assertThat(head.sseCustomerKeyMD5()).isEqualTo(keyMD5(KEY_A));

        var get = client.getObjectAsBytes(
                b -> b.bucket(containerName).key("blob")
                        .sseCustomerAlgorithm("AES256")
                        .sseCustomerKey(encodeKey(KEY_A))
                        .sseCustomerKeyMD5(keyMD5(KEY_A)));
        assertThat(get.response().serverSideEncryption()).isNull();
        assertThat(get.response().sseCustomerAlgorithm())
                .isEqualTo("AES256");
        assertThat(get.response().sseCustomerKeyMD5())
                .isEqualTo(keyMD5(KEY_A));
        assertThat(get.asUtf8String()).isEqualTo("payload");
    }

    @Test
    public void testCustomerKeyAnswersOnlyToItself() throws Exception {
        startEncrypting();
        client.putObject(b -> b.bucket(containerName).key("blob")
                        .sseCustomerAlgorithm("AES256")
                        .sseCustomerKey(encodeKey(KEY_A))
                        .sseCustomerKeyMD5(keyMD5(KEY_A)),
                RequestBody.fromString("payload"));

        // Reading without the key is a request the object cannot answer,
        // and reading with another key is one it must not.
        assertStatus(400, () -> client.getObjectAsBytes(
                b -> b.bucket(containerName).key("blob")));
        assertStatus(400, () -> client.headObject(
                b -> b.bucket(containerName).key("blob")));
        assertStatus(400, () -> client.getObjectAsBytes(
                b -> b.bucket(containerName).key("blob")
                        .sseCustomerAlgorithm("AES256")
                        .sseCustomerKey(encodeKey(KEY_B))
                        .sseCustomerKeyMD5(keyMD5(KEY_B))));

        // Its attributes are no more to be had without the key than its
        // headers are.
        assertStatus(400, () -> client.getObjectAttributes(
                b -> b.bucket(containerName).key("blob")
                        .objectAttributes(ObjectAttributes.E_TAG,
                                ObjectAttributes.OBJECT_SIZE)));
        assertStatus(400, () -> client.getObjectAttributes(
                b -> b.bucket(containerName).key("blob")
                        .objectAttributes(ObjectAttributes.E_TAG)
                        .sseCustomerAlgorithm("AES256")
                        .sseCustomerKey(encodeKey(KEY_B))
                        .sseCustomerKeyMD5(keyMD5(KEY_B))));
        assertThat(client.getObjectAttributes(
                b -> b.bucket(containerName).key("blob")
                        .objectAttributes(ObjectAttributes.OBJECT_SIZE)
                        .sseCustomerAlgorithm("AES256")
                        .sseCustomerKey(encodeKey(KEY_A))
                        .sseCustomerKeyMD5(keyMD5(KEY_A))).objectSize())
                .isEqualTo(7);

        // An object resting under no key refuses any key offered.
        client.putObject(b -> b.bucket(containerName).key("plain"),
                RequestBody.fromString("payload"));
        assertStatus(400, () -> client.getObjectAsBytes(
                b -> b.bucket(containerName).key("plain")
                        .sseCustomerAlgorithm("AES256")
                        .sseCustomerKey(encodeKey(KEY_A))
                        .sseCustomerKeyMD5(keyMD5(KEY_A))));
    }

    @Test
    public void testCustomerKeyVetted() throws Exception {
        startEncrypting();

        // An MD5 that is not the key's.
        assertStatus(400, () -> client.putObject(
                b -> b.bucket(containerName).key("blob")
                        .sseCustomerAlgorithm("AES256")
                        .sseCustomerKey(encodeKey(KEY_A))
                        .sseCustomerKeyMD5(keyMD5(KEY_B)),
                RequestBody.fromString("payload")));
        // A key shorter than 256 bits.
        assertStatus(400, () -> client.putObject(
                b -> b.bucket(containerName).key("blob")
                        .sseCustomerAlgorithm("AES256")
                        .sseCustomerKey(Base64.getEncoder().encodeToString(
                                "short".getBytes(StandardCharsets.UTF_8)))
                        .sseCustomerKeyMD5(keyMD5(
                                "short".getBytes(StandardCharsets.UTF_8))),
                RequestBody.fromString("payload")));
        // An algorithm with no key to go with it.
        assertStatus(400, () -> client.putObject(
                b -> b.bucket(containerName).key("blob")
                        .sseCustomerAlgorithm("AES256"),
                RequestBody.fromString("payload")));
        // Both modes at once.
        assertStatus(400, () -> client.putObject(
                b -> b.bucket(containerName).key("blob")
                        .serverSideEncryption(ServerSideEncryption.AES256)
                        .sseCustomerAlgorithm("AES256")
                        .sseCustomerKey(encodeKey(KEY_A))
                        .sseCustomerKeyMD5(keyMD5(KEY_A)),
                RequestBody.fromString("payload")));

        // Nothing above may have stored anything readable.
        assertThat(client.listObjectsV2(b -> b.bucket(containerName))
                .contents()).isEmpty();
    }

    @Test
    public void testCustomerKeyCopy() throws Exception {
        startEncrypting();
        client.putObject(b -> b.bucket(containerName).key("blob")
                        .sseCustomerAlgorithm("AES256")
                        .sseCustomerKey(encodeKey(KEY_A))
                        .sseCustomerKeyMD5(keyMD5(KEY_A)),
                RequestBody.fromString("payload"));

        // Reading the source needs its key; the destination rests under
        // its own, named in the plain variants of the same headers.
        assertStatus(400, () -> client.copyObject(b -> b
                .sourceBucket(containerName).sourceKey("blob")
                .destinationBucket(containerName).destinationKey("copy")));
        assertStatus(400, () -> client.copyObject(b -> b
                .sourceBucket(containerName).sourceKey("blob")
                .destinationBucket(containerName).destinationKey("copy")
                .copySourceSSECustomerAlgorithm("AES256")
                .copySourceSSECustomerKey(encodeKey(KEY_B))
                .copySourceSSECustomerKeyMD5(keyMD5(KEY_B))));

        var copy = client.copyObject(b -> b
                .sourceBucket(containerName).sourceKey("blob")
                .destinationBucket(containerName).destinationKey("copy")
                .copySourceSSECustomerAlgorithm("AES256")
                .copySourceSSECustomerKey(encodeKey(KEY_A))
                .copySourceSSECustomerKeyMD5(keyMD5(KEY_A))
                .sseCustomerAlgorithm("AES256")
                .sseCustomerKey(encodeKey(KEY_B))
                .sseCustomerKeyMD5(keyMD5(KEY_B)));
        assertThat(copy.sseCustomerAlgorithm()).isEqualTo("AES256");
        assertThat(copy.sseCustomerKeyMD5()).isEqualTo(keyMD5(KEY_B));

        var get = client.getObjectAsBytes(
                b -> b.bucket(containerName).key("copy")
                        .sseCustomerAlgorithm("AES256")
                        .sseCustomerKey(encodeKey(KEY_B))
                        .sseCustomerKeyMD5(keyMD5(KEY_B)));
        assertThat(get.asUtf8String()).isEqualTo("payload");

        // A copy asking for no encryption rests under the default, which
        // any later read may have without a key.
        client.copyObject(b -> b
                .sourceBucket(containerName).sourceKey("blob")
                .destinationBucket(containerName).destinationKey("decrypted")
                .copySourceSSECustomerAlgorithm("AES256")
                .copySourceSSECustomerKey(encodeKey(KEY_A))
                .copySourceSSECustomerKeyMD5(keyMD5(KEY_A)));
        assertThat(client.getObjectAsBytes(
                b -> b.bucket(containerName).key("decrypted"))
                .asUtf8String()).isEqualTo("payload");
    }

    @Test
    public void testCustomerKeyMultipart() throws Exception {
        startEncrypting();

        var create = client.createMultipartUpload(
                b -> b.bucket(containerName).key("mpu")
                        .sseCustomerAlgorithm("AES256")
                        .sseCustomerKey(encodeKey(KEY_A))
                        .sseCustomerKeyMD5(keyMD5(KEY_A)));
        assertThat(create.serverSideEncryption()).isNull();
        assertThat(create.sseCustomerAlgorithm()).isEqualTo("AES256");
        assertThat(create.sseCustomerKeyMD5()).isEqualTo(keyMD5(KEY_A));

        // Every part must present the create-time key again, and any
        // other request is malformed rather than merely denied.
        assertStatus(400, () -> client.uploadPart(
                b -> b.bucket(containerName).key("mpu")
                        .uploadId(create.uploadId()).partNumber(1),
                RequestBody.fromString("payload")));
        assertStatus(400, () -> client.uploadPart(
                b -> b.bucket(containerName).key("mpu")
                        .uploadId(create.uploadId()).partNumber(1)
                        .sseCustomerAlgorithm("AES256")
                        .sseCustomerKey(encodeKey(KEY_B))
                        .sseCustomerKeyMD5(keyMD5(KEY_B)),
                RequestBody.fromString("payload")));

        var part = client.uploadPart(
                b -> b.bucket(containerName).key("mpu")
                        .uploadId(create.uploadId()).partNumber(1)
                        .sseCustomerAlgorithm("AES256")
                        .sseCustomerKey(encodeKey(KEY_A))
                        .sseCustomerKeyMD5(keyMD5(KEY_A)),
                RequestBody.fromString("payload"));
        assertThat(part.sseCustomerAlgorithm()).isEqualTo("AES256");
        assertThat(part.sseCustomerKeyMD5()).isEqualTo(keyMD5(KEY_A));

        // A part copied in needs the create-time key like an uploaded one,
        // before any bytes move.
        client.putObject(b -> b.bucket(containerName).key("src"),
                RequestBody.fromString("payload"));
        assertStatus(400, () -> client.uploadPartCopy(b -> b
                .sourceBucket(containerName).sourceKey("src")
                .destinationBucket(containerName).destinationKey("mpu")
                .uploadId(create.uploadId()).partNumber(2)));

        // The completion must present the create-time key again, as every
        // part did; the object then answers only to that key.
        assertStatus(400, () -> client.completeMultipartUpload(
                b -> b.bucket(containerName).key("mpu")
                        .uploadId(create.uploadId())
                        .multipartUpload(CompletedMultipartUpload.builder()
                                .parts(CompletedPart.builder()
                                        .partNumber(1)
                                        .eTag(part.eTag())
                                        .build())
                                .build())));
        client.completeMultipartUpload(
                b -> b.bucket(containerName).key("mpu")
                        .uploadId(create.uploadId())
                        .multipartUpload(CompletedMultipartUpload.builder()
                                .parts(CompletedPart.builder()
                                        .partNumber(1)
                                        .eTag(part.eTag())
                                        .build())
                                .build())
                        .sseCustomerAlgorithm("AES256")
                        .sseCustomerKey(encodeKey(KEY_A))
                        .sseCustomerKeyMD5(keyMD5(KEY_A)));

        assertStatus(400, () -> client.getObjectAsBytes(
                b -> b.bucket(containerName).key("mpu")));
        var get = client.getObjectAsBytes(
                b -> b.bucket(containerName).key("mpu")
                        .sseCustomerAlgorithm("AES256")
                        .sseCustomerKey(encodeKey(KEY_A))
                        .sseCustomerKeyMD5(keyMD5(KEY_A)));
        assertThat(get.response().sseCustomerAlgorithm())
                .isEqualTo("AES256");
        assertThat(get.response().sseCustomerKeyMD5())
                .isEqualTo(keyMD5(KEY_A));
        assertThat(get.asUtf8String()).isEqualTo("payload");
    }

    @Test
    public void testCustomerKeyMultipartPartAnswersOnlyToItsKey()
            throws Exception {
        startEncrypting();

        var create = client.createMultipartUpload(
                b -> b.bucket(containerName).key("mpu")
                        .sseCustomerAlgorithm("AES256")
                        .sseCustomerKey(encodeKey(KEY_A))
                        .sseCustomerKeyMD5(keyMD5(KEY_A)));
        var part = client.uploadPart(
                b -> b.bucket(containerName).key("mpu")
                        .uploadId(create.uploadId()).partNumber(1)
                        .sseCustomerAlgorithm("AES256")
                        .sseCustomerKey(encodeKey(KEY_A))
                        .sseCustomerKeyMD5(keyMD5(KEY_A)),
                RequestBody.fromString("payload"));

        // The store keeps the part under a name of its own, which a request
        // may read while the upload is in flight -- ListMultipartUploads
        // hands out everything the name is made of.  The bytes are the ones
        // the finished object will hold, and answer to the same key.
        // as the nio2 stores name a part
        var partKey = ".mpus-" + create.uploadId() + "-mpu-1";
        assertStatus(400, () -> client.getObjectAsBytes(
                b -> b.bucket(containerName).key(partKey)));
        assertStatus(400, () -> client.getObjectAsBytes(
                b -> b.bucket(containerName).key(partKey)
                        .sseCustomerAlgorithm("AES256")
                        .sseCustomerKey(encodeKey(KEY_B))
                        .sseCustomerKeyMD5(keyMD5(KEY_B))));
        assertStatus(400, () -> client.headObject(
                b -> b.bucket(containerName).key(partKey)));
        assertStatus(400, () -> client.getObjectAttributes(
                b -> b.bucket(containerName).key(partKey)
                        .objectAttributes(ObjectAttributes.E_TAG,
                                ObjectAttributes.OBJECT_SIZE)));

        // Nor may a copy carry them out from under the key, whole or as a
        // part of some other upload.
        assertStatus(400, () -> client.copyObject(b -> b
                .sourceBucket(containerName).sourceKey(partKey)
                .destinationBucket(containerName).destinationKey("copy")));
        var plain = client.createMultipartUpload(
                b -> b.bucket(containerName).key("copy"));
        assertStatus(400, () -> client.uploadPartCopy(b -> b
                .sourceBucket(containerName).sourceKey(partKey)
                .destinationBucket(containerName).destinationKey("copy")
                .uploadId(plain.uploadId()).partNumber(1)));
        assertThat(client.listObjectsV2(b -> b.bucket(containerName))
                .contents()).isEmpty();
        assertThat(client.listParts(b -> b.bucket(containerName).key("copy")
                .uploadId(plain.uploadId())).parts()).isEmpty();

        // The upload itself is none the worse for its parts being held to
        // the key: it completes, and the object holds what was uploaded.
        client.completeMultipartUpload(
                b -> b.bucket(containerName).key("mpu")
                        .uploadId(create.uploadId())
                        .multipartUpload(CompletedMultipartUpload.builder()
                                .parts(CompletedPart.builder()
                                        .partNumber(1)
                                        .eTag(part.eTag())
                                        .build())
                                .build())
                        .sseCustomerAlgorithm("AES256")
                        .sseCustomerKey(encodeKey(KEY_A))
                        .sseCustomerKeyMD5(keyMD5(KEY_A)));
        assertThat(client.getObjectAsBytes(
                b -> b.bucket(containerName).key("mpu")
                        .sseCustomerAlgorithm("AES256")
                        .sseCustomerKey(encodeKey(KEY_A))
                        .sseCustomerKeyMD5(keyMD5(KEY_A))).asUtf8String())
                .isEqualTo("payload");
    }

    @Test
    public void testCustomerKeyETagIsNoDigestOfTheData() throws Exception {
        startEncrypting();
        byte[] md5 = MD5.hash("payload".getBytes(StandardCharsets.UTF_8));
        String md5ETag = "\"" + HexFormat.of().formatHex(md5) + "\"";

        // A listing shows an object's ETag to callers who present no key,
        // so under a customer key it is no MD5 of the data, as on S3: one
        // would let them confirm any guess at what the object holds.
        var put = client.putObject(b -> b.bucket(containerName).key("blob")
                        .sseCustomerAlgorithm("AES256")
                        .sseCustomerKey(encodeKey(KEY_A))
                        .sseCustomerKeyMD5(keyMD5(KEY_A)),
                RequestBody.fromString("payload"));
        assertThat(put.eTag()).isNotEqualTo(md5ETag);
        assertThat(client.listObjectsV2(b -> b.bucket(containerName))
                .contents()).singleElement().satisfies(object ->
                        assertThat(object.eTag()).isEqualTo(put.eTag()));

        // The key's holder is told the ETag the listing shows.
        assertThat(client.headObject(
                b -> b.bucket(containerName).key("blob")
                        .sseCustomerAlgorithm("AES256")
                        .sseCustomerKey(encodeKey(KEY_A))
                        .sseCustomerKeyMD5(keyMD5(KEY_A))).eTag())
                .isEqualTo(put.eTag());

        // Nor does it tell that two objects hold the same data.
        var twin = client.putObject(b -> b.bucket(containerName).key("twin")
                        .sseCustomerAlgorithm("AES256")
                        .sseCustomerKey(encodeKey(KEY_A))
                        .sseCustomerKeyMD5(keyMD5(KEY_A)),
                RequestBody.fromString("payload"));
        assertThat(twin.eTag()).isNotEqualTo(put.eTag());

        // A part is listed without the key as well, and the ETag of the
        // object assembled from it digests the part's.
        var create = client.createMultipartUpload(
                b -> b.bucket(containerName).key("mpu")
                        .sseCustomerAlgorithm("AES256")
                        .sseCustomerKey(encodeKey(KEY_A))
                        .sseCustomerKeyMD5(keyMD5(KEY_A)));
        var part = client.uploadPart(
                b -> b.bucket(containerName).key("mpu")
                        .uploadId(create.uploadId()).partNumber(1)
                        .sseCustomerAlgorithm("AES256")
                        .sseCustomerKey(encodeKey(KEY_A))
                        .sseCustomerKeyMD5(keyMD5(KEY_A)),
                RequestBody.fromString("payload"));
        assertThat(part.eTag()).isNotEqualTo(md5ETag);
        assertThat(client.listParts(b -> b.bucket(containerName).key("mpu")
                .uploadId(create.uploadId())).parts()).singleElement()
                .satisfies(listed ->
                        assertThat(listed.eTag()).isEqualTo(part.eTag()));
        var complete = client.completeMultipartUpload(
                b -> b.bucket(containerName).key("mpu")
                        .uploadId(create.uploadId())
                        .multipartUpload(CompletedMultipartUpload.builder()
                                .parts(CompletedPart.builder()
                                        .partNumber(1)
                                        .eTag(part.eTag())
                                        .build())
                                .build())
                        .sseCustomerAlgorithm("AES256")
                        .sseCustomerKey(encodeKey(KEY_A))
                        .sseCustomerKeyMD5(keyMD5(KEY_A)));
        assertThat(complete.eTag()).isNotEqualTo(
                "\"" + HexFormat.of().formatHex(MD5.hash(md5)) + "-1\"");

        // An object under no key keeps the MD5 of its data.
        var plain = client.putObject(
                b -> b.bucket(containerName).key("plain"),
                RequestBody.fromString("payload"));
        assertThat(plain.eTag()).isEqualTo(md5ETag);
    }

    @Test
    public void testBucketEncryptionRoundTrip() throws Exception {
        startEncrypting();

        // A bucket that was never configured answers with S3's own code,
        // not an empty configuration.
        assertBucketEncryptionNotFound();

        client.putBucketEncryption(b -> b.bucket(containerName)
                .serverSideEncryptionConfiguration(encryptionConfiguration(
                        "AES256", /*kmsKeyId=*/ null,
                        /*bucketKeyEnabled=*/ null)));
        var rule = client.getBucketEncryption(b -> b.bucket(containerName))
                .serverSideEncryptionConfiguration().rules().get(0);
        assertThat(rule.applyServerSideEncryptionByDefault().sseAlgorithm())
                .isEqualTo(ServerSideEncryption.AES256);
        assertThat(rule.applyServerSideEncryptionByDefault()
                .kmsMasterKeyID()).isNull();

        // A new configuration replaces the last one whole.
        client.putBucketEncryption(b -> b.bucket(containerName)
                .serverSideEncryptionConfiguration(encryptionConfiguration(
                        "aws:kms", KMS_KEY_ID, /*bucketKeyEnabled=*/ true)));
        rule = client.getBucketEncryption(b -> b.bucket(containerName))
                .serverSideEncryptionConfiguration().rules().get(0);
        assertThat(rule.applyServerSideEncryptionByDefault().sseAlgorithm())
                .isEqualTo(ServerSideEncryption.AWS_KMS);
        assertThat(rule.applyServerSideEncryptionByDefault()
                .kmsMasterKeyID()).isEqualTo(KMS_KEY_ID);
        assertThat(rule.bucketKeyEnabled()).isTrue();

        // Deleting is idempotent: removing what remains and removing what
        // is already absent both succeed.
        client.deleteBucketEncryption(b -> b.bucket(containerName));
        assertBucketEncryptionNotFound();
        client.deleteBucketEncryption(b -> b.bucket(containerName));
    }

    @Test
    public void testBucketEncryptionAppliesToUnadornedWrites()
            throws Exception {
        startEncrypting();

        // Written before any configuration: rests under the plain default
        // and stays there, since the configuration is not retroactive.
        client.putObject(b -> b.bucket(containerName).key("before"),
                RequestBody.fromString("payload"));

        client.putBucketEncryption(b -> b.bucket(containerName)
                .serverSideEncryptionConfiguration(encryptionConfiguration(
                        "aws:kms", KMS_KEY_ID, /*bucketKeyEnabled=*/ null)));

        var before = client.headObject(
                b -> b.bucket(containerName).key("before"));
        assertThat(before.serverSideEncryption())
                .isEqualTo(ServerSideEncryption.AES256);
        assertThat(before.ssekmsKeyId()).isNull();

        // A put naming nothing rests under the bucket's default.
        var put = client.putObject(b -> b.bucket(containerName).key("blob"),
                RequestBody.fromString("payload"));
        assertThat(put.serverSideEncryption())
                .isEqualTo(ServerSideEncryption.AWS_KMS);
        assertThat(put.ssekmsKeyId()).isEqualTo(KMS_KEY_ID);

        var head = client.headObject(b -> b.bucket(containerName).key("blob"));
        assertThat(head.serverSideEncryption())
                .isEqualTo(ServerSideEncryption.AWS_KMS);
        assertThat(head.ssekmsKeyId()).isEqualTo(KMS_KEY_ID);

        // So does an unadorned copy's destination.
        var copy = client.copyObject(b -> b
                .sourceBucket(containerName).sourceKey("before")
                .destinationBucket(containerName).destinationKey("copy"));
        assertThat(copy.serverSideEncryption())
                .isEqualTo(ServerSideEncryption.AWS_KMS);
        assertThat(copy.ssekmsKeyId()).isEqualTo(KMS_KEY_ID);

        // And an unadorned multipart upload, from create to completion.
        var create = client.createMultipartUpload(
                b -> b.bucket(containerName).key("mpu"));
        assertThat(create.serverSideEncryption())
                .isEqualTo(ServerSideEncryption.AWS_KMS);
        assertThat(create.ssekmsKeyId()).isEqualTo(KMS_KEY_ID);
        var part = client.uploadPart(b -> b.bucket(containerName).key("mpu")
                        .uploadId(create.uploadId()).partNumber(1),
                RequestBody.fromString("payload"));
        client.completeMultipartUpload(b -> b.bucket(containerName).key("mpu")
                .uploadId(create.uploadId())
                .multipartUpload(CompletedMultipartUpload.builder()
                        .parts(CompletedPart.builder().partNumber(1)
                                .eTag(part.eTag()).build())
                        .build()));
        var mpu = client.headObject(b -> b.bucket(containerName).key("mpu"));
        assertThat(mpu.serverSideEncryption())
                .isEqualTo(ServerSideEncryption.AWS_KMS);
        assertThat(mpu.ssekmsKeyId()).isEqualTo(KMS_KEY_ID);

        // A write that names its own encryption is not defaulted.
        var explicit = client.putObject(b -> b.bucket(containerName)
                        .key("explicit")
                        .serverSideEncryption(ServerSideEncryption.AES256),
                RequestBody.fromString("payload"));
        assertThat(explicit.serverSideEncryption())
                .isEqualTo(ServerSideEncryption.AES256);
        assertThat(explicit.ssekmsKeyId()).isNull();
    }

    @Test
    public void testBucketEncryptionVetted() throws Exception {
        startEncrypting();

        // A KMS key under an algorithm that does not name one.
        assertThatThrownBy(() -> client.putBucketEncryption(b -> b
                .bucket(containerName)
                .serverSideEncryptionConfiguration(encryptionConfiguration(
                        "AES256", KMS_KEY_ID, /*bucketKeyEnabled=*/ null))))
                .isInstanceOfSatisfying(S3Exception.class, e -> {
                    assertThat(e.statusCode()).isEqualTo(400);
                    assertThat(e.awsErrorDetails().errorCode())
                            .isEqualTo("InvalidArgument");
                });

        // aws:kms naming no key: this store has no account default key to
        // reach for, the answer its object write path gives.
        assertStatus(400, () -> client.putBucketEncryption(b -> b
                .bucket(containerName)
                .serverSideEncryptionConfiguration(encryptionConfiguration(
                        "aws:kms", /*kmsKeyId=*/ null,
                        /*bucketKeyEnabled=*/ null))));

        // An algorithm S3 has never had fails the schema.
        assertThatThrownBy(() -> client.putBucketEncryption(b -> b
                .bucket(containerName)
                .serverSideEncryptionConfiguration(encryptionConfiguration(
                        "MADEUP", /*kmsKeyId=*/ null,
                        /*bucketKeyEnabled=*/ null))))
                .isInstanceOfSatisfying(S3Exception.class, e -> {
                    assertThat(e.statusCode()).isEqualTo(400);
                    assertThat(e.awsErrorDetails().errorCode())
                            .isEqualTo("MalformedXML");
                });

        // None of it was stored.
        assertBucketEncryptionNotFound();
    }

    @Test
    public void testBucketEncryptionRefusedWhereBackendCannot()
            throws Exception {
        startRefusing();

        assertRefused(() -> client.getBucketEncryption(
                b -> b.bucket(containerName)));
        assertRefused(() -> client.putBucketEncryption(b -> b
                .bucket(containerName)
                .serverSideEncryptionConfiguration(encryptionConfiguration(
                        "AES256", /*kmsKeyId=*/ null,
                        /*bucketKeyEnabled=*/ null))));
        assertRefused(() -> client.deleteBucketEncryption(
                b -> b.bucket(containerName)));
    }

    /** One rule naming the default, built without the varargs consumers. */
    private static ServerSideEncryptionConfiguration encryptionConfiguration(
            String algorithm, String kmsKeyId, Boolean bucketKeyEnabled) {
        var byDefault = ServerSideEncryptionByDefault.builder()
                .sseAlgorithm(algorithm);
        if (kmsKeyId != null) {
            byDefault.kmsMasterKeyID(kmsKeyId);
        }
        return ServerSideEncryptionConfiguration.builder()
                .rules(ServerSideEncryptionRule.builder()
                        .applyServerSideEncryptionByDefault(byDefault.build())
                        .bucketKeyEnabled(bucketKeyEnabled)
                        .build())
                .build();
    }

    private void assertBucketEncryptionNotFound() {
        assertThatThrownBy(() -> client.getBucketEncryption(
                b -> b.bucket(containerName)))
                .isInstanceOfSatisfying(S3Exception.class, e -> {
                    assertThat(e.statusCode()).isEqualTo(404);
                    assertThat(e.awsErrorDetails().errorCode()).isEqualTo(
                            "ServerSideEncryptionConfigurationNotFoundError");
                });
    }

    private static String encodeKey(byte[] key) {
        return Base64.getEncoder().encodeToString(key);
    }

    private static String keyMD5(byte[] key) {
        return Base64.getEncoder().encodeToString(MD5.hash(key));
    }

    private static void assertRefused(ThrowingCallable callable) {
        assertStatus(501, callable);
    }

    private static void assertStatus(int status, ThrowingCallable callable) {
        assertThatThrownBy(callable)
                .isInstanceOfSatisfying(S3Exception.class,
                        e -> assertThat(e.statusCode()).isEqualTo(status));
    }
}
