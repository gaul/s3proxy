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
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Properties;

import com.google.common.io.ByteSource;

import org.assertj.core.api.Assertions;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.Constants;
import org.gaul.s3proxy.sts.SessionToken;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.auth.signer.Aws4Signer;
import software.amazon.awssdk.auth.signer.params.Aws4SignerParams;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.http.ContentStreamProvider;
import software.amazon.awssdk.http.SdkHttpConfigurationOption;
import software.amazon.awssdk.http.SdkHttpFullRequest;
import software.amazon.awssdk.http.SdkHttpMethod;
import software.amazon.awssdk.http.SdkHttpRequest;
import software.amazon.awssdk.http.apache5.Apache5HttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.model.CompletedPart;
import software.amazon.awssdk.services.s3.model.ObjectAttributes;
import software.amazon.awssdk.services.s3.model.ObjectIdentifier;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.services.s3.presigner.S3Presigner;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.Credentials;
import software.amazon.awssdk.services.sts.model.GetFederationTokenResponse;
import software.amazon.awssdk.services.sts.model.PolicyDescriptorType;
import software.amazon.awssdk.services.sts.model.StsException;
import software.amazon.awssdk.utils.AttributeMap;

/**
 * GetFederationToken end to end, through the stock AWS SDK: a configured
 * identity mints temporary credentials narrowed by a session policy, and an
 * S3 client holding them may do what the policy allows and nothing else.
 */
public final class StsFederationTokenTest {
    private static final String POLICY_TEMPLATE = """
            {"Version": "2012-10-17", "Statement": [
              {"Effect": "Allow",
               "Action": ["s3:GetObject", "s3:PutObject",
                          "s3:AbortMultipartUpload"],
               "Resource": "arn:aws:s3:::BUCKET/home/alice/*"},
              {"Effect": "Allow", "Action": "s3:ListBucket",
               "Resource": "arn:aws:s3:::BUCKET",
               "Condition": {"StringLike": {"s3:prefix": "home/alice/*"}}},
              {"Effect": "Deny", "Action": "s3:PutObject",
               "Resource": "arn:aws:s3:::BUCKET/home/alice/readonly/*"}
            ]}""";

    private S3Proxy s3Proxy;
    private BlobStore blobStore;
    private URI endpoint;
    private URI plainEndpoint;
    private AwsBasicCredentials parentCredentials;
    private String bucket;
    private String otherBucket;
    private final List<AutoCloseable> closeables = new ArrayList<>();

    @BeforeEach
    public void setUp() throws Exception {
        TestUtils.S3ProxyLaunchInfo info = TestUtils.startS3Proxy(
                "s3proxy-sts.conf");
        String blobStoreType = info.getProperties().getProperty(
                Constants.PROPERTY_PROVIDER, "");
        assumeTrue(blobStoreType.isEmpty() ||
                blobStoreType.equals("transient"));
        s3Proxy = info.getS3Proxy();
        blobStore = info.getBlobStore();
        endpoint = URI.create(info.getSecureEndpoint().toString() +
                info.getServicePath());
        plainEndpoint = URI.create(info.getEndpoint().toString() +
                info.getServicePath());
        parentCredentials = AwsBasicCredentials.create(
                info.getS3Identity(), info.getS3Credential());
        bucket = TestUtils.createRandomContainerName();
        otherBucket = TestUtils.createRandomContainerName();
        blobStore.createContainer(bucket);
        blobStore.createContainer(otherBucket);
    }

    @AfterEach
    public void tearDown() throws Exception {
        for (AutoCloseable closeable : closeables) {
            closeable.close();
        }
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
        if (blobStore != null) {
            for (String container : List.of(bucket, otherBucket)) {
                if (container != null &&
                        blobStore.containerExists(container)) {
                    blobStore.deleteContainer(container);
                }
            }
        }
    }

    @Test
    public void testResponseShape() {
        GetFederationTokenResponse response = sts(parentCredentials)
                .getFederationToken(b -> b.name("alice-job")
                        .durationSeconds(3600).policy(policy()));
        Credentials credentials = response.credentials();
        assertThat(credentials.accessKeyId()).startsWith("ASIA").hasSize(20);
        assertThat(credentials.secretAccessKey()).hasSize(40);
        assertThat(credentials.sessionToken()).isNotEmpty();
        assertThat(credentials.expiration()).isBetween(
                Instant.now().plus(Duration.ofMinutes(59)),
                Instant.now().plus(Duration.ofMinutes(61)));
        assertThat(response.federatedUser().arn())
                .endsWith(":federated-user/alice-job");
        assertThat(response.federatedUser().federatedUserId())
                .endsWith(":alice-job");
        // whole seconds, matching the expiry the token enforces
        assertThat(credentials.expiration()).isEqualTo(
                credentials.expiration().truncatedTo(ChronoUnit.SECONDS));
    }

    @Test
    public void testScopedReadWrite() {
        S3Client client = scopedClient(policy());

        client.putObject(b -> b.bucket(bucket).key("home/alice/a.txt"),
                RequestBody.fromString("hello"));
        assertThat(client.getObjectAsBytes(b -> b.bucket(bucket)
                .key("home/alice/a.txt")).asUtf8String()).isEqualTo("hello");
        client.headObject(b -> b.bucket(bucket).key("home/alice/a.txt"));

        // outside the prefix, in the same bucket and in another
        assertDenied(() -> client.putObject(
                b -> b.bucket(bucket).key("home/bob/a.txt"),
                RequestBody.fromString("x")));
        putDirect(bucket, "home/bob/secret");
        assertDenied(() -> client.getObjectAsBytes(
                b -> b.bucket(bucket).key("home/bob/secret")));
        assertDenied(() -> client.headObject(
                b -> b.bucket(bucket).key("home/bob/secret")));
        assertDenied(() -> client.putObject(
                b -> b.bucket(otherBucket).key("home/alice/a.txt"),
                RequestBody.fromString("x")));
        // a prefix match must not be a string match on the key alone
        assertDenied(() -> client.putObject(
                b -> b.bucket(bucket).key("home/alice"),
                RequestBody.fromString("x")));
    }

    @Test
    public void testExplicitDenyWins() {
        S3Client client = scopedClient(policy());
        assertDenied(() -> client.putObject(
                b -> b.bucket(bucket).key("home/alice/readonly/x"),
                RequestBody.fromString("x")));
        putDirect(bucket, "home/alice/readonly/x");
        client.getObjectAsBytes(b -> b.bucket(bucket)
                .key("home/alice/readonly/x"));
    }

    @Test
    public void testOperationsNotGranted() {
        S3Client client = scopedClient(policy());
        putDirect(bucket, "home/alice/a.txt");
        assertDenied(() -> client.deleteObject(
                b -> b.bucket(bucket).key("home/alice/a.txt")));
        assertThat(blobStore.blobExists(bucket, "home/alice/a.txt")).isTrue();
        assertDenied(() -> client.listBuckets());
        assertDenied(() -> client.createBucket(b -> b.bucket(
                TestUtils.createRandomContainerName())));
        assertDenied(() -> client.deleteBucket(b -> b.bucket(otherBucket)));
        assertDenied(() -> client.getObjectAcl(
                b -> b.bucket(bucket).key("home/alice/a.txt")));
        // writing an ACL along with an object needs s3:PutObjectAcl too
        assertDenied(() -> client.putObject(
                b -> b.bucket(bucket).key("home/alice/public")
                        .acl("public-read"),
                RequestBody.fromString("x")));
    }

    @Test
    public void testListRequiresMatchingPrefix() {
        S3Client client = scopedClient(policy());
        putDirect(bucket, "home/alice/a.txt");
        putDirect(bucket, "home/bob/b.txt");

        assertThat(client.listObjectsV2(b -> b.bucket(bucket)
                .prefix("home/alice/")).contents())
                .extracting(o -> o.key())
                .containsExactly("home/alice/a.txt");
        assertDenied(() -> client.listObjectsV2(b -> b.bucket(bucket)));
        assertDenied(() -> client.listObjectsV2(b -> b.bucket(bucket)
                .prefix("home/")));
        assertDenied(() -> client.listObjectsV2(b -> b.bucket(bucket)
                .prefix("home/bob/")));
        assertDenied(() -> client.listObjects(b -> b.bucket(bucket)));
    }

    @Test
    public void testCopyChecksSourceAndDestination() {
        S3Client client = scopedClient(policy());
        putDirect(bucket, "home/alice/a.txt");
        putDirect(bucket, "home/bob/secret");

        client.copyObject(b -> b.sourceBucket(bucket)
                .sourceKey("home/alice/a.txt").destinationBucket(bucket)
                .destinationKey("home/alice/b.txt"));
        assertThat(blobStore.blobExists(bucket, "home/alice/b.txt")).isTrue();

        // reading a source the session may not GET
        assertDenied(() -> client.copyObject(b -> b.sourceBucket(bucket)
                .sourceKey("home/bob/secret").destinationBucket(bucket)
                .destinationKey("home/alice/loot")));
        assertThat(blobStore.blobExists(bucket, "home/alice/loot")).isFalse();
        // writing a destination the session may not PUT
        assertDenied(() -> client.copyObject(b -> b.sourceBucket(bucket)
                .sourceKey("home/alice/a.txt").destinationBucket(bucket)
                .destinationKey("home/bob/planted")));
    }

    @Test
    public void testMultipartUpload() {
        S3Client client = scopedClient(policy());
        String key = "home/alice/mpu";
        String uploadId = client.createMultipartUpload(
                b -> b.bucket(bucket).key(key)).uploadId();
        String etag = client.uploadPart(b -> b.bucket(bucket).key(key)
                .uploadId(uploadId).partNumber(1),
                RequestBody.fromString("part")).eTag();
        client.completeMultipartUpload(b -> b.bucket(bucket).key(key)
                .uploadId(uploadId).multipartUpload(m -> m.parts(
                        CompletedPart.builder().partNumber(1).eTag(etag)
                                .build())));
        assertThat(blobStore.blobExists(bucket, key)).isTrue();

        assertDenied(() -> client.createMultipartUpload(
                b -> b.bucket(bucket).key("home/bob/mpu")));
        // the policy does not grant s3:ListMultipartUploadParts
        String other = client.createMultipartUpload(
                b -> b.bucket(bucket).key(key)).uploadId();
        assertDenied(() -> client.listParts(b -> b.bucket(bucket).key(key)
                .uploadId(other)));
        client.abortMultipartUpload(b -> b.bucket(bucket).key(key)
                .uploadId(other));
    }

    @Test
    public void testDeleteObjectsChecksEveryKey() {
        String policy = """
                {"Version": "2012-10-17", "Statement": {"Effect": "Allow",
                 "Action": "s3:DeleteObject",
                 "Resource": "arn:aws:s3:::BUCKET/home/alice/*"}}"""
                .replace("BUCKET", bucket);
        S3Client client = scopedClient(policy);
        putDirect(bucket, "home/alice/a");
        putDirect(bucket, "home/bob/b");

        assertDenied(() -> client.deleteObjects(b -> b.bucket(bucket)
                .delete(d -> d.objects(objectId("home/alice/a"),
                        objectId("home/bob/b")))));
        assertThat(blobStore.blobExists(bucket, "home/alice/a")).isTrue();
        assertThat(blobStore.blobExists(bucket, "home/bob/b")).isTrue();

        client.deleteObjects(b -> b.bucket(bucket).delete(d -> d.objects(
                objectId("home/alice/a"))));
        assertThat(blobStore.blobExists(bucket, "home/alice/a")).isFalse();
    }

    @Test
    public void testNoPolicyGrantsNothing() {
        Credentials credentials = sts(parentCredentials).getFederationToken(
                b -> b.name("nobody")).credentials();
        S3Client client = s3(sessionCredentials(credentials));
        putDirect(bucket, "a");
        assertDenied(() -> client.getObjectAsBytes(
                b -> b.bucket(bucket).key("a")));
        assertDenied(() -> client.listBuckets());
    }

    @Test
    public void testWildcardPolicyGrantsEverything() {
        S3Client client = scopedClient("""
                {"Version": "2012-10-17", "Statement": {"Effect": "Allow",
                 "Action": "s3:*", "Resource": "*"}}""");
        client.listBuckets();
        client.putObject(b -> b.bucket(otherBucket).key("k"),
                RequestBody.fromString("x"));
        client.deleteObject(b -> b.bucket(otherBucket).key("k"));
    }

    @Test
    public void testPresignedUrl() throws Exception {
        Credentials credentials = mint(policy());
        putDirect(bucket, "home/alice/a.txt");
        putDirect(bucket, "home/bob/secret");
        try (S3Presigner presigner = S3Presigner.builder()
                .credentialsProvider(StaticCredentialsProvider.create(
                        sessionCredentials(credentials)))
                .region(Region.US_EAST_1)
                .endpointOverride(plainEndpoint)
                .serviceConfiguration(S3Configuration.builder()
                        .pathStyleAccessEnabled(true).build())
                .build()) {
            URI allowed = presigner.presignGetObject(b -> b
                    .signatureDuration(Duration.ofMinutes(5))
                    .getObjectRequest(g -> g.bucket(bucket)
                            .key("home/alice/a.txt"))).url().toURI();
            URI denied = presigner.presignGetObject(b -> b
                    .signatureDuration(Duration.ofMinutes(5))
                    .getObjectRequest(g -> g.bucket(bucket)
                            .key("home/bob/secret"))).url().toURI();
            assertThat(allowed.getQuery()).contains("X-Amz-Security-Token");
            assertThat(httpGet(allowed)).isEqualTo(200);
            assertThat(httpGet(denied)).isEqualTo(403);
        }
    }

    @Test
    public void testTamperedTokenIsRejected() {
        Credentials credentials = mint(policy());
        String token = credentials.sessionToken();
        // flip one character in the encrypted claims
        int i = token.length() - 10;
        char flipped = token.charAt(i) == 'A' ? 'B' : 'A';
        String tampered = token.substring(0, i) + flipped +
                token.substring(i + 1);
        S3Client client = s3(AwsSessionCredentials.create(
                credentials.accessKeyId(), credentials.secretAccessKey(),
                tampered));
        assertErrorCode(() -> client.putObject(
                b -> b.bucket(bucket).key("home/alice/a"),
                RequestBody.fromString("x")), "InvalidToken");
    }

    @Test
    public void testTokenBoundToItsAccessKey() {
        Credentials first = mint(policy());
        Credentials second = mint(policy());
        // second's key and secret with first's token: the signature is valid
        // for second's secret, but the token belongs to first's access key
        S3Client client = s3(AwsSessionCredentials.create(
                second.accessKeyId(), second.secretAccessKey(),
                first.sessionToken()));
        assertErrorCode(() -> client.putObject(
                b -> b.bucket(bucket).key("home/alice/a"),
                RequestBody.fromString("x")), "InvalidToken");
    }

    @Test
    public void testWrongSecretIsRejected() {
        Credentials credentials = mint(policy());
        S3Client client = s3(AwsSessionCredentials.create(
                credentials.accessKeyId(), parentCredentials.secretAccessKey(),
                credentials.sessionToken()));
        assertErrorCode(() -> client.putObject(
                b -> b.bucket(bucket).key("home/alice/a"),
                RequestBody.fromString("x")), "SignatureDoesNotMatch");
    }

    @Test
    public void testTemporaryKeyWithoutTokenIsUnknown() {
        Credentials credentials = mint(policy());
        S3Client client = s3(AwsBasicCredentials.create(
                credentials.accessKeyId(), credentials.secretAccessKey()));
        assertErrorCode(() -> client.putObject(
                b -> b.bucket(bucket).key("home/alice/a"),
                RequestBody.fromString("x")), "InvalidAccessKeyId");
    }

    @Test
    public void testSessionCannotMintMore() {
        Credentials credentials = mint(policy());
        StsException e = Assertions.catchThrowableOfType(StsException.class,
                () -> sts(sessionCredentials(credentials))
                        .getFederationToken(b -> b.name("again")));
        assertThat(e).isNotNull();
        assertThat(e.awsErrorDetails().errorCode()).isEqualTo("AccessDenied");
    }

    @Test
    public void testRotatedParentSecretRevokesTokens() throws Exception {
        Credentials credentials = mint(policy());
        // the same identity, now configured with a different secret
        String token = credentials.sessionToken();
        assertThat(SessionToken.parentAccessKeyId(token))
                .isEqualTo(parentCredentials.accessKeyId());
        s3Proxy.setBlobStoreLocator((identity, container, blob) ->
                parentCredentials.accessKeyId().equals(identity) ?
                        new AccessGrant("rotated-credential", blobStore) :
                        null);
        S3Client client = s3(sessionCredentials(credentials));
        assertErrorCode(() -> client.putObject(
                b -> b.bucket(bucket).key("home/alice/a"),
                RequestBody.fromString("x")), "InvalidToken");
    }

    @Test
    public void testExpiredToken() {
        // Mint a token that has already expired, as the proxy would have an
        // hour ago, rather than wait out the fifteen-minute minimum.
        var random = new SecureRandom();
        String accessKeyId = SessionToken.newAccessKeyId(random);
        String token = new SessionToken(parentCredentials.accessKeyId(),
                accessKeyId, Instant.now().minusSeconds(1), "expired",
                policy()).encode(parentCredentials.secretAccessKey(), random);
        S3Client client = s3(AwsSessionCredentials.create(accessKeyId,
                SessionToken.secretAccessKey(parentCredentials.accessKeyId(),
                        accessKeyId, parentCredentials.secretAccessKey()),
                token));
        assertErrorCode(() -> client.putObject(
                b -> b.bucket(bucket).key("home/alice/a"),
                RequestBody.fromString("x")), "ExpiredToken");
    }

    @Test
    public void testInvalidRequests() {
        StsClient sts = sts(parentCredentials);
        assertStsError(() -> sts.getFederationToken(b -> b.name("x")),
                "ValidationError");
        assertStsError(() -> sts.getFederationToken(b -> b.name("ok-name")
                .durationSeconds(899)), "ValidationError");
        assertStsError(() -> sts.getFederationToken(b -> b.name("ok-name")
                .policy("{not json")), "MalformedPolicyDocument");
        assertStsError(() -> sts.getFederationToken(b -> b.name("ok-name")
                .policy("""
                        {"Version": "2012-10-17", "Statement": {
                         "Effect": "Allow", "NotAction": "s3:DeleteObject",
                         "Resource": "*"}}""")), "MalformedPolicyDocument");
        assertStsError(() -> sts.getFederationToken(b -> b.name("ok-name")
                .policy("""
                        {"Version": "2012-10-17", "Statement": {
                         "Effect": "Allow", "Action": "s3:GetObject",
                         "Resource": "*", "Condition": {"IpAddress":
                         {"aws:SourceIp": "10.0.0.0/8"}}}}""")),
                "MalformedPolicyDocument");
        assertStsError(() -> sts.getFederationToken(b -> b.name("ok-name")
                .policy(largePolicy())), "ValidationError");
        assertStsError(() -> sts.getFederationToken(b -> b.name("ok-name")
                .policyArns(PolicyDescriptorType.builder()
                        .arn("arn:aws:iam::aws:policy/Admin").build())),
                "ValidationError");
        assertStsError(() -> sts.getCallerIdentity(), "InvalidAction");
    }

    @Test
    public void testDotSegmentsCannotEscapeThePrefix() {
        S3Client client = scopedClient(policy());
        putDirect(bucket, "home/bob/secret");
        putDirect(bucket, "home/alice/a.txt");
        String escape = "home/alice/../bob/secret";
        assertDenied(() -> client.getObjectAsBytes(
                b -> b.bucket(bucket).key(escape)));
        assertDenied(() -> client.headObject(
                b -> b.bucket(bucket).key(escape)));
        assertDenied(() -> client.putObject(
                b -> b.bucket(bucket).key("home/alice/../bob/planted"),
                RequestBody.fromString("x")));
        assertDenied(() -> client.copyObject(b -> b.sourceBucket(bucket)
                .sourceKey(escape).destinationBucket(bucket)
                .destinationKey("home/alice/loot")));
        assertDenied(() -> client.createMultipartUpload(
                b -> b.bucket(bucket).key("home/alice/./../bob/mpu")));
        assertDenied(() -> client.listObjectsV2(b -> b.bucket(bucket)
                .prefix("home/alice/../bob/")));
        // An empty segment would let home/alice//readonly/ dodge the Deny.
        // Through the URI the SDK and the proxy canonicalize the double
        // slash differently, so the signature fails before the policy is
        // asked; SessionTest covers the segment rule itself.
        assertThat(Assertions.catchThrowableOfType(S3Exception.class,
                () -> client.putObject(
                        b -> b.bucket(bucket).key("home/alice//readonly/x"),
                        RequestBody.fromString("x"))).statusCode())
                .isEqualTo(403);
        assertThat(blobStore.blobExists(bucket, "home/alice/readonly/x"))
                .isFalse();
        assertThat(blobStore.blobExists(bucket, "home/alice/loot")).isFalse();
        // a trailing slash, as a directory marker has, is still a key
        client.putObject(b -> b.bucket(bucket).key("home/alice/dir/"),
                RequestBody.empty());
    }

    @Test
    public void testDeleteObjectsRefusesDotSegments() {
        S3Client client = scopedClient("""
                {"Statement": {"Effect": "Allow",
                 "Action": "s3:DeleteObject",
                 "Resource": "arn:aws:s3:::BUCKET/home/alice/*"}}"""
                .replace("BUCKET", bucket));
        putDirect(bucket, "home/bob/secret");
        assertDenied(() -> client.deleteObjects(b -> b.bucket(bucket)
                .delete(d -> d.objects(
                        objectId("home/alice/../bob/secret")))));
        assertThat(blobStore.blobExists(bucket, "home/bob/secret")).isTrue();
    }

    @Test
    public void testPrivateCannedAclNeedsNoAclPermission() {
        S3Client client = scopedClient(policy());
        client.putObject(b -> b.bucket(bucket).key("home/alice/p")
                .acl("private"), RequestBody.fromString("x"));
    }

    @Test
    public void testObjectAttributesNeedGetObject() {
        putDirect(bucket, "home/alice/a.txt");
        S3Client client = scopedClient("""
                {"Statement": {"Effect": "Allow",
                 "Action": "s3:GetObjectAttributes", "Resource": "*"}}""");
        assertDenied(() -> client.getObjectAttributes(b -> b.bucket(bucket)
                .key("home/alice/a.txt").objectAttributes(
                        ObjectAttributes.E_TAG)));
    }

    @Test
    public void testListObjectsV1WithPrefix() {
        S3Client client = scopedClient(policy());
        putDirect(bucket, "home/alice/a.txt");
        assertThat(client.listObjects(b -> b.bucket(bucket)
                .prefix("home/alice/")).contents()).hasSize(1);
    }

    @Test
    public void testLargeNonAsciiPolicyFitsInAHeader() {
        // As many three-byte characters as the limit takes: the token must
        // still fit in the request header every later request carries it in.
        String template = """
                {"Statement": [
                 {"Effect": "Allow", "Action": "s3:PutObject",
                  "Resource": "arn:aws:s3:::BUCKET/*"},
                 {"Effect": "Deny", "Action": "s3:PutObject",
                  "Resource": "arn:aws:s3:::BUCKET/PREFIX*"}]}"""
                .replace("BUCKET", bucket);
        int room = 2048 - template.replace("PREFIX", "")
                .getBytes(StandardCharsets.UTF_8).length;
        String prefix = "\u6587".repeat(room / 3);
        String policy = template.replace("PREFIX", prefix);
        assertThat(policy.getBytes(StandardCharsets.UTF_8).length)
                .isBetween(2046, 2048);
        S3Client client = scopedClient(policy);
        client.putObject(b -> b.bucket(bucket).key("x"),
                RequestBody.fromString("x"));
        assertStsError(() -> sts(parentCredentials).getFederationToken(
                b -> b.name("big").policy(policy.replace("Deny",
                        "Deny\", \"Sid\": \"" + "\u6587".repeat(40)))),
                "ValidationError");
    }

    // The legacy signer signs as botocore does, with no x-amz-content-sha256,
    // which is the path under test; its replacement always adds the header.
    @SuppressWarnings("deprecation")
    @Test
    public void testStsBodyIsCoveredBySignature() throws Exception {
        String body = "Action=GetFederationToken&Version=2011-06-15" +
                "&Name=alice-job&DurationSeconds=900";
        SdkHttpFullRequest unsigned = SdkHttpFullRequest.builder()
                .method(SdkHttpMethod.POST)
                .uri(plainEndpoint.resolve("/"))
                .putHeader("Content-Type",
                        "application/x-www-form-urlencoded; charset=utf-8")
                .contentStreamProvider(
                        ContentStreamProvider.fromUtf8String(body))
                .build();
        SdkHttpFullRequest signed = Aws4Signer.create().sign(unsigned,
                Aws4SignerParams.builder()
                        .awsCredentials(parentCredentials)
                        .signingName("sts")
                        .signingRegion(Region.US_EAST_1)
                        .build());
        // no x-amz-content-sha256, so only the canonical request's own hash
        // of the body protects it
        assertThat(signed.firstMatchingHeader("x-amz-content-sha256"))
                .isEmpty();

        assertThat(postSigned(signed, body).statusCode()).isEqualTo(200);
        // the same signature over a longer session must not mint one
        HttpResponse<String> tampered = postSigned(signed,
                body.replace("=900", "=129600"));
        assertThat(tampered.statusCode()).isEqualTo(403);
        assertThat(tampered.body()).contains("SignatureDoesNotMatch");
    }

    @Test
    public void testUploadIdBoundToItsKey() {
        // An upload the parent began elsewhere, made public: the session
        // must not finish it under a key of its own, taking its ACL, nor
        // abort it from there.
        S3Client parent = s3(parentCredentials);
        String bobs = parent.createMultipartUpload(b -> b.bucket(bucket)
                .key("home/bob/big").acl("public-read")).uploadId();
        S3Client client = scopedClient(policy());
        String key = "home/alice/big";
        assertErrorCode(() -> client.uploadPart(b -> b.bucket(bucket).key(key)
                .uploadId(bobs).partNumber(1),
                RequestBody.fromString("part")), "NoSuchUpload");
        assertErrorCode(() -> client.completeMultipartUpload(b -> b
                .bucket(bucket).key(key).uploadId(bobs)
                .multipartUpload(m -> m.parts(CompletedPart.builder()
                        .partNumber(1).eTag("\"x\"").build()))),
                "NoSuchUpload");
        assertErrorCode(() -> client.abortMultipartUpload(b -> b
                .bucket(bucket).key(key).uploadId(bobs)), "NoSuchUpload");
        assertThat(blobStore.blobExists(bucket, key)).isFalse();
        // the parent's own upload is intact
        parent.abortMultipartUpload(b -> b.bucket(bucket)
                .key("home/bob/big").uploadId(bobs));
    }

    @Test
    public void testUnknownIdentityOnSts() {
        assertStsError(() -> sts(AwsBasicCredentials.create("nobody",
                "nothing")).getFederationToken(b -> b.name("x-y")),
                "InvalidClientTokenId");
    }

    @Test
    public void testV2AuthorizationRefused() throws Exception {
        s3Proxy.stop();
        s3Proxy = null;
        var properties = new Properties();
        try (var is = getClass().getResourceAsStream("/s3proxy-sts.conf")) {
            properties.load(is);
        }
        properties.setProperty("s3proxy.authorization", "aws-v2");
        // the keystore path is relative to the test classpath; plain HTTP
        // suffices to reach the check
        properties.remove("s3proxy.secure-endpoint");
        S3Proxy.Builder builder = S3Proxy.Builder.fromProperties(properties)
                .blobStore(blobStore);
        Assertions.assertThatThrownBy(builder::build)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("STS requires");
    }

    @Test
    public void testDurationCappedByConfiguration() throws Exception {
        s3Proxy.stop();
        TestUtils.S3ProxyLaunchInfo info = TestUtils.startS3Proxy(
                "s3proxy-sts-short.conf");
        s3Proxy = info.getS3Proxy();
        endpoint = URI.create(info.getSecureEndpoint().toString() +
                info.getServicePath());
        Credentials credentials = sts(parentCredentials).getFederationToken(
                b -> b.name("capped").durationSeconds(129_600))
                .credentials();
        assertThat(credentials.expiration()).isBetween(
                Instant.now().plus(Duration.ofMinutes(14)),
                Instant.now().plus(Duration.ofMinutes(16)));
    }

    /** A valid policy past the 2048 bytes GetFederationToken takes. */
    private static String largePolicy() {
        String statement = "{\"Effect\":\"Allow\"," +
                "\"Action\":\"s3:GetObject\",\"Resource\":\"*\"}";
        return "{\"Statement\":[" +
                String.join(",", Collections.nCopies(60, statement)) +
                "]}";
    }

    private String policy() {
        return POLICY_TEMPLATE.replace("BUCKET", bucket);
    }

    private Credentials mint(String policy) {
        return sts(parentCredentials).getFederationToken(
                b -> b.name("alice-job").policy(policy)).credentials();
    }

    private S3Client scopedClient(String policy) {
        return s3(sessionCredentials(mint(policy)));
    }

    private static AwsSessionCredentials sessionCredentials(
            Credentials credentials) {
        return AwsSessionCredentials.create(credentials.accessKeyId(),
                credentials.secretAccessKey(), credentials.sessionToken());
    }

    private static AttributeMap trustAll() {
        return AttributeMap.builder()
                .put(SdkHttpConfigurationOption.TRUST_ALL_CERTIFICATES, true)
                .build();
    }

    private StsClient sts(AwsCredentials credentials) {
        StsClient client = StsClient.builder()
                .credentialsProvider(StaticCredentialsProvider.create(
                        credentials))
                .region(Region.US_EAST_1)
                .endpointOverride(endpoint)
                .httpClient(Apache5HttpClient.builder()
                        .buildWithDefaults(trustAll()))
                .build();
        closeables.add(client);
        return client;
    }

    private S3Client s3(AwsCredentials credentials) {
        S3Client client = S3Client.builder()
                .credentialsProvider(StaticCredentialsProvider.create(
                        credentials))
                .region(Region.US_EAST_1)
                .endpointOverride(endpoint)
                .httpClient(Apache5HttpClient.builder()
                        .buildWithDefaults(trustAll()))
                .serviceConfiguration(S3Configuration.builder()
                        .pathStyleAccessEnabled(true)
                        .build())
                .build();
        closeables.add(client);
        return client;
    }

    private void putDirect(String container, String key) {
        try {
            TestUtils.putBlob(blobStore, container, key,
                    ByteSource.wrap("data".getBytes(StandardCharsets.UTF_8)));
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }

    private static ObjectIdentifier objectId(String key) {
        return ObjectIdentifier.builder().key(key).build();
    }

    private static void assertDenied(Runnable runnable) {
        assertErrorCode(runnable, "AccessDenied");
    }

    private static void assertErrorCode(Runnable runnable, String code) {
        S3Exception e = Assertions.catchThrowableOfType(S3Exception.class,
                runnable::run);
        assertThat(e).as("expected %s", code).isNotNull();
        if (e.awsErrorDetails().errorCode() != null) {
            assertThat(e.awsErrorDetails().errorCode()).isEqualTo(code);
        } else {
            // HEAD responses carry no body to name the code in
            assertThat(e.statusCode()).isEqualTo(
                    code.equals("AccessDenied") ? 403 : 400);
        }
    }

    private static void assertStsError(Runnable runnable, String code) {
        StsException e = Assertions.catchThrowableOfType(StsException.class,
                runnable::run);
        assertThat(e).as("expected %s", code).isNotNull();
        assertThat(e.awsErrorDetails().errorCode()).isEqualTo(code);
    }

    private static HttpResponse<String> postSigned(SdkHttpRequest signed,
            String body) throws Exception {
        var builder = HttpRequest.newBuilder(signed.getUri())
                .POST(HttpRequest.BodyPublishers.ofString(body));
        signed.forEachHeader((name, values) -> {
            if (!name.equalsIgnoreCase("Host") &&
                    !name.equalsIgnoreCase("Content-Length")) {
                values.forEach(value -> builder.header(name, value));
            }
        });
        return HttpClient.newHttpClient().send(builder.build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private static int httpGet(URI uri) throws Exception {
        return HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(uri).GET().build(),
                HttpResponse.BodyHandlers.discarding()).statusCode();
    }
}
