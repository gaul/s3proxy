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
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Random;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.http.SdkHttpConfigurationOption;
import software.amazon.awssdk.http.apache5.Apache5HttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.model.BucketVersioningStatus;
import software.amazon.awssdk.services.s3.model.CompletedMultipartUpload;
import software.amazon.awssdk.services.s3.model.CompletedPart;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.s3.model.Permission;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.services.s3.model.Type;
import software.amazon.awssdk.utils.AttributeMap;

/**
 * Object versioning (issue #74) against whichever store the conf names:
 * writes stack rather than replace, a delete leaves a marker over the
 * history instead of removing it, and every version stays addressable by
 * its id.  The transient store implements this natively and the
 * google-cloud-storage backend translates it onto GCS generations; a store
 * that cannot express Suspended skips those tests through
 * {@code suspendVersioning}.  The filesystem store shares the transient
 * code but answers {@code supportsVersioning() == false}, which is what
 * keeps these requests a 501 there -- see
 * {@code Nio2VersioningSupportTest}.
 */
public final class VersionedBlobStoreTest {
    private static final byte[] FIRST = "first".getBytes(
            StandardCharsets.UTF_8);
    private static final byte[] SECOND = "second".getBytes(
            StandardCharsets.UTF_8);

    private S3Proxy s3Proxy;
    private BlobStore blobStore;
    private S3Client client;
    private String containerName;

    @BeforeEach
    public void setUp() throws Exception {
        TestUtils.S3ProxyLaunchInfo info = TestUtils.startS3Proxy(
                System.getProperty("s3proxy.test.conf", "s3proxy.conf"));
        blobStore = info.getBlobStore();
        s3Proxy = info.getS3Proxy();

        var creds = AwsBasicCredentials.create(info.getS3Identity(),
                info.getS3Credential());
        var attributeMap = AttributeMap.builder()
                .put(SdkHttpConfigurationOption.TRUST_ALL_CERTIFICATES, true)
                .build();
        client = S3Client.builder()
                .credentialsProvider(StaticCredentialsProvider.create(creds))
                .region(Region.US_EAST_1)
                .endpointOverride(URI.create(
                        info.getSecureEndpoint().toString() +
                        info.getServicePath()))
                .httpClient(Apache5HttpClient.builder()
                        .buildWithDefaults(attributeMap))
                .serviceConfiguration(S3Configuration.builder()
                        .pathStyleAccessEnabled(true)
                        .build())
                .build();

        containerName = "container-" + new Random().nextInt(Integer.MAX_VALUE);
        blobStore.createContainer(containerName);
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (client != null) {
            client.close();
        }
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
        if (blobStore != null && containerName != null) {
            blobStore.deleteContainer(containerName);
        }
    }

    private void enableVersioning() {
        client.putBucketVersioning(b -> b.bucket(containerName)
                .versioningConfiguration(v -> v.status(
                        BucketVersioningStatus.ENABLED)));
    }

    private void suspendVersioning() {
        try {
            client.putBucketVersioning(b -> b.bucket(containerName)
                    .versioningConfiguration(v -> v.status(
                            BucketVersioningStatus.SUSPENDED)));
        } catch (S3Exception se) {
            // GCS versioning is on or off, so that store refuses S3's third
            // state rather than half-emulating the null-version rule.
            Assumptions.abort("store cannot suspend versioning: " + se);
        }
    }

    private String put(String key, byte[] content) {
        return client.putObject(b -> b.bucket(containerName).key(key),
                RequestBody.fromBytes(content)).versionId();
    }

    private byte[] get(String key) {
        return client.getObjectAsBytes(
                b -> b.bucket(containerName).key(key)).asByteArray();
    }

    private byte[] get(String key, String versionId) {
        return client.getObjectAsBytes(b -> b.bucket(containerName).key(key)
                .versionId(versionId)).asByteArray();
    }

    @Test
    public void testBucketStartsUnversioned() {
        assertThat(client.getBucketVersioning(b -> b.bucket(containerName))
                .status()).isNull();
    }

    @Test
    public void testStatusRoundTrips() {
        enableVersioning();
        assertThat(client.getBucketVersioning(b -> b.bucket(containerName))
                .status()).isEqualTo(BucketVersioningStatus.ENABLED);

        suspendVersioning();
        assertThat(client.getBucketVersioning(b -> b.bucket(containerName))
                .status()).isEqualTo(BucketVersioningStatus.SUSPENDED);
    }

    /** A write to a bucket that was never enabled carries no version. */
    @Test
    public void testUnversionedWriteHasNoVersionId() {
        assertThat(put("blob", FIRST)).isNull();
        assertThat(get("blob")).isEqualTo(FIRST);
    }

    @Test
    public void testWritesStackRatherThanReplace() {
        enableVersioning();
        String first = put("blob", FIRST);
        String second = put("blob", SECOND);

        assertThat(first).isNotNull();
        assertThat(second).isNotNull().isNotEqualTo(first);
        assertThat(get("blob")).isEqualTo(SECOND);
        assertThat(get("blob", first)).isEqualTo(FIRST);
        assertThat(get("blob", second)).isEqualTo(SECOND);

        var listing = client.listObjectVersions(b -> b.bucket(containerName));
        assertThat(listing.versions()).hasSize(2);
        assertThat(listing.versions().get(0).versionId()).isEqualTo(second);
        assertThat(listing.versions().get(0).isLatest()).isTrue();
        assertThat(listing.versions().get(1).versionId()).isEqualTo(first);
        assertThat(listing.versions().get(1).isLatest()).isFalse();
        assertThat(listing.versions().get(1).size()).isEqualTo(FIRST.length);

        // The current version alone is an object.
        assertThat(client.listObjectsV2(b -> b.bucket(containerName))
                .contents().stream().map(o -> o.key()))
                .containsExactly("blob");
    }

    @Test
    public void testDeleteLeavesAMarkerOverTheHistory() {
        enableVersioning();
        String first = put("blob", FIRST);

        var deleted = client.deleteObject(
                b -> b.bucket(containerName).key("blob"));
        assertThat(deleted.deleteMarker()).isTrue();
        assertThat(deleted.versionId()).isNotNull().isNotEqualTo(first);

        // Gone as far as an ordinary read is concerned...
        assertThatThrownBy(() -> get("blob"))
                .isInstanceOf(NoSuchKeyException.class);
        assertThat(client.listObjectsV2(b -> b.bucket(containerName))
                .contents()).isEmpty();
        // ...while the version it hid is still there to be read.
        assertThat(get("blob", first)).isEqualTo(FIRST);

        var listing = client.listObjectVersions(b -> b.bucket(containerName));
        assertThat(listing.deleteMarkers()).hasSize(1);
        assertThat(listing.deleteMarkers().get(0).versionId())
                .isEqualTo(deleted.versionId());
        assertThat(listing.deleteMarkers().get(0).isLatest()).isTrue();
        assertThat(listing.versions()).hasSize(1);
        assertThat(listing.versions().get(0).isLatest()).isFalse();
    }

    @Test
    public void testDeletingTheMarkerBringsTheObjectBack() {
        enableVersioning();
        put("blob", FIRST);
        String markerId = client.deleteObject(
                b -> b.bucket(containerName).key("blob")).versionId();

        client.deleteObject(b -> b.bucket(containerName).key("blob")
                .versionId(markerId));

        assertThat(get("blob")).isEqualTo(FIRST);
        assertThat(client.listObjectVersions(b -> b.bucket(containerName))
                .deleteMarkers()).isEmpty();
    }

    /** Reading a delete marker by id is refused rather than answered. */
    @Test
    public void testReadingADeleteMarkerIsRefused() {
        enableVersioning();
        put("blob", FIRST);
        String markerId = client.deleteObject(
                b -> b.bucket(containerName).key("blob")).versionId();

        assertThatThrownBy(() -> get("blob", markerId))
                .isInstanceOf(S3Exception.class)
                .satisfies(thrown -> assertThat(
                        ((S3Exception) thrown).statusCode()).isEqualTo(405));
    }

    @Test
    public void testDeletingAVersionRemovesItsData() {
        enableVersioning();
        String first = put("blob", FIRST);
        put("blob", SECOND);

        client.deleteObject(b -> b.bucket(containerName).key("blob")
                .versionId(first));

        assertThat(get("blob")).isEqualTo(SECOND);
        assertThatThrownBy(() -> get("blob", first))
                .isInstanceOf(S3Exception.class)
                .satisfies(thrown -> assertThat(
                        ((S3Exception) thrown).awsErrorDetails().errorCode())
                        .isEqualTo("NoSuchVersion"));
        assertThat(client.listObjectVersions(b -> b.bucket(containerName))
                .versions()).hasSize(1);
    }

    /** Deleting the current version uncovers the one below it. */
    @Test
    public void testDeletingTheCurrentVersionUncoversTheOlder() {
        enableVersioning();
        String first = put("blob", FIRST);
        String second = put("blob", SECOND);

        client.deleteObject(b -> b.bucket(containerName).key("blob")
                .versionId(second));

        assertThat(get("blob")).isEqualTo(FIRST);
        var listing = client.listObjectVersions(b -> b.bucket(containerName));
        assertThat(listing.versions()).hasSize(1);
        assertThat(listing.versions().get(0).versionId()).isEqualTo(first);
        assertThat(listing.versions().get(0).isLatest()).isTrue();
    }

    /**
     * A suspended bucket mints the "null" version, of which S3 keeps one: the
     * versions written while it was enabled stay, the null one is replaced.
     * The write announces no version id -- there is no version to point the
     * caller at -- while the one it wrote stays addressable as "null".
     */
    @Test
    public void testSuspendedWritesReplaceTheNullVersion() {
        enableVersioning();
        String enabled = put("blob", FIRST);
        suspendVersioning();

        assertThat(put("blob", SECOND)).isNull();
        assertThat(put("blob", FIRST)).isNull();

        assertThat(get("blob")).isEqualTo(FIRST);
        assertThat(get("blob", "null")).isEqualTo(FIRST);
        var versions = client.listObjectVersions(
                b -> b.bucket(containerName)).versions();
        assertThat(versions.stream().map(v -> v.versionId()))
                .containsExactly("null", enabled);
    }

    @Test
    public void testCopyCanNameASourceVersion() {
        enableVersioning();
        String first = put("blob", FIRST);
        put("blob", SECOND);

        var copy = client.copyObject(b -> b
                .sourceBucket(containerName).sourceKey("blob")
                .sourceVersionId(first)
                .destinationBucket(containerName).destinationKey("copy"));
        assertThat(copy.copySourceVersionId()).isEqualTo(first);
        assertThat(get("copy")).isEqualTo(FIRST);

        // The restore idiom: copy an old version onto the key itself.
        var restore = client.copyObject(b -> b
                .sourceBucket(containerName).sourceKey("blob")
                .sourceVersionId(first)
                .destinationBucket(containerName).destinationKey("blob"));
        assertThat(restore.versionId()).isNotNull().isNotEqualTo(first);
        assertThat(get("blob")).isEqualTo(FIRST);
    }

    @Test
    public void testMultipartUploadIsVersioned() {
        enableVersioning();
        String single = put("blob", FIRST);

        String uploadId = client.createMultipartUpload(
                b -> b.bucket(containerName).key("blob")).uploadId();
        var part = client.uploadPart(b -> b.bucket(containerName).key("blob")
                .uploadId(uploadId).partNumber(1),
                RequestBody.fromBytes(SECOND));
        var completed = client.completeMultipartUpload(b -> b
                .bucket(containerName).key("blob").uploadId(uploadId)
                .multipartUpload(CompletedMultipartUpload.builder()
                        .parts(CompletedPart.builder().partNumber(1)
                                .eTag(part.eTag()).build())
                        .build()));

        assertThat(completed.versionId()).isNotNull().isNotEqualTo(single);
        assertThat(get("blob")).isEqualTo(SECOND);
        assertThat(get("blob", single)).isEqualTo(FIRST);
    }

    @Test
    public void testListVersionsPagesAndRollsUpPrefixes() {
        enableVersioning();
        List<String> ids = List.of(put("dir/blob", FIRST),
                put("dir/blob", SECOND), put("top", FIRST));

        var firstPage = client.listObjectVersions(b -> b
                .bucket(containerName).maxKeys(2));
        assertThat(firstPage.isTruncated()).isTrue();
        assertThat(firstPage.versions()).hasSize(2);
        assertThat(firstPage.nextKeyMarker()).isEqualTo("dir/blob");

        var secondPage = client.listObjectVersions(b -> b
                .bucket(containerName)
                .keyMarker(firstPage.nextKeyMarker())
                .versionIdMarker(firstPage.nextVersionIdMarker()));
        assertThat(secondPage.isTruncated()).isFalse();
        assertThat(secondPage.versions().stream().map(v -> v.key()))
                .containsExactly("top");
        assertThat(secondPage.versions().get(0).versionId())
                .isEqualTo(ids.get(2));

        var rolled = client.listObjectVersions(b -> b
                .bucket(containerName).delimiter("/"));
        assertThat(rolled.commonPrefixes().stream().map(p -> p.prefix()))
                .containsExactly("dir/");
        assertThat(rolled.versions().stream().map(v -> v.key()))
                .containsExactly("top");
    }

    /** Whether the ACL grants AllUsers READ, which is public-read. */
    private boolean isPublic(String key, @Nullable String versionId) {
        return client.getObjectAcl(b -> b.bucket(containerName).key(key)
                        .versionId(versionId)).grants().stream()
                .anyMatch(grant -> grant.permission() == Permission.READ &&
                        grant.grantee().type() == Type.GROUP);
    }

    /** An ACL belongs to one version, not to the key. */
    @Test
    public void testAclAppliesToOneVersion() {
        enableVersioning();
        String first = put("blob", FIRST);
        String second = put("blob", SECOND);

        client.putObjectAcl(b -> b.bucket(containerName).key("blob")
                .versionId(first).acl("public-read"));

        assertThat(isPublic("blob", first)).isTrue();
        assertThat(isPublic("blob", second)).isFalse();
        // naming no version reads and writes the current one
        assertThat(isPublic("blob", null)).isFalse();

        client.putObjectAcl(b -> b.bucket(containerName).key("blob")
                .acl("public-read"));
        assertThat(isPublic("blob", null)).isTrue();
        assertThat(isPublic("blob", second)).isTrue();
    }

    @Test
    public void testAclOfAVersionThatDoesNotExistIsRefused() {
        enableVersioning();
        put("blob", FIRST);
        // A well-formed id that names nothing: mint one, then delete it.
        // A fabricated string would test the store's id syntax instead --
        // S3 answers those InvalidArgument, not NoSuchVersion.
        String gone = put("blob", SECOND);
        client.deleteObject(b -> b.bucket(containerName).key("blob")
                .versionId(gone));

        assertThatThrownBy(() -> client.getObjectAcl(b ->
                b.bucket(containerName).key("blob").versionId(gone)))
                .isInstanceOf(S3Exception.class)
                .satisfies(thrown -> assertThat(
                        ((S3Exception) thrown).awsErrorDetails().errorCode())
                        .isEqualTo("NoSuchVersion"));
    }

    /** Versions and markers keep a bucket from being deleted, as on S3. */
    @Test
    public void testVersionsKeepTheBucketAlive() {
        enableVersioning();
        put("blob", FIRST);
        client.deleteObject(b -> b.bucket(containerName).key("blob"));

        assertThatThrownBy(() -> client.deleteBucket(
                b -> b.bucket(containerName)))
                .isInstanceOf(S3Exception.class)
                .satisfies(thrown -> assertThat(
                        ((S3Exception) thrown).awsErrorDetails().errorCode())
                        .isEqualTo("BucketNotEmpty"));
    }
}
