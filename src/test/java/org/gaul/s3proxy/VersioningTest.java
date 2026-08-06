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

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import org.assertj.core.api.Fail;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.model.BucketVersioningStatus;
import software.amazon.awssdk.services.s3.model.DeleteMarkerEntry;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.s3.model.ObjectIdentifier;
import software.amazon.awssdk.services.s3.model.ObjectVersion;
import software.amazon.awssdk.services.s3.model.S3Exception;

/**
 * Exercises the versioning API end-to-end against a versioned in-memory
 * store: bucket versioning configuration, versioned reads and deletes,
 * delete markers, version listing, and versioned copies.
 */
public final class VersioningTest {
    private BlobStore blobStore;
    private S3Proxy s3Proxy;
    private S3Client client;
    private String containerName;

    @BeforeEach
    public void setUp() throws Exception {
        blobStore = new InMemoryVersionedBlobStore();
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

    @AfterEach
    public void tearDown() throws Exception {
        if (client != null) {
            client.close();
        }
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
        if (blobStore != null) {
            blobStore.close();
        }
    }

    private void enableVersioning() {
        client.putBucketVersioning(b -> b.bucket(containerName)
                .versioningConfiguration(v -> v.status(
                        BucketVersioningStatus.ENABLED)));
    }

    @Test
    public void testGetBucketVersioning() throws Exception {
        // never versioned: no status at all
        var response = client.getBucketVersioning(
                b -> b.bucket(containerName));
        assertThat(response.status()).isNull();

        enableVersioning();
        response = client.getBucketVersioning(b -> b.bucket(containerName));
        assertThat(response.status()).isEqualTo(
                BucketVersioningStatus.ENABLED);

        client.putBucketVersioning(b -> b.bucket(containerName)
                .versioningConfiguration(v -> v.status(
                        BucketVersioningStatus.SUSPENDED)));
        response = client.getBucketVersioning(b -> b.bucket(containerName));
        assertThat(response.status()).isEqualTo(
                BucketVersioningStatus.SUSPENDED);
    }

    @Test
    public void testPutReturnsVersionAndGetByVersion() throws Exception {
        enableVersioning();
        var key = "key";

        var put1 = client.putObject(b -> b.bucket(containerName).key(key),
                RequestBody.fromString("one"));
        var put2 = client.putObject(b -> b.bucket(containerName).key(key),
                RequestBody.fromString("two"));
        assertThat(put1.versionId()).isNotNull();
        assertThat(put2.versionId()).isNotNull();
        assertThat(put1.versionId()).isNotEqualTo(put2.versionId());

        // the current object is the second write
        var current = client.getObject(b -> b.bucket(containerName).key(key));
        assertThat(new String(current.readAllBytes())).isEqualTo("two");
        assertThat(current.response().versionId()).isEqualTo(
                put2.versionId());

        // each version remains readable by its id
        var first = client.getObject(b -> b.bucket(containerName).key(key)
                .versionId(put1.versionId()));
        assertThat(new String(first.readAllBytes())).isEqualTo("one");
        assertThat(first.response().versionId()).isEqualTo(put1.versionId());

        var head = client.headObject(b -> b.bucket(containerName).key(key)
                .versionId(put1.versionId()));
        assertThat(head.versionId()).isEqualTo(put1.versionId());
        assertThat(head.contentLength()).isEqualTo(3);
    }

    @Test
    public void testGetNoSuchVersion() throws Exception {
        enableVersioning();
        var key = "key";
        client.putObject(b -> b.bucket(containerName).key(key),
                RequestBody.fromString("one"));

        try {
            client.getObject(b -> b.bucket(containerName).key(key)
                    .versionId("v9999999999999999"));
            Fail.failBecauseExceptionWasNotThrown(S3Exception.class);
        } catch (S3Exception e) {
            assertThat(e.statusCode()).isEqualTo(404);
            assertThat(e.awsErrorDetails().errorCode()).isEqualTo(
                    "NoSuchVersion");
        }
    }

    @Test
    public void testDeleteCreatesMarkerAndVersionedDeleteRestores()
            throws Exception {
        enableVersioning();
        var key = "key";
        var put = client.putObject(b -> b.bucket(containerName).key(key),
                RequestBody.fromString("one"));

        // an unversioned delete hides the object behind a marker
        var delete = client.deleteObject(b -> b.bucket(containerName)
                .key(key));
        assertThat(delete.deleteMarker()).isTrue();
        String markerVersionId = delete.versionId();
        assertThat(markerVersionId).isNotNull();

        try {
            client.getObject(b -> b.bucket(containerName).key(key));
            Fail.failBecauseExceptionWasNotThrown(NoSuchKeyException.class);
        } catch (NoSuchKeyException e) {
            // the 404 says it hit a delete marker, not a missing key
            assertThat(e.awsErrorDetails().sdkHttpResponse()
                    .firstMatchingHeader("x-amz-delete-marker"))
                    .contains("true");
            assertThat(e.awsErrorDetails().sdkHttpResponse()
                    .firstMatchingHeader("x-amz-version-id"))
                    .contains(markerVersionId);
        }

        // the data version is still readable by its id
        var blob = client.getObject(b -> b.bucket(containerName).key(key)
                .versionId(put.versionId()));
        assertThat(new String(blob.readAllBytes())).isEqualTo("one");

        // reading the marker itself is refused
        try {
            client.getObject(b -> b.bucket(containerName).key(key)
                    .versionId(markerVersionId));
            Fail.failBecauseExceptionWasNotThrown(S3Exception.class);
        } catch (S3Exception e) {
            assertThat(e.statusCode()).isEqualTo(405);
            assertThat(e.awsErrorDetails().sdkHttpResponse()
                    .firstMatchingHeader("x-amz-delete-marker"))
                    .contains("true");
        }

        // deleting the marker restores the object
        var undelete = client.deleteObject(b -> b.bucket(containerName)
                .key(key).versionId(markerVersionId));
        assertThat(undelete.deleteMarker()).isTrue();
        var restored = client.getObject(b -> b.bucket(containerName)
                .key(key));
        assertThat(new String(restored.readAllBytes())).isEqualTo("one");

        // deleting the data version by id removes it for good
        var remove = client.deleteObject(b -> b.bucket(containerName)
                .key(key).versionId(put.versionId()));
        assertThat(remove.versionId()).isEqualTo(put.versionId());
        try {
            client.getObject(b -> b.bucket(containerName).key(key));
            Fail.failBecauseExceptionWasNotThrown(NoSuchKeyException.class);
        } catch (NoSuchKeyException e) {
            assertThat(e.awsErrorDetails().sdkHttpResponse()
                    .firstMatchingHeader("x-amz-delete-marker"))
                    .contains("false");
        }
    }

    @Test
    public void testListObjectVersions() throws Exception {
        enableVersioning();
        var put1 = client.putObject(b -> b.bucket(containerName).key("a"),
                RequestBody.fromString("one"));
        var put2 = client.putObject(b -> b.bucket(containerName).key("a"),
                RequestBody.fromString("two"));
        client.putObject(b -> b.bucket(containerName).key("b"),
                RequestBody.fromString("three"));
        client.deleteObject(b -> b.bucket(containerName).key("b"));

        var response = client.listObjectVersions(
                b -> b.bucket(containerName));
        List<ObjectVersion> versions = response.versions();
        List<DeleteMarkerEntry> markers = response.deleteMarkers();

        assertThat(versions).hasSize(3);
        // key "a": newest first
        assertThat(versions.get(0).key()).isEqualTo("a");
        assertThat(versions.get(0).versionId()).isEqualTo(put2.versionId());
        assertThat(versions.get(0).isLatest()).isTrue();
        assertThat(versions.get(0).size()).isEqualTo(3);
        assertThat(versions.get(1).key()).isEqualTo("a");
        assertThat(versions.get(1).versionId()).isEqualTo(put1.versionId());
        assertThat(versions.get(1).isLatest()).isFalse();
        // key "b": the data version hides behind the marker
        assertThat(versions.get(2).key()).isEqualTo("b");
        assertThat(versions.get(2).isLatest()).isFalse();

        assertThat(markers).hasSize(1);
        assertThat(markers.get(0).key()).isEqualTo("b");
        assertThat(markers.get(0).isLatest()).isTrue();
    }

    @Test
    public void testListObjectVersionsPagination() throws Exception {
        enableVersioning();
        for (int i = 0; i < 3; i++) {
            client.putObject(b -> b.bucket(containerName).key("a"),
                    RequestBody.fromString("payload"));
            client.putObject(b -> b.bucket(containerName).key("b"),
                    RequestBody.fromString("payload"));
        }

        var collected = new ArrayList<String>();
        String keyMarker = null;
        String versionIdMarker = null;
        while (true) {
            final String finalKeyMarker = keyMarker;
            final String finalVersionIdMarker = versionIdMarker;
            var response = client.listObjectVersions(
                    b -> b.bucket(containerName).maxKeys(2)
                            .keyMarker(finalKeyMarker)
                            .versionIdMarker(finalVersionIdMarker));
            for (ObjectVersion version : response.versions()) {
                collected.add(version.key() + ":" + version.versionId());
            }
            if (!Boolean.TRUE.equals(response.isTruncated())) {
                break;
            }
            keyMarker = response.nextKeyMarker();
            versionIdMarker = response.nextVersionIdMarker();
        }

        assertThat(collected).hasSize(6);
        assertThat(collected).doesNotHaveDuplicates();
    }

    @Test
    public void testListObjectVersionsPrefixAndDelimiter() throws Exception {
        enableVersioning();
        client.putObject(b -> b.bucket(containerName).key("dir/a"),
                RequestBody.fromString("one"));
        client.putObject(b -> b.bucket(containerName).key("dir/b"),
                RequestBody.fromString("two"));
        client.putObject(b -> b.bucket(containerName).key("top"),
                RequestBody.fromString("three"));

        var response = client.listObjectVersions(
                b -> b.bucket(containerName).delimiter("/"));
        assertThat(response.versions()).hasSize(1);
        assertThat(response.versions().get(0).key()).isEqualTo("top");
        assertThat(response.commonPrefixes()).hasSize(1);
        assertThat(response.commonPrefixes().get(0).prefix()).isEqualTo(
                "dir/");

        response = client.listObjectVersions(
                b -> b.bucket(containerName).prefix("dir/"));
        assertThat(response.versions()).hasSize(2);
    }

    @Test
    public void testMultiObjectDeleteWithVersions() throws Exception {
        enableVersioning();
        var put1 = client.putObject(b -> b.bucket(containerName).key("a"),
                RequestBody.fromString("one"));
        client.putObject(b -> b.bucket(containerName).key("b"),
                RequestBody.fromString("two"));

        var response = client.deleteObjects(b -> b.bucket(containerName)
                .delete(d -> d.objects(
                        ObjectIdentifier.builder().key("a")
                                .versionId(put1.versionId()).build(),
                        ObjectIdentifier.builder().key("b").build())));

        assertThat(response.deleted()).hasSize(2);
        assertThat(response.errors()).isEmpty();
        for (var deleted : response.deleted()) {
            if (deleted.key().equals("a")) {
                // deleted the named version outright
                assertThat(deleted.versionId()).isEqualTo(put1.versionId());
                assertThat(deleted.deleteMarker()).isNull();
            } else {
                // hid the current object behind a new marker
                assertThat(deleted.key()).isEqualTo("b");
                assertThat(deleted.deleteMarker()).isTrue();
                assertThat(deleted.deleteMarkerVersionId()).isNotNull();
            }
        }

        // deleting a version that does not exist reports NoSuchVersion for
        // that key alone
        var errorResponse = client.deleteObjects(b -> b.bucket(containerName)
                .delete(d -> d.objects(
                        ObjectIdentifier.builder().key("a")
                                .versionId("v9999999999999999").build())));
        assertThat(errorResponse.errors()).hasSize(1);
        assertThat(errorResponse.errors().get(0).code()).isEqualTo(
                "NoSuchVersion");
    }

    @Test
    public void testCopyObjectSourceVersion() throws Exception {
        enableVersioning();
        var key = "source";
        var put1 = client.putObject(b -> b.bucket(containerName).key(key),
                RequestBody.fromString("one"));
        client.putObject(b -> b.bucket(containerName).key(key),
                RequestBody.fromString("two"));

        // copy the older version over the key itself, restoring it
        var copy = client.copyObject(b -> b
                .sourceBucket(containerName).sourceKey(key)
                .sourceVersionId(put1.versionId())
                .destinationBucket(containerName).destinationKey(key));
        assertThat(copy.copySourceVersionId()).isEqualTo(put1.versionId());
        assertThat(copy.versionId()).isNotNull();

        var restored = client.getObject(b -> b.bucket(containerName)
                .key(key));
        assertThat(new String(restored.readAllBytes())).isEqualTo("one");
    }

    @Test
    public void testSuspendedVersioning() throws Exception {
        enableVersioning();
        var key = "key";
        var put1 = client.putObject(b -> b.bucket(containerName).key(key),
                RequestBody.fromString("one"));

        client.putBucketVersioning(b -> b.bucket(containerName)
                .versioningConfiguration(v -> v.status(
                        BucketVersioningStatus.SUSPENDED)));

        // suspended writes mint the "null" version and replace each other
        var put2 = client.putObject(b -> b.bucket(containerName).key(key),
                RequestBody.fromString("two"));
        assertThat(put2.versionId()).isEqualTo("null");
        client.putObject(b -> b.bucket(containerName).key(key),
                RequestBody.fromString("three"));

        var response = client.listObjectVersions(
                b -> b.bucket(containerName));
        assertThat(response.versions()).hasSize(2);
        assertThat(response.versions().get(0).versionId()).isEqualTo("null");
        assertThat(response.versions().get(1).versionId()).isEqualTo(
                put1.versionId());

        // the enabled-era version is still readable
        var blob = client.getObject(b -> b.bucket(containerName).key(key)
                .versionId(put1.versionId()));
        assertThat(new String(blob.readAllBytes())).isEqualTo("one");

        // and the "null" version is addressable by that literal name
        var nullVersion = client.getObject(b -> b.bucket(containerName)
                .key(key).versionId("null"));
        assertThat(new String(nullVersion.readAllBytes())).isEqualTo("three");
    }
}
