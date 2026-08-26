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
import java.util.List;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.Constants;
import org.gaul.s3proxy.blobstore.ForwardingBlobStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.model.GetBucketAclRequest;
import software.amazon.awssdk.services.s3.model.GetBucketAclResponse;
import software.amazon.awssdk.services.s3.model.GetObjectAclRequest;
import software.amazon.awssdk.services.s3.model.GetObjectAclResponse;
import software.amazon.awssdk.services.s3.model.Grant;
import software.amazon.awssdk.services.s3.model.Grantee;
import software.amazon.awssdk.services.s3.model.ObjectCannedACL;
import software.amazon.awssdk.services.s3.model.Owner;
import software.amazon.awssdk.services.s3.model.Permission;
import software.amazon.awssdk.services.s3.model.Type;

/**
 * A store that keeps real grants has them relayed to the caller, instead of
 * S3Proxy answering with a policy of its own making.  Everything asserted
 * here is beyond what a canned name can say -- another account's id, a
 * grant of READ_ACP -- so a synthesized answer cannot pass by accident.
 */
public final class AccessControlPolicyRelayTest {
    private static final Owner OTHER_OWNER = Owner.builder()
            .id("d34db33f")
            .displayName("someone-else@example.com")
            .build();
    private static final Grant EVERYONE_READS = Grant.builder()
            .grantee(Grantee.builder()
                    .type(Type.GROUP)
                    .uri(Constants.ALL_USERS_URI)
                    .build())
            .permission(Permission.READ)
            .build();
    private static final List<Grant> OTHER_GRANTS = List.of(
            EVERYONE_READS,
            Grant.builder()
                    .grantee(Grantee.builder()
                            .type(Type.CANONICAL_USER)
                            .id("cafebabe")
                            .displayName("auditor@example.com")
                            .build())
                    .permission(Permission.READ_ACP)
                    .build());
    /**
     * The same policy said in a way a canned name can express, so that
     * writing it back has somewhere to land.  Its owner is still not the one
     * S3Proxy invents, which is the whole point of reading it back.
     */
    private static final String ROUND_TRIP_KEY = "round-trip";
    private static final List<Grant> ROUND_TRIP_GRANTS = List.of(
            EVERYONE_READS,
            Grant.builder()
                    .grantee(Grantee.builder()
                            .type(Type.CANONICAL_USER)
                            .id(OTHER_OWNER.id())
                            .displayName(OTHER_OWNER.displayName())
                            .build())
                    .permission(Permission.FULL_CONTROL)
                    .build());

    private BlobStore blobStore;
    private S3Proxy s3Proxy;
    private S3Client client;
    private String containerName;

    @BeforeEach
    public void setUp() throws Exception {
        blobStore = TestUtils.createTransientBlobStore();
        containerName = TestUtils.createRandomContainerName();
        blobStore.createContainer(containerName);

        // Stand in for a backend whose policies S3Proxy did not invent.
        BlobStore withPolicies = new ForwardingBlobStore(blobStore) {
            @Override
            public GetObjectAclResponse getBlobAcl(
                    GetObjectAclRequest request) {
                return GetObjectAclResponse.builder()
                        .owner(OTHER_OWNER)
                        .grants(ROUND_TRIP_KEY.equals(request.key()) ?
                                ROUND_TRIP_GRANTS : OTHER_GRANTS)
                        .build();
            }

            @Override
            public GetBucketAclResponse getContainerAcl(
                    GetBucketAclRequest request) {
                return GetBucketAclResponse.builder()
                        .owner(OTHER_OWNER)
                        .grants(OTHER_GRANTS)
                        .build();
            }
        };

        // Behind a plain middleware, which has to pass the policy along
        // rather than answering from the canned access underneath it.
        BlobStore wrapped = new ForwardingBlobStore(withPolicies) { };

        s3Proxy = S3Proxy.builder()
                .stopTimeout(0)
                .endpoint(URI.create("http://127.0.0.1:0"))
                .blobStore(wrapped)
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

    @Test
    public void testObjectAclRelaysWhatTheStoreHolds() throws Exception {
        String blobName = "blob-name";
        client.putObject(b -> b.bucket(containerName).key(blobName),
                RequestBody.fromString("content"));

        GetObjectAclResponse acl = client.getObjectAcl(
                b -> b.bucket(containerName).key(blobName));
        assertPolicyRelayed(acl.owner(), acl.grants());
    }

    @Test
    public void testRelayedPolicyCanBeWrittenBack() throws Exception {
        // Reading a policy and putting it back unchanged is how a client
        // adds one grant to an object, so a policy S3Proxy hands out has to
        // be one it will take -- the owner in it belongs to the store, not
        // to S3Proxy, and pinning that name would refuse the write.
        client.putObject(b -> b.bucket(containerName).key(ROUND_TRIP_KEY),
                RequestBody.fromString("content"));

        GetObjectAclResponse acl = client.getObjectAcl(
                b -> b.bucket(containerName).key(ROUND_TRIP_KEY));
        assertThat(acl.owner().id()).isNotEqualTo(Constants.OWNER_ID);

        client.putObjectAcl(b -> b.bucket(containerName).key(ROUND_TRIP_KEY)
                .accessControlPolicy(p -> p.owner(acl.owner())
                        .grants(acl.grants())));

        // The public read it names is what the store was left holding.
        assertThat(blobStore.getBlobAccess(containerName, ROUND_TRIP_KEY))
                .isEqualTo(ObjectCannedACL.PUBLIC_READ);
    }

    @Test
    public void testBucketAclRelaysWhatTheStoreHolds() throws Exception {
        GetBucketAclResponse acl = client.getBucketAcl(
                b -> b.bucket(containerName));
        assertPolicyRelayed(acl.owner(), acl.grants());
    }

    private static void assertPolicyRelayed(Owner owner, List<Grant> grants) {
        assertThat(owner.id()).isEqualTo(OTHER_OWNER.id());
        assertThat(owner.displayName()).isEqualTo(OTHER_OWNER.displayName());
        assertThat(owner.id()).isNotEqualTo(Constants.OWNER_ID);

        assertThat(grants).hasSize(2);

        Grantee everyone = grants.get(0).grantee();
        assertThat(everyone.type()).isEqualTo(Type.GROUP);
        assertThat(everyone.uri()).isEqualTo(Constants.ALL_USERS_URI);
        assertThat(grants.get(0).permission()).isEqualTo(Permission.READ);

        // The grant no canned name can express, and whose grantee is nobody
        // S3Proxy would have named by itself.
        Grantee auditor = grants.get(1).grantee();
        assertThat(auditor.type()).isEqualTo(Type.CANONICAL_USER);
        assertThat(auditor.id()).isEqualTo("cafebabe");
        assertThat(auditor.displayName()).isEqualTo("auditor@example.com");
        assertThat(grants.get(1).permission()).isEqualTo(Permission.READ_ACP);
    }
}
