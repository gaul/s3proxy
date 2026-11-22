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

package org.gaul.s3proxy.azureblob;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;

import java.net.URI;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import com.google.common.base.Suppliers;

import org.gaul.s3proxy.blobstore.Credentials;
import org.junit.jupiter.api.Test;

import reactor.core.publisher.Mono;

/**
 * With no endpoint configured the store reaches the public cloud's for the
 * storage account its identity names, and where the identity names none it
 * says which setting is missing.  Issue #469.
 */
public final class AzureEndpointTest {
    private static final String KEY = Base64.getEncoder().encodeToString(
            new byte[32]);

    @Test
    public void testConfiguredEndpointIsKept() {
        assertThat(AzureBlobStore.resolveEndpoint(
                "http://127.0.0.1:10000/devstoreaccount1",
                new Credentials("account", KEY)))
                .isEqualTo("http://127.0.0.1:10000/devstoreaccount1");
    }

    @Test
    public void testEndpointDerivedFromTheAccount() {
        for (String endpoint : new String[] {"", null}) {
            assertThat(AzureBlobStore.resolveEndpoint(endpoint,
                    new Credentials("account1", KEY)))
                    .isEqualTo("https://account1.blob.core.windows.net");
        }
    }

    /** A shared access signature may come with the account it is for. */
    @Test
    public void testEndpointDerivedBesideASessionToken() {
        assertThat(AzureBlobStore.resolveEndpoint("",
                new Credentials("account1", "", "sv=2026-02-06&sig=x")))
                .isEqualTo("https://account1.blob.core.windows.net");
    }

    @Test
    public void testNoEndpointAndNoAccountIsRefusedByName() {
        // absent, a client id, a name Azure would not allow
        for (String identity : List.of("",
                "8f0c2b0e-1d1f-4c59-9d0a-1f2e3d4c5b6a", "Account", "ab",
                "account.example.com")) {
            assertThatThrownBy(() -> AzureBlobStore.resolveEndpoint("",
                    new Credentials(identity, KEY)))
                    .as(identity)
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("jclouds.endpoint");
        }
    }

    /** The store built without an endpoint sends its requests there. */
    @Test
    public void testRequestsGoToTheDerivedEndpoint() {
        List<String> urls = Collections.synchronizedList(
                new ArrayList<String>());
        var store = new AzureBlobStore(
                Suppliers.ofInstance(new Credentials("account1", KEY)),
                /*endpointUrl=*/ "", /*eTagMode=*/ "opaque", /*auth=*/ null,
                /*versioning=*/ false, request -> {
                    urls.add(request.getUrl().toString());
                    return Mono.error(new IllegalStateException("seen"));
                });

        assertThat(catchThrowable(store::list)).isNotNull();

        assertThat(urls).isNotEmpty().allSatisfy(url -> {
            var uri = URI.create(url);
            assertThat(uri.getScheme()).isEqualTo("https");
            assertThat(uri.getHost()).isEqualTo(
                    "account1.blob.core.windows.net");
        });
    }

    @Test
    public void testStoreWithoutEndpointOrAccountIsRefused() {
        assertThatThrownBy(() -> new AzureBlobStore(
                Suppliers.ofInstance(new Credentials("", "", "token")),
                /*endpointUrl=*/ "", /*eTagMode=*/ "opaque",
                /*auth=*/ "bearer"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("jclouds.endpoint");
    }
}
