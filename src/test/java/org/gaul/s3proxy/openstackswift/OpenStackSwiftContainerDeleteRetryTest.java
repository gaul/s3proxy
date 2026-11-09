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

package org.gaul.s3proxy.openstackswift;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.concurrent.atomic.AtomicInteger;

import org.gaul.s3proxy.blobstore.S3Exceptions;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.S3Exception;

public final class OpenStackSwiftContainerDeleteRetryTest {

    @Test
    public void testRetriesBucketNotEmptyAndSucceeds() {
        var attempts = new AtomicInteger();

        OpenStackSwiftBlobStore.deleteContainerWithRetries(() -> {
            if (attempts.incrementAndGet() < 3) {
                throw S3Exceptions.bucketNotEmpty("container");
            }
        });

        assertThat(attempts).hasValue(3);
    }

    @Test
    public void testDoesNotRetryOtherErrors() {
        var attempts = new AtomicInteger();
        var failure = S3Exception.builder()
                .message("temporary service failure")
                .statusCode(503)
                .build();

        assertThatThrownBy(() ->
                OpenStackSwiftBlobStore.deleteContainerWithRetries(() -> {
                    attempts.incrementAndGet();
                    throw failure;
                })).isSameAs(failure);

        assertThat(attempts).hasValue(1);
    }

    @Test
    public void testBoundsRetriesWhenContainerRemainsNonEmpty() {
        var attempts = new AtomicInteger();

        assertThatThrownBy(() ->
                OpenStackSwiftBlobStore.deleteContainerWithRetries(() -> {
                    attempts.incrementAndGet();
                    throw S3Exceptions.bucketNotEmpty("container");
                }))
                .isInstanceOf(S3Exception.class)
                .hasMessageContaining("container is not empty");

        assertThat(attempts).hasValue(6);
    }
}
