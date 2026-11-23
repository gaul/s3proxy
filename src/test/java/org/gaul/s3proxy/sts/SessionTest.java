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

package org.gaul.s3proxy.sts;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.lang.reflect.Proxy;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;

import org.assertj.core.api.Assertions;
import org.gaul.s3proxy.AwsHttpHeaders;
import org.gaul.s3proxy.S3ErrorCode;
import org.gaul.s3proxy.S3Operation;
import org.gaul.s3proxy.S3ProxyException;
import org.junit.jupiter.api.Test;

public final class SessionTest {
    private static final String POLICY = """
            {"Statement": [
             {"Effect": "Allow", "Action": "s3:PutObject",
              "Resource": "arn:aws:s3:::b/home/alice/*"},
             {"Effect": "Deny", "Action": "s3:PutObject",
              "Resource": "arn:aws:s3:::b/home/alice/readonly/*"}]}""";

    private static final String READ_WRITE_DELETE_POLICY = """
            {"Statement": {"Effect": "Allow",
              "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
              "Resource": "arn:aws:s3:::b/home/alice/*"}}""";

    private static final String OBJECT_LOCK_POLICY = """
            {"Statement": [
             {"Effect": "Allow",
              "Action": ["s3:PutObject", "s3:DeleteObject",
                         "s3:GetObjectLegalHold", "s3:PutObjectLegalHold",
                         "s3:GetObjectRetention", "s3:PutObjectRetention",
                         "s3:BypassGovernanceRetention"],
              "Resource": "arn:aws:s3:::b/home/alice/*"},
             {"Effect": "Allow",
              "Action": ["s3:GetBucketOwnershipControls",
                         "s3:PutBucketOwnershipControls",
                         "s3:GetBucketPublicAccessBlock",
                         "s3:PutBucketPublicAccessBlock",
                         "s3:GetBucketObjectLockConfiguration",
                         "s3:PutBucketObjectLockConfiguration"],
              "Resource": "arn:aws:s3:::b"}]}""";

    private static final List<S3Operation> OBJECT_LOCK_AND_BUCKET_CONTROLS =
            List.of(
                    S3Operation.GET_OBJECT_LEGAL_HOLD,
                    S3Operation.PUT_OBJECT_LEGAL_HOLD,
                    S3Operation.GET_OBJECT_RETENTION,
                    S3Operation.PUT_OBJECT_RETENTION,
                    S3Operation.GET_OBJECT_LOCK_CONFIGURATION,
                    S3Operation.PUT_OBJECT_LOCK_CONFIGURATION,
                    S3Operation.GET_BUCKET_OWNERSHIP_CONTROLS,
                    S3Operation.PUT_BUCKET_OWNERSHIP_CONTROLS,
                    S3Operation.DELETE_BUCKET_OWNERSHIP_CONTROLS,
                    S3Operation.GET_PUBLIC_ACCESS_BLOCK,
                    S3Operation.PUT_PUBLIC_ACCESS_BLOCK,
                    S3Operation.DELETE_PUBLIC_ACCESS_BLOCK);

    private final Session session = session(POLICY);

    @Test
    public void testCanonicalKeysAllowed() {
        session.authorizeObject("s3:PutObject", "b", "home/alice/x");
        session.authorizeObject("s3:PutObject", "b", "home/alice/dir/");
        session.authorizeObject("s3:PutObject", "b", "home/alice/..x");
    }

    @Test
    public void testNonCanonicalKeysRefused() {
        for (String key : new String[] {
            // dodges the Deny by string, opens the denied file by path
            "home/alice//readonly/x",
            "home/alice/./readonly/x",
            "home/alice/../alice/readonly/x",
            "home/alice/..",
            "/home/alice/x",
        }) {
            assertThatThrownBy(() -> session.authorizeObject(
                    "s3:PutObject", "b", key))
                    .as(key)
                    .isInstanceOf(S3ProxyException.class)
                    .hasMessageContaining("path segments");
        }
    }

    @Test
    public void testObjectLockAndBucketControlsNeedTheirActions() {
        Session readWrite = session(READ_WRITE_DELETE_POLICY);
        Session objectLock = session(OBJECT_LOCK_POLICY);
        for (S3Operation operation : OBJECT_LOCK_AND_BUCKET_CONTROLS) {
            assertDenied(() -> readWrite.authorize(operation,
                    request(Map.of()), "b", "home/alice/a"));
            objectLock.authorize(operation, request(Map.of()), "b",
                    "home/alice/a");
        }
    }

    @Test
    public void testLockHeadersOnWriteNeedTheirActions() {
        Session readWrite = session(READ_WRITE_DELETE_POLICY);
        Session objectLock = session(OBJECT_LOCK_POLICY);
        for (Map<String, String> headers : List.of(
                Map.of(AwsHttpHeaders.OBJECT_LOCK_LEGAL_HOLD, "ON"),
                Map.of(AwsHttpHeaders.OBJECT_LOCK_MODE, "GOVERNANCE"),
                Map.of(AwsHttpHeaders.OBJECT_LOCK_RETAIN_UNTIL_DATE,
                        "2030-01-01T00:00:00Z"))) {
            for (S3Operation operation : List.of(S3Operation.PUT_OBJECT,
                    S3Operation.COPY_OBJECT,
                    S3Operation.CREATE_MULTIPART_UPLOAD)) {
                assertDenied(() -> readWrite.authorize(operation,
                        request(headers), "b", "home/alice/a"));
                objectLock.authorize(operation, request(headers), "b",
                        "home/alice/a");
            }
        }
    }

    @Test
    public void testBypassGovernanceNeedsItsAction() {
        Session readWrite = session(READ_WRITE_DELETE_POLICY);
        Session objectLock = session(OBJECT_LOCK_POLICY);
        var bypass = Map.of(AwsHttpHeaders.BYPASS_GOVERNANCE_RETENTION, "true");
        readWrite.authorize(S3Operation.DELETE_OBJECT, request(Map.of()), "b",
                "home/alice/a");
        for (S3Operation operation : List.of(S3Operation.DELETE_OBJECT,
                S3Operation.PUT_OBJECT_RETENTION)) {
            assertDenied(() -> readWrite.authorize(operation, request(bypass),
                    "b", "home/alice/a"));
            objectLock.authorize(operation, request(bypass), "b",
                    "home/alice/a");
        }
    }

    private static Session session(String policy) {
        return new Session(new SessionToken("parent", "ASIAEXAMPLE",
                Instant.MAX, "n", policy), SessionPolicy.parse(policy));
    }

    /** A request carrying these headers and no query parameters. */
    private static HttpServletRequest request(Map<String, String> headers) {
        return (HttpServletRequest) Proxy.newProxyInstance(
                SessionTest.class.getClassLoader(),
                new Class<?>[] {HttpServletRequest.class},
                (proxy, method, args) -> switch (method.getName()) {
                case "getHeader" -> headers.get((String) args[0]);
                case "getParameter" -> null;
                default -> throw new UnsupportedOperationException(
                        method.getName());
                });
    }

    private static void assertDenied(Runnable runnable) {
        S3ProxyException e = Assertions.catchThrowableOfType(
                S3ProxyException.class, runnable::run);
        assertThat(e).isNotNull();
        assertThat(e.getError()).isEqualTo(S3ErrorCode.ACCESS_DENIED);
    }
}
