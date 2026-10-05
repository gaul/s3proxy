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

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;

import org.gaul.s3proxy.S3ProxyException;
import org.junit.jupiter.api.Test;

public final class SessionTest {
    private static final String POLICY = """
            {"Statement": [
             {"Effect": "Allow", "Action": "s3:PutObject",
              "Resource": "arn:aws:s3:::b/home/alice/*"},
             {"Effect": "Deny", "Action": "s3:PutObject",
              "Resource": "arn:aws:s3:::b/home/alice/readonly/*"}]}""";

    private final Session session = new Session(new SessionToken("parent",
            "ASIAEXAMPLE", Instant.MAX, "n", POLICY),
            SessionPolicy.parse(POLICY));

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
}
