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

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.List;

import org.junit.jupiter.api.Test;

public final class SessionTokenTest {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String SECRET = "parent-secret";

    @Test
    public void testRoundTrip() {
        var token = new SessionToken("parent", "ASIAEXAMPLE",
                Instant.ofEpochSecond(1_900_000_000L), "name", "{\"p\":1}");
        String encoded = token.encode(SECRET, RANDOM);
        assertThat(SessionToken.parentAccessKeyId(encoded))
                .isEqualTo("parent");
        assertThat(SessionToken.decode(encoded, SECRET)).isEqualTo(token);
        // the claims are encrypted, not merely signed
        assertThat(new String(Base64.getUrlDecoder().decode(encoded),
                StandardCharsets.ISO_8859_1))
                .doesNotContain("ASIAEXAMPLE").doesNotContain("{\"p\":1}");
        // two tokens for the same claims differ
        assertThat(token.encode(SECRET, RANDOM)).isNotEqualTo(encoded);
    }

    @Test
    public void testWrongSecret() {
        String encoded = sample().encode(SECRET, RANDOM);
        assertThatThrownBy(() -> SessionToken.decode(encoded, "other"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    public void testEveryByteIsAuthenticated() {
        byte[] bytes = Base64.getUrlDecoder().decode(
                sample().encode(SECRET, RANDOM));
        for (int i = 0; i < bytes.length; i++) {
            byte[] tampered = bytes.clone();
            tampered[i] ^= 1;
            String encoded = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(tampered);
            assertThatThrownBy(() -> SessionToken.decode(encoded, SECRET))
                    .as("byte %d", i)
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Test
    public void testParentIdCannotBeSwapped() {
        // the parent id is in the clear; rewriting it must break the tag
        // even where the attacker knows the other identity's name
        byte[] bytes = Base64.getUrlDecoder().decode(new SessionToken(
                "aaaa", "ASIAX", Instant.EPOCH, "n", "{}")
                .encode(SECRET, RANDOM));
        bytes[3] = 'b';
        String encoded = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(bytes);
        assertThat(SessionToken.parentAccessKeyId(encoded)).isEqualTo("baaa");
        assertThatThrownBy(() -> SessionToken.decode(encoded, SECRET))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    public void testMalformed() {
        for (String encoded : List.of("", "!!!", "AA", "AQAA", "AgABYQ",
                "AQABYQ", "AQAFYQ")) {
            assertThatThrownBy(() -> SessionToken.decode(encoded, SECRET))
                    .as(encoded)
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Test
    public void testSecretDerivation() {
        String secret = SessionToken.secretAccessKey("parent", "ASIAONE", SECRET);
        assertThat(secret).hasSize(40);
        assertThat(SessionToken.secretAccessKey("parent", "ASIAONE", SECRET))
                .isEqualTo(secret);
        assertThat(SessionToken.secretAccessKey("parent", "ASIATWO", SECRET))
                .isNotEqualTo(secret);
        assertThat(SessionToken.secretAccessKey("parent", "ASIAONE", "other"))
                .isNotEqualTo(secret);
        // the same secret under another identity derives another key
        assertThat(SessionToken.secretAccessKey("other", "ASIAONE", SECRET))
                .isNotEqualTo(secret);
    }

    @Test
    public void testAccessKeyId() {
        String id = SessionToken.newAccessKeyId(RANDOM);
        assertThat(id).matches("ASIA[A-Z2-7]{16}");
    }

    private static SessionToken sample() {
        return new SessionToken("parent", "ASIAEXAMPLE", Instant.EPOCH,
                "name", "{}");
    }
}
