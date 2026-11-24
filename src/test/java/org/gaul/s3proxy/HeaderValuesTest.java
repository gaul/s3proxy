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

import org.junit.jupiter.api.Test;

import software.amazon.awssdk.awscore.exception.AwsServiceException;

/**
 * Every expected value here is what AWS sent back for the same input,
 * measured 2026-11-24: user metadata stored through POST Object and read
 * back, response-* overrides on a presigned GET, and system headers stored
 * through POST Object.
 */
public final class HeaderValuesTest {
    @Test
    public void testUserMetadataAsAwsEncodesIt() {
        assertThat(HeaderValues.userMetadata("plain value"))
                .isEqualTo("plain value");
        assertThat(HeaderValues.userMetadata("a b\u007f"))
                .isEqualTo("=?UTF-8?Q?a_b=7F?=");
        assertThat(HeaderValues.userMetadata("a=b?c_d\u007f"))
                .isEqualTo("=?UTF-8?Q?a=3Db=3Fc=5Fd=7F?=");
        assertThat(HeaderValues.userMetadata("café"))
                .isEqualTo("=?UTF-8?Q?caf=C3=A9?=");
        assertThat(HeaderValues.userMetadata("aǇb"))
                .isEqualTo("=?UTF-8?Q?a=C7=87b?=");
        assertThat(HeaderValues.userMetadata("a\u0001b"))
                .isEqualTo("=?UTF-8?Q?a=01b?=");
        assertThat(HeaderValues.userMetadata("a\nb\u007f"))
                .isEqualTo("=?UTF-8?Q?a=0Ab=7F?=");
        // what a Latin-1 reading of the UTF-8 bytes of "café" becomes
        assertThat(HeaderValues.userMetadata("cafÃ©"))
                .isEqualTo("=?UTF-8?Q?caf=C3=83=C2=A9?=");
    }

    @Test
    public void testUserMetadataNeedingNoEncoding() {
        assertThat(HeaderValues.userMetadata("a\tb")).isEqualTo("a\tb");
        assertThat(HeaderValues.userMetadata("a\nb")).isEqualTo("a b");
        assertThat(HeaderValues.userMetadata("a\rb")).isEqualTo("a b");
    }

    /** Base64 once such characters are at least half of the value. */
    @Test
    public void testUserMetadataMostlyNonAsciiIsBase64() {
        assertThat(HeaderValues.userMetadata("ǇǇa"))
                .isEqualTo("=?UTF-8?B?x4fHh2E=?=");
        assertThat(HeaderValues.userMetadata("日本語"))
                .isEqualTo("=?UTF-8?B?5pel5pys6Kqe?=");
    }

    /** A value too long for one word is halved until its words fit. */
    @Test
    public void testUserMetadataSplitsIntoWords() {
        assertThat(HeaderValues.userMetadata("\u007f" + "x".repeat(100)))
                .isEqualTo("=?UTF-8?Q?=7F" + "x".repeat(49) +
                        "?= =?UTF-8?Q?" + "x".repeat(51) + "?=");
        String half = "w6nDqcOpw6nDqcOpw6nDqcOpw6nDqcOpw6nDqcOpw6nDqcOpw6nDqQ==";
        assertThat(HeaderValues.userMetadata("é".repeat(40)))
                .isEqualTo("=?UTF-8?B?" + half + "?= =?UTF-8?B?" + half +
                        "?=");
    }

    @Test
    public void testOverrideSpacesControls() {
        assertThat(HeaderValues.override("max-age=60"))
                .isEqualTo("max-age=60");
        assertThat(HeaderValues.override("a\u007fb")).isEqualTo("a b");
        assertThat(HeaderValues.override("a\u0001b")).isEqualTo("a b");
        assertThat(HeaderValues.override("a\nb")).isEqualTo("a b");
        assertThat(HeaderValues.override("a\r\nInjected: yes"))
                .isEqualTo("a  Injected: yes");
        assertThat(HeaderValues.override("a\tb")).isEqualTo("a\tb");
        assertThat(HeaderValues.override("café")).isEqualTo("café");
        // response-expires is any string, a date or not
        assertThat(HeaderValues.override("soon")).isEqualTo("soon");
    }

    @Test
    public void testOverrideBeyondLatin1IsRefused() {
        assertThatThrownBy(() -> HeaderValues.override("aǇb"))
                .isInstanceOfSatisfying(AwsServiceException.class, e -> {
                    assertThat(e.statusCode()).isEqualTo(400);
                    assertThat(e.awsErrorDetails().errorCode())
                            .isEqualTo("InvalidArgument");
                    assertThat(e.awsErrorDetails().errorMessage())
                            .isEqualTo("Header value cannot be represented" +
                                    " using ISO-8859-1.");
                });
    }

    @Test
    public void testStoredSystemHeader() {
        assertThat(HeaderValues.stored("café")).isEqualTo("café");
        assertThat(HeaderValues.stored("aǇb")).isEqualTo("a?b");
        assertThat(HeaderValues.stored("text/a\u007fb")).isEqualTo("text/a b");
        assertThat(HeaderValues.stored("a\tb")).isEqualTo("a\tb");
    }
}
