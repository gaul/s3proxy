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

import java.time.Instant;
import java.util.Date;
import java.util.Locale;

import org.junit.jupiter.api.Test;

/**
 * The dates s3proxy sends Swift for If-Modified-Since and If-Unmodified-Since
 * have to satisfy the HTTP grammar, not merely RFC 1123: a server holding to
 * the fixed-width form takes anything else as no header at all and answers
 * unconditionally.  That failure hides for three weeks of every month.
 */
public final class HttpDateTest {
    /** The first nine of each month are where the two forms differ. */
    @Test
    public void testSingleDigitDayIsPadded() {
        assertThat(format("2026-08-01T07:05:11Z"))
                .isEqualTo("Sat, 01 Aug 2026 07:05:11 GMT");
        assertThat(format("2026-08-09T23:59:59Z"))
                .isEqualTo("Sun, 09 Aug 2026 23:59:59 GMT");
    }

    @Test
    public void testTwoDigitDayIsUnchanged() {
        assertThat(format("2026-07-31T23:12:00Z"))
                .isEqualTo("Fri, 31 Jul 2026 23:12:00 GMT");
        assertThat(format("2026-08-10T00:00:00Z"))
                .isEqualTo("Mon, 10 Aug 2026 00:00:00 GMT");
    }

    /** Every day of a month, so no single one can regress unnoticed. */
    @Test
    public void testEveryDayIsFixedWidth() {
        for (int day = 1; day <= 31; ++day) {
            String date = format("2026-01-%02dT12:00:00Z".formatted(day));
            assertThat(date).matches(
                    "[A-Z][a-z]{2}, \\d{2} [A-Z][a-z]{2} \\d{4}" +
                    " \\d{2}:\\d{2}:\\d{2} GMT");
        }
    }

    /**
     * The names are the header's own, not the server's: a JVM defaulting to
     * another language must not spell them in it.
     */
    @Test
    public void testNamesStayEnglishUnderAnotherLocale() {
        Locale previous = Locale.getDefault();
        try {
            Locale.setDefault(Locale.forLanguageTag("fr-FR"));
            assertThat(format("2026-08-01T07:05:11Z"))
                    .isEqualTo("Sat, 01 Aug 2026 07:05:11 GMT");
        } finally {
            Locale.setDefault(previous);
        }
    }

    /** The zone is named GMT and the time is in it, whatever the JVM's is. */
    @Test
    public void testRendersInUtc() {
        assertThat(format("2026-08-01T00:30:00Z"))
                .isEqualTo("Sat, 01 Aug 2026 00:30:00 GMT");
    }

    private static String format(String instant) {
        return OpenStackSwiftBlobStore.toHttpDate(
                Date.from(Instant.parse(instant)));
    }
}
