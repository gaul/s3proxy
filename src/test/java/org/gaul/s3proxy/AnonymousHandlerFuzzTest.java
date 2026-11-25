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

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;

/**
 * Whole requests to a proxy that authenticates nothing; see
 * {@link HandlerFuzzTest} for what the requests are and what is checked.
 */
@Tag("fuzz")
public final class AnonymousHandlerFuzzTest {
    private static HandlerFuzzTest.Target target;

    @BeforeAll
    static void setUp() throws Exception {
        target = HandlerFuzzTest.Target.start(/*signs=*/ false);
    }

    @AfterAll
    static void tearDown() throws Exception {
        if (target != null) {
            target.stop();
        }
    }

    @FuzzTest
    void anonymousRequest(FuzzedDataProvider data) throws Exception {
        target.exchange(data);
    }
}
