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

import software.amazon.awssdk.awscore.exception.AwsServiceException;

/**
 * What the parser fuzz targets hold a parser to: it may refuse its input
 * only with an exception the handler answers as a client error, since any
 * other is a 500.
 */
final class FuzzOracles {
    private FuzzOracles() { }

    /** Whether the handler answers this exception as the client's fault. */
    static boolean isClientError(Throwable t) {
        return t instanceof IllegalArgumentException ||
                t instanceof IllegalStateException ||
                t instanceof UnsupportedOperationException ||
                (t instanceof AwsServiceException ase &&
                        ase.statusCode() < 500);
    }

    static void refusedAsClientError(Runnable parse) {
        try {
            parse.run();
        } catch (RuntimeException re) {
            if (!isClientError(re)) {
                throw re;
            }
        }
    }
}
