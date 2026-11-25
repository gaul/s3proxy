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
 * What the parser fuzz targets hold a parser to: it may refuse its input only
 * with an exception that reaches the client as its fault, since any other is
 * a 500.  An IllegalArgumentException is one only from a parser whose callers
 * all catch it and answer with an S3 error; the Jetty handler answers any
 * that reaches it 500.
 */
final class FuzzOracles {
    private FuzzOracles() { }

    /**
     * Whether the handler answers this exception as the client's fault, or
     * as 501 NotImplemented, which is no fault at all.
     */
    static boolean isClientError(Throwable t) {
        return t instanceof UnsupportedOperationException ||
                (t instanceof AwsServiceException ase &&
                        ase.statusCode() < 500);
    }

    /** For a parser that refuses its input with an S3 error. */
    static void refusedAsClientError(Runnable parse) {
        try {
            parse.run();
        } catch (RuntimeException re) {
            if (!isClientError(re)) {
                throw re;
            }
        }
    }

    /**
     * For a parser that refuses its input with an IllegalArgumentException,
     * which every caller catches and answers with an S3 error.  An
     * IllegalStateException is no refusal: the callers let it through.
     */
    static void refusedWithIllegalArgument(Runnable parse) {
        try {
            parse.run();
        } catch (IllegalArgumentException iae) {
            // refused, as the callers expect
        } catch (RuntimeException re) {
            if (!isClientError(re)) {
                throw re;
            }
        }
    }
}
