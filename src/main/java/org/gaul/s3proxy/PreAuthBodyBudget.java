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

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.atomic.AtomicLong;

import jakarta.servlet.http.HttpServletRequest;

/**
 * The bytes of request bodies held before their requests are authenticated,
 * counted against one budget for the whole proxy.  Two bodies are read whole
 * before anything has said who sent them: a form POST, whose policy and
 * signature are fields inside it, and a V4 request whose signature covers a
 * digest of its body.  Each is bounded on its own, but how many may be read
 * at once was bounded only by the request threads, and on virtual threads
 * not at all.  A body takes from the budget as its bytes arrive, so one that
 * trickles in holds only what it has sent, and gives it all back once its
 * request is answered.  A read the budget cannot cover is refused with 503
 * SlowDown, which clients retry after backing off.
 */
final class PreAuthBodyBudget {
    private static final String ATTRIBUTE =
            PreAuthBodyBudget.class.getName() + ".reserved";

    private final AtomicLong remaining;

    PreAuthBodyBudget(long bytes) {
        remaining = new AtomicLong(bytes);
    }

    /** No budget: every read is covered. */
    static PreAuthBodyBudget unlimited() {
        return new PreAuthBodyBudget(Long.MAX_VALUE);
    }

    /**
     * The request's body as a stream whose reads take from the budget, to
     * be given back by {@link #release} once the request is answered.
     */
    InputStream track(HttpServletRequest request, InputStream in) {
        var reserved = (AtomicLong) request.getAttribute(ATTRIBUTE);
        if (reserved == null) {
            reserved = new AtomicLong();
            request.setAttribute(ATTRIBUTE, reserved);
        }
        return new Tracked(in, reserved);
    }

    /** Gives back what the request's body took from the budget. */
    void release(HttpServletRequest request) {
        var reserved = (AtomicLong) request.getAttribute(ATTRIBUTE);
        if (reserved != null) {
            remaining.addAndGet(reserved.getAndSet(0));
        }
    }

    private void take(AtomicLong reserved, long count) {
        while (true) {
            long current = remaining.get();
            if (current < count) {
                throw new S3ProxyException(S3ErrorCode.SLOW_DOWN);
            }
            if (remaining.compareAndSet(current, current - count)) {
                reserved.addAndGet(count);
                return;
            }
        }
    }

    private final class Tracked extends FilterInputStream {
        private final AtomicLong reserved;

        Tracked(InputStream in, AtomicLong reserved) {
            super(in);
            this.reserved = reserved;
        }

        @Override
        public int read() throws IOException {
            int b = super.read();
            if (b != -1) {
                take(reserved, 1);
            }
            return b;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            int count = super.read(b, off, len);
            if (count > 0) {
                take(reserved, count);
            }
            return count;
        }

        @Override
        public long skip(long n) throws IOException {
            // skipped bytes are not held
            return super.skip(n);
        }
    }
}
