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

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;
import java.util.function.Supplier;

import org.gaul.s3proxy.auth.AuthenticationType;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.ForwardingBlobStore;
import org.gaul.s3proxy.blobstore.S3Exceptions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.ILoggerFactory;
import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import software.amazon.awssdk.services.s3.model.ListBucketsResponse;

/**
 * A backend's failure reaches the client as an S3 error document and the
 * operator as a warning carrying its detail, which the client is not told.
 */
public final class ServerErrorTest {
    private final HttpClient httpClient = HttpClient.newHttpClient();
    private final ListAppender<ILoggingEvent> logged = new ListAppender<>();
    private Logger jettyLogger;

    @BeforeEach
    public void setUp() throws InterruptedException {
        // Test classes start concurrently, and while one is initializing
        // logging SLF4J hands the others stand-in loggers, which logback's
        // appenders cannot be added to.
        ILoggerFactory factory = LoggerFactory.getILoggerFactory();
        for (int i = 0; !(factory instanceof LoggerContext) && i < 500;
                ++i) {
            Thread.sleep(10);
            factory = LoggerFactory.getILoggerFactory();
        }
        jettyLogger = ((LoggerContext) factory).getLogger(
                S3ProxyHandlerJetty.class);
        logged.start();
        jettyLogger.addAppender(logged);
    }

    @AfterEach
    public void tearDown() {
        jettyLogger.detachAppender(logged);
    }

    /**
     * A 500 a backend raises as an S3 error, e.g. for a credential supplier
     * that lost its token, was rendered and logged only at debug, so the
     * operator had nothing to go on.
     */
    @Test
    public void testBackendServerErrorIsLogged() throws Exception {
        var failure = S3Exceptions.noSessionToken();

        HttpResponse<String> response = listFailingWith(() -> failure);

        assertThat(response.statusCode()).isEqualTo(500);
        assertThat(response.body()).contains("<Code>InternalError</Code>")
                .doesNotContain("session token");
        assertThat(warningsFor(failure)).isEqualTo(1);
    }

    /** NotImplemented says what is unsupported, which is no fault. */
    @Test
    public void testNotImplementedIsNotAWarning() throws Exception {
        var refusal = S3Exceptions.notImplemented("not here");

        HttpResponse<String> response = listFailingWith(() -> refusal);

        assertThat(response.statusCode()).isEqualTo(501);
        assertThat(warningsFor(refusal)).isZero();
    }

    /**
     * A backend failure that carries only a status, no S3 error code, is
     * answered with S3's document for that status.  It was the status alone
     * with no body, which an S3 client reports as an unknown error.
     */
    @Test
    public void testStatusWithoutCodeIsAnErrorDocument() throws Exception {
        for (var entry : Map.of(500, "InternalError", 501, "NotImplemented",
                503, "ServiceUnavailable").entrySet()) {
            HttpResponse<String> response = listFailingWith(
                    () -> S3Exceptions.fromStatusCode(entry.getKey()));

            assertThat(response.statusCode()).isEqualTo(entry.getKey());
            assertThat(response.body()).as(entry.getValue())
                    .contains("<Code>" + entry.getValue() + "</Code>");
        }
    }

    private long warningsFor(Throwable failure) {
        // AppenderBase appends under the appender's own monitor
        synchronized (logged) {
            return logged.list.stream()
                    .filter(event -> event.getLevel() == Level.WARN)
                    .filter(event -> event.getThrowableProxy() != null &&
                            event.getThrowableProxy().getMessage().equals(
                                    failure.getMessage()))
                    .count();
        }
    }

    /** Lists the buckets of a store whose listing throws what is given. */
    private HttpResponse<String> listFailingWith(
            Supplier<RuntimeException> failure) throws Exception {
        BlobStore blobStore = new ForwardingBlobStore(
                TestUtils.createTransientBlobStore()) {
            @Override
            public ListBucketsResponse list() {
                throw failure.get();
            }
        };
        S3Proxy proxy = S3Proxy.builder()
                .stopTimeout(0)
                .blobStore(blobStore)
                .awsAuthentication(AuthenticationType.NONE, "identity",
                        "credential")
                .endpoint(URI.create("http://127.0.0.1:0"))
                .build();
        proxy.start();
        while (!proxy.getState().equals("STARTED")) {
            Thread.sleep(10);
        }
        try {
            return httpClient.send(HttpRequest.newBuilder(URI.create(
                    "http://127.0.0.1:" + proxy.getPort() + "/")).GET()
                    .build(), HttpResponse.BodyHandlers.ofString());
        } finally {
            proxy.stop();
        }
    }
}
