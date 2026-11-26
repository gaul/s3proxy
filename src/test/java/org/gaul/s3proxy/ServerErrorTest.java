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
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.util.Map;
import java.util.function.Supplier;

import org.gaul.s3proxy.auth.AuthenticationType;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.ForwardingBlobStore;
import org.gaul.s3proxy.blobstore.S3Exceptions;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
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
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.ListBucketsResponse;

/**
 * A backend's failure reaches the client as an S3 error document and the
 * operator as a warning carrying its detail, which the client is not told.
 */
public final class ServerErrorTest {
    private final HttpClient httpClient = HttpClient.newHttpClient();
    private final ListAppender<ILoggingEvent> logged = new ListAppender<>();
    private Logger jettyLogger;
    private Logger handlerLogger;

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
        var context = (LoggerContext) factory;
        jettyLogger = context.getLogger(S3ProxyHandlerJetty.class);
        handlerLogger = context.getLogger(S3ProxyHandler.class);
        logged.start();
        jettyLogger.addAppender(logged);
        handlerLogger.addAppender(logged);
    }

    @AfterEach
    public void tearDown() {
        jettyLogger.detachAppender(logged);
        handlerLogger.detachAppender(logged);
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
     * with no body, which an S3 client reports as an unknown error.  A bare
     * 400 is InvalidRequest: it was BadDigest, which a client retries.
     */
    @Test
    public void testStatusWithoutCodeIsAnErrorDocument() throws Exception {
        for (var entry : Map.of(400, "InvalidRequest", 500, "InternalError",
                501, "NotImplemented", 503, "ServiceUnavailable").entrySet()) {
            HttpResponse<String> response = listFailingWith(
                    () -> S3Exceptions.fromStatusCode(entry.getKey()));

            assertThat(response.statusCode()).isEqualTo(entry.getKey());
            assertThat(response.body()).as(entry.getValue())
                    .contains("<Code>" + entry.getValue() + "</Code>");
        }
    }

    /**
     * A store that does not version completes an upload while the handler
     * keeps the connection alive with whitespace, the 200 already sent.  An
     * Error there ended the completing thread with nothing recorded, and the
     * success document went out for an object never assembled, which every
     * SDK takes for success.  It is now the late InternalError S3 sends.
     */
    @Test
    public void testErrorDuringCompletionIsNoSuccess() throws Exception {
        HttpResponse<String> response = completeFailingWith(
                () -> new AssertionError("completion failed"));

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body())
                .contains("<Error><Code>InternalError</Code>")
                .doesNotContain("CompleteMultipartUploadResult");
    }

    /**
     * A store's 5xx during that late completion is answered in the body,
     * as its own code, and logged as a warning as it would have been
     * before the response was committed.  It was logged only at debug.
     */
    @Test
    public void testLateServerErrorIsLogged() throws Exception {
        var failure = S3Exceptions.serviceUnavailable(/*cause=*/ null);

        HttpResponse<String> response = completeFailingWith(() -> failure);

        assertThat(response.body())
                .contains("<Error><Code>ServiceUnavailable</Code>");
        assertThat(warningsFor(failure)).isEqualTo(1);
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

    /**
     * Completes a one-part upload on a store without versioning whose
     * completion throws what is given, answering the completion.
     */
    private HttpResponse<String> completeFailingWith(
            Supplier<Throwable> failure) throws Exception {
        BlobStore transientStore = TestUtils.createTransientBlobStore();
        transientStore.createContainer("bucket");
        BlobStore blobStore = new ForwardingBlobStore(transientStore) {
            @Override
            public CompleteMultipartUploadResponse completeMultipartUpload(
                    MultipartUpload mpu,
                    CompleteMultipartUploadRequest request) {
                Throwable t = failure.get();
                if (t instanceof Error e) {
                    throw e;
                }
                throw (RuntimeException) t;
            }

            // A versioning store completes before anything is sent.
            @Override
            public boolean supportsVersioning() {
                return false;
            }
        };
        S3Proxy proxy = start(blobStore);
        try {
            String object = "http://127.0.0.1:" + proxy.getPort() +
                    "/bucket/key";
            String created = send(HttpRequest.newBuilder(URI.create(
                    object + "?uploads")).POST(BodyPublishers.noBody()))
                    .body();
            String uploadId = created.substring(
                    created.indexOf("<UploadId>") + "<UploadId>".length(),
                    created.indexOf("</UploadId>"));
            String eTag = send(HttpRequest.newBuilder(URI.create(object +
                    "?partNumber=1&uploadId=" + uploadId))
                    .PUT(BodyPublishers.ofString("part")))
                    .headers().firstValue("ETag").orElseThrow();
            return send(HttpRequest.newBuilder(URI.create(object +
                    "?uploadId=" + uploadId)).POST(BodyPublishers.ofString(
                    "<CompleteMultipartUpload><Part><PartNumber>1" +
                    "</PartNumber><ETag>" + eTag + "</ETag></Part>" +
                    "</CompleteMultipartUpload>")));
        } finally {
            proxy.stop();
        }
    }

    private HttpResponse<String> send(HttpRequest.Builder request)
            throws Exception {
        return httpClient.send(request.build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private static S3Proxy start(BlobStore blobStore) throws Exception {
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
        return proxy;
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
        S3Proxy proxy = start(blobStore);
        try {
            return send(HttpRequest.newBuilder(URI.create(
                    "http://127.0.0.1:" + proxy.getPort() + "/")).GET());
        } finally {
            proxy.stop();
        }
    }
}
