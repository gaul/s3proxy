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

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.TimeUnit;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;

import org.eclipse.jetty.server.LocalConnector;
import org.gaul.s3proxy.auth.AuthenticationType;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.ThrowableProxy;
import ch.qos.logback.core.AppenderBase;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

/**
 * Whole requests, built from S3's own vocabulary of subresources and
 * headers with arbitrary values, handed to Jetty as written through an
 * in-memory connector.  Whatever the request, the answer is never a server
 * error, since a 500 says the server failed and a client retries it; nor
 * one Jetty cannot parse, nor one kept waiting most of a second, nor a 400
 * from an exception that no S3Proxy code threw.
 *
 * <p>Without JAZZER_FUZZ these run the saved inputs only.  To fuzz one
 * target, which is all Jazzer fuzzes in a run:
 * {@code JAZZER_FUZZ=1 mvn test -Dtest=HandlerFuzzTest#anonymousRequest
 * -Djazzer.max_duration=10m}.  A finding is saved under
 * src/test/resources/.../HandlerFuzzTestInputs, where every later test run
 * replays it; Maven copies it to target/test-classes and does not remove
 * it from there when it is deleted.  The corpus grows in .cifuzz-corpus.
 */
public final class HandlerFuzzTest {
    private static final String BUCKET = "fuzz";
    private static final long SLOW_MILLIS = 900;

    private static final List<String> METHODS = List.of(
            "GET", "PUT", "POST", "HEAD", "DELETE", "OPTIONS");

    private static final List<String> PARAMETERS = List.of(
            "acl", "attributes", "continuation-token", "cors", "delete",
            "delimiter", "encoding-type", "encryption", "fetch-owner",
            "key-marker", "legal-hold", "lifecycle", "list-type",
            "location", "marker", "max-keys", "max-parts", "max-uploads",
            "object-lock", "ownershipControls", "partNumber",
            "part-number-marker", "policy", "prefix", "publicAccessBlock",
            "response-cache-control", "response-content-disposition",
            "response-content-type", "response-expires", "retention",
            "start-after", "tagging", "upload-id-marker", "uploadId",
            "uploads", "version-id-marker", "versionId", "versioning",
            "versions", "website", "x-id",
            // presigned
            "AWSAccessKeyId", "Expires", "Signature", "X-Amz-Algorithm",
            "X-Amz-Credential", "X-Amz-Date", "X-Amz-Expires",
            "X-Amz-Security-Token", "X-Amz-Signature",
            "X-Amz-SignedHeaders");

    private static final List<String> HEADERS = List.of(
            "Authorization", "Cache-Control", "Content-Disposition",
            "Content-Encoding", "Content-MD5", "Content-Type", "Expect",
            "Expires", "If-Match", "If-Modified-Since", "If-None-Match",
            "If-Unmodified-Since", "Origin", "Range",
            "Access-Control-Request-Method", "Access-Control-Request-Headers",
            "Transfer-Encoding",
            "x-amz-acl", "x-amz-bucket-object-lock-enabled",
            "x-amz-bypass-governance-retention", "x-amz-checksum-algorithm",
            "x-amz-checksum-crc32", "x-amz-checksum-crc32c",
            "x-amz-checksum-crc64nvme", "x-amz-checksum-sha1",
            "x-amz-checksum-sha256", "x-amz-checksum-type",
            "x-amz-content-sha256", "x-amz-copy-source",
            "x-amz-copy-source-if-match",
            "x-amz-copy-source-if-modified-since",
            "x-amz-copy-source-if-none-match",
            "x-amz-copy-source-if-unmodified-since",
            "x-amz-copy-source-range", "x-amz-date",
            "x-amz-decoded-content-length", "x-amz-expected-bucket-owner",
            "x-amz-grant-full-control", "x-amz-grant-read",
            "x-amz-grant-read-acp", "x-amz-grant-write",
            "x-amz-grant-write-acp", "x-amz-if-match-last-modified-time",
            "x-amz-if-match-size", "x-amz-meta-fuzz",
            "x-amz-metadata-directive", "x-amz-mp-object-size",
            "x-amz-object-attributes", "x-amz-object-lock-legal-hold",
            "x-amz-object-lock-mode", "x-amz-object-lock-retain-until-date",
            "x-amz-object-ownership", "x-amz-sdk-checksum-algorithm",
            "x-amz-security-token", "x-amz-server-side-encryption",
            "x-amz-server-side-encryption-customer-algorithm",
            "x-amz-server-side-encryption-customer-key",
            "x-amz-server-side-encryption-customer-key-MD5",
            "x-amz-storage-class", "x-amz-tagging",
            "x-amz-tagging-directive", "x-amz-trailer",
            "x-amz-write-offset-bytes");

    /**
     * The IllegalArgumentExceptions and IllegalStateExceptions that the
     * Jetty handler answered 400 although no S3Proxy code threw them: an
     * unchecked parse or a library's precondition, which says the request
     * reached code that did not expect it.  S3Proxy's own refusals throw
     * from S3Proxy code and are not collected.
     */
    private static final Queue<Throwable> UNANTICIPATED =
            new ConcurrentLinkedQueue<>();

    private static S3Proxy anonymous;
    private static LocalConnector anonymousConnector;
    private static S3Proxy signed;
    private static LocalConnector signedConnector;

    @BeforeAll
    static void setUp() throws Exception {
        var jettyLogger = (ch.qos.logback.classic.Logger)
                LoggerFactory.getLogger(S3ProxyHandlerJetty.class);
        jettyLogger.setLevel(Level.DEBUG);
        jettyLogger.setAdditive(false);
        var appender = new AppenderBase<ILoggingEvent>() {
            @Override
            protected void append(ILoggingEvent event) {
                if (!(event.getThrowableProxy() instanceof
                        ThrowableProxy proxy)) {
                    return;
                }
                Throwable t = proxy.getThrowable();
                if (!(t instanceof IllegalArgumentException ||
                        t instanceof IllegalStateException)) {
                    return;
                }
                StackTraceElement[] trace = t.getStackTrace();
                if (trace.length == 0 || !trace[0].getClassName()
                        .startsWith("org.gaul.s3proxy.")) {
                    UNANTICIPATED.add(t);
                }
            }
        };
        appender.setContext(jettyLogger.getLoggerContext());
        appender.start();
        jettyLogger.addAppender(appender);

        anonymous = build(AuthenticationType.NONE);
        anonymousConnector = anonymous.addLocalConnector();
        start(anonymous);
        signed = build(AuthenticationType.AWS_V2_OR_V4);
        signedConnector = signed.addLocalConnector();
        start(signed);
    }

    @AfterAll
    static void tearDown() throws Exception {
        for (S3Proxy proxy : new S3Proxy[] {anonymous, signed}) {
            if (proxy != null) {
                proxy.stop();
            }
        }
    }

    private static S3Proxy build(AuthenticationType type) {
        BlobStore blobStore = TestUtils.createTransientBlobStore();
        blobStore.createContainer(BUCKET);
        for (String key : List.of("key", "dir/key")) {
            blobStore.putBlob(PutObjectRequest.builder()
                    .bucket(BUCKET).key(key).build(),
                    new ByteArrayInputStream(
                            "content".getBytes(StandardCharsets.UTF_8)));
        }
        return S3Proxy.builder()
                .stopTimeout(0)
                .blobStore(blobStore)
                .awsAuthentication(type, "identity", "credential")
                .endpoint(URI.create("http://127.0.0.1:0"))
                .build();
    }

    private static void start(S3Proxy proxy) throws Exception {
        proxy.start();
        while (!proxy.getState().equals("STARTED")) {
            Thread.sleep(10);
        }
    }

    @FuzzTest
    void anonymousRequest(FuzzedDataProvider data) throws Exception {
        send(anonymousConnector, data);
    }

    @FuzzTest
    void signedRequest(FuzzedDataProvider data) throws Exception {
        send(signedConnector, data);
    }

    private static void send(LocalConnector connector,
            FuzzedDataProvider data) throws Exception {
        var request = new StringBuilder();
        String method = data.pickValue(METHODS);
        request.append(method).append(" /");
        String bucket = data.pickValue(List.of(BUCKET, BUCKET, "", "other"));
        request.append(bucket);
        if (!bucket.isEmpty() && data.consumeBoolean()) {
            request.append('/').append(encode(data.pickValue(List.of(
                    "key", "dir/key", "dir/", data.consumeString(24))),
                    /*path=*/ true));
        }
        int parameters = data.consumeInt(0, 3);
        for (int i = 0; i < parameters; ++i) {
            request.append(i == 0 ? '?' : '&')
                    .append(data.pickValue(PARAMETERS));
            if (data.consumeBoolean()) {
                request.append('=').append(encode(data.consumeString(40),
                        /*path=*/ false));
            }
        }
        request.append(" HTTP/1.1\r\nHost: 127.0.0.1\r\n")
                .append("Connection: close\r\n");
        int headers = data.consumeInt(0, 4);
        for (int i = 0; i < headers; ++i) {
            request.append(data.pickValue(HEADERS)).append(": ")
                    .append(headerValue(data.consumeString(60)))
                    .append("\r\n");
        }
        byte[] body = data.consumeRemainingAsBytes();
        request.append("Content-Length: ").append(body.length)
                .append("\r\n\r\n");

        byte[] head = request.toString().getBytes(StandardCharsets.UTF_8);
        ByteBuffer buffer = ByteBuffer.allocate(head.length + body.length)
                .put(head).put(body).flip();
        UNANTICIPATED.clear();
        long start = System.nanoTime();
        ByteBuffer response = connector.getResponse(buffer,
                method.equals("HEAD"), 10, TimeUnit.SECONDS);
        long millis = TimeUnit.NANOSECONDS.toMillis(
                System.nanoTime() - start);
        if (response == null) {
            // Jetty's own client-side parser gave up: on a connection that
            // closed without an answer, or on one it will not read, such as
            // a header value holding a byte no header may
            throw new AssertionError((millis >= 10_000 ?
                    "no answer within 10 s" : "no answer Jetty could parse") +
                    " to:\n" + request + "<" + body.length + " byte body>");
        }
        // The transient store answers in microseconds; a request kept
        // waiting most of a second is waiting on a timeout, not on work.
        if (millis > SLOW_MILLIS) {
            throw new AssertionError("answered only after " + millis +
                    " ms:\n" + request + "<" + body.length + " byte body>");
        }
        String status = statusLine(response);
        // "HTTP/1.1 500 Server Error"
        String[] parts = status.split(" ", 3);
        if (parts.length < 2) {
            throw new AssertionError("no status line, got \"" + status +
                    "\" for:\n" + request);
        }
        int code = Integer.parseInt(parts[1]);
        Throwable unanticipated = UNANTICIPATED.poll();
        if (unanticipated != null) {
            throw new AssertionError(status + " from an exception no S3Proxy " +
                    "code threw, for:\n" + request + "<" + body.length +
                    " byte body>", unanticipated);
        }
        if (code >= 500 && code != 501) {
            throw new AssertionError(status + " for:\n" + request +
                    "<" + body.length + " byte body>");
        }
    }

    private static String statusLine(ByteBuffer response) {
        var line = new StringBuilder();
        while (response.hasRemaining()) {
            char c = (char) (response.get() & 0xff);
            if (c == '\n') {
                break;
            } else if (c != '\r') {
                line.append(c);
            }
        }
        return line.toString();
    }

    /** A value that keeps to its own header line. */
    private static String headerValue(String value) {
        return value.replaceAll("[\r\n\0]", "");
    }

    private static String encode(String value, boolean path) {
        var encoded = new StringBuilder();
        for (byte b : value.getBytes(StandardCharsets.UTF_8)) {
            int c = b & 0xff;
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                    (c >= '0' && c <= '9') || c == '-' || c == '.' ||
                    c == '_' || c == '~' || (path && c == '/')) {
                encoded.append((char) c);
            } else {
                encoded.append('%').append(String.format("%02X", c));
            }
        }
        return encoded.toString();
    }
}
