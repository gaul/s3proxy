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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Queue;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.TimeUnit;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import com.google.common.base.Strings;

import org.eclipse.jetty.server.LocalConnector;
import org.gaul.s3proxy.auth.AuthenticationType;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.ThrowableProxy;
import ch.qos.logback.core.AppenderBase;
import software.amazon.awssdk.checksums.DefaultChecksumAlgorithm;
import software.amazon.awssdk.http.ContentStreamProvider;
import software.amazon.awssdk.http.SdkHttpFullRequest;
import software.amazon.awssdk.http.SdkHttpMethod;
import software.amazon.awssdk.http.SdkHttpRequest;
import software.amazon.awssdk.http.auth.aws.signer.AwsV4FamilyHttpSigner;
import software.amazon.awssdk.http.auth.aws.signer.AwsV4HttpSigner;
import software.amazon.awssdk.http.auth.spi.signer.SignedRequest;
import software.amazon.awssdk.identity.spi.AwsCredentialsIdentity;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

/**
 * Whole requests, built from S3's own vocabulary of subresources and
 * headers with arbitrary values, handed to Jetty as written through an
 * in-memory connector.  Whatever the request, the answer is never a server
 * error, since a 500 says the server failed and a client retries it; nor
 * one Jetty cannot parse, nor one kept waiting most of a second, nor a 400
 * from an exception that no S3Proxy code threw.
 *
 * <p>Each input starts from the same store, emptied and seeded again, and
 * sends a short sequence of requests to it.  A request that fails only
 * after what an earlier one left behind is then found within one input,
 * whose saved copy reproduces it alone; with one store for the whole run,
 * a finding depended on inputs long gone, and each input ran against more
 * accumulated state, which slowed the run by half within minutes.
 *
 * <p>The signed target signs most of its requests, with V2 or with the
 * SDK's V4 signer in each of its forms, so that they reach the operation
 * they name rather than stopping at SignatureDoesNotMatch; see
 * {@link Signing}.
 *
 * <p>Without JAZZER_FUZZ these run the saved inputs only.  To fuzz one
 * target, which is all Jazzer fuzzes in a run:
 * {@code JAZZER_FUZZ=1 mvn test -Dtest=HandlerFuzzTest#anonymousRequest
 * -Djazzer.max_duration=10m -Dsurefire.timeout=0}; without the last,
 * Surefire kills a run at five minutes and Jazzer saves the input it was
 * on as though it had failed.  A finding is saved under
 * src/test/resources/.../HandlerFuzzTestInputs, where every later test run
 * replays it; Maven copies it to target/test-classes and does not remove
 * it from there when it is deleted.  The corpus grows in .cifuzz-corpus.
 */
public final class HandlerFuzzTest {
    private static final String IDENTITY = "identity";
    private static final String CREDENTIAL = "credential";
    private static final AwsCredentialsIdentity CREDENTIALS =
            AwsCredentialsIdentity.create(IDENTITY, CREDENTIAL);
    private static final AwsV4HttpSigner V4_SIGNER = AwsV4HttpSigner.create();
    private static final String BUCKET = "fuzz";
    private static final List<String> SEEDED_KEYS = List.of("key", "dir/key");
    private static final long SLOW_MILLIS = 900;
    /** Enough for a write followed by a read or a write it conflicts with. */
    private static final int MAX_REQUESTS = 3;
    /** The body of a request other than the last, which takes the rest. */
    private static final int MAX_EARLIER_BODY = 256;

    /**
     * The subresources a V2 signature covers: those of the specification,
     * and the two that S3Proxy requires signed because they turn one
     * operation into another.  This harness signs to get past
     * authentication, not to judge how S3Proxy canonicalizes, so it signs
     * as S3Proxy verifies.
     */
    private static final Set<String> V2_SUBRESOURCES = Set.of(
            "acl", "attributes", "delete", "encryption", "lifecycle",
            "location", "logging", "notification", "partNumber", "policy",
            "requestPayment", "response-cache-control",
            "response-content-disposition", "response-content-encoding",
            "response-content-language", "response-content-type",
            "response-expires", "torrent", "uploadId", "uploads",
            "versionId", "versioning", "versions", "website");

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

    private static BlobStore anonymousStore;
    private static S3Proxy anonymous;
    private static LocalConnector anonymousConnector;
    private static BlobStore signedStore;
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

        anonymousStore = TestUtils.createTransientBlobStore();
        anonymous = build(anonymousStore, AuthenticationType.NONE);
        anonymousConnector = anonymous.addLocalConnector();
        start(anonymous);
        signedStore = TestUtils.createTransientBlobStore();
        signed = build(signedStore, AuthenticationType.AWS_V2_OR_V4);
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

    private static S3Proxy build(BlobStore blobStore,
            AuthenticationType type) {
        return S3Proxy.builder()
                .stopTimeout(0)
                .blobStore(blobStore)
                .awsAuthentication(type, IDENTITY, CREDENTIAL)
                .endpoint(URI.create("http://127.0.0.1:0"))
                .build();
    }

    private static void start(S3Proxy proxy) throws Exception {
        proxy.start();
        while (!proxy.getState().equals("STARTED")) {
            Thread.sleep(10);
        }
    }

    /**
     * Empties the store and seeds it again.  Every bucket an input can
     * create is one the store lists, and the nio2 stores keep all of a
     * bucket's state -- its versions, uploads, ACLs and configuration --
     * beneath its directory, which deleteContainer removes whole.
     */
    private static void reset(BlobStore blobStore) {
        for (var bucket : blobStore.list().buckets()) {
            blobStore.deleteContainer(bucket.name());
        }
        blobStore.createContainer(BUCKET);
        for (String key : SEEDED_KEYS) {
            blobStore.putBlob(PutObjectRequest.builder()
                    .bucket(BUCKET).key(key).build(),
                    new ByteArrayInputStream(
                            "content".getBytes(StandardCharsets.UTF_8)));
        }
    }

    @FuzzTest
    void anonymousRequest(FuzzedDataProvider data) throws Exception {
        exchange(anonymousStore, anonymousConnector, data, /*signs=*/ false);
    }

    @FuzzTest
    void signedRequest(FuzzedDataProvider data) throws Exception {
        exchange(signedStore, signedConnector, data, /*signs=*/ true);
    }

    /**
     * Every way the signed target signs gets past authentication, read and
     * write, with a subresource and a header the signature has to cover;
     * otherwise the fuzzer would only ever meet SignatureDoesNotMatch.  Each
     * writes the request it says it does, and an aws-chunked body arrives
     * decoded.
     */
    @Test
    void testEverySigningAuthenticates() throws Exception {
        reset(signedStore);
        byte[] content = "content".getBytes(StandardCharsets.UTF_8);
        for (Signing signing : Signing.values()) {
            if (signing == Signing.NONE) {
                continue;
            }
            String key = "/" + BUCKET + "/" + signing;
            var put = new Request("PUT", key, List.of(), List.of(
                    new Header("x-amz-meta-fuzz", " a  b "),
                    new Header("Content-Type", "text/plain")), content);
            Wire wire = write(put, signing, -1);
            assertThat(wire.head()).as("%s", signing)
                    .contains(wireMarker(signing));
            assertThat(answer(wire)).as("%s %s", signing, put)
                    .startsWith("HTTP/1.1 200 ");

            var get = new Request("GET", key, List.of(new Parameter(
                    "response-content-type", "text/a b&c=d")),
                    List.of(), new byte[0]);
            assertThat(answer(write(get, signing, -1)))
                    .as("%s %s", signing, get)
                    .startsWith("HTTP/1.1 200 ")
                    .endsWith("\r\n\r\ncontent");

            var list = new Request("GET", "/" + BUCKET, List.of(
                    new Parameter("list-type", "2"),
                    new Parameter("prefix", "dir/"),
                    new Parameter("encoding-type", null)),
                    List.of(), new byte[0]);
            assertThat(answer(write(list, signing, -1)))
                    .as("%s %s", signing, list)
                    .startsWith("HTTP/1.1 200 ");

            if (signing.chunked()) {
                assertThat(answer(write(put, signing, /*tamper=*/ 0)))
                        .as("%s tampered", signing)
                        .startsWith("HTTP/1.1 4");
            }
        }
    }

    /** What the request has to carry for it to be signed as named. */
    private static String wireMarker(Signing signing) {
        return switch (signing) {
        case NONE -> "";
        case V2_HEADER -> "Authorization: AWS " + IDENTITY + ":";
        case V2_QUERY -> "&Signature=";
        case V4_HEADER -> "Authorization: AWS4-HMAC-SHA256 ";
        case V4_UNSIGNED_PAYLOAD -> ": UNSIGNED-PAYLOAD\r\n";
        case V4_QUERY -> "&X-Amz-Signature=";
        case V4_CHUNKED -> ": STREAMING-AWS4-HMAC-SHA256-PAYLOAD\r\n";
        case V4_CHUNKED_TRAILER ->
            ": STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER\r\n";
        case V4_UNSIGNED_TRAILER -> ": STREAMING-UNSIGNED-PAYLOAD-TRAILER\r\n";
        };
    }

    private static String answer(Wire wire) throws Exception {
        ByteBuffer response = signedConnector.getResponse(wire.buffer(),
                false, 10, TimeUnit.SECONDS);
        assertThat(response).as("%s", wire.head()).isNotNull();
        return StandardCharsets.ISO_8859_1.decode(response).toString();
    }

    private static void exchange(BlobStore blobStore,
            LocalConnector connector, FuzzedDataProvider data,
            boolean signs) throws Exception {
        reset(blobStore);
        var earlier = new StringBuilder();
        int requests = data.consumeInt(1, MAX_REQUESTS);
        for (int i = 1; i <= requests; ++i) {
            byte[] body = i == requests ? null :
                    data.consumeBytes(data.consumeInt(0, MAX_EARLIER_BODY));
            send(connector, data, signs, body, earlier);
        }
    }

    /** A query parameter, decoded; a null value is one without an '='. */
    private record Parameter(String name, @Nullable String value) { }

    private record Header(String name, String value) { }

    /** A request as the fuzzer chose it, before it is signed and written. */
    private static final class Request {
        private final String method;
        private final String encodedPath;
        private final List<Parameter> parameters;
        private final List<Header> headers;
        private final byte[] body;

        Request(String method, String encodedPath,
                List<Parameter> parameters, List<Header> headers,
                byte[] body) {
            this.method = method;
            this.encodedPath = encodedPath;
            this.parameters = parameters;
            this.headers = headers;
            this.body = body;
        }

        String method() {
            return method;
        }

        String encodedPath() {
            return encodedPath;
        }

        List<Parameter> parameters() {
            return parameters;
        }

        List<Header> headers() {
            return headers;
        }

        byte[] body() {
            return body;
        }

        @Override
        public String toString() {
            return method + " " + encodedPath + " " + parameters + " " +
                    headers;
        }
    }

    /** A request as Jetty is to read it. */
    private static final class Wire {
        private final String head;
        private final byte[] body;

        Wire(String head, byte[] body) {
            this.head = head;
            this.body = body;
        }

        String head() {
            return head;
        }

        byte[] body() {
            return body;
        }

        ByteBuffer buffer() {
            byte[] bytes = head.getBytes(StandardCharsets.UTF_8);
            return ByteBuffer.allocate(bytes.length + body.length)
                    .put(bytes).put(body).flip();
        }
    }

    /**
     * How a request of the signed target authenticates.  Signed as it
     * should be, a request gets past authentication into the operation it
     * names, where the fuzzer can reach what the anonymous target reaches
     * and the paths that only signed requests take: the payload hashes,
     * the aws-chunked decoder checking each chunk's signature and the
     * trailing checksums.  Unsigned, it is what the fuzzer wrote, its own
     * Authorization included.
     */
    private enum Signing {
        NONE,
        V2_HEADER,
        V2_QUERY,
        V4_HEADER,
        V4_UNSIGNED_PAYLOAD,
        V4_QUERY,
        V4_CHUNKED,
        V4_CHUNKED_TRAILER,
        V4_UNSIGNED_TRAILER;

        boolean chunked() {
            return this == V4_CHUNKED || this == V4_CHUNKED_TRAILER ||
                    this == V4_UNSIGNED_TRAILER;
        }
    }

    /**
     * Sends one request and judges its answer.  A null body takes the rest
     * of the input.  Requests sent earlier in the input are recorded in
     * earlier, so that a failure names the state it arose from.
     */
    private static void send(LocalConnector connector,
            FuzzedDataProvider data, boolean signs,
            byte @Nullable [] earlierBody, StringBuilder earlier)
            throws Exception {
        String method = data.pickValue(METHODS);
        var path = new StringBuilder("/");
        String bucket = data.pickValue(List.of(BUCKET, BUCKET, "", "other"));
        path.append(bucket);
        if (!bucket.isEmpty() && data.consumeBoolean()) {
            path.append('/').append(encode(data.pickValue(List.of(
                    "key", "dir/key", "dir/", data.consumeString(24))),
                    /*path=*/ true));
        }
        var parameters = new ArrayList<Parameter>();
        int parameterCount = data.consumeInt(0, 3);
        for (int i = 0; i < parameterCount; ++i) {
            String name = data.pickValue(PARAMETERS);
            parameters.add(new Parameter(name,
                    data.consumeBoolean() ? data.consumeString(40) : null));
        }
        var headers = new ArrayList<Header>();
        int headerCount = data.consumeInt(0, 4);
        for (int i = 0; i < headerCount; ++i) {
            headers.add(new Header(data.pickValue(HEADERS),
                    headerValue(data.consumeString(60))));
        }
        Signing signing = signs ? data.pickValue(Signing.values()) :
                Signing.NONE;
        // A byte of an aws-chunked body to corrupt after it is signed, for
        // the paths that find a chunk's signature or the trailer wrong
        int tamper = signing.chunked() && data.consumeBoolean() ?
                data.consumeInt(0, Integer.MAX_VALUE) : -1;
        byte[] body = earlierBody != null ? earlierBody :
                data.consumeRemainingAsBytes();
        Wire wire = write(new Request(method, path.toString(), parameters,
                headers, body), signing, tamper);
        String described = (earlier.isEmpty() ? "" :
                "after:\n" + earlier + "the request:\n") +
                wire.head() + "<" + wire.body().length + " byte body>";

        UNANTICIPATED.clear();
        long start = System.nanoTime();
        ByteBuffer response = connector.getResponse(wire.buffer(),
                method.equals("HEAD"), 10, TimeUnit.SECONDS);
        long millis = TimeUnit.NANOSECONDS.toMillis(
                System.nanoTime() - start);
        if (response == null) {
            // Jetty's own client-side parser gave up: on a connection that
            // closed without an answer, or on one it will not read, such as
            // a header value holding a byte no header may
            throw new AssertionError((millis >= 10_000 ?
                    "no answer within 10 s" : "no answer Jetty could parse") +
                    " to:\n" + described);
        }
        // The transient store answers in microseconds; a request kept
        // waiting most of a second is waiting on a timeout, not on work.
        if (millis > SLOW_MILLIS) {
            throw new AssertionError("answered only after " + millis +
                    " ms:\n" + described);
        }
        String status = statusLine(response);
        // "HTTP/1.1 500 Server Error"
        String[] parts = status.split(" ", 3);
        if (parts.length < 2) {
            throw new AssertionError("no status line, got \"" + status +
                    "\" for:\n" + described);
        }
        int code = Integer.parseInt(parts[1]);
        Throwable unanticipated = UNANTICIPATED.poll();
        if (unanticipated != null) {
            throw new AssertionError(status + " from an exception no S3Proxy " +
                    "code threw, for:\n" + described, unanticipated);
        }
        if (code >= 500 && code != 501) {
            throw new AssertionError(status + " for:\n" + described);
        }
        earlier.append(wire.head()).append('<').append(wire.body().length)
                .append(" byte body> answered ").append(status)
                .append('\n');
    }

    /** Writes the request, signed as signing says. */
    private static Wire write(Request request, Signing signing,
            int tamper) {
        return switch (signing) {
        case NONE -> writeUnsigned(request);
        case V2_HEADER, V2_QUERY -> writeV2(request,
                signing == Signing.V2_QUERY);
        default -> writeV4(request, signing, tamper);
        };
    }

    private static Wire writeUnsigned(Request request) {
        var head = new StringBuilder(request.method()).append(' ')
                .append(request.encodedPath());
        char separator = '?';
        for (Parameter parameter : request.parameters()) {
            head.append(separator).append(parameter.name());
            if (parameter.value() != null) {
                head.append('=').append(encode(parameter.value(),
                        /*path=*/ false));
            }
            separator = '&';
        }
        head.append(" HTTP/1.1\r\nHost: 127.0.0.1\r\n")
                .append("Connection: close\r\n");
        for (Header header : request.headers()) {
            head.append(header.name()).append(": ").append(header.value())
                    .append("\r\n");
        }
        head.append("Content-Length: ").append(request.body().length)
                .append("\r\n\r\n");
        return new Wire(head.toString(), request.body());
    }

    /**
     * Signs with Signature Version 2, which no current SDK signs, by its
     * specification.  The fuzzer's own Authorization and x-amz-date give
     * way, since the signature has to be computed over the date it sends.
     */
    private static Wire writeV2(Request request, boolean query) {
        var headers = new ArrayList<Header>();
        for (Header header : request.headers()) {
            if (!header.name().equalsIgnoreCase("Authorization") &&
                    !header.name().equalsIgnoreCase("x-amz-date")) {
                headers.add(header);
            }
        }
        var parameters = new ArrayList<>(request.parameters());
        String date;
        if (query) {
            date = String.valueOf(Instant.now().plusSeconds(300)
                    .getEpochSecond());
        } else {
            date = DateTimeFormatter.RFC_1123_DATE_TIME.format(
                    ZonedDateTime.now(ZoneOffset.UTC));
            headers.add(new Header("Date", date));
        }

        var stringToSign = new StringBuilder(request.method()).append('\n')
                .append(firstHeader(headers, "Content-MD5")).append('\n')
                .append(firstHeader(headers, "Content-Type")).append('\n')
                .append(date).append('\n');
        var amzHeaders = new TreeMap<String, List<String>>();
        for (Header header : headers) {
            String name = header.name().toLowerCase(Locale.ROOT);
            if (name.startsWith("x-amz-")) {
                // Jetty trims the value of the whitespace around it
                amzHeaders.computeIfAbsent(name, unused -> new ArrayList<>())
                        .add(header.value().strip());
            }
        }
        amzHeaders.forEach((name, values) -> stringToSign.append(name)
                .append(':').append(String.join(",", values)).append('\n'));
        stringToSign.append(request.encodedPath());
        var subresources = new TreeMap<String, String>();
        for (Parameter parameter : parameters) {
            if (V2_SUBRESOURCES.contains(parameter.name())) {
                subresources.putIfAbsent(parameter.name(),
                        Strings.nullToEmpty(parameter.value()));
            }
        }
        char separator = '?';
        for (var entry : subresources.entrySet()) {
            stringToSign.append(separator).append(entry.getKey());
            if (!entry.getValue().isEmpty()) {
                stringToSign.append('=').append(entry.getValue());
            }
            separator = '&';
        }

        String signature;
        try {
            var mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(CREDENTIAL.getBytes(
                    StandardCharsets.UTF_8), "HmacSHA1"));
            signature = Base64.getEncoder().encodeToString(mac.doFinal(
                    stringToSign.toString().getBytes(
                            StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException e) {
            throw new AssertionError(e);
        }
        if (query) {
            parameters.add(new Parameter("AWSAccessKeyId", IDENTITY));
            parameters.add(new Parameter("Expires", date));
            parameters.add(new Parameter("Signature", signature));
        } else {
            headers.add(new Header("Authorization",
                    "AWS " + IDENTITY + ":" + signature));
        }
        return writeUnsigned(new Request(request.method(),
                request.encodedPath(), parameters, headers, request.body()));
    }

    private static String firstHeader(List<Header> headers, String name) {
        for (Header header : headers) {
            if (header.name().equalsIgnoreCase(name)) {
                return header.value().strip();
            }
        }
        return "";
    }

    /**
     * Signs with the SDK's own Signature Version 4 signer, which S3Proxy
     * does not share: in the header or the query, over the payload or not,
     * and the aws-chunked encodings with and without signatures and
     * trailing checksums.  It replaces the fuzzer's Authorization, date and
     * payload hash with its own.
     */
    private static Wire writeV4(Request request, Signing signing,
            int tamper) {
        var builder = SdkHttpFullRequest.builder()
                .method(SdkHttpMethod.fromValue(request.method()))
                // Over plain HTTP the SDK signs the payload whatever it is
                // told, a presigned URL's included; the scheme is otherwise
                // not signed, and 443 leaves the Host as Jetty reads it
                .protocol("https")
                .host("127.0.0.1")
                .port(443)
                .encodedPath(request.encodedPath());
        for (Parameter parameter : request.parameters()) {
            builder.appendRawQueryParameter(parameter.name(),
                    parameter.value());
        }
        for (Header header : request.headers()) {
            if (!header.name().equalsIgnoreCase("Authorization")) {
                builder.appendHeader(header.name(), header.value());
            }
        }
        builder.putHeader("Content-Length",
                String.valueOf(request.body().length));
        boolean query = signing == Signing.V4_QUERY;
        SignedRequest signed;
        byte[] body;
        try {
            signed = signV4(builder.build(), request.body(), signing, query);
            // The aws-chunked encoding is produced as it is read
            body = signed.payload().isPresent() ?
                    signed.payload().get().newStream().readAllBytes() :
                    request.body();
        } catch (IOException ioe) {
            throw new UncheckedIOException(ioe);
        } catch (RuntimeException e) {
            // The signer refuses some requests no SDK would send, such as an
            // x-amz-trailer naming a header that is not there; they still
            // go, as the fuzzer wrote them.  testEverySigningAuthenticates
            // keeps this from hiding a signer that refuses everything.
            return writeUnsigned(request);
        }

        SdkHttpRequest signedRequest = signed.request();
        URI uri = signedRequest.getUri();
        var head = new StringBuilder(request.method()).append(' ')
                .append(uri.getRawPath());
        if (uri.getRawQuery() != null) {
            head.append('?').append(uri.getRawQuery());
        }
        head.append(" HTTP/1.1\r\nConnection: close\r\n");
        if (signedRequest.firstMatchingHeader("Host").isEmpty()) {
            head.append("Host: 127.0.0.1\r\n");
        }
        signedRequest.forEachHeader((name, values) -> {
            for (String value : values) {
                head.append(name).append(": ").append(value).append("\r\n");
            }
        });
        head.append("\r\n");
        if (tamper >= 0 && body.length > 0) {
            body = body.clone();
            body[tamper % body.length] ^= 1;
        }
        return new Wire(head.toString(), body);
    }

    private static SignedRequest signV4(SdkHttpFullRequest request,
            byte[] body, Signing signing, boolean query) {
        return V4_SIGNER.sign(r -> {
            r.identity(CREDENTIALS)
                    .request(request)
                    .payload(ContentStreamProvider.fromByteArrayUnsafe(
                            body))
                    .putProperty(AwsV4HttpSigner.SERVICE_SIGNING_NAME, "s3")
                    .putProperty(AwsV4HttpSigner.REGION_NAME, "us-east-1")
                    .putProperty(AwsV4HttpSigner.DOUBLE_URL_ENCODE, false)
                    .putProperty(AwsV4HttpSigner.NORMALIZE_PATH, false)
                    .putProperty(AwsV4HttpSigner.PAYLOAD_SIGNING_ENABLED,
                            signing != Signing.V4_UNSIGNED_PAYLOAD &&
                            signing != Signing.V4_UNSIGNED_TRAILER && !query)
                    .putProperty(AwsV4HttpSigner.CHUNK_ENCODING_ENABLED,
                            signing.chunked())
                    .putProperty(AwsV4HttpSigner.AUTH_LOCATION, query ?
                            AwsV4FamilyHttpSigner.AuthLocation.QUERY_STRING :
                            AwsV4FamilyHttpSigner.AuthLocation.HEADER);
            if (query) {
                r.putProperty(AwsV4HttpSigner.EXPIRATION_DURATION,
                        Duration.ofMinutes(5));
            }
            if (signing == Signing.V4_CHUNKED_TRAILER ||
                    signing == Signing.V4_UNSIGNED_TRAILER) {
                r.putProperty(AwsV4HttpSigner.CHECKSUM_ALGORITHM,
                        DefaultChecksumAlgorithm.CRC32);
            }
        });
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
