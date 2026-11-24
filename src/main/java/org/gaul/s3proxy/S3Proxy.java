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

import static com.google.common.base.Preconditions.checkArgument;
import static java.util.Objects.requireNonNull;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Properties;

import javax.net.ssl.SSLContext;

import com.google.common.base.Splitter;
import com.google.common.base.Strings;

import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.ee10.servlet.ServletHolder;
import org.eclipse.jetty.http.HttpCompliance;
import org.eclipse.jetty.http.UriCompliance;
import org.eclipse.jetty.server.CustomRequestLog;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.RequestLog;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.Slf4jRequestLogWriter;
import org.eclipse.jetty.server.handler.GracefulHandler;
import org.eclipse.jetty.util.VirtualThreads;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.eclipse.jetty.util.thread.QueuedThreadPool;
import org.gaul.s3proxy.auth.AuthenticationType;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.sts.StsHandler;
import org.jspecify.annotations.Nullable;

/**
 * S3Proxy translates S3 HTTP operations into provider-agnostic blobstore
 * operations.  This allows applications using the S3 API to interface with
 * storage backends such as Google Cloud Storage, Microsoft Azure, and
 * OpenStack Swift.
 */
public final class S3Proxy {
    // Default for Builder.stopTimeout: how long stop() waits for in-flight
    // requests; SIGKILL usually arrives sooner (docker stop defaults to
    // 10 seconds, Kubernetes to 30).
    private static final long STOP_TIMEOUT_MS = 30_000;
    /** The logger the access log writes to, at INFO. */
    private static final String ACCESS_LOG_NAME = "org.gaul.s3proxy.access";
    /**
     * Client address, request line, status, request and response body
     * bytes, milliseconds taken, and user agent.  %U is the path without
     * its query string, which in a presigned URL carries the access key and
     * the signature.  There is no timestamp, the logger adding its own.
     */
    private static final String ACCESS_LOG_FORMAT =
            "%{client}a \"%m %U %H\" %s %I %O %{ms}T \"%{User-Agent}i\"";

    private final Server server;
    // Non-null only when metrics are served on a dedicated port instead of
    // the S3 endpoint.
    @Nullable private final Server metricsServer;
    private final S3ProxyHandlerJetty handler;
    @Nullable private final S3ProxyMetrics metrics;
    private final boolean listenHTTP;
    private final boolean listenHTTPS;

    S3Proxy(Builder builder) {
        checkArgument(builder.endpoint != null ||
                        builder.secureEndpoint != null,
                "Must provide endpoint or secure-endpoint");
        if (builder.endpoint != null) {
            // an opaque URI, such as host:port lacking a scheme, has none
            String path = builder.endpoint.getPath();
            checkArgument(path != null && path.isEmpty(),
                    "endpoint path must be empty, was: %s", path);
        }
        if (builder.secureEndpoint != null) {
            String path = builder.secureEndpoint.getPath();
            checkArgument(path != null && path.isEmpty(),
                    "secure-endpoint path must be empty, was: %s", path);
            if (builder.sslContext == null) {
                // an argument check, not a null check: a configuration
                // error is reported as one, where a NullPointerException
                // reads as a fault in S3Proxy
                checkArgument(builder.keyStorePath != null,
                        "Must provide keyStorePath with HTTPS endpoint");
                checkArgument(builder.keyStorePassword != null,
                        "Must provide keyStorePassword with HTTPS endpoint");
            }
        }
        checkArgument(Strings.isNullOrEmpty(builder.identity) ^
                !Strings.isNullOrEmpty(builder.credential),
                "Must provide both identity and credential");
        BlobStore blobStore = requireNonNull(builder.blobStore,
                "Must provide blobStore");

        var pool = new QueuedThreadPool(builder.jettyMaxThreads);
        pool.setName("S3Proxy-Jetty");
        // A request whose body trickles in holds its thread for as long as
        // its sender likes, and some bodies are read before anything has
        // authenticated them: a few hundred slow connections held every
        // pooled thread, and the proxy stopped answering.  A virtual thread
        // waiting on a read costs a few kilobytes and no pooled thread, so
        // requests run on them where the runtime has them; Jetty keeps its
        // own selector and acceptor threads in the pool.  What the waiting
        // bodies hold is bounded by the pre-auth body budget instead.
        if (builder.jettyVirtualThreads && VirtualThreads.areSupported()) {
            pool.setVirtualThreadsExecutor(
                    VirtualThreads.getNamedVirtualThreadsExecutor(
                            "S3Proxy-Jetty-virtual-"));
        }
        server = new Server(pool);

        var httpConfiguration = new HttpConfiguration();
        // Legacy compliance keeps header values as the client spelled them,
        // which signatures cover, but it also accepts a request that frames
        // its body twice.  The chunks of Transfer-Encoding then delimit the
        // body while Content-Length stays in the headers, where signing and
        // the upload handlers read it as the length of a body that can have
        // any other: a presigned URL that signed Content-Length would store
        // an object of any size.  No S3 client sends both and RFC 9112 6.3
        // has such a message handled as an error, so refuse it with 400 as
        // Jetty's stricter modes do.
        httpConfiguration.setHttpCompliance(HttpCompliance.LEGACY.without(
                "S3PROXY", HttpCompliance.Violation
                        .TRANSFER_ENCODING_WITH_CONTENT_LENGTH));
        httpConfiguration.setUriCompliance(UriCompliance.LEGACY);
        httpConfiguration.setHeaderCacheCaseSensitive(true);
        // Do not name the embedded server or its version, in the Server header
        // or in the error pages Jetty renders for requests that never reach
        // S3ProxyHandler.  S3 does not, and the version tells an attacker
        // which Jetty advisories to try.
        httpConfiguration.setSendServerVersion(false);
        // Read an S3 request's parameters from its query string alone.
        // Jetty otherwise parses a PUT or POST body labelled
        // application/x-www-form-urlencoded as form fields the first time a
        // parameter is asked for, consuming the object a client uploads and
        // adding its bytes to the parameters that signing and routing read.
        // S3 treats that Content-Type as the object's metadata and nothing
        // more; POST policy uploads are multipart/form-data, parsed apart.
        httpConfiguration.setFormEncodedMethods();

        var src = new SecureRequestCustomizer();
        src.setSniHostCheck(false);
        httpConfiguration.addCustomizer(src);
        HttpConnectionFactory httpConnectionFactory =
                new HttpConnectionFactory(httpConfiguration);
        ServerConnector connector;
        if (builder.endpoint != null) {
            connector = new ServerConnector(server, httpConnectionFactory);
            connector.setHost(builder.endpoint.getHost());
            connector.setPort(builder.endpoint.getPort());
            server.addConnector(connector);
            listenHTTP = true;
        } else {
            listenHTTP = false;
        }

        if (builder.secureEndpoint != null) {
            SslContextFactory.Server sslContextFactory =
                new SslContextFactory.Server();
            if (builder.sslContext != null) {
                sslContextFactory.setSslContext(builder.sslContext);
            } else {
                sslContextFactory.setKeyStorePath(builder.keyStorePath);
                sslContextFactory.setKeyStorePassword(builder.keyStorePassword);
            }
            connector = new ServerConnector(server, sslContextFactory,
                    httpConnectionFactory);
            connector.setHost(builder.secureEndpoint.getHost());
            connector.setPort(builder.secureEndpoint.getPort());
            server.addConnector(connector);
            listenHTTPS = true;
        } else {
            listenHTTPS = false;
        }
        if (builder.metricsEnabled) {
            this.metrics = new S3ProxyMetrics();
        } else {
            this.metrics = null;
        }

        handler = new S3ProxyHandlerJetty(blobStore,
                builder.authenticationType, builder.identity,
                builder.credential, builder.virtualHost,
                builder.maxSinglePartObjectSize,
                builder.v4MaxNonChunkedRequestSize,
                builder.v4MaxChunkSize,
                builder.ignoreUnknownHeaders, builder.corsRules,
                builder.servicePath, builder.maximumTimeSkew, metrics,
                builder.stsEnabled ?
                        new StsHandler(builder.stsMaxDuration) : null);
        handler.getHandler().setPreAuthBodyBudget(new PreAuthBodyBudget(
                builder.preAuthBodyBudget >= 0 ? builder.preAuthBodyBudget :
                        Math.max(Runtime.getRuntime().maxMemory() / 4,
                                builder.v4MaxNonChunkedRequestSize)));

        var context = new ServletContextHandler();
        if (builder.servicePath != null && !builder.servicePath.isEmpty()) {
            context.setContextPath(builder.servicePath);
        }
        // Serve /metrics on a dedicated listener when a metrics port is
        // configured, so it is not exposed on the S3 endpoint; otherwise
        // register it on the S3 server for backwards compatibility.
        if (metrics != null && builder.metricsPort >= 0) {
            var metricsPool = new QueuedThreadPool();
            metricsPool.setName("S3Proxy-Metrics");
            metricsServer = new Server(metricsPool);
            var metricsConnector = new ServerConnector(metricsServer,
                    /*acceptors=*/ 1, /*selectors=*/ 1,
                    new HttpConnectionFactory());
            String metricsHost = builder.metricsHost;
            if (metricsHost == null) {
                // checkArgument above guarantees endpoint or secureEndpoint
                metricsHost = builder.endpoint != null ?
                        builder.endpoint.getHost() :
                        requireNonNull(builder.secureEndpoint).getHost();
            }
            metricsConnector.setHost(metricsHost);
            metricsConnector.setPort(builder.metricsPort);
            metricsServer.addConnector(metricsConnector);
            var metricsContext = new ServletContextHandler();
            metricsContext.addServlet(new ServletHolder(
                    new MetricsHandler(metrics)), "/metrics");
            metricsServer.setHandler(metricsContext);
        } else {
            metricsServer = null;
            if (metrics != null) {
                context.addServlet(new ServletHolder(
                        new MetricsHandler(metrics)), "/metrics");
            }
        }
        context.addServlet(new ServletHolder(handler), "/*");
        // Reject new requests during stop and let server.stop() wait for
        // in-flight ones, so SIGTERM drains rather than dropping transfers.
        server.setHandler(new GracefulHandler(context));
        // Answer the requests Jetty rejects on its own -- a URI or header the
        // parser refuses never reaches S3ProxyHandler -- with an S3 error
        // document instead of Jetty's HTML page.
        server.setErrorHandler(new S3ErrorHandler());
        if (builder.accessLog) {
            // Logged by Jetty rather than by S3ProxyHandler so that the
            // requests Jetty rejects on its own are logged as well.
            RequestLog.Writer writer = builder.accessLogWriter;
            if (writer == null) {
                var slf4jWriter = new Slf4jRequestLogWriter();
                slf4jWriter.setLoggerName(ACCESS_LOG_NAME);
                writer = slf4jWriter;
            }
            server.setRequestLog(new CustomRequestLog(writer,
                    ACCESS_LOG_FORMAT));
        }
        server.setStopTimeout(builder.stopTimeout);
    }

    public static final class Builder {
        @Nullable private BlobStore blobStore;
        @Nullable private URI endpoint;
        @Nullable private URI secureEndpoint;
        @Nullable private String servicePath;
        private AuthenticationType authenticationType =
                AuthenticationType.NONE;
        @Nullable private String identity;
        @Nullable private String credential;
        @Nullable private SSLContext sslContext;
        @Nullable private String keyStorePath;
        @Nullable private String keyStorePassword;
        @Nullable private String virtualHost;
        private long maxSinglePartObjectSize = 5L * 1024 * 1024 * 1024;
        private long v4MaxNonChunkedRequestSize = 128 * 1024 * 1024;
        private int v4MaxChunkSize = 16 * 1024 * 1024;
        private boolean ignoreUnknownHeaders;
        @Nullable private CrossOriginResourceSharing corsRules;
        private int jettyMaxThreads = 200;  // sourced from QueuedThreadPool()
        private boolean jettyVirtualThreads = true;
        // negative: a quarter of the heap, at least one largest body
        private long preAuthBodyBudget = -1;
        private int maximumTimeSkew = 15 * 60;
        private boolean accessLog;
        private RequestLog.@Nullable Writer accessLogWriter;
        private boolean metricsEnabled;
        private int metricsPort = -1;
        @Nullable private String metricsHost;
        private long stopTimeout = STOP_TIMEOUT_MS;
        private boolean stsEnabled;
        private Duration stsMaxDuration = StsHandler.MAX_DURATION;

        Builder() {
        }

        public S3Proxy build() {
            return new S3Proxy(this);
        }

        public static Builder fromProperties(Properties properties)
                throws URISyntaxException {
            var builder = new Builder();

            String endpoint = properties.getProperty(
                    S3ProxyConstants.PROPERTY_ENDPOINT);
            String secureEndpoint = properties.getProperty(
                    S3ProxyConstants.PROPERTY_SECURE_ENDPOINT);
            boolean hasEndpoint = !Strings.isNullOrEmpty(endpoint);
            boolean hasSecureEndpoint = !Strings.isNullOrEmpty(secureEndpoint);
            if (!hasEndpoint && !hasSecureEndpoint) {
                throw new IllegalArgumentException(
                        "Properties file must contain: " +
                        S3ProxyConstants.PROPERTY_ENDPOINT + " or " +
                        S3ProxyConstants.PROPERTY_SECURE_ENDPOINT);
            }
            if (!Strings.isNullOrEmpty(endpoint)) {
                builder.endpoint(new URI(endpoint));
            }
            if (!Strings.isNullOrEmpty(secureEndpoint)) {
                builder.secureEndpoint(new URI(secureEndpoint));
            }

            String authorizationString = properties.getProperty(
                    S3ProxyConstants.PROPERTY_AUTHORIZATION);
            if (authorizationString == null) {
                throw new IllegalArgumentException(
                        "Properties file must contain: " +
                        S3ProxyConstants.PROPERTY_AUTHORIZATION);
            }

            AuthenticationType authorization =
                    AuthenticationType.fromString(authorizationString);
            String localIdentity = null;
            String localCredential = null;
            switch (authorization) {
            case AWS_V2, AWS_V4, AWS_V2_OR_V4 -> {
                localIdentity = properties.getProperty(
                        S3ProxyConstants.PROPERTY_IDENTITY);
                localCredential = properties.getProperty(
                        S3ProxyConstants.PROPERTY_CREDENTIAL);
                if (localIdentity == null || localCredential == null) {
                    throw new IllegalArgumentException("Must specify both " +
                            S3ProxyConstants.PROPERTY_IDENTITY + " and " +
                            S3ProxyConstants.PROPERTY_CREDENTIAL +
                            " when using authentication");
                }
            }
            case NONE -> { }
            default -> throw new IllegalArgumentException(
                    S3ProxyConstants.PROPERTY_AUTHORIZATION +
                    " invalid value, was: " + authorization);
            }

            if (localIdentity != null || localCredential != null) {
                builder.awsAuthentication(authorization, localIdentity,
                        localCredential);
            }

            String servicePath = Strings.nullToEmpty(properties.getProperty(
                    S3ProxyConstants.PROPERTY_SERVICE_PATH));
            builder.servicePath(servicePath);

            String keyStorePath = properties.getProperty(
                    S3ProxyConstants.PROPERTY_KEYSTORE_PATH);
            String keyStorePassword = properties.getProperty(
                    S3ProxyConstants.PROPERTY_KEYSTORE_PASSWORD);
            if (keyStorePath != null || keyStorePassword != null) {
                if (keyStorePath == null || keyStorePassword == null) {
                    throw new IllegalArgumentException("Must specify both " +
                            S3ProxyConstants.PROPERTY_KEYSTORE_PATH + " and " +
                            S3ProxyConstants.PROPERTY_KEYSTORE_PASSWORD);
                }
                builder.keyStore(keyStorePath, keyStorePassword);
            }

            String virtualHost = properties.getProperty(
                    S3ProxyConstants.PROPERTY_VIRTUAL_HOST);
            if (!Strings.isNullOrEmpty(virtualHost)) {
                builder.virtualHost(virtualHost);
            }

            String maxSinglePartObjectSize = properties.getProperty(
                    S3ProxyConstants.PROPERTY_MAX_SINGLE_PART_OBJECT_SIZE);
            if (maxSinglePartObjectSize != null) {
                builder.maxSinglePartObjectSize(Long.parseLong(
                        maxSinglePartObjectSize));
            }

            String v4MaxNonChunkedRequestSize = properties.getProperty(
                    S3ProxyConstants.PROPERTY_V4_MAX_NON_CHUNKED_REQUEST_SIZE);
            if (v4MaxNonChunkedRequestSize != null) {
                builder.v4MaxNonChunkedRequestSize(Long.parseLong(
                        v4MaxNonChunkedRequestSize));
            }

            String v4MaxChunkSize = properties.getProperty(
                    S3ProxyConstants.PROPERTY_V4_MAX_CHUNK_SIZE);
            if (v4MaxChunkSize != null) {
                builder.v4MaxChunkSize(Integer.parseInt(v4MaxChunkSize));
            }

            String ignoreUnknownHeaders = properties.getProperty(
                    S3ProxyConstants.PROPERTY_IGNORE_UNKNOWN_HEADERS);
            if (!Strings.isNullOrEmpty(ignoreUnknownHeaders)) {
                builder.ignoreUnknownHeaders(Boolean.parseBoolean(
                        ignoreUnknownHeaders));
            }

            String corsAllowAll = properties.getProperty(
                    S3ProxyConstants.PROPERTY_CORS_ALLOW_ALL);
            if (!Strings.isNullOrEmpty(corsAllowAll) && Boolean.parseBoolean(
                         corsAllowAll)) {
                builder.corsRules(new CrossOriginResourceSharing());
            } else {
                String corsAllowOrigins = Strings.nullToEmpty(
                        properties.getProperty(
                                S3ProxyConstants.PROPERTY_CORS_ALLOW_ORIGINS));
                String corsAllowMethods = Strings.nullToEmpty(
                        properties.getProperty(
                                S3ProxyConstants.PROPERTY_CORS_ALLOW_METHODS));
                String corsAllowHeaders = Strings.nullToEmpty(
                        properties.getProperty(
                                S3ProxyConstants.PROPERTY_CORS_ALLOW_HEADERS));
                String corsExposedHeaders = Strings.nullToEmpty(
                        properties.getProperty(
                                S3ProxyConstants.PROPERTY_CORS_EXPOSED_HEADERS));
                String allowCredentials = Strings.nullToEmpty(
                        properties.getProperty(
                                S3ProxyConstants.PROPERTY_CORS_ALLOW_CREDENTIAL));

                Splitter splitter = Splitter.on(" ").trimResults()
                        .omitEmptyStrings();

                //Validate configured methods
                Collection<String> allowedMethods = new ArrayList<>(
                        splitter.splitToList(corsAllowMethods));
                allowedMethods.removeAll(
                        CrossOriginResourceSharing.SUPPORTED_METHODS);
                if (!allowedMethods.isEmpty()) {
                    throw new IllegalArgumentException(
                        S3ProxyConstants.PROPERTY_CORS_ALLOW_METHODS +
                        " contains not supported values: " +
                        String.join(" ", allowedMethods));
                }

                builder.corsRules(new CrossOriginResourceSharing(
                        splitter.splitToList(corsAllowOrigins),
                        splitter.splitToList(corsAllowMethods),
                        splitter.splitToList(corsAllowHeaders),
                        splitter.splitToList(corsExposedHeaders),
                        allowCredentials));
            }

            String jettyMaxThreads = properties.getProperty(
                    S3ProxyConstants.PROPERTY_JETTY_MAX_THREADS);
            if (jettyMaxThreads != null) {
                builder.jettyMaxThreads(Integer.parseInt(jettyMaxThreads));
            }

            String jettyVirtualThreads = properties.getProperty(
                    S3ProxyConstants.PROPERTY_JETTY_VIRTUAL_THREADS);
            if (jettyVirtualThreads != null) {
                builder.jettyVirtualThreads(
                        Boolean.parseBoolean(jettyVirtualThreads));
            }

            String preAuthBodyBudget = properties.getProperty(
                    S3ProxyConstants.PROPERTY_PRE_AUTH_BODY_BUDGET);
            if (preAuthBodyBudget != null && !preAuthBodyBudget.isBlank()) {
                builder.preAuthBodyBudget(Long.parseLong(preAuthBodyBudget));
            }

            String maximumTimeSkew = properties.getProperty(
                    S3ProxyConstants.PROPERTY_MAXIMUM_TIME_SKEW);
            if (maximumTimeSkew != null && !maximumTimeSkew.isBlank()) {
                builder.maximumTimeSkew(Integer.parseInt(maximumTimeSkew));
            }

            String accessLog = properties.getProperty(
                    S3ProxyConstants.PROPERTY_ACCESS_LOG);
            if (!Strings.isNullOrEmpty(accessLog)) {
                builder.accessLog(Boolean.parseBoolean(accessLog));
            }

            String metricsEnabled = properties.getProperty(
                    S3ProxyConstants.PROPERTY_METRICS_ENABLED);
            if (!Strings.isNullOrEmpty(metricsEnabled)) {
                builder.metricsEnabled(Boolean.parseBoolean(metricsEnabled));
            }

            String metricsPort = properties.getProperty(
                    S3ProxyConstants.PROPERTY_METRICS_PORT);
            if (!Strings.isNullOrEmpty(metricsPort)) {
                builder.metricsPort(Integer.parseInt(metricsPort));
            }

            String metricsHost = properties.getProperty(
                    S3ProxyConstants.PROPERTY_METRICS_HOST);
            if (!Strings.isNullOrEmpty(metricsHost)) {
                builder.metricsHost(metricsHost);
            }

            String stsEnabled = properties.getProperty(
                    S3ProxyConstants.PROPERTY_STS_ENABLED);
            if (!Strings.isNullOrEmpty(stsEnabled)) {
                builder.stsEnabled(Boolean.parseBoolean(stsEnabled));
            }

            String stsMaxDuration = properties.getProperty(
                    S3ProxyConstants.PROPERTY_STS_MAX_DURATION);
            if (!Strings.isNullOrEmpty(stsMaxDuration)) {
                builder.stsMaxDuration(Duration.ofSeconds(
                        Long.parseLong(stsMaxDuration)));
            }

            return builder;
        }

        public Builder blobStore(BlobStore blobStore) {
            this.blobStore = requireNonNull(blobStore);
            return this;
        }

        public Builder endpoint(URI endpoint) {
            this.endpoint = requireNonNull(endpoint);
            return this;
        }

        public Builder secureEndpoint(URI secureEndpoint) {
            this.secureEndpoint = requireNonNull(secureEndpoint);
            return this;
        }

        public Builder awsAuthentication(AuthenticationType authenticationType,
                @Nullable String identity, @Nullable String credential) {
            this.authenticationType = authenticationType;
            if (!AuthenticationType.NONE.equals(authenticationType)) {
                this.identity = requireNonNull(identity);
                this.credential = requireNonNull(credential);
            }
            return this;
        }

        public Builder sslContext(SSLContext sslContext) {
            this.sslContext = requireNonNull(sslContext);
            this.keyStorePath = null;
            this.keyStorePassword = null;
            return this;
        }

        public Builder keyStore(String keyStorePath, String keyStorePassword) {
            this.keyStorePath = requireNonNull(keyStorePath);
            this.keyStorePassword = requireNonNull(keyStorePassword);
            this.sslContext = null;
            return this;
        }

        public Builder virtualHost(String virtualHost) {
            this.virtualHost = requireNonNull(virtualHost);
            return this;
        }

        public Builder maxSinglePartObjectSize(long maxSinglePartObjectSize) {
            if (maxSinglePartObjectSize <= 0) {
                throw new IllegalArgumentException(
                        "must be greater than zero, was: " +
                        maxSinglePartObjectSize);
            }
            this.maxSinglePartObjectSize = maxSinglePartObjectSize;
            return this;
        }

        public Builder v4MaxNonChunkedRequestSize(
                long v4MaxNonChunkedRequestSize) {
            if (v4MaxNonChunkedRequestSize <= 0) {
                throw new IllegalArgumentException(
                        "must be greater than zero, was: " +
                        v4MaxNonChunkedRequestSize);
            }
            this.v4MaxNonChunkedRequestSize = v4MaxNonChunkedRequestSize;
            return this;
        }

        public Builder v4MaxChunkSize(int v4MaxChunkSize) {
            if (v4MaxChunkSize <= 0) {
                throw new IllegalArgumentException(
                        "must be greater than zero, was: " +
                        v4MaxChunkSize);
            }
            this.v4MaxChunkSize = v4MaxChunkSize;
            return this;
        }

        public Builder ignoreUnknownHeaders(boolean ignoreUnknownHeaders) {
            this.ignoreUnknownHeaders = ignoreUnknownHeaders;
            return this;
        }

        public Builder corsRules(CrossOriginResourceSharing corsRules) {
            this.corsRules = corsRules;
            return this;
        }

        public Builder jettyMaxThreads(int jettyMaxThreads) {
            this.jettyMaxThreads = jettyMaxThreads;
            return this;
        }

        /**
         * Whether requests run on virtual threads where the runtime has
         * them; see {@link S3ProxyConstants#PROPERTY_JETTY_VIRTUAL_THREADS}.
         */
        public Builder jettyVirtualThreads(boolean jettyVirtualThreads) {
            this.jettyVirtualThreads = jettyVirtualThreads;
            return this;
        }

        /**
         * The most bytes of bodies held before their requests are
         * authenticated; see
         * {@link S3ProxyConstants#PROPERTY_PRE_AUTH_BODY_BUDGET}.
         */
        public Builder preAuthBodyBudget(long preAuthBodyBudget) {
            checkArgument(preAuthBodyBudget >= 0,
                    "Pre-auth body budget must not be negative");
            this.preAuthBodyBudget = preAuthBodyBudget;
            return this;
        }

        /**
         * How many milliseconds {@link S3Proxy#stop} waits for in-flight
         * requests to drain.  Zero stops immediately, aborting them and
         * closing keep-alive connections without the grace Jetty otherwise
         * allows them; test fixtures want this since their requests have
         * completed by teardown, and an idle connection a client left open
         * holds an otherwise instant stop for two seconds.
         */
        public Builder stopTimeout(long stopTimeout) {
            if (stopTimeout < 0) {
                throw new IllegalArgumentException(
                        "must not be negative, was: " + stopTimeout);
            }
            this.stopTimeout = stopTimeout;
            return this;
        }

        public Builder maximumTimeSkew(int maximumTimeSkew) {
            this.maximumTimeSkew = maximumTimeSkew;
            return this;
        }

        /**
         * Log one line for each completed request to the logger named
         * org.gaul.s3proxy.access.  The path is logged without its query
         * string.
         */
        public Builder accessLog(boolean accessLog) {
            this.accessLog = accessLog;
            return this;
        }

        /** Where the access log is written instead of its logger: for tests. */
        Builder accessLogWriter(RequestLog.Writer accessLogWriter) {
            this.accessLogWriter = requireNonNull(accessLogWriter);
            return this;
        }

        public Builder metricsEnabled(boolean metricsEnabled) {
            this.metricsEnabled = metricsEnabled;
            return this;
        }

        public Builder metricsPort(int metricsPort) {
            this.metricsPort = metricsPort;
            return this;
        }

        public Builder metricsHost(String metricsHost) {
            this.metricsHost = metricsHost;
            return this;
        }

        public Builder stsEnabled(boolean stsEnabled) {
            this.stsEnabled = stsEnabled;
            return this;
        }

        public Builder stsMaxDuration(Duration stsMaxDuration) {
            this.stsMaxDuration = requireNonNull(stsMaxDuration);
            return this;
        }

        public Builder servicePath(String s3ProxyServicePath) {
            String path = Strings.nullToEmpty(s3ProxyServicePath);

            if (!path.isEmpty()) {
                if (!path.startsWith("/")) {
                    path = "/" + path;
                }
            }

            this.servicePath = path;

            return this;
        }

        @Nullable public URI getEndpoint() {
            return endpoint;
        }

        @Nullable public URI getSecureEndpoint() {
            return secureEndpoint;
        }

        @Nullable public String getServicePath() {
            return servicePath;
        }

        @Nullable public String getIdentity() {
            return identity;
        }

        @Nullable public String getCredential() {
            return credential;
        }

        List<String> differingProperties(Builder that) {
            var differences = new ArrayList<String>();
            if (!Objects.equals(this.endpoint, that.endpoint)) {
                differences.add(S3ProxyConstants.PROPERTY_ENDPOINT);
            }
            if (!Objects.equals(this.secureEndpoint, that.secureEndpoint)) {
                differences.add(S3ProxyConstants.PROPERTY_SECURE_ENDPOINT);
            }
            if (!Objects.equals(this.sslContext, that.sslContext)) {
                differences.add("programmatic SSL context");
            }
            if (!Objects.equals(this.keyStorePath, that.keyStorePath)) {
                differences.add(S3ProxyConstants.PROPERTY_KEYSTORE_PATH);
            }
            if (!Objects.equals(this.keyStorePassword,
                    that.keyStorePassword)) {
                differences.add(S3ProxyConstants.PROPERTY_KEYSTORE_PASSWORD);
            }
            if (!Objects.equals(this.virtualHost, that.virtualHost)) {
                differences.add(S3ProxyConstants.PROPERTY_VIRTUAL_HOST);
            }
            if (!Objects.equals(this.servicePath, that.servicePath)) {
                differences.add(S3ProxyConstants.PROPERTY_SERVICE_PATH);
            }
            if (this.maxSinglePartObjectSize !=
                    that.maxSinglePartObjectSize) {
                differences.add(
                        S3ProxyConstants.PROPERTY_MAX_SINGLE_PART_OBJECT_SIZE);
            }
            if (this.v4MaxNonChunkedRequestSize !=
                    that.v4MaxNonChunkedRequestSize) {
                differences.add(S3ProxyConstants
                        .PROPERTY_V4_MAX_NON_CHUNKED_REQUEST_SIZE);
            }
            if (this.v4MaxChunkSize != that.v4MaxChunkSize) {
                differences.add(S3ProxyConstants.PROPERTY_V4_MAX_CHUNK_SIZE);
            }
            if (this.ignoreUnknownHeaders != that.ignoreUnknownHeaders) {
                differences.add(
                        S3ProxyConstants.PROPERTY_IGNORE_UNKNOWN_HEADERS);
            }
            if (!Objects.equals(this.corsRules, that.corsRules)) {
                differences.add("s3proxy.cors-*");
            }
            if (!Objects.equals(this.authenticationType,
                    that.authenticationType)) {
                differences.add(S3ProxyConstants.PROPERTY_AUTHORIZATION);
            }
            if (this.jettyMaxThreads != that.jettyMaxThreads) {
                differences.add(S3ProxyConstants.PROPERTY_JETTY_MAX_THREADS);
            }
            if (this.jettyVirtualThreads != that.jettyVirtualThreads) {
                differences.add(
                        S3ProxyConstants.PROPERTY_JETTY_VIRTUAL_THREADS);
            }
            if (this.preAuthBodyBudget != that.preAuthBodyBudget) {
                differences.add(
                        S3ProxyConstants.PROPERTY_PRE_AUTH_BODY_BUDGET);
            }
            if (this.maximumTimeSkew != that.maximumTimeSkew) {
                differences.add(S3ProxyConstants.PROPERTY_MAXIMUM_TIME_SKEW);
            }
            if (this.accessLog != that.accessLog) {
                differences.add(S3ProxyConstants.PROPERTY_ACCESS_LOG);
            }
            if (this.metricsEnabled != that.metricsEnabled) {
                differences.add(S3ProxyConstants.PROPERTY_METRICS_ENABLED);
            }
            if (this.metricsPort != that.metricsPort) {
                differences.add(S3ProxyConstants.PROPERTY_METRICS_PORT);
            }
            if (!Objects.equals(this.metricsHost, that.metricsHost)) {
                differences.add(S3ProxyConstants.PROPERTY_METRICS_HOST);
            }
            if (this.stsEnabled != that.stsEnabled) {
                differences.add(S3ProxyConstants.PROPERTY_STS_ENABLED);
            }
            if (!Objects.equals(this.stsMaxDuration, that.stsMaxDuration)) {
                differences.add(S3ProxyConstants.PROPERTY_STS_MAX_DURATION);
            }
            return List.copyOf(differences);
        }

        @Override
        public boolean equals(@Nullable Object object) {
            if (this == object) {
                return true;
            } else if (!(object instanceof S3Proxy.Builder)) {
                return false;
            }
            S3Proxy.Builder that = (S3Proxy.Builder) object;
            // do not check credentials or storage backend fields
            return differingProperties(that).isEmpty();
        }

        @Override
        public int hashCode() {
            return Objects.hash(authenticationType, jettyMaxThreads,
                    jettyVirtualThreads, preAuthBodyBudget,
                    maximumTimeSkew, accessLog, metricsEnabled, metricsPort,
                    metricsHost,
                    endpoint, secureEndpoint, sslContext,
                    keyStorePath, keyStorePassword, virtualHost, servicePath,
                    maxSinglePartObjectSize, v4MaxNonChunkedRequestSize,
                    v4MaxChunkSize, ignoreUnknownHeaders, corsRules,
                    stsEnabled, stsMaxDuration);
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    public void start() throws Exception {
        server.start();
        if (metricsServer != null) {
            metricsServer.start();
        }
    }

    public void stop() throws Exception {
        server.stop();
        if (metricsServer != null) {
            metricsServer.stop();
        }
        if (metrics != null) {
            metrics.close();
        }
    }

    /**
     * Returns the port serving /metrics when a dedicated metrics port is
     * configured, or -1 otherwise.  Resolves the ephemeral port when
     * configured as 0.
     */
    public int getMetricsPort() {
        if (metricsServer == null) {
            return -1;
        }
        return ((ServerConnector) metricsServer.getConnectors()[0])
                .getLocalPort();
    }

    public int getPort() {
        if (listenHTTP) {
            return ((ServerConnector) server.getConnectors()[0]).getLocalPort();
        } else {
            return -1;
        }
    }

    public int getSecurePort() {
        if (listenHTTPS) {
            ServerConnector connector;
            if (listenHTTP) {
                connector = (ServerConnector) server.getConnectors()[1];
            } else {
                connector = (ServerConnector) server.getConnectors()[0];
            }
            return connector.getLocalPort();
        }

        return -1;
    }

    public String getState() {
        return server.getState();
    }

    public void setBlobStoreLocator(BlobStoreLocator lookup) {
        handler.getHandler().setBlobStoreLocator(lookup);
    }
}
