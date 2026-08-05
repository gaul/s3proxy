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

import static java.util.Objects.requireNonNull;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.PushbackInputStream;
import java.io.Writer;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.SortedMap;
import java.util.TimeZone;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;

import com.google.common.base.CharMatcher;
import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Streams;
import com.google.common.escape.Escaper;
import com.google.common.hash.HashCode;
import com.google.common.hash.HashFunction;
import com.google.common.hash.Hasher;
import com.google.common.hash.Hashing;
import com.google.common.io.BaseEncoding;
import com.google.common.io.ByteSource;
import com.google.common.io.ByteStreams;
import com.google.common.net.HostAndPort;
import com.google.common.net.HttpHeaders;
import com.google.common.net.PercentEscaper;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.eclipse.jetty.http.MultiPartFormData;
import org.eclipse.jetty.io.ByteBufferPool;
import org.eclipse.jetty.io.content.InputStreamContentSource;
import org.eclipse.jetty.util.Promise;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.BucketAlreadyExistsException;
import org.gaul.s3proxy.blobstore.ContainerNotFoundException;
import org.gaul.s3proxy.blobstore.ContentMetadata;
import org.gaul.s3proxy.blobstore.KeyNotFoundException;
import org.gaul.s3proxy.blobstore.VersionNotFoundException;
import org.gaul.s3proxy.blobstore.domain.Blob;
import org.gaul.s3proxy.blobstore.domain.BlobAccess;
import org.gaul.s3proxy.blobstore.domain.BlobMetadata;
import org.gaul.s3proxy.blobstore.domain.ContainerAccess;
import org.gaul.s3proxy.blobstore.domain.CopyResult;
import org.gaul.s3proxy.blobstore.domain.MultipartPart;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.gaul.s3proxy.blobstore.domain.PageSet;
import org.gaul.s3proxy.blobstore.domain.PutResult;
import org.gaul.s3proxy.blobstore.domain.RemoveResult;
import org.gaul.s3proxy.blobstore.domain.StorageClass;
import org.gaul.s3proxy.blobstore.domain.StorageMetadata;
import org.gaul.s3proxy.blobstore.domain.VersionMetadata;
import org.gaul.s3proxy.blobstore.domain.VersionPage;
import org.gaul.s3proxy.blobstore.domain.VersioningStatus;
import org.gaul.s3proxy.blobstore.options.CopyOptions;
import org.gaul.s3proxy.blobstore.options.CreateContainerOptions;
import org.gaul.s3proxy.blobstore.options.GetOptions;
import org.gaul.s3proxy.blobstore.options.ListContainerOptions;
import org.gaul.s3proxy.blobstore.options.ListVersionsOptions;
import org.gaul.s3proxy.blobstore.options.PutOptions;
import org.gaul.s3proxy.nio2blob.AbstractNio2BlobStore;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import tools.jackson.core.exc.StreamReadException;
import tools.jackson.databind.DatabindException;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.dataformat.xml.XmlFactory;
import tools.jackson.dataformat.xml.XmlMapper;
import tools.jackson.dataformat.xml.XmlReadFeature;

/** HTTP server-independent handler for S3 requests. */
public class S3ProxyHandler {
    private static final Logger logger = LoggerFactory.getLogger(
            S3ProxyHandler.class);

    public static final class RequestContext {
        @Nullable private S3Operation operation;
        @Nullable private String bucket;

        @Nullable public S3Operation getOperation() {
            return operation;
        }

        public void setOperation(S3Operation operation) {
            this.operation = operation;
        }

        @Nullable public String getBucket() {
            return bucket;
        }

        public void setBucket(String bucket) {
            this.bucket = bucket;
        }
    }
    private static final String AWS_XMLNS =
            "http://s3.amazonaws.com/doc/2006-03-01/";
    // TODO: support configurable metadata prefix
    private static final String USER_METADATA_PREFIX = "x-amz-meta-";
    // TODO: fake owner
    private static final String FAKE_OWNER_ID =
            "75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a";
    private static final String FAKE_OWNER_DISPLAY_NAME =
            "CustomersName@amazon.com";
    private static final String FAKE_INITIATOR_ID =
            "arn:aws:iam::111122223333:" +
            "user/some-user-11116a31-17b5-4fb7-9df5-b288870f11xx";
    private static final String FAKE_INITIATOR_DISPLAY_NAME =
            "umat-user-11116a31-17b5-4fb7-9df5-b288870f11xx";
    private static final CharMatcher VALID_BUCKET_FIRST_CHAR =
            CharMatcher.inRange('a', 'z')
                    .or(CharMatcher.inRange('A', 'Z'))
                    .or(CharMatcher.inRange('0', '9'));
    private static final CharMatcher VALID_BUCKET =
            VALID_BUCKET_FIRST_CHAR
                    .or(CharMatcher.is('.'))
                    .or(CharMatcher.is('_'))
                    .or(CharMatcher.is('-'));
    private static final long MAX_MULTIPART_COPY_SIZE =
            5L * 1024L * 1024L * 1024L;
    /**
     * The largest body read into a single array, whatever
     * v4MaxNonChunkedRequestSize is configured to: the JVM will not allocate
     * an array of Integer.MAX_VALUE on every implementation, and a request
     * this side of that limit has other problems.
     */
    private static final long MAX_BUFFERED_PAYLOAD = Integer.MAX_VALUE - 8;
    /** The most buckets ListBuckets returns, and its max-buckets ceiling. */
    private static final int MAX_BUCKETS = 10_000;
    /** An S3 composite ETag: the parts' MD5s hashed, then the part count. */
    private static final Pattern COMPOSITE_ETAG = Pattern.compile(
            "[0-9a-fA-F]{32}-([0-9]+)");
    private static final Set<String> UNSUPPORTED_PARAMETERS = Set.of(
            "accelerate",
            "analytics",
            "cors",
            "encryption",
            "inventory",
            "legal-hold",
            "lifecycle",
            "logging",
            "metrics",
            "notification",
            "object-lock",
            "ownershipControls",
            "policyStatus",
            "publicAccessBlock",
            "replication",
            "requestPayment",
            "restore",
            "retention",
            "tagging",
            "torrent",
            "website"
    );
    /**
     * Subresources that are readable but not writable.  PUT and DELETE on a
     * bucket ignore the subresource and dispatch to CreateBucket and
     * DeleteBucket, so these must be rejected before that happens.
     */
    private static final Set<String> UNSUPPORTED_WRITE_PARAMETERS = Set.of(
            "policy"
    );
    /** The parameters that replace response headers on a read. */
    private static final Set<String> RESPONSE_HEADER_OVERRIDES = Set.of(
            "response-cache-control",
            "response-content-disposition",
            "response-content-encoding",
            "response-content-language",
            "response-content-type",
            "response-expires"
    );
    /** All supported x-amz- headers, except for x-amz-meta- user metadata. */
    private static final Set<String> SUPPORTED_X_AMZ_HEADERS = Set.of(
            AwsHttpHeaders.ACL,
            AwsHttpHeaders.API_VERSION,
            AwsHttpHeaders.BUCKET_OBJECT_LOCK_ENABLED,
            AwsHttpHeaders.CHECKSUM_ALGORITHM,
            AwsHttpHeaders.CHECKSUM_CRC32,
            AwsHttpHeaders.CHECKSUM_CRC32C,
            AwsHttpHeaders.CHECKSUM_CRC64NVME,
            AwsHttpHeaders.CHECKSUM_MODE,
            AwsHttpHeaders.CHECKSUM_SHA1,
            AwsHttpHeaders.CHECKSUM_SHA256,
            AwsHttpHeaders.CHECKSUM_TYPE,
            AwsHttpHeaders.CONTENT_SHA256,
            AwsHttpHeaders.COPY_SOURCE,
            AwsHttpHeaders.COPY_SOURCE_IF_MATCH,
            AwsHttpHeaders.COPY_SOURCE_IF_MODIFIED_SINCE,
            AwsHttpHeaders.COPY_SOURCE_IF_NONE_MATCH,
            AwsHttpHeaders.COPY_SOURCE_IF_UNMODIFIED_SINCE,
            AwsHttpHeaders.COPY_SOURCE_RANGE,
            AwsHttpHeaders.DATE,
            AwsHttpHeaders.DECODED_CONTENT_LENGTH,
            AwsHttpHeaders.METADATA_DIRECTIVE,
            AwsHttpHeaders.OBJECT_ATTRIBUTES,
            AwsHttpHeaders.SDK_CHECKSUM_ALGORITHM,  // TODO: ignoring header
            AwsHttpHeaders.STORAGE_CLASS,
            AwsHttpHeaders.TRAILER,
            AwsHttpHeaders.TRANSFER_ENCODING,  // TODO: ignoring header
            AwsHttpHeaders.USER_AGENT
    );
    private static final Set<String> CANNED_ACLS = Set.of(
            "private",
            "public-read",
            "public-read-write",
            "authenticated-read",
            "bucket-owner-read",
            "bucket-owner-full-control",
            "log-delivery-write"
    );
    private static final String XML_CONTENT_TYPE = "application/xml";
    private static final String UTF_8 = "UTF-8";
    // Reserved prefix for the stub blob that carries object metadata between
    // initiate and complete multipart upload for MULTIPART_REQUIRES_STUB
    // backends.  These stubs are hidden from list() to match S3 semantics
    // where multipart internals are not exposed.  Using a dedicated prefix
    // rather than matching the UUID-shaped upload id avoids hiding legitimate
    // user objects whose keys happen to look like a UUID.
    private static final String MULTIPART_STUB_PREFIX = ".s3proxy-mpu-stub-";
    // Reserved user-metadata key prefix persisting the flexible checksum
    // asserted at upload time so HEAD/GET with x-amz-checksum-mode: ENABLED
    // can return it.  Underscores rather than hyphens since Azure metadata
    // keys must be valid C# identifiers.  Never exposed as x-amz-meta- and
    // stripped from incoming user metadata so clients cannot forge it.
    private static final String CHECKSUM_METADATA_PREFIX = "s3proxy_checksum_";
    /** Records an upload's checksum type; never copied onto the object. */
    private static final String CHECKSUM_TYPE_METADATA_KEY =
            CHECKSUM_METADATA_PREFIX + "type";
    private static final String COMPOSITE = "COMPOSITE";
    private static final String FULL_OBJECT = "FULL_OBJECT";
    /** URLEncoder escapes / which we do not want. */
    private static final Escaper urlEscaper = new PercentEscaper(
            "*-./_", /*plusForSpace=*/ false);
    @SuppressWarnings("deprecation")
    private static final HashFunction MD5 = Hashing.md5();
    private static final ObjectMapper JSON_MAPPER = new ObjectMapper();
    private static final String GIT_HASH = loadGitHash();
    private static final java.text.SimpleDateFormat ISO8601_DATE_FORMAT;
    static {
        ISO8601_DATE_FORMAT = new java.text.SimpleDateFormat(
                "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", java.util.Locale.US);
        ISO8601_DATE_FORMAT.setTimeZone(
                java.util.TimeZone.getTimeZone("UTC"));
    }

    private final Instant launchTime = Instant.now();
    private final boolean anonymousIdentity;
    private final AuthenticationType authenticationType;
    private final Optional<String> virtualHost;
    private final long maxSinglePartObjectSize;
    private final long v4MaxNonChunkedRequestSize;
    private final int v4MaxChunkSize;
    private final boolean ignoreUnknownHeaders;
    private final CrossOriginResourceSharing corsRules;
    private final String servicePath;
    private final int maximumTimeSkew;
    private final XmlMapper mapper = createXmlMapper();
    private final XMLOutputFactory xmlOutputFactory =
            XMLOutputFactory.newInstance();
    private BlobStoreLocator blobStoreLocator;
    // TODO: hack to allow per-request anonymous access
    private final BlobStore defaultBlobStore;
    /**
     * S3 supports arbitrary keys for the marker while some blobstores only
     * support opaque markers.  Emulate the common case for these by mapping
     * the last key from a listing to the corresponding previously returned
     * marker.
     */
    private final Cache<Map.Entry<String, String>, String> lastKeyToMarker =
            CacheBuilder.newBuilder()
            .maximumSize(10000)
            .expireAfterWrite(Duration.ofMinutes(10))
            .build();

    public S3ProxyHandler(final BlobStore blobStore,
            AuthenticationType authenticationType,
            @Nullable final String identity,
            @Nullable final String credential, @Nullable String virtualHost,
            long maxSinglePartObjectSize, long v4MaxNonChunkedRequestSize,
            int v4MaxChunkSize,
            boolean ignoreUnknownHeaders,
            @Nullable CrossOriginResourceSharing corsRules,
            @Nullable final String servicePath, int maximumTimeSkew) {
        if (corsRules != null) {
            this.corsRules = corsRules;
        } else {
            // No configured policy means no cross-origin sharing.  Defaulting
            // to allow-all would let any web page read from a proxy that its
            // browser can reach but its author cannot, e.g. one bound to
            // localhost with anonymous authorization.
            this.corsRules = CrossOriginResourceSharing.disabled();
        }
        if (authenticationType != AuthenticationType.NONE) {
            anonymousIdentity = false;
            final String localIdentity = requireNonNull(identity);
            final String localCredential = requireNonNull(credential);
            blobStoreLocator = new BlobStoreLocator() {
                @Override
                public @Nullable AccessGrant locateBlobStore(
                        @Nullable String identityArg,
                        @Nullable String container, @Nullable String blob) {
                    if (!localIdentity.equals(identityArg)) {
                        return null;
                    }
                    return new AccessGrant(localCredential, blobStore);
                }
            };
        } else {
            anonymousIdentity = true;
            final AccessGrant anonymousGrant =
                    AccessGrant.anonymous(blobStore);
            blobStoreLocator = new BlobStoreLocator() {
                @Override
                public AccessGrant locateBlobStore(
                        @Nullable String identityArg,
                        @Nullable String container, @Nullable String blob) {
                    return anonymousGrant;
                }
            };
        }
        this.authenticationType = authenticationType;
        this.virtualHost = Optional.ofNullable(virtualHost);
        this.maxSinglePartObjectSize = maxSinglePartObjectSize;
        this.v4MaxNonChunkedRequestSize = v4MaxNonChunkedRequestSize;
        this.v4MaxChunkSize = v4MaxChunkSize;
        this.ignoreUnknownHeaders = ignoreUnknownHeaders;
        this.defaultBlobStore = blobStore;
        xmlOutputFactory.setProperty("javax.xml.stream.isRepairingNamespaces", false);
        this.servicePath = Strings.nullToEmpty(servicePath);
        this.maximumTimeSkew = maximumTimeSkew;
    }

    private static XmlMapper createXmlMapper() {
        XMLInputFactory inputFactory = XMLInputFactory.newFactory();
        inputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        inputFactory.setProperty(
                XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        return XmlMapper.builder(new XmlFactory(inputFactory))
                .configure(
                        DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES,
                        false)
                .disable(XmlReadFeature.AUTO_DETECT_XSI_TYPE)
                .build();
    }

    /**
     * Parse a request body, answering MalformedXML for a body Jackson
     * refuses.  StreamReadException alone is not enough: it covers XML that
     * does not parse, while XML that parses but will not bind -- a PartNumber
     * that is not a number, a Quiet that is not a boolean -- fails with
     * DatabindException, a sibling rather than a subclass.  Those used to
     * reach the catch-all in S3ProxyHandlerJetty and answer 500, which tells
     * a client to retry a request that cannot ever succeed.
     *
     * <p>Between them the two cover every way Jackson reports bad content.
     * JacksonIOException, which wraps a failure to read the body rather than
     * a complaint about it, is deliberately left to propagate to the
     * IOException handling that knows what it means.
     */
    private <T> T readXmlBody(InputStream is, Class<T> type)
            throws S3Exception {
        try {
            return mapper.readValue(is, type);
        } catch (StreamReadException | DatabindException e) {
            throw new S3Exception(S3ErrorCode.MALFORMED_X_M_L, e);
        }
    }

    private <T> T readXmlBody(byte[] body, Class<T> type)
            throws S3Exception {
        return readXmlBody(new ByteArrayInputStream(body), type);
    }

    private static String formatIso8601Date(Date date) {
        synchronized (ISO8601_DATE_FORMAT) {
            return ISO8601_DATE_FORMAT.format(date);
        }
    }

    private static String getBlobStoreType(BlobStore blobStore) {
        BlobStore inner = blobStore;
        while (inner instanceof org.gaul.s3proxy.blobstore.ForwardingBlobStore fbs) {
            inner = fbs.delegate();
        }
        String name = inner.getClass().getName();
        if (name.contains(".azureblob.")) {
            return "azureblob";
        }
        if (name.contains(".gcloudsdk.")) {
            return "google-cloud-storage";
        }
        if (name.contains(".awssdk.")) {
            return "aws-s3";
        }
        if (name.contains(".openstackswift.")) {
            return "openstack-swift";
        }
        if (name.contains(".sftp.")) {
            return "sftp";
        }
        if (name.contains(".nio2blob.")) {
            return name.endsWith(".TransientNio2BlobStore") ?
                    "transient" : "filesystem";
        }
        return "";
    }

    /**
     * Name of the stub blob holding multipart-upload metadata for an upload id
     * on MULTIPART_REQUIRES_STUB backends.  The returned name is filtered from
     * list() so the stub is not exposed as a user-visible object.
     */
    private static String multipartStubName(String uploadId) {
        return MULTIPART_STUB_PREFIX + uploadId;
    }

    private static boolean isValidContainer(String containerName) {
        if (containerName == null ||
                containerName.length() < 3 || containerName.length() > 255 ||
                containerName.startsWith(".") || containerName.endsWith(".") ||
                validateIpAddress(containerName) ||
                !VALID_BUCKET_FIRST_CHAR.matches(containerName.charAt(0)) ||
                !VALID_BUCKET.matchesAllOf(containerName)) {
            return false;
        }
        return true;
    }

    public final void doHandle(HttpServletRequest baseRequest,
            HttpServletRequest request, HttpServletResponse response,
            InputStream is, @Nullable RequestContext ctx)
            throws IOException, S3Exception {
        String method = request.getMethod();
        String uri = request.getRequestURI();
        String originalUri = request.getRequestURI();

        String healthzUri = servicePath.isEmpty() ? "/healthz" :
                servicePath + "/healthz";
        if (healthzUri.equals(uri) && "GET".equalsIgnoreCase(method)) {
            handleStatuszRequest(response);
            return;
        }

        if (!this.servicePath.isEmpty()) {
            if (uri.length() > this.servicePath.length()) {
                uri = uri.substring(this.servicePath.length());
            }
        }

        logger.debug("request: {}", request);
        String hostHeader = request.getHeader(HttpHeaders.HOST);
        if (hostHeader != null && virtualHost.isPresent()) {
            hostHeader = HostAndPort.fromString(hostHeader).getHost();
            String virtualHostSuffix = "." + virtualHost.orElseThrow();
            if (!hostHeader.equals(virtualHost.orElseThrow())) {
                if (hostHeader.endsWith(virtualHostSuffix)) {
                    String bucket = hostHeader.substring(0,
                            hostHeader.length() - virtualHostSuffix.length());
                    uri = "/" + bucket + uri;
                } else {
                    String bucket = hostHeader.toLowerCase();
                    uri = "/" + bucket + uri;
                }
            }
        }

        response.addHeader(AwsHttpHeaders.REQUEST_ID, generateRequestId());

        boolean hasDateHeader = false;
        boolean hasXAmzDateHeader = false;
        for (String headerName : Collections.list(request.getHeaderNames())) {
            for (String headerValue : Collections.list(request.getHeaders(
                    headerName))) {
                logger.trace("header: {}: {}", headerName,
                        Strings.nullToEmpty(headerValue));
            }
            if (headerName.equalsIgnoreCase(HttpHeaders.DATE)) {
                hasDateHeader = true;
            } else if (headerName.equalsIgnoreCase(AwsHttpHeaders.DATE)) {
                if (!Strings.isNullOrEmpty(request.getHeader(
                        AwsHttpHeaders.DATE))) {
                    hasXAmzDateHeader = true;
                }
            }
        }
        boolean haveBothDateHeader = false;
        if (hasDateHeader && hasXAmzDateHeader) {
            haveBothDateHeader = true;
        }

        // The bucket and key the request names, decoded once here so that the
        // anonymous path below and the authenticated one further down agree
        // about what they are.  getRequestURI leaves them as they arrived, so
        // reading them raw looks for a key spelled with the escapes rather
        // than the key those escapes stand for.
        String[] path = uri.split("/", 3);
        for (int i = 0; i < path.length; i++) {
            path[i] = URLDecoder.decode(path[i], StandardCharsets.UTF_8);
        }

        // when access information is not provided in request header,
        // treat it as anonymous, return all public accessible information
        if (!anonymousIdentity &&
                (method.equals("GET") || method.equals("HEAD") ||
                method.equals("POST") || method.equals("OPTIONS")) &&
                request.getHeader(HttpHeaders.AUTHORIZATION) == null &&
                // v2 or /v4
                request.getParameter("X-Amz-Algorithm") == null && // v4 query
                request.getParameter("AWSAccessKeyId") == null &&  // v2 query
                defaultBlobStore != null) {
            doHandleAnonymous(request, response, is, uri, path,
                    defaultBlobStore, ctx);
            return;
        }

        // should according the AWSAccessKeyId=  Signature  or auth header nil
        if (!anonymousIdentity && !hasDateHeader && !hasXAmzDateHeader &&
                request.getParameter("X-Amz-Date") == null &&
                request.getParameter("Expires") == null) {
            throw new S3Exception(S3ErrorCode.ACCESS_DENIED,
                    "AWS authentication requires a valid Date or" +
                    " x-amz-date header");
        }

        BlobStore blobStore;
        String requestIdentity = null;
        String headerAuthorization = request.getHeader(
                HttpHeaders.AUTHORIZATION);
        S3AuthorizationHeader authHeader = null;
        boolean presignedUrl = false;

        if (!anonymousIdentity) {
            // An Authorization header naming a scheme that is not ours belongs
            // to something else the caller is talking to -- S3 reads the
            // signature out of the query string in that case rather than
            // refusing the request, so a presigned URL keeps working when the
            // client also carries a bearer token of its own.  A header naming
            // our scheme but failing to parse is still an error: falling back
            // would answer a malformed signature with AccessDenied instead.
            if (!Strings.isNullOrEmpty(headerAuthorization) &&
                    S3AuthorizationHeader.hasAwsScheme(headerAuthorization)) {
                try {
                    authHeader = new S3AuthorizationHeader(headerAuthorization);
                    //whether v2 or v4 (normal header and query)
                } catch (IllegalArgumentException iae) {
                    throw new S3Exception(S3ErrorCode.INVALID_ARGUMENT, iae);
                }
            }
            if (authHeader == null) {
                String algorithm = request.getParameter("X-Amz-Algorithm");
                if (algorithm == null) { //v2 query
                    String identity = request.getParameter("AWSAccessKeyId");
                    String signature = request.getParameter("Signature");
                    if (identity == null || signature == null) {
                        throw new S3Exception(S3ErrorCode.ACCESS_DENIED);
                    }
                    headerAuthorization = "AWS " + identity + ":" + signature;
                    presignedUrl = true;
                } else if (algorithm.equals("AWS4-HMAC-SHA256")) { //v4 query
                    String credential = request.getParameter(
                            "X-Amz-Credential");
                    String signedHeaders = request.getParameter(
                            "X-Amz-SignedHeaders");
                    String signature = request.getParameter(
                            "X-Amz-Signature");
                    if (credential == null || signedHeaders == null ||
                            signature == null) {
                        throw new S3Exception(S3ErrorCode.ACCESS_DENIED);
                    }
                    headerAuthorization = "AWS4-HMAC-SHA256" +
                            " Credential=" + credential +
                            ", requestSignedHeaders=" + signedHeaders +
                            ", Signature=" + signature;
                    presignedUrl = true;
                } else {
                    throw new IllegalArgumentException("unknown algorithm: " +
                            algorithm);
                }

                try {
                    authHeader = new S3AuthorizationHeader(headerAuthorization);
                    //whether v2 or v4 (normal header and query)
                } catch (IllegalArgumentException iae) {
                    throw new S3Exception(S3ErrorCode.INVALID_ARGUMENT, iae);
                }
            }
            requestIdentity = authHeader.getIdentity();
        }

        long dateSkew = 0; //date for timeskew check

        //v2 GET /s3proxy-1080747708/foo?AWSAccessKeyId=local-identity&Expires=
        //1510322602&Signature=UTyfHY1b1Wgr5BFEn9dpPlWdtFE%3D)
        //have no date

        // non-anonymous requests always parse an Authorization header above
        if (authHeader != null) {
            boolean haveDate = true;

            AuthenticationType finalAuthType = null;
            if (authHeader.getAuthenticationType() ==
                    AuthenticationType.AWS_V2 &&
                    (authenticationType == AuthenticationType.AWS_V2 ||
                    authenticationType == AuthenticationType.AWS_V2_OR_V4)) {
                finalAuthType = AuthenticationType.AWS_V2;
            } else if (
                authHeader.getAuthenticationType() ==
                        AuthenticationType.AWS_V4 &&
                        (authenticationType == AuthenticationType.AWS_V4 ||
                    authenticationType == AuthenticationType.AWS_V2_OR_V4)) {
                finalAuthType = AuthenticationType.AWS_V4;
            } else if (authenticationType != AuthenticationType.NONE) {
                throw new S3Exception(S3ErrorCode.ACCESS_DENIED);
            }

            // An x-amz-date that is present but unparseable -- empty or
            // malformed -- carries no time to compare against.  Answer
            // AccessDenied the way S3 does, rather than deferring to the
            // signature comparison below, which fails for an unrelated reason
            // and reports a misleading SignatureDoesNotMatch.
            String xAmzDate = request.getHeader(AwsHttpHeaders.DATE);
            if (xAmzDate != null) { //format diff between v2 and v4
                if (xAmzDate.isBlank()) {
                    throw new S3Exception(S3ErrorCode.ACCESS_DENIED,
                            "AWS authentication requires a valid Date or" +
                            " x-amz-date header");
                }
                try {
                    if (finalAuthType == AuthenticationType.AWS_V2) {
                        dateSkew = request.getDateHeader(AwsHttpHeaders.DATE);
                        dateSkew /= 1000;
                        //case sensitive?
                    } else if (finalAuthType == AuthenticationType.AWS_V4) {
                        dateSkew = parseIso8601(xAmzDate);
                    }
                } catch (IllegalArgumentException iae) {
                    throw new S3Exception(S3ErrorCode.ACCESS_DENIED,
                            "AWS authentication requires a valid Date or" +
                            " x-amz-date header", iae);
                }
            } else if (hasDateHeader) {
                try {
                    dateSkew = request.getDateHeader(HttpHeaders.DATE);
                    dateSkew /= 1000;
                } catch (IllegalArgumentException iae) {
                    try {
                        dateSkew = parseIso8601(request.getHeader(
                                HttpHeaders.DATE));
                    } catch (IllegalArgumentException iae2) {
                        throw new S3Exception(S3ErrorCode.ACCESS_DENIED, iae);
                    }
                }
            } else {
                haveDate = false;
            }
            if (haveDate) {
                isTimeSkewed(dateSkew, presignedUrl);
            }
        }

        boolean writeMethod = method.equals("PUT") || method.equals("DELETE");
        for (String parameter : Collections.list(
                request.getParameterNames())) {
            if (UNSUPPORTED_PARAMETERS.contains(parameter) ||
                    (writeMethod &&
                            UNSUPPORTED_WRITE_PARAMETERS.contains(parameter))) {
                logger.error("Unknown parameters {} with URI {}",
                        parameter, request.getRequestURI());
                throw new S3Exception(S3ErrorCode.NOT_IMPLEMENTED);
            }
        }

        // emit NotImplemented for unknown x-amz- headers
        for (String headerName : Collections.list(request.getHeaderNames())) {
            headerName = headerName.toLowerCase();
            if (ignoreUnknownHeaders) {
                continue;
            }
            if (!headerName.startsWith("x-amz-")) {
                continue;
            }
            if (headerName.startsWith(USER_METADATA_PREFIX)) {
                continue;
            }
            if (!SUPPORTED_X_AMZ_HEADERS.contains(headerName)) {
                logger.error("Unknown header {} with URI {}",
                        headerName, request.getRequestURI());
                throw new S3Exception(S3ErrorCode.NOT_IMPLEMENTED);
            }
        }

        AccessGrant grant = blobStoreLocator.locateBlobStore(
                requestIdentity, path.length > 1 ? path[1] : null,
                path.length > 2 ? path[2] : null);
        if (anonymousIdentity) {
            if (grant == null) {
                throw new S3Exception(S3ErrorCode.ACCESS_DENIED);
            }
            // A presigned URL states when it stops working, and it stops
            // working here too.  The proxy cannot check the signature over
            // that window without a credential to check it against, so this
            // says nothing about who sent the request -- anyone who can reach
            // a proxy running without authorization can read from it, expiry
            // or no expiry.  What it does is keep a URL from outliving what it
            // says: a caller who asks for fifteen seconds and gets an object
            // an hour later has been told something untrue.
            checkPresignedExpiry(request);
            blobStore = grant.blobStore();
            String contentSha256 = request.getHeader(
                    AwsHttpHeaders.CONTENT_SHA256);
            if ("STREAMING-AWS4-HMAC-SHA256-PAYLOAD".equals(contentSha256)) {
                is = new ChunkedInputStream(is, v4MaxChunkSize);
            } else if ("STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER".equals(
                    contentSha256) ||
                    "STREAMING-UNSIGNED-PAYLOAD-TRAILER".equals(
                    contentSha256)) {
                // The proxy does not verify per-chunk signatures when
                // authorization is disabled, so the signed and unsigned
                // trailer variants decode identically.
                is = new ChunkedInputStream(is, v4MaxChunkSize,
                        request.getHeader(AwsHttpHeaders.TRAILER));
            }
        } else if (requestIdentity == null) {
            throw new S3Exception(S3ErrorCode.ACCESS_DENIED);
        } else {
            if (grant == null) {
                throw new S3Exception(S3ErrorCode.INVALID_ACCESS_KEY_ID);
            }
            // non-anonymous requests always parse an Authorization header
            requireNonNull(authHeader);

            String credential = grant.credential().orElseThrow(
                    () -> new S3Exception(S3ErrorCode.INVALID_ACCESS_KEY_ID));
            blobStore = grant.blobStore();

            checkPresignedExpiry(request);
            // The aim ?
            switch (authHeader.getAuthenticationType()) {
            case AWS_V2 -> {
                switch (authenticationType) {
                case AWS_V2, AWS_V2_OR_V4, NONE -> { }
                default -> throw new S3Exception(S3ErrorCode.ACCESS_DENIED);
                }
            }
            case AWS_V4 -> {
                switch (authenticationType) {
                case AWS_V4, AWS_V2_OR_V4, NONE -> { }
                default -> throw new S3Exception(S3ErrorCode.ACCESS_DENIED);
                }
            }
            case NONE -> { }
            default -> throw new IllegalArgumentException("Unhandled type: " +
                    authHeader.getAuthenticationType());
            }

            String expectedSignature = null;
            AwsSignature.SignatureDetail signatureDetail = null;

            if (authHeader.getHmacAlgorithm() == null) { //v2
                // When presigned url is generated, it doesn't consider
                // service path
                String uriForSigning = presignedUrl ? uri : this.servicePath +
                        uri;
                signatureDetail = AwsSignature.createAuthorizationSignature(
                        request, uriForSigning, credential, presignedUrl,
                        haveBothDateHeader);
                expectedSignature = signatureDetail.signature();
                // The canonicalized resource of a bucket-level request is
                // "/bucket/": the request URI relative to the bucket is "/",
                // which a virtual-host-style request line carries literally
                // while a path-style one carries only "/bucket".  Clients sign
                // the former in both cases, so accept it alongside the URI as
                // sent.
                if (!constantTimeEquals(expectedSignature,
                        authHeader.getSignature()) &&
                        isBucketRootUri(uri)) {
                    signatureDetail =
                            AwsSignature.createAuthorizationSignature(
                                    request, uriForSigning + "/", credential,
                                    presignedUrl, haveBothDateHeader);
                    expectedSignature = signatureDetail.signature();
                }
            } else {
                String contentSha256 = request.getHeader(
                        AwsHttpHeaders.CONTENT_SHA256);
                try {
                    byte[] payload;
                    if (request.getParameter("X-Amz-Algorithm") != null) {
                        payload = new byte[0];
                    } else if ("STREAMING-AWS4-HMAC-SHA256-PAYLOAD".equals(
                            contentSha256) ||
                            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER".equals(
                            contentSha256)) {
                        payload = new byte[0];
                        // ChunkedInputStream constructed below after deriving
                        // the signing key so per-chunk signatures can be
                        // verified.
                    } else if ("STREAMING-UNSIGNED-PAYLOAD-TRAILER".equals(contentSha256)) {
                        payload = new byte[0];
                        is = new ChunkedInputStream(is, v4MaxChunkSize, request.getHeader(AwsHttpHeaders.TRAILER));
                    } else if ("UNSIGNED-PAYLOAD".equals(contentSha256)) {
                        payload = new byte[0];
                    } else {
                        // The signature covers a digest of the body, so the
                        // body has to be in hand before the request can be
                        // authenticated: everything read here is read on
                        // behalf of a caller who has so far offered only an
                        // access key id, which is not a secret.  Refuse a
                        // length that says up front it will not fit, rather
                        // than reading the limit's worth to find out, and
                        // read a length that will fit into a buffer of
                        // exactly that size, since growing one of unknown
                        // size ends up holding twice the body it keeps.
                        long declaredLength = request.getContentLengthLong();
                        if (declaredLength > v4MaxNonChunkedRequestSize) {
                            throw new S3Exception(
                                    S3ErrorCode.MAX_MESSAGE_LENGTH_EXCEEDED);
                        }
                        if (declaredLength >= 0 &&
                                declaredLength <= MAX_BUFFERED_PAYLOAD) {
                            payload = is.readNBytes((int) declaredLength);
                        } else {
                            // A body of unannounced length, e.g. one framed
                            // by Transfer-Encoding: chunked.
                            payload = ByteStreams.limit(is,
                                    v4MaxNonChunkedRequestSize + 1)
                                    .readAllBytes();
                            if (payload.length ==
                                    v4MaxNonChunkedRequestSize + 1) {
                                throw new S3Exception(
                                        S3ErrorCode
                                        .MAX_MESSAGE_LENGTH_EXCEEDED);
                            }
                        }

                        // maybe we should check this when signing,
                        // a lot of dup code with aws sign code.
                        MessageDigest md = MessageDigest.getInstance(
                            authHeader.getHashAlgorithm());
                        byte[] hash = md.digest(payload);
                        if (!BaseEncoding.base16().lowerCase().encode(hash)
                                .equals(contentSha256)) {
                            throw new S3Exception(
                                    S3ErrorCode
                                    .X_AMZ_CONTENT_S_H_A_256_MISMATCH);
                        }
                        is = new ByteArrayInputStream(payload);
                    }

                    // originalUri already includes the service path and, unlike
                    // uri, does not have the virtual host bucket prepended,
                    // matching what clients sign for v4.
                    String uriForSigning = originalUri;
                    String pinnedSha256 = AwsSignature.pinnedPayloadHash(
                            baseRequest);
                    signatureDetail = AwsSignature
                            .createAuthorizationSignatureV4(// v4 sign
                            baseRequest, authHeader, payload, uriForSigning,
                            credential, presignedUrl, pinnedSha256);
                    expectedSignature = signatureDetail.signature();
                    // A URL that pins a payload hash may have signed it on the
                    // payload line or left UNSIGNED-PAYLOAD there: the AWS SDK
                    // presigner writes the token whatever headers it signs,
                    // while other signers write the hash.  Both spellings need
                    // the same secret, so accepting either costs nothing.
                    if (pinnedSha256 != null && !constantTimeEquals(
                            expectedSignature, authHeader.getSignature())) {
                        signatureDetail = AwsSignature
                                .createAuthorizationSignatureV4(
                                baseRequest, authHeader, payload, uriForSigning,
                                credential, presignedUrl, /*pinnedHash=*/ null);
                        expectedSignature = signatureDetail.signature();
                    }
                    if ("STREAMING-AWS4-HMAC-SHA256-PAYLOAD".equals(
                            contentSha256) ||
                            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER".equals(
                            contentSha256)) {
                        byte[] signingKey = AwsSignature.deriveSigningKeyV4(
                                authHeader, credential);
                        String scope = authHeader.getDate() + "/" +
                                authHeader.getRegion() + "/" +
                                authHeader.getService() + "/aws4_request";
                        String timestamp = request.getHeader(
                                AwsHttpHeaders.DATE);
                        if (timestamp == null) {
                            timestamp = request.getParameter("X-Amz-Date");
                        }
                        String trailer = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
                                .equals(contentSha256) ?
                                request.getHeader(AwsHttpHeaders.TRAILER) :
                                null;
                        is = new ChunkedInputStream(is, v4MaxChunkSize,
                                expectedSignature, signingKey,
                                authHeader.getHmacAlgorithm(), timestamp,
                                scope, trailer);
                    }
                } catch (InvalidKeyException | NoSuchAlgorithmException e) {
                    throw new S3Exception(S3ErrorCode.INVALID_ARGUMENT, e);
                }
            }

            // AWS does not check signatures with OPTIONS verb
            if (!method.equals("OPTIONS") && !constantTimeEquals(
                    expectedSignature, authHeader.getSignature())) {
                throw signatureDoesNotMatch(baseRequest, authHeader,
                        signatureDetail, presignedUrl);
            }

            // A presigned URL that signed x-amz-content-sha256 pins the body
            // it may upload, which is the point of signing it: the URL becomes
            // usable for one payload rather than any.  Enforce that as the
            // body streams by, since the hash arrived signed and needs no
            // buffering to check, unlike the header-authorized path above.
            String pinnedSha256 = AwsSignature.pinnedPayloadHash(baseRequest);
            if (pinnedSha256 != null) {
                is = new ChecksumValidatingInputStream(is, Hashing.sha256(),
                        BaseEncoding.base16().lowerCase().decode(
                                pinnedSha256.toLowerCase()),
                        /*bigEndianInt=*/ false,
                        request.getContentLengthLong(),
                        S3ErrorCode.X_AMZ_CONTENT_S_H_A_256_MISMATCH);
            }
        }

        // Validate container name
        if (!uri.equals("/") && !isValidContainer(path[1])) {
            if (method.equals("PUT") &&
                    (path.length <= 2 || path[2].isEmpty()) &&
                    !"".equals(request.getParameter("acl")))  {
                throw new S3Exception(S3ErrorCode.INVALID_BUCKET_NAME);
            } else {
                throw new S3Exception(S3ErrorCode.NO_SUCH_BUCKET);
            }
        }

        checkVersionId(request, blobStore);

        String uploadId = request.getParameter("uploadId");

        if (ctx != null && path.length > 1 && !path[1].isEmpty()) {
            ctx.setBucket(path[1]);
        }

        switch (method) {
        case "DELETE" -> {
            if (path.length <= 2 || path[2].isEmpty()) {
                // Bucket subresources that cannot be deleted must not fall
                // through to DeleteBucket, which ignores the parameter and
                // would remove the bucket itself.
                if (request.getParameter("versioning") != null ||
                        request.getParameter("versions") != null) {
                    throw new S3Exception(S3ErrorCode.NOT_IMPLEMENTED);
                }
                setOperation(ctx, S3Operation.DELETE_BUCKET);
                handleContainerDelete(request, response, blobStore, path[1]);
                return;
            } else if (uploadId != null) {
                setOperation(ctx, S3Operation.ABORT_MULTIPART_UPLOAD);
                handleAbortMultipartUpload(request, response, blobStore,
                        path[1], path[2], uploadId);
                return;
            } else {
                setOperation(ctx, S3Operation.DELETE_OBJECT);
                handleBlobRemove(request, response, blobStore, path[1],
                        path[2]);
                return;
            }
        }
        case "GET" -> {
            if (uri.equals("/")) {
                setOperation(ctx, S3Operation.LIST_BUCKETS);
                handleContainerList(request, response, blobStore);
                return;
            } else if (path.length <= 2 || path[2].isEmpty()) {
                if (request.getParameter("acl") != null) {
                    setOperation(ctx, S3Operation.GET_BUCKET_ACL);
                    handleGetContainerAcl(request, response, blobStore,
                            path[1]);
                    return;
                } else if (request.getParameter("location") != null) {
                    setOperation(ctx, S3Operation.GET_BUCKET_LOCATION);
                    handleContainerLocation(request, response);
                    return;
                } else if (request.getParameter("policy") != null) {
                    setOperation(ctx, S3Operation.GET_BUCKET_POLICY);
                    handleBucketPolicy(blobStore, path[1]);
                    return;
                } else if (request.getParameter("uploads") != null) {
                    setOperation(ctx, S3Operation.LIST_MULTIPART_UPLOADS);
                    handleListMultipartUploads(request, response, blobStore,
                            path[1]);
                    return;
                } else if (request.getParameter("versioning") != null) {
                    setOperation(ctx, S3Operation.GET_BUCKET_VERSIONING);
                    handleGetBucketVersioning(request, response, blobStore,
                            path[1]);
                    return;
                } else if (request.getParameter("versions") != null) {
                    setOperation(ctx, S3Operation.LIST_OBJECT_VERSIONS);
                    handleListObjectVersions(request, response, blobStore,
                            path[1]);
                    return;
                }
                setOperation(ctx, S3Operation.LIST_OBJECTS_V2);
                handleBlobList(request, response, blobStore, path[1]);
                return;
            } else {
                if (request.getParameter("acl") != null) {
                    setOperation(ctx, S3Operation.GET_OBJECT_ACL);
                    handleGetBlobAcl(request, response, blobStore, path[1],
                            path[2]);
                    return;
                } else if (request.getParameter("attributes") != null) {
                    setOperation(ctx, S3Operation.GET_OBJECT_ATTRIBUTES);
                    handleGetObjectAttributes(request, response, blobStore,
                            path[1], path[2]);
                    return;
                } else if (uploadId != null) {
                    setOperation(ctx, S3Operation.LIST_PARTS);
                    handleListParts(request, response, blobStore, path[1],
                            path[2], uploadId);
                    return;
                }
                setOperation(ctx, S3Operation.GET_OBJECT);
                handleGetBlob(request, response, blobStore, path[1],
                        path[2]);
                return;
            }
        }
        case "HEAD" -> {
            if (path.length <= 2 || path[2].isEmpty()) {
                setOperation(ctx, S3Operation.HEAD_BUCKET);
                handleContainerExists(request, response, blobStore, path[1]);
                return;
            } else {
                setOperation(ctx, S3Operation.HEAD_OBJECT);
                handleBlobMetadata(request, response, blobStore, path[1],
                        path[2]);
                return;
            }
        }
        case "POST" -> {
            if (request.getParameter("delete") != null) {
                setOperation(ctx, S3Operation.DELETE_OBJECTS);
                handleMultiBlobRemove(request, response, is, blobStore,
                        path[1]);
                return;
            } else if (request.getParameter("uploads") != null) {
                setOperation(ctx, S3Operation.CREATE_MULTIPART_UPLOAD);
                handleInitiateMultipartUpload(request, response, blobStore,
                        path[1], path[2]);
                return;
            } else if (uploadId != null &&
                    request.getParameter("partNumber") == null) {
                setOperation(ctx, S3Operation.COMPLETE_MULTIPART_UPLOAD);
                handleCompleteMultipartUpload(request, response, is, blobStore,
                        path[1], path[2], uploadId);
                return;
            }
        }
        case "PUT" -> {
            if (path.length <= 2 || path[2].isEmpty()) {
                if (request.getParameter("acl") != null) {
                    setOperation(ctx, S3Operation.PUT_BUCKET_ACL);
                    handleSetContainerAcl(request, response, is, blobStore,
                            path[1]);
                    return;
                }
                if (request.getParameter("versioning") != null) {
                    setOperation(ctx, S3Operation.PUT_BUCKET_VERSIONING);
                    handleSetBucketVersioning(request, response, is, blobStore,
                            path[1]);
                    return;
                }
                setOperation(ctx, S3Operation.CREATE_BUCKET);
                handleContainerCreate(request, response, is, blobStore,
                        path[1]);
                return;
            } else if (uploadId != null) {
                if (request.getHeader(AwsHttpHeaders.COPY_SOURCE) != null) {
                    setOperation(ctx, S3Operation.UPLOAD_PART_COPY);
                    handleCopyPart(request, response, blobStore,
                            requestIdentity, path[1], path[2], uploadId);
                } else {
                    setOperation(ctx, S3Operation.UPLOAD_PART);
                    handleUploadPart(request, response, is, blobStore, path[1],
                            path[2], uploadId);
                }
                return;
            } else if (request.getHeader(AwsHttpHeaders.COPY_SOURCE) != null) {
                setOperation(ctx, S3Operation.COPY_OBJECT);
                handleCopyBlob(request, response, blobStore,
                        requestIdentity, path[1], path[2]);
                return;
            } else {
                if (request.getParameter("acl") != null) {
                    setOperation(ctx, S3Operation.PUT_OBJECT_ACL);
                    handleSetBlobAcl(request, response, is, blobStore, path[1],
                            path[2]);
                    return;
                }
                setOperation(ctx, S3Operation.PUT_OBJECT);
                handlePutBlob(request, response, is, blobStore, path[1],
                        path[2]);
                return;
            }
        }
        case "OPTIONS" -> {
            setOperation(ctx, S3Operation.OPTIONS_OBJECT);
            handleOptionsBlob(request, response, blobStore, path[1]);
            return;
        }
        default -> { }
        }
        setOperation(ctx, S3Operation.UNKNOWN);
        logger.error("Unknown method {} with URI {}",
                method, request.getRequestURI());
        throw new S3Exception(S3ErrorCode.NOT_IMPLEMENTED);
    }

    private static void setOperation(@Nullable RequestContext ctx,
            S3Operation operation) {
        if (ctx != null) {
            ctx.setOperation(operation);
        }
    }

    /**
     * Refuse the parameters that replace response headers on a read, which S3
     * honours only for a request it can attribute to a caller.  They let the
     * URL decide what the response says it contains -- text/html for an object
     * stored as JSON, say, or a Content-Disposition naming a filename the
     * object does not have.  On a request nobody signed that turns any object
     * a reader can fetch into markup served from the proxy's own origin, so
     * the caller has to prove it holds a credential before it may choose.
     *
     * <p>A presigned URL may still carry them: it reaches doHandle rather than
     * here, and they are part of the query string it signs.
     */
    private static void checkNoResponseHeaderOverrides(
            HttpServletRequest request) throws S3Exception {
        for (String parameter : RESPONSE_HEADER_OVERRIDES) {
            if (request.getParameter(parameter) != null) {
                throw new S3Exception(S3ErrorCode.INVALID_REQUEST,
                        "Request specific response headers cannot be used for" +
                        " anonymous GET requests.");
            }
        }
    }

    private static boolean checkPublicAccess(BlobStore blobStore,
            String containerName, String blobName) throws S3Exception {
        String blobStoreType = getBlobStoreType(blobStore);
        try {
            if (Quirks.NO_BLOB_ACCESS_CONTROL.contains(blobStoreType)) {
                ContainerAccess access = blobStore.getContainerAccess(
                        containerName);
                return access == ContainerAccess.PUBLIC_READ;
            }
            BlobAccess access = blobStore.getBlobAccess(containerName,
                    blobName);
            return access == BlobAccess.PUBLIC_READ;
        } catch (ContainerNotFoundException e) {
            throw new S3Exception(S3ErrorCode.NO_SUCH_BUCKET, e);
        } catch (KeyNotFoundException e) {
            throw new S3Exception(S3ErrorCode.NO_SUCH_KEY, e);
        }
    }

    private void doHandleAnonymous(HttpServletRequest request,
            HttpServletResponse response, InputStream is, String uri,
            String[] path, BlobStore blobStore, @Nullable RequestContext ctx)
            throws IOException, S3Exception {
        String method = request.getMethod();

        if (ctx != null && path.length > 1 && !path[1].isEmpty()) {
            ctx.setBucket(path[1]);
        }

        // The authenticated path refuses a name no bucket can have rather
        // than asking a backend about it, and so does this one: the two
        // disagreeing about what a bucket is called is how a request comes to
        // be answered differently depending on who is asking.
        if (!uri.equals("/") &&
                (path.length <= 1 || !isValidContainer(path[1]))) {
            throw new S3Exception(S3ErrorCode.NO_SUCH_BUCKET);
        }

        if (method.equals("GET") || method.equals("HEAD")) {
            checkNoResponseHeaderOverrides(request);
        }

        checkVersionId(request, blobStore);

        switch (method) {
        case "GET" -> {
            if (uri.equals("/")) {
                setOperation(ctx, S3Operation.LIST_BUCKETS);
                throw new S3Exception(S3ErrorCode.ACCESS_DENIED);
            } else if (path.length <= 2 || path[2].isEmpty()) {
                String containerName = path[1];
                ContainerAccess access = blobStore.getContainerAccess(
                        containerName);
                if (access == ContainerAccess.PRIVATE) {
                    setOperation(ctx, S3Operation.LIST_OBJECTS_V2);
                    throw new S3Exception(S3ErrorCode.ACCESS_DENIED);
                }
                if (request.getParameter("versioning") != null) {
                    setOperation(ctx, S3Operation.GET_BUCKET_VERSIONING);
                    handleGetBucketVersioning(request, response, blobStore,
                            containerName);
                    return;
                }
                if (request.getParameter("versions") != null) {
                    setOperation(ctx, S3Operation.LIST_OBJECT_VERSIONS);
                    handleListObjectVersions(request, response, blobStore,
                            containerName);
                    return;
                }
                setOperation(ctx, S3Operation.LIST_OBJECTS_V2);
                handleBlobList(request, response, blobStore, containerName);
                return;
            } else {
                String containerName = path[1];
                String blobName = path[2];
                if (!checkPublicAccess(blobStore, containerName, blobName)) {
                    setOperation(ctx, S3Operation.GET_OBJECT);
                    throw new S3Exception(S3ErrorCode.ACCESS_DENIED);
                }
                setOperation(ctx, S3Operation.GET_OBJECT);
                handleGetBlob(request, response, blobStore, containerName,
                        blobName);
                return;
            }
        }
        case "HEAD" -> {
            if (path.length <= 2 || path[2].isEmpty()) {
                String containerName = path[1];
                ContainerAccess access = blobStore.getContainerAccess(
                        containerName);
                if (access == ContainerAccess.PRIVATE) {
                    setOperation(ctx, S3Operation.HEAD_BUCKET);
                    throw new S3Exception(S3ErrorCode.ACCESS_DENIED);
                }
                setOperation(ctx, S3Operation.HEAD_BUCKET);
                if (!blobStore.containerExists(containerName)) {
                    throw new S3Exception(S3ErrorCode.NO_SUCH_BUCKET);
                }
            } else {
                String containerName = path[1];
                String blobName = path[2];
                if (!checkPublicAccess(blobStore, containerName, blobName)) {
                    setOperation(ctx, S3Operation.HEAD_OBJECT);
                    throw new S3Exception(S3ErrorCode.ACCESS_DENIED);
                }
                setOperation(ctx, S3Operation.HEAD_OBJECT);
                handleBlobMetadata(request, response, blobStore, containerName,
                        blobName);
            }
            return;
        }
        case "POST" -> {
            if (path.length <= 2 || path[2].isEmpty()) {
                setOperation(ctx, S3Operation.PUT_OBJECT);
                handlePostBlob(request, response, is, path[1]);
                return;
            }
        }
        case "OPTIONS" -> {
            if (uri.equals("/")) {
                setOperation(ctx, S3Operation.OPTIONS_OBJECT);
                throw new S3Exception(S3ErrorCode.ACCESS_DENIED);
            } else {
                String containerName = path[1];
                setOperation(ctx, S3Operation.OPTIONS_OBJECT);
                handleOptionsBlob(request, response, blobStore, containerName);
                return;
            }
        }
        default -> { }
        }
        setOperation(ctx, S3Operation.UNKNOWN);
        logger.error("Unknown method {} with URI {}",
                method, request.getRequestURI());
        throw new S3Exception(S3ErrorCode.NOT_IMPLEMENTED);
    }

    private void handleGetContainerAcl(HttpServletRequest request,
            HttpServletResponse response, BlobStore blobStore,
            String containerName) throws IOException, S3Exception {
        if (!blobStore.containerExists(containerName)) {
            throw new S3Exception(S3ErrorCode.NO_SUCH_BUCKET);
        }
        ContainerAccess access = blobStore.getContainerAccess(containerName);

        response.setCharacterEncoding(UTF_8);
        addCorsResponseHeader(request, response);
        try (Writer writer = response.getWriter()) {
            response.setContentType(XML_CONTENT_TYPE);
            XMLStreamWriter xml = xmlOutputFactory.createXMLStreamWriter(
                    writer);
            xml.writeStartDocument();
            xml.writeStartElement("AccessControlPolicy");
            xml.writeDefaultNamespace(AWS_XMLNS);

            writeOwnerStanza(xml);

            xml.writeStartElement("AccessControlList");

            // S3 lists the group grant ahead of the owner's, which clients
            // rely on to tell the two apart without inspecting every grantee.
            if (access == ContainerAccess.PUBLIC_READ) {
                writeAllUsersReadGrant(xml);
            }

            writeOwnerFullControlGrant(xml);

            xml.writeEndElement();

            xml.writeEndElement();
            xml.flush();
        } catch (XMLStreamException xse) {
            throw new IOException(xse);
        }
    }

    private void handleSetContainerAcl(HttpServletRequest request,
            HttpServletResponse response, InputStream is, BlobStore blobStore,
            String containerName) throws IOException, S3Exception {
        ContainerAccess access;

        String cannedAcl = request.getHeader(AwsHttpHeaders.ACL);
        if (cannedAcl == null || "private".equalsIgnoreCase(cannedAcl)) {
            access = ContainerAccess.PRIVATE;
        } else if ("public-read".equalsIgnoreCase(cannedAcl)) {
            access = ContainerAccess.PUBLIC_READ;
        } else if (CANNED_ACLS.contains(cannedAcl)) {
            throw new S3Exception(S3ErrorCode.NOT_IMPLEMENTED);
        } else {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        var pis = new PushbackInputStream(is);
        int ch = pis.read();
        if (ch != -1) {
            pis.unread(ch);
            AccessControlPolicy policy = readXmlBody(
                    pis, AccessControlPolicy.class);
            String accessString = mapXmlAclsToCannedPolicy(policy);
            if (accessString.equals("private")) {
                access = ContainerAccess.PRIVATE;
            } else if (accessString.equals("public-read")) {
                access = ContainerAccess.PUBLIC_READ;
            } else {
                throw new S3Exception(S3ErrorCode.NOT_IMPLEMENTED);
            }
        }

        blobStore.setContainerAccess(containerName, access);
        addCorsResponseHeader(request, response);
    }

    private void handleGetBlobAcl(HttpServletRequest request,
            HttpServletResponse response, BlobStore blobStore,
            String containerName, String blobName)
            throws IOException, S3Exception {
        // Resolves only the current object; ignoring a versionId would
        // answer with the wrong version's ACL.
        checkVersionId(request);

        BlobAccess access = blobStore.getBlobAccess(containerName, blobName);

        response.setCharacterEncoding(UTF_8);
        addCorsResponseHeader(request, response);
        try (Writer writer = response.getWriter()) {
            response.setContentType(XML_CONTENT_TYPE);
            XMLStreamWriter xml = xmlOutputFactory.createXMLStreamWriter(
                    writer);
            xml.writeStartDocument();
            xml.writeStartElement("AccessControlPolicy");
            xml.writeDefaultNamespace(AWS_XMLNS);

            writeOwnerStanza(xml);

            xml.writeStartElement("AccessControlList");

            if (access == BlobAccess.PUBLIC_READ) {
                writeAllUsersReadGrant(xml);
            }

            writeOwnerFullControlGrant(xml);

            xml.writeEndElement();

            xml.writeEndElement();
            xml.flush();
        } catch (XMLStreamException xse) {
            throw new IOException(xse);
        }
    }

    private void handleSetBlobAcl(HttpServletRequest request,
            HttpServletResponse response, InputStream is, BlobStore blobStore,
            String containerName, String blobName)
            throws IOException, S3Exception {
        // Resolves only the current object; ignoring a versionId would
        // change the wrong version's ACL.
        checkVersionId(request);

        BlobAccess access;

        String cannedAcl = request.getHeader(AwsHttpHeaders.ACL);
        if (cannedAcl == null || "private".equalsIgnoreCase(cannedAcl)) {
            access = BlobAccess.PRIVATE;
        } else if ("public-read".equalsIgnoreCase(cannedAcl)) {
            access = BlobAccess.PUBLIC_READ;
        } else if (CANNED_ACLS.contains(cannedAcl)) {
            throw new S3Exception(S3ErrorCode.NOT_IMPLEMENTED);
        } else {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        var pis = new PushbackInputStream(is);
        int ch = pis.read();
        if (ch != -1) {
            pis.unread(ch);
            AccessControlPolicy policy = readXmlBody(
                    pis, AccessControlPolicy.class);
            String accessString = mapXmlAclsToCannedPolicy(policy);
            if (accessString.equals("private")) {
                access = BlobAccess.PRIVATE;
            } else if (accessString.equals("public-read")) {
                access = BlobAccess.PUBLIC_READ;
            } else {
                throw new S3Exception(S3ErrorCode.NOT_IMPLEMENTED);
            }
        }

        blobStore.setBlobAccess(containerName, blobName, access);
        addCorsResponseHeader(request, response);
    }

    /** Map XML ACLs to a canned policy if an exact transformation exists. */
    private static String mapXmlAclsToCannedPolicy(
            AccessControlPolicy policy) throws S3Exception {
        if (!policy.owner().id().equals(FAKE_OWNER_ID)) {
            throw new S3Exception(S3ErrorCode.NOT_IMPLEMENTED);
        }

        boolean ownerFullControl = false;
        boolean allUsersRead = false;
        if (policy.aclList() != null) {
            for (AccessControlPolicy.AccessControlList.Grant grant :
                    policy.aclList().grants()) {
                if (grant.grantee().type().equals("CanonicalUser") &&
                        grant.grantee().id().equals(FAKE_OWNER_ID) &&
                        grant.permission().equals("FULL_CONTROL")) {
                    ownerFullControl = true;
                } else if (grant.grantee().type().equals("Group") &&
                        grant.grantee().uri().equals("http://acs.amazonaws.com/" +
                                "groups/global/AllUsers") &&
                        grant.permission().equals("READ")) {
                    allUsersRead = true;
                } else {
                    throw new S3Exception(S3ErrorCode.NOT_IMPLEMENTED);
                }
            }
        }

        if (ownerFullControl) {
            if (allUsersRead) {
                return "public-read";
            }
            return "private";
        } else {
            throw new S3Exception(S3ErrorCode.NOT_IMPLEMENTED);
        }
    }

    private void handleContainerList(HttpServletRequest request,
            HttpServletResponse response, BlobStore blobStore)
            throws IOException, S3Exception {
        // S3 lists buckets ordered by name; the backends promise no order of
        // their own, and paginating an unstable one would drop or repeat
        // buckets between pages.
        var buckets = new ArrayList<StorageMetadata>();
        for (StorageMetadata metadata : blobStore.list()) {
            buckets.add(metadata);
        }
        buckets.sort(Comparator.comparing(StorageMetadata::name));

        int maxBuckets = MAX_BUCKETS;
        String maxBucketsString = request.getParameter("max-buckets");
        if (maxBucketsString != null) {
            try {
                maxBuckets = Integer.parseInt(maxBucketsString);
            } catch (NumberFormatException nfe) {
                throw new S3Exception(S3ErrorCode.INVALID_ARGUMENT, nfe);
            }
            if (maxBuckets < 1 || maxBuckets > MAX_BUCKETS) {
                throw new S3Exception(S3ErrorCode.INVALID_ARGUMENT);
            }
        }
        // the token names the last bucket the previous page returned
        String continuationToken = request.getParameter("continuation-token");
        String prefix = request.getParameter("prefix");

        var page = new ArrayList<StorageMetadata>();
        String nextContinuationToken = null;
        for (StorageMetadata metadata : buckets) {
            String name = metadata.name();
            if (prefix != null && !name.startsWith(prefix)) {
                continue;
            }
            if (continuationToken != null &&
                    name.compareTo(continuationToken) <= 0) {
                continue;
            }
            if (page.size() == maxBuckets) {
                nextContinuationToken = page.get(page.size() - 1).name();
                break;
            }
            page.add(metadata);
        }

        response.setCharacterEncoding(UTF_8);
        addCorsResponseHeader(request, response);
        try (Writer writer = response.getWriter()) {
            response.setContentType(XML_CONTENT_TYPE);
            XMLStreamWriter xml = xmlOutputFactory.createXMLStreamWriter(
                    writer);
            xml.writeStartDocument();
            xml.writeStartElement("ListAllMyBucketsResult");
            xml.writeDefaultNamespace(AWS_XMLNS);

            writeOwnerStanza(xml);

            xml.writeStartElement("Buckets");
            for (StorageMetadata metadata : page) {
                xml.writeStartElement("Bucket");

                writeSimpleElement(xml, "Name", metadata.name());

                Date creationDate = metadata.creationDate();
                if (creationDate == null) {
                    // Some providers, e.g., Swift, do not provide container
                    // creation date.  Emit a bogus one to satisfy clients like
                    // s3cmd which require one.
                    creationDate = new Date(0);
                }
                writeSimpleElement(xml, "CreationDate",
                        formatIso8601Date(creationDate).trim());

                xml.writeEndElement();
            }
            xml.writeEndElement();

            // present only while more buckets remain, which is how clients
            // know to stop
            if (nextContinuationToken != null) {
                writeSimpleElement(xml, "ContinuationToken",
                        nextContinuationToken);
            }
            if (prefix != null) {
                writeSimpleElement(xml, "Prefix", prefix);
            }

            xml.writeEndElement();
            xml.flush();
        } catch (XMLStreamException xse) {
            throw new IOException(xse);
        }
    }

    private void handleContainerLocation(HttpServletRequest request,
            HttpServletResponse response) throws IOException {
        response.setCharacterEncoding(UTF_8);
        addCorsResponseHeader(request, response);
        try (Writer writer = response.getWriter()) {
            response.setContentType(XML_CONTENT_TYPE);
            XMLStreamWriter xml = xmlOutputFactory.createXMLStreamWriter(
                    writer);
            xml.writeStartDocument();
            // TODO: using us-standard semantics but could emit actual location
            xml.writeStartElement("LocationConstraint");
            xml.writeDefaultNamespace(AWS_XMLNS);
            xml.writeEndElement();
            xml.flush();
        } catch (XMLStreamException xse) {
            throw new IOException(xse);
        }
    }

    private static void handleBucketPolicy(BlobStore blobStore,
            String containerName) throws S3Exception {
        if (!blobStore.containerExists(containerName)) {
            throw new S3Exception(S3ErrorCode.NO_SUCH_BUCKET);
        }
        throw new S3Exception(S3ErrorCode.NO_SUCH_POLICY);
    }

    /**
     * GetBucketVersioning.  A store without versioning still answers: its
     * buckets have never been versioned, which S3 spells as a configuration
     * with no Status element.
     */
    private void handleGetBucketVersioning(HttpServletRequest request,
            HttpServletResponse response, BlobStore blobStore,
            String containerName) throws IOException, S3Exception {
        VersioningStatus status;
        if (blobStore.supportsVersioning()) {
            status = blobStore.getContainerVersioning(containerName);
        } else {
            if (!blobStore.containerExists(containerName)) {
                throw new S3Exception(S3ErrorCode.NO_SUCH_BUCKET);
            }
            status = null;
        }

        response.setCharacterEncoding(UTF_8);
        addCorsResponseHeader(request, response);
        try (Writer writer = response.getWriter()) {
            response.setContentType(XML_CONTENT_TYPE);
            XMLStreamWriter xml = xmlOutputFactory.createXMLStreamWriter(
                    writer);
            xml.writeStartDocument();
            xml.writeStartElement("VersioningConfiguration");
            xml.writeDefaultNamespace(AWS_XMLNS);
            if (status != null) {
                writeSimpleElement(xml, "Status", status.value());
            }
            xml.writeEndElement();
            xml.flush();
        } catch (XMLStreamException xse) {
            throw new IOException(xse);
        }
    }

    private void handleSetBucketVersioning(HttpServletRequest request,
            HttpServletResponse response, InputStream is, BlobStore blobStore,
            String containerName) throws IOException, S3Exception {
        if (!blobStore.supportsVersioning()) {
            throw new S3Exception(S3ErrorCode.NOT_IMPLEMENTED,
                    "Versioning is not supported.");
        }

        // Bound the buffered body: the configuration is a few elements, but
        // the request is otherwise attacker-controlled.
        byte[] body = ByteStreams.limit(is, v4MaxNonChunkedRequestSize + 1)
                .readAllBytes();
        if (body.length == v4MaxNonChunkedRequestSize + 1) {
            throw new S3Exception(S3ErrorCode.MAX_MESSAGE_LENGTH_EXCEEDED);
        }
        VersioningConfigurationRequest vcr = readXmlBody(body,
                VersioningConfigurationRequest.class);
        if (vcr.mfaDelete() != null) {
            throw new S3Exception(S3ErrorCode.NOT_IMPLEMENTED,
                    "MFA delete is not supported.");
        }
        VersioningStatus status = vcr.status() == null ? null :
                VersioningStatus.fromValue(vcr.status());
        if (status == null) {
            throw new S3Exception(S3ErrorCode.MALFORMED_X_M_L);
        }

        blobStore.setContainerVersioning(containerName, status);
        addCorsResponseHeader(request, response);
    }

    private void handleListObjectVersions(HttpServletRequest request,
            HttpServletResponse response, BlobStore blobStore,
            String containerName) throws IOException, S3Exception {
        if (!blobStore.supportsVersioning()) {
            throw new S3Exception(S3ErrorCode.NOT_IMPLEMENTED,
                    "Versioning is not supported.");
        }

        String encodingType = request.getParameter("encoding-type");
        var optionsBuilder = ListVersionsOptions.builder();
        String prefix = request.getParameter("prefix");
        if (prefix != null && !prefix.isEmpty()) {
            optionsBuilder.prefix(prefix);
        }
        String delimiter = request.getParameter("delimiter");
        if (delimiter != null && !delimiter.isEmpty()) {
            optionsBuilder.delimiter(delimiter);
        }
        String keyMarker = request.getParameter("key-marker");
        if (keyMarker != null) {
            optionsBuilder.keyMarker(keyMarker);
        }
        String versionIdMarker = request.getParameter("version-id-marker");
        if (versionIdMarker != null) {
            optionsBuilder.versionIdMarker(versionIdMarker);
        }

        int maxKeys = 1000;
        String maxKeysString = request.getParameter("max-keys");
        if (maxKeysString != null) {
            try {
                maxKeys = Integer.parseInt(maxKeysString);
            } catch (NumberFormatException nfe) {
                throw new S3Exception(S3ErrorCode.INVALID_ARGUMENT, nfe);
            }
            if (maxKeys < 0) {
                throw new S3Exception(S3ErrorCode.INVALID_ARGUMENT);
            }
            if (maxKeys > 1000) {
                maxKeys = 1000;
            }
        }
        optionsBuilder.maxResults(maxKeys);

        VersionPage page = blobStore.listVersions(containerName,
                optionsBuilder.build());

        addCorsResponseHeader(request, response);
        response.setCharacterEncoding(UTF_8);
        try (Writer writer = response.getWriter()) {
            response.setContentType(XML_CONTENT_TYPE);
            XMLStreamWriter xml = xmlOutputFactory.createXMLStreamWriter(
                    writer);
            xml.writeStartDocument();
            xml.writeStartElement("ListVersionsResult");
            xml.writeDefaultNamespace(AWS_XMLNS);

            writeSimpleElement(xml, "Name", containerName);

            if (prefix == null) {
                xml.writeEmptyElement("Prefix");
            } else {
                writeSimpleElement(xml, "Prefix", encodeBlob(
                        encodingType, prefix));
            }

            if (keyMarker == null) {
                xml.writeEmptyElement("KeyMarker");
            } else {
                writeSimpleElement(xml, "KeyMarker", encodeBlob(
                        encodingType, keyMarker));
            }

            if (versionIdMarker == null) {
                xml.writeEmptyElement("VersionIdMarker");
            } else {
                writeSimpleElement(xml, "VersionIdMarker", versionIdMarker);
            }

            writeSimpleElement(xml, "MaxKeys", String.valueOf(maxKeys));

            if (!Strings.isNullOrEmpty(delimiter)) {
                writeSimpleElement(xml, "Delimiter", encodeBlob(
                        encodingType, delimiter));
            }

            if (encodingType != null && encodingType.equals("url")) {
                writeSimpleElement(xml, "EncodingType", encodingType);
            }

            String nextKeyMarker = page.nextKeyMarker();
            if (nextKeyMarker != null) {
                writeSimpleElement(xml, "IsTruncated", "true");
                writeSimpleElement(xml, "NextKeyMarker", encodeBlob(
                        encodingType, nextKeyMarker));
                String nextVersionIdMarker = page.nextVersionIdMarker();
                if (nextVersionIdMarker != null) {
                    writeSimpleElement(xml, "NextVersionIdMarker",
                            nextVersionIdMarker);
                }
            } else {
                writeSimpleElement(xml, "IsTruncated", "false");
            }

            for (VersionMetadata version : page.versions()) {
                xml.writeStartElement(
                        version.deleteMarker() ? "DeleteMarker" : "Version");

                writeSimpleElement(xml, "Key", encodeBlob(encodingType,
                        version.name()));
                writeSimpleElement(xml, "VersionId", version.versionId());
                writeSimpleElement(xml, "IsLatest",
                        String.valueOf(version.latest()));
                Date lastModified = version.lastModified();
                if (lastModified != null) {
                    writeSimpleElement(xml, "LastModified",
                            formatDate(lastModified));
                }

                if (!version.deleteMarker()) {
                    String eTag = version.eTag();
                    if (eTag != null) {
                        writeSimpleElement(xml, "ETag", maybeQuoteETag(eTag));
                    }
                    Long size = version.size();
                    if (size != null) {
                        writeSimpleElement(xml, "Size", String.valueOf(size));
                    }
                }

                writeOwnerStanza(xml);

                if (!version.deleteMarker()) {
                    writeSimpleElement(xml, "StorageClass",
                            version.storageClass().toString());
                }

                xml.writeEndElement();
            }

            for (String commonPrefix : page.commonPrefixes()) {
                xml.writeStartElement("CommonPrefixes");
                writeSimpleElement(xml, "Prefix", encodeBlob(encodingType,
                        commonPrefix));
                xml.writeEndElement();
            }

            xml.writeEndElement();
            xml.flush();
        } catch (XMLStreamException xse) {
            throw new IOException(xse);
        }
    }

    private void handleListMultipartUploads(HttpServletRequest request,
            HttpServletResponse response, BlobStore blobStore,
            String container) throws IOException, S3Exception {
        String delimiter = request.getParameter("delimiter");
        if (delimiter != null && !delimiter.isEmpty() &&
                !delimiter.equals("/")) {
            throw new S3Exception(S3ErrorCode.NOT_IMPLEMENTED);
        }
        String keyMarker = request.getParameter("key-marker");
        String uploadIdMarker = request.getParameter("upload-id-marker");

        int maxUploads = 1000;
        String maxUploadsString = request.getParameter("max-uploads");
        if (maxUploadsString != null) {
            try {
                maxUploads = Integer.parseInt(maxUploadsString);
            } catch (NumberFormatException nfe) {
                throw new S3Exception(S3ErrorCode.INVALID_ARGUMENT, nfe);
            }
            if (maxUploads < 0) {
                throw new S3Exception(S3ErrorCode.INVALID_ARGUMENT);
            }
            if (maxUploads > 1000) {
                maxUploads = 1000;
            }
        }

        String encodingType = request.getParameter("encoding-type");
        String prefix = request.getParameter("prefix");

        List<MultipartUpload> uploads = blobStore.listMultipartUploads(
                container);

        List<MultipartUpload> filtered = uploads.stream()
                .filter(u -> prefix == null || u.blobName().startsWith(prefix))
                .filter(u -> {
                    if (keyMarker == null) {
                        return true;
                    }
                    int cmp = u.blobName().compareTo(keyMarker);
                    if (cmp > 0) {
                        return true;
                    }
                    if (cmp == 0 && uploadIdMarker != null) {
                        return u.id().compareTo(uploadIdMarker) > 0;
                    }
                    return false;
                })
                .sorted(Comparator.comparing(MultipartUpload::blobName)
                        .thenComparing(MultipartUpload::id))
                .collect(Collectors.toList());

        boolean isTruncated = filtered.size() > maxUploads;
        List<MultipartUpload> page = isTruncated ?
                filtered.subList(0, maxUploads) :
                filtered;

        response.setCharacterEncoding(UTF_8);
        addCorsResponseHeader(request, response);
        try (Writer writer = response.getWriter()) {
            response.setContentType(XML_CONTENT_TYPE);
            XMLStreamWriter xml = xmlOutputFactory.createXMLStreamWriter(
                    writer);
            xml.writeStartDocument();
            xml.writeStartElement("ListMultipartUploadsResult");
            xml.writeDefaultNamespace(AWS_XMLNS);

            writeSimpleElement(xml, "Bucket", container);

            if (Strings.isNullOrEmpty(keyMarker)) {
                xml.writeEmptyElement("KeyMarker");
            } else {
                writeSimpleElement(xml, "KeyMarker", encodeBlob(
                        encodingType, keyMarker));
            }
            if (Strings.isNullOrEmpty(uploadIdMarker)) {
                xml.writeEmptyElement("UploadIdMarker");
            } else {
                writeSimpleElement(xml, "UploadIdMarker", uploadIdMarker);
            }
            if (isTruncated && !page.isEmpty()) {
                MultipartUpload last = page.get(page.size() - 1);
                writeSimpleElement(xml, "NextKeyMarker", encodeBlob(
                        encodingType, last.blobName()));
                writeSimpleElement(xml, "NextUploadIdMarker", last.id());
            } else {
                xml.writeEmptyElement("NextKeyMarker");
                xml.writeEmptyElement("NextUploadIdMarker");
            }
            if (Strings.isNullOrEmpty(delimiter)) {
                xml.writeEmptyElement("Delimiter");
            } else {
                writeSimpleElement(xml, "Delimiter", encodeBlob(
                        encodingType, delimiter));
            }

            if (Strings.isNullOrEmpty(prefix)) {
                xml.writeEmptyElement("Prefix");
            } else {
                writeSimpleElement(xml, "Prefix", encodeBlob(
                        encodingType, prefix));
            }

            writeSimpleElement(xml, "MaxUploads", String.valueOf(maxUploads));
            writeSimpleElement(xml, "IsTruncated",
                    String.valueOf(isTruncated));

            if (encodingType != null && encodingType.equals("url")) {
                writeSimpleElement(xml, "EncodingType", encodingType);
            }

            for (MultipartUpload upload : page) {
                xml.writeStartElement("Upload");

                writeSimpleElement(xml, "Key", encodeBlob(
                        encodingType, upload.blobName()));
                writeSimpleElement(xml, "UploadId", upload.id());
                writeInitiatorStanza(xml);
                writeOwnerStanza(xml);
                // TODO: bogus value
                writeSimpleElement(xml, "StorageClass", "STANDARD");

                // TODO: bogus value
                writeSimpleElement(xml, "Initiated",
                        formatIso8601Date(new Date()));

                xml.writeEndElement();
            }

            // TODO: CommonPrefixes

            xml.writeEndElement();

            xml.flush();
        } catch (XMLStreamException xse) {
            throw new IOException(xse);
        }
    }

    private void handleContainerExists(HttpServletRequest request,
            HttpServletResponse response, BlobStore blobStore,
            String containerName) throws IOException, S3Exception {
        if (!blobStore.containerExists(containerName)) {
            throw new S3Exception(S3ErrorCode.NO_SUCH_BUCKET);
        }
        addCorsResponseHeader(request, response);
    }

    private void handleContainerCreate(HttpServletRequest request,
            HttpServletResponse response, InputStream is, BlobStore blobStore,
            String containerName) throws IOException, S3Exception {
        if (containerName.isEmpty()) {
            throw new S3Exception(S3ErrorCode.METHOD_NOT_ALLOWED);
        }

        // Some clients send this header on every bucket they create, rclone
        // among them, so refusing it outright leaves them unable to create a
        // bucket at all.  Only a bucket that asks for object lock has to be
        // refused: it needs versioning, which S3Proxy does not implement, and
        // creating an ordinary bucket instead would quietly give the caller
        // less than it asked for.
        String objectLock = request.getHeader(
                AwsHttpHeaders.BUCKET_OBJECT_LOCK_ENABLED);
        if (Boolean.parseBoolean(objectLock)) {
            throw new S3Exception(S3ErrorCode.NOT_IMPLEMENTED);
        }

        String contentLengthString = request.getHeader(
                HttpHeaders.CONTENT_LENGTH);
        if (contentLengthString != null) {
            long contentLength;
            try {
                contentLength = Long.parseLong(contentLengthString);
            } catch (NumberFormatException nfe) {
                throw new S3Exception(S3ErrorCode.INVALID_ARGUMENT, nfe);
            }
            if (contentLength < 0) {
                throw new S3Exception(S3ErrorCode.INVALID_ARGUMENT);
            }
        }

        String locationString;
        try (PushbackInputStream pis = new PushbackInputStream(is)) {
            int ch = pis.read();
            if (ch == -1) {
                // handle empty bodies
                locationString = null;
            } else {
                pis.unread(ch);
                CreateBucketRequest cbr = readXmlBody(
                        pis, CreateBucketRequest.class);
                locationString = cbr.locationConstraint();
            }
        }

        // The backend determines the region; clients sending a
        // LocationConstraint other than the backend's region get no special
        // handling.
        logger.debug("Creating bucket with location: {}", locationString);

        // public-read-write grants AllUsers read as well as write.  A
        // ContainerAccess says only whether a container is readable, so the
        // write half is dropped -- but dropping the read half too left a
        // bucket created for anonymous use answering AccessDenied to the
        // anonymous reads its own ACL had allowed.
        String acl = request.getHeader(AwsHttpHeaders.ACL);
        var options = new CreateContainerOptions(
                "public-read".equalsIgnoreCase(acl) ||
                "public-read-write".equalsIgnoreCase(acl));

        boolean created;
        try {
            created = blobStore.createContainer(containerName, options);
        } catch (BucketAlreadyExistsException baee) {
            throw new S3Exception(S3ErrorCode.BUCKET_ALREADY_EXISTS, baee);
        }
        if (!created) {
            throw new S3Exception(S3ErrorCode.BUCKET_ALREADY_OWNED_BY_YOU,
                    S3ErrorCode.BUCKET_ALREADY_OWNED_BY_YOU.getMessage(),
                    null, Map.of("BucketName", containerName));
        }

        response.addHeader(HttpHeaders.LOCATION, "/" + containerName);
        addCorsResponseHeader(request, response);
    }

    private void handleContainerDelete(HttpServletRequest request,
            HttpServletResponse response, BlobStore blobStore,
            String containerName) throws IOException, S3Exception {
        if (!blobStore.containerExists(containerName)) {
            throw new S3Exception(S3ErrorCode.NO_SUCH_BUCKET);
        }

        if (!blobStore.deleteContainerIfEmpty(containerName)) {
            throw new S3Exception(S3ErrorCode.BUCKET_NOT_EMPTY);
        }

        addCorsResponseHeader(request, response);
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }

    private void handleBlobList(HttpServletRequest request,
            HttpServletResponse response, BlobStore blobStore,
            String containerName) throws IOException, S3Exception {
        String blobStoreType = getBlobStoreType(blobStore);
        var optionsBuilder = ListContainerOptions.builder();
        String encodingType = request.getParameter("encoding-type");
        String delimiter = request.getParameter("delimiter");
        if (delimiter != null) {
            optionsBuilder.delimiter(delimiter);
        }
        String prefix = request.getParameter("prefix");
        if (prefix != null && !prefix.isEmpty()) {
            optionsBuilder.prefix(prefix);
        }

        boolean isListV2 = false;
        String marker;
        String listType = request.getParameter("list-type");
        String continuationToken = request.getParameter("continuation-token");
        String startAfter = request.getParameter("start-after");
        if (listType == null) {
            marker = request.getParameter("marker");
        } else if (listType.equals("2")) {
            isListV2 = true;
            // S3 ignores start-after when continuation-token is set rather
            // than refusing the pair: the token already says where the last
            // page ended, so the two cannot disagree about where to resume.
            // Refusing it turned an ordinary paging loop -- a client that
            // names start-after once and then adds the token for each page
            // after -- into a 400 on the second request.
            marker = continuationToken != null ? continuationToken :
                    startAfter;
        } else {
            throw new S3Exception(S3ErrorCode.NOT_IMPLEMENTED);
        }
        if (marker != null) {
            if (Quirks.OPAQUE_MARKERS.contains(blobStoreType)) {
                String realMarker = lastKeyToMarker.getIfPresent(
                        Map.entry(containerName, marker));
                if (realMarker != null) {
                    marker = realMarker;
                }
            }
            optionsBuilder.afterMarker(marker);
        }

        boolean fetchOwner = !isListV2 ||
                "true".equals(request.getParameter("fetch-owner"));

        int maxKeys = 1000;
        String maxKeysString = request.getParameter("max-keys");
        if (maxKeysString != null) {
            try {
                maxKeys = Integer.parseInt(maxKeysString);
            } catch (NumberFormatException nfe) {
                throw new S3Exception(S3ErrorCode.INVALID_ARGUMENT, nfe);
            }
            if (maxKeys < 0) {
                throw new S3Exception(S3ErrorCode.INVALID_ARGUMENT);
            }
            if (maxKeys > 1000) {
                maxKeys = 1000;
            }
        }
        optionsBuilder.maxResults(maxKeys);

        PageSet<? extends StorageMetadata> set = blobStore.list(containerName,
                optionsBuilder.build());

        boolean filterStub = Quirks.MULTIPART_REQUIRES_STUB.contains(
                blobStoreType);
        int filteredCount = set.entries().size();
        if (filterStub) {
            filteredCount = 0;
            for (StorageMetadata sm : set) {
                if (!sm.name().startsWith(MULTIPART_STUB_PREFIX)) {
                    filteredCount++;
                }
            }
        }

        addCorsResponseHeader(request, response);

        response.setCharacterEncoding(UTF_8);
        try (Writer writer = response.getWriter()) {
            response.setContentType(XML_CONTENT_TYPE);
            XMLStreamWriter xml = xmlOutputFactory.createXMLStreamWriter(
                    writer);
            xml.writeStartDocument();
            xml.writeStartElement("ListBucketResult");
            xml.writeDefaultNamespace(AWS_XMLNS);

            writeSimpleElement(xml, "Name", containerName);

            if (prefix == null) {
                xml.writeEmptyElement("Prefix");
            } else {
                writeSimpleElement(xml, "Prefix", encodeBlob(
                        encodingType, prefix));
            }

            if (isListV2) {
                writeSimpleElement(xml, "KeyCount",
                        String.valueOf(filteredCount));
            }
            writeSimpleElement(xml, "MaxKeys", String.valueOf(maxKeys));

            if (!isListV2) {
                if (marker == null) {
                    xml.writeEmptyElement("Marker");
                } else {
                    writeSimpleElement(xml, "Marker", encodeBlob(
                            encodingType, marker));
                }
            } else {
                if (continuationToken == null) {
                    xml.writeEmptyElement("ContinuationToken");
                } else {
                    writeSimpleElement(xml, "ContinuationToken", encodeBlob(
                            encodingType, continuationToken));
                }
                if (startAfter == null) {
                    xml.writeEmptyElement("StartAfter");
                } else {
                    writeSimpleElement(xml, "StartAfter", encodeBlob(
                            encodingType, startAfter));
                }
            }

            if (!Strings.isNullOrEmpty(delimiter)) {
                writeSimpleElement(xml, "Delimiter", encodeBlob(
                        encodingType, delimiter));
            }

            if (encodingType != null && encodingType.equals("url")) {
                writeSimpleElement(xml, "EncodingType", encodingType);
            }

            String nextMarker = set.nextMarker();
            if (nextMarker != null) {
                writeSimpleElement(xml, "IsTruncated", "true");
                writeSimpleElement(xml,
                        isListV2 ? "NextContinuationToken" : "NextMarker",
                        encodeBlob(encodingType, nextMarker));
                if (Quirks.OPAQUE_MARKERS.contains(blobStoreType)) {
                    // A caller may page with the last key it was given rather
                    // than the marker, which S3 allows and which a store with
                    // opaque markers rejects.  Remember which marker produced
                    // that key so the next request can present it instead.
                    // Keyed on the name as the store spells it, since the
                    // marker is read back from the query string already
                    // decoded.  A caller echoing the marker needs no entry:
                    // one this cache does not know passes through untouched,
                    // which is what the store wants anyway.
                    StorageMetadata sm = Streams.findLast(
                            set.entries().stream()).orElse(null);
                    if (sm != null) {
                        lastKeyToMarker.put(
                                Map.entry(containerName, sm.name()),
                                nextMarker);
                    }
                }
            } else {
                writeSimpleElement(xml, "IsTruncated", "false");
            }

            Set<String> commonPrefixes = new TreeSet<>();
            for (StorageMetadata metadata : set) {
                if (filterStub && metadata.name().startsWith(
                        MULTIPART_STUB_PREFIX)) {
                    continue;
                }
                switch (metadata.type()) {
                case FOLDER, RELATIVE_PATH -> {
                    if (delimiter != null) {
                        commonPrefixes.add(metadata.name());
                        continue;
                    }
                }
                default -> { }
                }

                xml.writeStartElement("Contents");

                writeSimpleElement(xml, "Key", encodeBlob(encodingType,
                        metadata.name()));

                Date lastModified = metadata.lastModified();
                if (lastModified != null) {
                    writeSimpleElement(xml, "LastModified",
                            formatDate(lastModified));
                }

                String eTag = metadata.eTag();
                if (eTag != null) {
                    writeSimpleElement(xml, "ETag", maybeQuoteETag(eTag));
                }

                Long size = metadata.size();
                if (size != null) {
                    writeSimpleElement(xml, "Size", String.valueOf(size));
                }

                StorageClass storageClass = metadata.storageClass();
                if (storageClass != null) {
                    writeSimpleElement(xml, "StorageClass",
                            storageClass.toString());
                }

                if (fetchOwner) {
                    writeOwnerStanza(xml);
                }

                xml.writeEndElement();
            }

            for (String commonPrefix : commonPrefixes) {
                xml.writeStartElement("CommonPrefixes");

                writeSimpleElement(xml, "Prefix", encodeBlob(encodingType,
                        commonPrefix));

                xml.writeEndElement();
            }

            xml.writeEndElement();
            xml.flush();
        } catch (XMLStreamException xse) {
            throw new IOException(xse);
        }
    }

    private void handleBlobRemove(HttpServletRequest request,
            HttpServletResponse response, BlobStore blobStore,
            String containerName, String blobName)
            throws IOException, S3Exception {
        // Only directory buckets delete conditionally.  Reject the condition
        // rather than honor the delete and discard it, which would report
        // success for a delete the caller asked not to happen.  The
        // x-amz-if-match-size and x-amz-if-match-last-modified-time forms
        // are already refused as unknown x-amz- headers.
        if (request.getHeader(HttpHeaders.IF_MATCH) != null) {
            throw new S3Exception(S3ErrorCode.NOT_IMPLEMENTED);
        }
        if (blobStore.supportsVersioning()) {
            RemoveResult result = blobStore.removeBlob(containerName,
                    blobName, request.getParameter("versionId"));
            String versionId = result.versionId();
            if (versionId != null) {
                response.addHeader(AwsHttpHeaders.VERSION_ID, versionId);
            }
            if (result.deleteMarker()) {
                response.addHeader(AwsHttpHeaders.DELETE_MARKER, "true");
            }
        } else {
            blobStore.removeBlob(containerName, blobName);
        }
        addCorsResponseHeader(request, response);
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }

    /**
     * Validate the request body against Content-MD5 (legacy) or any
     * x-amz-checksum-* header (modern AWS SDKs).  Throws if no checksum is
     * present or if validation fails.
     */
    @SuppressWarnings("deprecation")
    private static void validateMultiBlobRemoveChecksum(
            HttpServletRequest request, byte[] body) throws S3Exception {
        String contentMD5 = request.getHeader(HttpHeaders.CONTENT_MD5);
        if (contentMD5 != null) {
            HashCode expected;
            try {
                expected = HashCode.fromBytes(
                        Base64.getDecoder().decode(contentMD5));
            } catch (IllegalArgumentException iae) {
                throw new S3Exception(S3ErrorCode.INVALID_DIGEST, iae);
            }
            if (expected.bits() != MD5.bits()) {
                throw new S3Exception(S3ErrorCode.INVALID_DIGEST);
            }
            if (!expected.equals(MD5.hashBytes(body))) {
                throw new S3Exception(S3ErrorCode.BAD_DIGEST);
            }
            return;
        }
        // Match modern AWS SDKs that send a flexible checksum header in
        // place of Content-MD5.  Try each algorithm we recognise; the SDK
        // sends only one.
        if (validateChecksumHeader(request, body, "x-amz-checksum-crc32",
                Hashing.crc32(), /*bigEndianInt=*/ true) ||
                validateChecksumHeader(request, body, "x-amz-checksum-crc32c",
                        Hashing.crc32c(), /*bigEndianInt=*/ true) ||
                validateChecksumHeader(request, body, "x-amz-checksum-sha1",
                        Hashing.sha1(), /*bigEndianInt=*/ false) ||
                validateChecksumHeader(request, body, "x-amz-checksum-sha256",
                        Hashing.sha256(), /*bigEndianInt=*/ false)) {
            return;
        }
        throw new S3Exception(S3ErrorCode.INVALID_REQUEST,
                "Missing required header for this request: Content-Md5");
    }

    private static boolean validateChecksumHeader(HttpServletRequest request,
            byte[] body, String header, HashFunction hashFunction,
            boolean bigEndianInt) throws S3Exception {
        String value = request.getHeader(header);
        if (value == null) {
            return false;
        }
        byte[] expected;
        try {
            expected = Base64.getDecoder().decode(value);
        } catch (IllegalArgumentException iae) {
            throw new S3Exception(S3ErrorCode.INVALID_DIGEST, iae);
        }
        HashCode hash = hashFunction.hashBytes(body);
        byte[] actual = bigEndianInt ?
                java.nio.ByteBuffer.allocate(4).putInt(hash.asInt()).array() :
                hash.asBytes();
        if (!java.util.Arrays.equals(expected, actual)) {
            throw new S3Exception(S3ErrorCode.BAD_DIGEST);
        }
        return true;
    }

    /**
     * The single flexible checksum carried as a regular x-amz-checksum-*
     * request header, or null.  Modern AWS SDKs send these on non-streaming
     * PutObject and UploadPart requests; the aws-chunked trailer variant is
     * validated by ChunkedInputStream instead.  S3 rejects requests
     * asserting more than one algorithm.
     */
    @Nullable
    private static FlexChecksum requestChecksumHeader(
            HttpServletRequest request) throws S3Exception {
        FlexChecksum found = null;
        for (FlexChecksum candidate : FlexChecksum.values()) {
            if (request.getHeader(candidate.header()) != null) {
                if (found != null) {
                    throw new S3Exception(S3ErrorCode.INVALID_REQUEST,
                            "Expecting a single x-amz-checksum- header.");
                }
                found = candidate;
            }
        }
        return found;
    }

    /**
     * Wrap {@code is} so the body is validated against the client-asserted
     * checksum as the stream is consumed.
     */
    private static InputStream wrapChecksumValidator(InputStream is,
            FlexChecksum checksum, String expectedBase64, long contentLength)
            throws S3Exception {
        return new ChecksumValidatingInputStream(is, checksum.hashFunction(),
                checksum.decodeValue(expectedBase64), checksum.bigEndianInt(),
                contentLength);
    }

    private void handleMultiBlobRemove(HttpServletRequest request,
            HttpServletResponse response, InputStream is,
            BlobStore blobStore, String containerName)
            throws IOException, S3Exception {
        // Bound the buffered body: a MultiObjectDelete is limited to 1000
        // keys, but the request is otherwise attacker-controlled, so read at
        // most one byte past the limit and reject rather than exhaust the heap.
        byte[] body = ByteStreams.limit(is, v4MaxNonChunkedRequestSize + 1)
                .readAllBytes();
        if (body.length == v4MaxNonChunkedRequestSize + 1) {
            throw new S3Exception(S3ErrorCode.MAX_MESSAGE_LENGTH_EXCEEDED);
        }
        validateMultiBlobRemoveChecksum(request, body);
        DeleteMultipleObjectsRequest dmor = readXmlBody(
                body, DeleteMultipleObjectsRequest.class);
        if (dmor.objects() == null) {
            throw new S3Exception(S3ErrorCode.MALFORMED_X_M_L);
        }

        if (dmor.objects().size() > 1_000) {
            throw new S3Exception(S3ErrorCode.INVALID_ARGUMENT);
        }

        boolean supportsVersioning = blobStore.supportsVersioning();
        boolean anyVersion = false;
        Collection<String> blobNames = new ArrayList<>();
        for (DeleteMultipleObjectsRequest.S3Object s3Object :
                dmor.objects()) {
            if (Strings.isNullOrEmpty(s3Object.key())) {
                throw new S3Exception(S3ErrorCode.MALFORMED_X_M_L);
            }
            if (s3Object.hasCondition()) {
                throw new S3Exception(S3ErrorCode.NOT_IMPLEMENTED);
            }
            // On a versioning store even the literal "null" names a version
            // -- the one written while the bucket was unversioned -- so any
            // VersionId element routes the delete through the versioned path.
            if (s3Object.versionId() != null && supportsVersioning) {
                anyVersion = true;
            } else if (s3Object.hasVersion()) {
                throw new S3Exception(S3ErrorCode.NOT_IMPLEMENTED,
                        "Versioning is not supported.");
            }
            blobNames.add(s3Object.key());
        }

        // A request naming versions deletes key by key for the per-key
        // results; one naming none keeps the store's bulk delete, whose
        // response reports no version information.
        List<DeletedObjectResult> results = null;
        if (anyVersion) {
            results = new ArrayList<>();
            for (DeleteMultipleObjectsRequest.S3Object s3Object :
                    dmor.objects()) {
                try {
                    RemoveResult result = blobStore.removeBlob(containerName,
                            s3Object.key(), s3Object.versionId());
                    results.add(new DeletedObjectResult(s3Object.key(),
                            s3Object.versionId(), result, null));
                } catch (VersionNotFoundException vnfe) {
                    results.add(new DeletedObjectResult(s3Object.key(),
                            s3Object.versionId(), null,
                            S3ErrorCode.NO_SUCH_VERSION));
                }
            }
        } else {
            blobStore.removeBlobs(containerName, blobNames);
        }

        response.setCharacterEncoding(UTF_8);
        addCorsResponseHeader(request, response);
        try (Writer writer = response.getWriter()) {
            response.setContentType(XML_CONTENT_TYPE);
            XMLStreamWriter xml = xmlOutputFactory.createXMLStreamWriter(
                    writer);
            xml.writeStartDocument();
            xml.writeStartElement("DeleteResult");
            xml.writeDefaultNamespace(AWS_XMLNS);

            if (results != null) {
                for (DeletedObjectResult result : results) {
                    S3ErrorCode error = result.error();
                    if (error != null) {
                        xml.writeStartElement("Error");
                        writeSimpleElement(xml, "Key", result.key());
                        String versionId = result.requestedVersionId();
                        if (versionId != null) {
                            writeSimpleElement(xml, "VersionId", versionId);
                        }
                        writeSimpleElement(xml, "Code", error.getErrorCode());
                        writeSimpleElement(xml, "Message", error.getMessage());
                        xml.writeEndElement();
                    } else if (!dmor.quiet()) {
                        xml.writeStartElement("Deleted");
                        writeSimpleElement(xml, "Key", result.key());
                        String versionId = result.requestedVersionId();
                        if (versionId != null) {
                            writeSimpleElement(xml, "VersionId", versionId);
                        }
                        RemoveResult removed = result.result();
                        if (removed != null && removed.deleteMarker()) {
                            writeSimpleElement(xml, "DeleteMarker", "true");
                            String markerVersionId = removed.versionId();
                            if (markerVersionId != null) {
                                writeSimpleElement(xml,
                                        "DeleteMarkerVersionId",
                                        markerVersionId);
                            }
                        }
                        xml.writeEndElement();
                    }
                }
            } else if (!dmor.quiet()) {
                for (String blobName : blobNames) {
                    xml.writeStartElement("Deleted");

                    writeSimpleElement(xml, "Key", blobName);

                    xml.writeEndElement();
                }
            }

            // TODO: emit error stanza for the bulk path
            xml.writeEndElement();
            xml.flush();
        } catch (XMLStreamException xse) {
            throw new IOException(xse);
        }
    }

    /** One key's outcome in a versioned DeleteObjects. */
    private record DeletedObjectResult(String key,
            @Nullable String requestedVersionId,
            @Nullable RemoveResult result, @Nullable S3ErrorCode error) {
    }

    private void handleBlobMetadata(HttpServletRequest request,
            HttpServletResponse response,
            BlobStore blobStore, String containerName,
            String blobName) throws IOException, S3Exception {
        BlobMetadata metadata = blobStore.supportsVersioning() ?
                blobStore.blobMetadata(containerName, blobName,
                        request.getParameter("versionId")) :
                blobStore.blobMetadata(containerName, blobName);
        if (metadata == null) {
            throw new S3Exception(S3ErrorCode.NO_SUCH_KEY);
        }
        checkPartNumber(request, metadata);

        if (checkConditionalHeaders(request, response, metadata)) {
            return;
        }

        response.setStatus(HttpServletResponse.SC_OK);
        addMetadataToResponse(request, response, metadata,
                /*partialContent=*/ false);
        addCorsResponseHeader(request, response);
    }

    /** The part count a composite ETag encodes, or 1 when it is not one. */
    private static int eTagPartCount(@Nullable String eTag) {
        if (eTag == null) {
            return 1;
        }
        var matcher = COMPOSITE_ETAG.matcher(unquoteETag(eTag));
        if (!matcher.matches()) {
            return 1;
        }
        try {
            return Integer.parseInt(matcher.group(1));
        } catch (NumberFormatException nfe) {
            return 1;
        }
    }

    /**
     * Vet a versionId against the store the request resolved to.  A store
     * without versioning cannot resolve a version, but ignoring the
     * parameter silently operates on the current object instead -- for a
     * DELETE that destroys data the caller never named.  "null" is the
     * version every object in an unversioned bucket carries, so it denotes
     * the current object and is allowed.  A store with versioning receives
     * the parameter in the operations that consume it; the ones that do not
     * -- object ACLs, GetObjectAttributes -- refuse it individually via
     * {@link #checkVersionId(HttpServletRequest)}.
     *
     * <p>Note this cannot live in UNSUPPORTED_PARAMETERS, which rejects a
     * parameter outright, and which anonymous requests never reach.  Both
     * dispatch paths run it before acting so that public reads are vetted
     * too.
     */
    private static void checkVersionId(HttpServletRequest request,
            BlobStore blobStore) throws S3Exception {
        if (!blobStore.supportsVersioning()) {
            checkVersionId(request);
        }
    }

    /** Vet a versionId for an operation that cannot resolve one. */
    private static void checkVersionId(HttpServletRequest request)
            throws S3Exception {
        String versionId = request.getParameter("versionId");
        if (versionId != null && !versionId.equals("null")) {
            throw new S3Exception(S3ErrorCode.NOT_IMPLEMENTED,
                    "Versioning is not supported.");
        }
    }

    /**
     * Vet a partNumber read.  S3 answers with that part of a multipart
     * object, or with the whole object when the object has just one part.
     * s3proxy does not record where the parts ended once the upload
     * completed, and the boundaries cannot be recovered afterwards -- an
     * object's size and part count do not determine the part size -- so serve
     * only the cases needing no boundaries and refuse the rest.  Answering
     * those with the whole object instead would corrupt a client fetching
     * parts 1..N to reassemble them: it would concatenate N copies of
     * everything.  The AWS SDK's async client probes with partNumber=1, so
     * the single-part case has to keep working.
     *
     * <p>A backend that mints its own ETags (Quirks.OPAQUE_ETAG) leaves a
     * multipart object indistinguishable from a single-part one, so there it
     * still reads back whole.
     *
     * <p>Note this cannot live in UNSUPPORTED_PARAMETERS, which is consulted
     * for every request -- UploadPart and UploadPartCopy use partNumber.
     */
    private static void checkPartNumber(HttpServletRequest request,
            @Nullable BlobMetadata metadata) throws S3Exception {
        String value = request.getParameter("partNumber");
        if (value == null || metadata == null) {
            return;
        }
        int partNumber;
        try {
            partNumber = Integer.parseInt(value);
        } catch (NumberFormatException nfe) {
            throw new S3Exception(S3ErrorCode.INVALID_ARGUMENT, nfe);
        }
        if (partNumber < 1 || partNumber > 10_000) {
            throw new S3Exception(S3ErrorCode.INVALID_ARGUMENT);
        }
        if (eTagPartCount(metadata.eTag()) > 1) {
            throw new S3Exception(S3ErrorCode.NOT_IMPLEMENTED,
                    "Reading one part of a multipart object is not" +
                    " supported.");
        }
        if (partNumber > 1) {
            // one part, so anything past it does not exist
            throw new S3Exception(S3ErrorCode.INVALID_PART);
        }
    }

    /**
     * Evaluate the conditional request headers for an operation that reads
     * only metadata, which BlobStore.blobMetadata cannot express as
     * GetOptions.  Returns true when the response is already complete, i.e.
     * the caller's copy is unchanged.
     */
    private static boolean checkConditionalHeaders(HttpServletRequest request,
            HttpServletResponse response, BlobMetadata metadata)
            throws S3Exception {
        String ifMatch = request.getHeader(HttpHeaders.IF_MATCH);
        String ifNoneMatch = request.getHeader(HttpHeaders.IF_NONE_MATCH);
        long ifModifiedSince = request.getDateHeader(
                HttpHeaders.IF_MODIFIED_SINCE);
        long ifUnmodifiedSince = request.getDateHeader(
                HttpHeaders.IF_UNMODIFIED_SINCE);

        String eTag = metadata.eTag();
        if (eTag != null) {
            eTag = maybeQuoteETag(eTag);
            if (ifMatch != null && !ifMatch.equals(eTag)) {
                throw new S3Exception(S3ErrorCode.PRECONDITION_FAILED);
            }
            if (ifNoneMatch != null && ifNoneMatch.equals(eTag)) {
                response.setStatus(HttpServletResponse.SC_NOT_MODIFIED);
                return true;
            }
        }

        Date lastModified = metadata.lastModified();
        if (lastModified != null) {
            if (ifModifiedSince != -1 && lastModified.compareTo(
                    new Date(ifModifiedSince)) <= 0) {
                response.setStatus(HttpServletResponse.SC_NOT_MODIFIED);
                return true;
            }
            if (ifUnmodifiedSince != -1 && lastModified.compareTo(
                    new Date(ifUnmodifiedSince)) > 0) {
                throw new S3Exception(S3ErrorCode.PRECONDITION_FAILED);
            }
        }
        return false;
    }

    private void handleGetObjectAttributes(HttpServletRequest request,
            HttpServletResponse response, BlobStore blobStore,
            String containerName, String blobName)
            throws IOException, S3Exception {
        // Resolves only the current object; ignoring a versionId would
        // answer with the wrong version's attributes.
        checkVersionId(request);
        Set<String> attributes = requestedObjectAttributes(request);

        BlobMetadata metadata = blobStore.blobMetadata(containerName,
                blobName);
        if (metadata == null) {
            throw new S3Exception(S3ErrorCode.NO_SUCH_KEY);
        }
        if (checkConditionalHeaders(request, response, metadata)) {
            return;
        }

        Date lastModified = metadata.lastModified();
        if (lastModified != null) {
            response.addDateHeader(HttpHeaders.LAST_MODIFIED,
                    lastModified.getTime());
        }

        response.setStatus(HttpServletResponse.SC_OK);
        response.setCharacterEncoding(UTF_8);
        addCorsResponseHeader(request, response);
        try (Writer writer = response.getWriter()) {
            response.setContentType(XML_CONTENT_TYPE);
            XMLStreamWriter xml = xmlOutputFactory.createXMLStreamWriter(
                    writer);
            xml.writeStartDocument();
            xml.writeStartElement("GetObjectAttributesOutput");
            xml.writeDefaultNamespace(AWS_XMLNS);

            String eTag = metadata.eTag();
            if (attributes.contains("ETag") && eTag != null) {
                // unquoted here, unlike the ETag header and every other body
                writeSimpleElement(xml, "ETag", unquoteETag(eTag));
            }

            if (attributes.contains("Checksum")) {
                writeChecksumStanza(xml, metadata);
            }

            // ObjectParts is deliberately absent.  Deriving it needs the part
            // boundaries, which most backends discard once the upload
            // completes; S3 likewise omits the element for an object that was
            // not uploaded in parts.

            if (attributes.contains("StorageClass")) {
                StorageClass storageClass = metadata.storageClass();
                writeSimpleElement(xml, "StorageClass", storageClass == null ?
                        StorageClass.STANDARD.toString() :
                        storageClass.toString());
            }

            Long size = metadata.size();
            if (attributes.contains("ObjectSize") && size != null) {
                writeSimpleElement(xml, "ObjectSize", String.valueOf(size));
            }

            xml.writeEndElement();
            xml.flush();
        } catch (XMLStreamException xse) {
            throw new IOException(xse);
        }
    }

    /**
     * The attributes a GetObjectAttributes request asks for.  The AWS SDKs
     * send a single comma-separated header but the value may also arrive
     * split across repeated headers.  Names s3proxy does not recognize are
     * ignored, leaving their elements out of the response.
     */
    private static Set<String> requestedObjectAttributes(
            HttpServletRequest request) throws S3Exception {
        var attributes = new HashSet<String>();
        for (String header : Collections.list(request.getHeaders(
                AwsHttpHeaders.OBJECT_ATTRIBUTES))) {
            for (String attribute : Splitter.on(',').split(header)) {
                String trimmed = attribute.trim();
                if (!trimmed.isEmpty()) {
                    attributes.add(trimmed);
                }
            }
        }
        if (attributes.isEmpty()) {
            throw new S3Exception(S3ErrorCode.INVALID_REQUEST,
                    "The x-amz-object-attributes header must be specified.");
        }
        return attributes;
    }

    /**
     * Write the object's whole-object checksum, which GetObjectAttributes
     * returns unconditionally -- unlike GetObject and HeadObject, which
     * withhold it until x-amz-checksum-mode asks.  Objects stored without a
     * checksum get no element at all, as on S3.
     */
    private static void writeChecksumStanza(XMLStreamWriter xml,
            BlobMetadata metadata) throws XMLStreamException {
        for (var entry : metadata.userMetadata().entrySet()) {
            FlexChecksum checksum = FlexChecksum.fromMetadataKey(
                    entry.getKey());
            if (checksum == null) {
                continue;
            }
            String value = entry.getValue();
            xml.writeStartElement("Checksum");
            writeSimpleElement(xml, checksum.element(), value);
            writeSimpleElement(xml, "ChecksumType", checksumType(value));
            xml.writeEndElement();
            return;
        }
    }

    private void handleOptionsBlob(HttpServletRequest request,
            HttpServletResponse response,
            BlobStore blobStore,
            String containerName) throws IOException, S3Exception {
        if (!blobStore.containerExists(containerName)) {
            // Don't leak internal information, although authenticated
            throw new S3Exception(S3ErrorCode.ACCESS_DENIED);
        }

        String corsOrigin = request.getHeader(HttpHeaders.ORIGIN);
        if (Strings.isNullOrEmpty(corsOrigin)) {
            throw new S3Exception(S3ErrorCode.INVALID_CORS_ORIGIN);
        }
        if (!corsRules.isOriginAllowed(corsOrigin)) {
            throw new S3Exception(S3ErrorCode.ACCESS_DENIED);
        }

        String corsMethod = request.getHeader(
                HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD);
        if (!corsRules.isMethodAllowed(corsMethod)) {
            throw new S3Exception(S3ErrorCode.INVALID_CORS_METHOD);
        }

        String corsHeaders = request.getHeader(
                HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS);
        if (!Strings.isNullOrEmpty(corsHeaders)) {
            if (corsRules.isEveryHeaderAllowed(corsHeaders)) {
                response.addHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS,
                        corsHeaders);
            } else {
                throw new S3Exception(S3ErrorCode.ACCESS_DENIED);
            }
        }

        response.addHeader(HttpHeaders.VARY, HttpHeaders.ORIGIN);
        response.addHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN,
                corsRules.getAllowedOrigin(corsOrigin));
        response.addHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS,
                corsRules.getAllowedMethods());

        String exposedHeaders = corsRules.getExposedHeaders();
        if (!Strings.isNullOrEmpty(exposedHeaders)) {
            response.addHeader(HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS,
                exposedHeaders);
        }

        if (corsRules.isAllowCredentials()) {
            response.addHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS,
                    "true");
        }

        response.setStatus(HttpServletResponse.SC_OK);
    }

    private void handleGetBlob(HttpServletRequest request,
            HttpServletResponse response, BlobStore blobStore,
            String containerName, String blobName)
            throws IOException, S3Exception {
        if (request.getParameter("partNumber") != null) {
            // needs the ETag to tell a multipart object apart, and the body
            // must not be fetched only to be thrown away on the error path
            checkPartNumber(request,
                    blobStore.blobMetadata(containerName, blobName));
        }

        int status = HttpServletResponse.SC_OK;
        var optionsBuilder = GetOptions.builder();

        if (blobStore.supportsVersioning()) {
            optionsBuilder.versionId(request.getParameter("versionId"));
        }

        String ifMatch = request.getHeader(HttpHeaders.IF_MATCH);
        if (ifMatch != null) {
            optionsBuilder.ifETagMatches(ifMatch);
        }

        String ifNoneMatch = request.getHeader(HttpHeaders.IF_NONE_MATCH);
        if (ifNoneMatch != null) {
            optionsBuilder.ifETagDoesntMatch(ifNoneMatch);
        }

        long ifModifiedSince = request.getDateHeader(
                HttpHeaders.IF_MODIFIED_SINCE);
        if (ifModifiedSince != -1) {
            optionsBuilder.ifModifiedSince(new Date(ifModifiedSince));
        }

        long ifUnmodifiedSince = request.getDateHeader(
                HttpHeaders.IF_UNMODIFIED_SINCE);
        if (ifUnmodifiedSince != -1) {
            optionsBuilder.ifUnmodifiedSince(new Date(ifUnmodifiedSince));
        }

        String range = request.getHeader(HttpHeaders.RANGE);
        if (range != null && range.startsWith("bytes=") &&
                // ignore multiple ranges
                range.indexOf(',') == -1 &&
                // ignore malformed ranges missing the hyphen
                range.indexOf('-') != -1) {
            range = range.substring("bytes=".length());
            String[] ranges = range.split("-", 2);
            try {
                if (ranges[0].isEmpty()) {
                    long tail = Long.parseLong(ranges[1]);
                    if (tail < 0) {
                        throw new S3Exception(S3ErrorCode.INVALID_RANGE);
                    }
                    optionsBuilder.tail(tail);
                } else if (ranges[1].isEmpty()) {
                    long startAt = Long.parseLong(ranges[0]);
                    if (startAt < 0) {
                        throw new S3Exception(S3ErrorCode.INVALID_RANGE);
                    }
                    optionsBuilder.startAt(startAt);
                } else {
                    long start = Long.parseLong(ranges[0]);
                    long end = Long.parseLong(ranges[1]);
                    if (start < 0 || end < start) {
                        throw new S3Exception(S3ErrorCode.INVALID_RANGE);
                    }
                    optionsBuilder.range(start, end);
                }
            } catch (NumberFormatException nfe) {
                throw new S3Exception(S3ErrorCode.INVALID_ARGUMENT, nfe);
            }
            status = HttpServletResponse.SC_PARTIAL_CONTENT;
        }

        Blob blob = blobStore.getBlob(containerName, blobName,
                optionsBuilder.build());
        if (blob == null) {
            throw new S3Exception(S3ErrorCode.NO_SUCH_KEY);
        }

        response.setStatus(status);

        addCorsResponseHeader(request, response);

        addMetadataToResponse(request, response, blob.getMetadata(),
                status == HttpServletResponse.SC_PARTIAL_CONTENT);

        // TODO: handles only a single range due to blobstore API limitations
        String contentRange = blob.getContentRange();
        if (contentRange != null) {
            response.addHeader(HttpHeaders.CONTENT_RANGE, contentRange);
            response.addHeader(HttpHeaders.ACCEPT_RANGES, "bytes");
        }

        try (InputStream is = requireNonNull(blob.getPayload());
             OutputStream os = response.getOutputStream()) {
            is.transferTo(os);
            os.flush();
        }
    }

    /**
     * The versionId the raw x-amz-copy-source header names, or null.  The
     * query must split from the raw header before percent-decoding: decoding
     * first would conflate a key containing an encoded "?versionId=" with
     * the version syntax.  On a store without versioning only the literal
     * "null" is accepted, denoting the current object as {@link
     * #checkVersionId(HttpServletRequest)} does for the query parameter.
     */
    @Nullable
    private static String parseCopySourceVersionId(String rawCopySource,
            BlobStore blobStore) throws S3Exception {
        int query = rawCopySource.indexOf('?');
        if (query == -1) {
            return null;
        }
        String queryString = rawCopySource.substring(query + 1);
        if (!queryString.startsWith("versionId=")) {
            throw new S3Exception(S3ErrorCode.INVALID_ARGUMENT);
        }
        String versionId = URLDecoder.decode(
                queryString.substring("versionId=".length()),
                StandardCharsets.UTF_8);
        if (versionId.isEmpty()) {
            throw new S3Exception(S3ErrorCode.INVALID_ARGUMENT);
        }
        if (!blobStore.supportsVersioning()) {
            if (!versionId.equals("null")) {
                throw new S3Exception(S3ErrorCode.NOT_IMPLEMENTED,
                        "Versioning is not supported.");
            }
            return null;
        }
        return versionId;
    }

    /** The x-amz-copy-source bucket/key with any query part removed. */
    private static String stripCopySourceQuery(String rawCopySource) {
        int query = rawCopySource.indexOf('?');
        return query == -1 ? rawCopySource : rawCopySource.substring(0, query);
    }

    /**
     * Authorize the bucket named by x-amz-copy-source.  doHandle resolves the
     * blob store from the bucket in the request URI, i.e. the copy
     * destination; the source names a second bucket that never passes through
     * that check.  A BlobStoreLocator which scopes buckets to identities --
     * GlobBlobStoreLocator does -- would otherwise still let a caller read a
     * bucket it cannot address directly by copying out of it.
     */
    private void authorizeCopySource(@Nullable String requestIdentity,
            String sourceContainerName, String sourceBlobName)
            throws S3Exception {
        if (blobStoreLocator.locateBlobStore(requestIdentity,
                sourceContainerName, sourceBlobName) == null) {
            throw new S3Exception(S3ErrorCode.ACCESS_DENIED);
        }
    }

    private void handleCopyBlob(HttpServletRequest request,
            HttpServletResponse response, BlobStore blobStore,
            @Nullable String requestIdentity,
            String destContainerName, String destBlobName)
            throws IOException, S3Exception {
        String rawCopySource = request.getHeader(AwsHttpHeaders.COPY_SOURCE);
        String sourceVersionId = parseCopySourceVersionId(rawCopySource,
                blobStore);
        String copySourceHeader = URLDecoder.decode(
                stripCopySourceQuery(rawCopySource), StandardCharsets.UTF_8);
        if (copySourceHeader.startsWith("/")) {
            // Some clients like boto do not include the leading slash
            copySourceHeader = copySourceHeader.substring(1);
        }
        String[] path = copySourceHeader.split("/", 2);
        if (path.length != 2) {
            throw new S3Exception(S3ErrorCode.INVALID_REQUEST);
        }
        String sourceContainerName = path[0];
        String sourceBlobName = path[1];
        authorizeCopySource(requestIdentity, sourceContainerName,
                sourceBlobName);
        boolean replaceMetadata = "REPLACE".equalsIgnoreCase(request.getHeader(
                AwsHttpHeaders.METADATA_DIRECTIVE));

        // Copying a named version of an object onto the object itself is a
        // legitimate way to restore that version, so the self-copy check
        // applies only to a copy of the current object.
        if (sourceContainerName.equals(destContainerName) &&
                sourceBlobName.equals(destBlobName) &&
                sourceVersionId == null &&
                !replaceMetadata) {
            throw new S3Exception(S3ErrorCode.INVALID_REQUEST);
        }

        CopyOptions.Builder options = CopyOptions.builder();
        options.sourceVersionId(sourceVersionId);

        // The access rides down with the copy so that the store applies it as
        // it creates the object, rather than a PutObjectAcl afterwards whose
        // failure would leave the copy readable to nobody who asked for it.
        String cannedAcl = request.getHeader(AwsHttpHeaders.ACL);
        if (cannedAcl != null && !"private".equalsIgnoreCase(cannedAcl)) {
            if ("public-read".equalsIgnoreCase(cannedAcl)) {
                options.blobAccess(BlobAccess.PUBLIC_READ);
            } else if (CANNED_ACLS.contains(cannedAcl)) {
                throw new S3Exception(S3ErrorCode.NOT_IMPLEMENTED);
            } else {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST);
                return;
            }
        }

        String ifMatch = request.getHeader(AwsHttpHeaders.COPY_SOURCE_IF_MATCH);
        if (ifMatch != null) {
            options.ifMatch(ifMatch);
        }
        String ifNoneMatch = request.getHeader(
                AwsHttpHeaders.COPY_SOURCE_IF_NONE_MATCH);
        if (ifNoneMatch != null) {
            options.ifNoneMatch(ifNoneMatch);
        }
        long ifModifiedSince = request.getDateHeader(
                AwsHttpHeaders.COPY_SOURCE_IF_MODIFIED_SINCE);
        if (ifModifiedSince != -1) {
            options.ifModifiedSince(new Date(ifModifiedSince));
        }
        long ifUnmodifiedSince = request.getDateHeader(
                AwsHttpHeaders.COPY_SOURCE_IF_UNMODIFIED_SINCE);
        if (ifUnmodifiedSince != -1) {
            options.ifUnmodifiedSince(new Date(ifUnmodifiedSince));
        }

        if (replaceMetadata) {
            ContentMetadata.Builder contentMetadata = ContentMetadata.builder();
            var userMetadata = ImmutableMap.<String, String>builder();
            for (String headerName : Collections.list(
                    request.getHeaderNames())) {
                String headerValue = Strings.nullToEmpty(request.getHeader(
                        headerName));
                if (headerName.equalsIgnoreCase(
                        HttpHeaders.CACHE_CONTROL)) {
                    contentMetadata.cacheControl(headerValue);
                } else if (headerName.equalsIgnoreCase(
                        HttpHeaders.CONTENT_DISPOSITION)) {
                    contentMetadata.contentDisposition(headerValue);
                } else if (headerName.equalsIgnoreCase(
                        HttpHeaders.CONTENT_ENCODING)) {
                    String stripped = stripAwsChunked(headerValue);
                    if (!stripped.isEmpty()) {
                        contentMetadata.contentEncoding(stripped);
                    }
                } else if (headerName.equalsIgnoreCase(
                        HttpHeaders.CONTENT_LANGUAGE)) {
                    contentMetadata.contentLanguage(headerValue);
                } else if (headerName.equalsIgnoreCase(
                        HttpHeaders.CONTENT_TYPE)) {
                    contentMetadata.contentType(headerValue);
                } else if (startsWithIgnoreCase(headerName,
                        USER_METADATA_PREFIX)) {
                    userMetadata.put(
                            headerName.substring(USER_METADATA_PREFIX.length()),
                            headerValue);
                }
                // TODO: Expires
            }
            options.contentMetadata(contentMetadata.build());
            options.userMetadata(userMetadata.build());
        }

        CopyResult copyResult;
        try {
            copyResult = blobStore.copyBlob(
                    sourceContainerName, sourceBlobName,
                    destContainerName, destBlobName, options.build());
        } catch (KeyNotFoundException knfe) {
            throw new S3Exception(S3ErrorCode.NO_SUCH_KEY, knfe);
        }

        BlobMetadata blobMetadata = blobStore.blobMetadata(destContainerName,
                destBlobName);
        response.setCharacterEncoding(UTF_8);
        addCorsResponseHeader(request, response);
        String copySourceVersionId = copyResult.copySourceVersionId();
        if (copySourceVersionId != null) {
            response.addHeader(AwsHttpHeaders.COPY_SOURCE_VERSION_ID,
                    copySourceVersionId);
        }
        String destVersionId = copyResult.versionId();
        if (destVersionId != null) {
            response.addHeader(AwsHttpHeaders.VERSION_ID, destVersionId);
        }
        try (Writer writer = response.getWriter()) {
            response.setContentType(XML_CONTENT_TYPE);
            XMLStreamWriter xml = xmlOutputFactory.createXMLStreamWriter(
                    writer);
            xml.writeStartDocument();
            xml.writeStartElement("CopyObjectResult");
            xml.writeDefaultNamespace(AWS_XMLNS);

            var lastModified = blobMetadata == null ? null :
                    blobMetadata.lastModified();
            if (lastModified != null) {
                writeSimpleElement(xml, "LastModified",
                        formatDate(lastModified));
            }

            String eTag = copyResult.eTag();
            if (eTag != null) {
                writeSimpleElement(xml, "ETag", maybeQuoteETag(eTag));
            }

            xml.writeEndElement();
            xml.flush();
        } catch (XMLStreamException xse) {
            throw new IOException(xse);
        }
    }

    private void handlePutBlob(HttpServletRequest request,
            HttpServletResponse response, InputStream is, BlobStore blobStore,
            String containerName, String blobName)
            throws IOException, S3Exception {
        // Flag headers present since HttpServletResponse.getHeader returns
        // null for empty headers values.
        String contentLengthString = null;
        String decodedContentLengthString = null;
        String contentMD5String = null;
        for (String headerName : Collections.list(request.getHeaderNames())) {
            String headerValue = Strings.nullToEmpty(request.getHeader(
                    headerName));
            if (headerName.equalsIgnoreCase(HttpHeaders.CONTENT_LENGTH)) {
                contentLengthString = headerValue;
            } else if (headerName.equalsIgnoreCase(
                    AwsHttpHeaders.DECODED_CONTENT_LENGTH)) {
                decodedContentLengthString = headerValue;
            } else if (headerName.equalsIgnoreCase(HttpHeaders.CONTENT_MD5)) {
                contentMD5String = headerValue;
            }
        }
        if (decodedContentLengthString != null) {
            contentLengthString = decodedContentLengthString;
        }

        HashCode contentMD5 = null;
        if (contentMD5String != null) {
            try {
                contentMD5 = HashCode.fromBytes(
                        Base64.getDecoder().decode(contentMD5String));
            } catch (IllegalArgumentException iae) {
                throw new S3Exception(S3ErrorCode.INVALID_DIGEST, iae);
            }
            if (contentMD5.bits() != MD5.bits()) {
                throw new S3Exception(S3ErrorCode.INVALID_DIGEST);
            }
        }

        if (contentLengthString == null) {
            byte[] body = readBodyOfUnknownLength(request, is);
            is = new ByteArrayInputStream(body);
            contentLengthString = String.valueOf(body.length);
        }
        long contentLength;
        try {
            contentLength = Long.parseLong(contentLengthString);
        } catch (NumberFormatException nfe) {
            throw new S3Exception(S3ErrorCode.INVALID_ARGUMENT, nfe);
        }
        if (contentLength < 0) {
            throw new S3Exception(S3ErrorCode.INVALID_ARGUMENT);
        }
        if (contentLength > maxSinglePartObjectSize) {
            throw new S3Exception(S3ErrorCode.ENTITY_TOO_LARGE);
        }
        if (decodedContentLengthString != null) {
            is = ByteStreams.limit(is, contentLength);
        }
        FlexChecksum checksum = requestChecksumHeader(request);
        String checksumValue = null;
        if (checksum != null) {
            checksumValue = request.getHeader(checksum.header());
            is = wrapChecksumValidator(is, checksum, checksumValue,
                    contentLength);
        }

        String ifMatch = request.getHeader(HttpHeaders.IF_MATCH);
        String ifNoneMatch = request.getHeader(HttpHeaders.IF_NONE_MATCH);
        String blobStoreType = getBlobStoreType(blobStore);

        // Providers that support native conditional writes
        boolean supportsNativeConditionalWrites =
                blobStoreType.equals("azureblob") ||
                blobStoreType.equals("aws-s3") ||
                blobStoreType.equals("google-cloud-storage") ||
                // the nio2 stores resolve If-None-Match as they write
                (Quirks.NATIVE_IF_NONE_MATCH.contains(blobStoreType) &&
                        ifMatch == null && ifNoneMatch != null) ||
                // sftp publishes exclusively like the other nio2 stores but
                // persists no ETag to compare a named form against
                (blobStoreType.equals("sftp") &&
                        ifMatch == null && "*".equals(ifNoneMatch)) ||
                // Swift only supports If-None-Match: * natively
                (blobStoreType.equals("openstack-swift") &&
                        ifMatch == null && "*".equals(ifNoneMatch));

        // Emulating the rest would mean a HEAD followed by an unconditional
        // write, which answers correctly only while nothing else is writing
        // the same key -- and a conditional write is asked for precisely
        // because something might be.  Rather than appear to offer a
        // guarantee it cannot keep, refuse where the store cannot help:
        // only the nio2 stores, whose If-Match is bounded by this process,
        // still emulate.
        if ((ifMatch != null || ifNoneMatch != null) &&
                !supportsNativeConditionalWrites &&
                !Quirks.NATIVE_IF_NONE_MATCH.contains(blobStoreType)) {
            throw new S3Exception(S3ErrorCode.NOT_IMPLEMENTED,
                    "Conditional writes are not supported by this backend.");
        }

        // S3 answers any If-Match naming a key that does not exist with 404,
        // since there is nothing to have matched.  The native backends do not
        // agree -- Azure and GCS report 412, LocalStack 501 -- so settle
        // existence here rather than let their answer through.  Once it is
        // established, If-Match: * asks nothing further, so drop it: Azure
        // and LocalStack reject that form outright.  A specific ETag stays
        // with the backend, which compares it atomically.
        //
        // Note: this makes the existence check non-atomic (HEAD then PUT).
        if (ifMatch != null && supportsNativeConditionalWrites) {
            if (!blobStore.blobExists(containerName, blobName)) {
                throw new S3Exception(S3ErrorCode.NO_SUCH_KEY);
            }
            if (ifMatch.equals("*")) {
                ifMatch = null;
            }
        }

        // Emulate conditional put for backends without native support.
        // Note: this is a non-atomic operation (HEAD then PUT).
        if ((ifMatch != null || ifNoneMatch != null) &&
                !supportsNativeConditionalWrites) {
            checkConditionalWrite(blobStore.blobMetadata(containerName,
                    blobName), ifMatch, ifNoneMatch);
        }

        BlobAccess access;
        String cannedAcl = request.getHeader(AwsHttpHeaders.ACL);
        if (cannedAcl == null || cannedAcl.equalsIgnoreCase("private")) {
            access = BlobAccess.PRIVATE;
        } else if (cannedAcl.equalsIgnoreCase("public-read")) {
            access = BlobAccess.PUBLIC_READ;
        } else if (CANNED_ACLS.contains(cannedAcl)) {
            throw new S3Exception(S3ErrorCode.NOT_IMPLEMENTED);
        } else {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        var options = PutOptions.builder()
                .blobAccess(access)
                .ifMatch(ifMatch)
                .ifNoneMatch(ifNoneMatch)
                .build();

        Blob.Builder builder = Blob.builder(blobName)
                .payload(is)
                .contentLength(contentLength);

        String storageClass = request.getHeader(AwsHttpHeaders.STORAGE_CLASS);
        if (storageClass == null || storageClass.equalsIgnoreCase("STANDARD")) {
            // defaults to STANDARD
        } else {
            try {
                builder.storageClass(StorageClass.valueOf(storageClass));
            } catch (IllegalArgumentException iae) {
                throw new S3Exception(S3ErrorCode.INVALID_STORAGE_CLASS, iae);
            }
        }

        addContentMetadataFromHttpRequest(builder, request, checksum,
                checksumValue);
        if (contentMD5 != null) {
            builder = builder.contentMD5(contentMD5);
        }

        PutResult result = blobStore.putBlob(containerName, builder.build(),
                options);

        addCorsResponseHeader(request, response);

        String eTag = result.eTag();
        if (eTag != null) {
            response.addHeader(HttpHeaders.ETAG, maybeQuoteETag(eTag));
        }
        String versionId = result.versionId();
        if (versionId != null) {
            response.addHeader(AwsHttpHeaders.VERSION_ID, versionId);
        }
        if (checksum != null) {
            response.addHeader(checksum.header(), checksumValue);
        }
    }

    private void handleStatuszRequest(HttpServletResponse response)
            throws IOException {
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("application/json");
        response.setCharacterEncoding(UTF_8);

        Map<String, String> body = Map.of(
                "status", "OK",
                "gitHash", GIT_HASH,
                "launchTime", launchTime.toString(),
                "currentTime", Instant.now().toString());

        try (PrintWriter writer = response.getWriter()) {
            JSON_MAPPER.writeValue(writer, body);
        }
    }

    private static String loadGitHash() {
        // Resolved against this class's package, not the classpath root: an
        // application embedding s3proxy often has a git.properties of its own
        // there and the first one found would answer for both.
        try (InputStream stream =
                S3ProxyHandler.class.getResourceAsStream("git.properties")) {
            if (stream == null) {
                return "unknown";
            }
            Properties properties = new Properties();
            properties.load(stream);
            String hash = properties.getProperty("git.commit.id.abbrev");
            if (hash == null) {
                hash = properties.getProperty("git.commit.id", "unknown");
            }
            return hash;
        } catch (IOException ioe) {
            logger.debug("Unable to load git.properties", ioe);
            return "unknown";
        }
    }

    private void handlePostBlob(HttpServletRequest request,
            HttpServletResponse response, InputStream is,
            String containerName)
            throws IOException, S3Exception {
        String contentTypeHeader = request.getHeader(HttpHeaders.CONTENT_TYPE);
        if (contentTypeHeader == null) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }
        List<String> contentTypeParts = Splitter.on(';').splitToList(
                contentTypeHeader);
        if (contentTypeParts.size() < 2 || !contentTypeParts.get(0).trim()
                .equalsIgnoreCase("multipart/form-data")) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }
        String boundary = null;
        for (int i = 1; i < contentTypeParts.size(); i++) {
            String param = contentTypeParts.get(i).trim();
            int eq = param.indexOf('=');
            if (eq > 0 && param.substring(0, eq).trim()
                    .equalsIgnoreCase("boundary")) {
                boundary = param.substring(eq + 1).trim();
                if (boundary.length() >= 2 && boundary.startsWith("\"") &&
                        boundary.endsWith("\"")) {
                    boundary = boundary.substring(1, boundary.length() - 1);
                }
                break;
            }
        }
        if (Strings.isNullOrEmpty(boundary)) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        // Every field, lowercased, since both a policy condition and the form
        // field it names are matched without regard to case.  The payload is
        // deliberately absent: it is the one field whose value is not a
        // string, and the policy constrains its length rather than its bytes.
        var fields = new LinkedHashMap<String, String>();
        String fileName = null;
        byte[] payload = null;
        FlexChecksum checksum = null;
        String checksumValue = null;
        var parser = new MultiPartFormData.Parser(boundary);
        parser.setFilesDirectory(java.nio.file.Path.of(
                System.getProperty("java.io.tmpdir")));
        // Jetty bounds the number of parts and nothing else, so say how large
        // a body may be.  Nothing has authorized this one -- a form POST
        // carries no Authorization header, and the policy that speaks for it
        // is inside the body still being read -- so an unbounded body is one
        // anyone who can reach the proxy may send, and it is spilled to the
        // filesystem on its way to being held whole in memory.  Bound it
        // where the other body read into memory is bounded.
        parser.setMaxLength(v4MaxNonChunkedRequestSize);
        var futureParts = new CompletableFuture<MultiPartFormData.Parts>();
        parser.parse(new InputStreamContentSource(is,
                ByteBufferPool.SIZED_NON_POOLING),
                Promise.Invocable.toPromise(futureParts));
        MultiPartFormData.Parts parts;
        try {
            parts = futureParts.join();
        } catch (CompletionException ce) {
            throw multipartParseFailure(ce);
        }
        try {
            for (var part : parts) {
                var name = part.getName();
                if (name.equalsIgnoreCase("file")) {
                    // TODO: buffers entire payload
                    payload = part.getContentAsString(
                            StandardCharsets.ISO_8859_1)
                            .getBytes(StandardCharsets.ISO_8859_1);
                    fileName = part.getFileName();
                    continue;
                }
                String value = part.getContentAsString(StandardCharsets.UTF_8);
                fields.put(name.toLowerCase(java.util.Locale.ROOT), value);
                FlexChecksum candidate = FlexChecksum.fromHeaderName(name);
                if (candidate != null) {
                    if (checksum != null && checksum != candidate) {
                        throw new S3Exception(S3ErrorCode.INVALID_REQUEST,
                                "Expecting a single x-amz-checksum- field.");
                    }
                    checksum = candidate;
                    checksumValue = value;
                }
            }
        } finally {
            parts.close();
        }

        String blobName = fields.get("key");
        // Substituted before the policy sees it, so a condition constrains the
        // name the object is stored under rather than the literal the form
        // sent.  A form that names ${filename} and a policy that requires the
        // key to start with "foo" agree only after this.
        if (blobName != null && blobName.contains("${filename}")) {
            blobName = blobName.replace("${filename}",
                    Strings.nullToEmpty(fileName));
            fields.put("key", blobName);
        }
        // The bucket a condition is matched against is the one being written
        // to, not a bucket field the form supplied: a form may name any bucket
        // it likes, and a policy naming the same one must still not authorize
        // a POST aimed elsewhere.
        fields.put("bucket", containerName);

        byte[] policy = null;
        String policyField = fields.get("policy");
        if (policyField != null) {
            policy = policyField.getBytes(StandardCharsets.ISO_8859_1);
        }
        String identity = fields.get("awsaccesskeyid");
        if (identity == null) {
            identity = fields.get("x-amz-credential");
        }
        String signature = fields.get("signature");
        if (signature == null) {
            signature = fields.get("x-amz-signature");
        }
        String algorithm = fields.get("x-amz-algorithm");
        String contentType = fields.get("content-type");

        if (blobName == null || payload == null) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        // A POST carries no Authorization header -- doHandle routes a request
        // without one here -- so the policy is the only thing that can say the
        // caller may write.  A form carrying none is refused, where S3 answers
        // it from the bucket's own permissions and uploads when those grant
        // AllUsers WRITE.  S3Proxy has nowhere to keep such a grant:
        // CreateBucket drops the write half of public-read-write, PutBucketAcl
        // answers NotImplemented for it, and the anonymous path implements no
        // PUT or DELETE at all -- so a bucket anyone may write to is not a
        // thing this proxy can be told about, and honouring a form that
        // assumes one would let anyone who can reach the proxy create and
        // overwrite objects in every bucket the backend holds.  s3-tests marks
        // the three POSTs that expect otherwise.
        if (policy == null && signature == null && identity == null) {
            throw new S3Exception(S3ErrorCode.ACCESS_DENIED);
        }
        // Carrying some but not all of them is a form built wrong rather than
        // one that meant to go unsigned, and saying so beats reporting it as a
        // refusal the caller cannot act on.
        if (policy == null || signature == null) {
            throw new S3Exception(S3ErrorCode.INVALID_ARGUMENT,
                    "Bucket POST must contain both 'policy' and a signature" +
                    " when it is authenticated.");
        }

        String headerAuthorization = null;
        S3AuthorizationHeader authHeader = null;
        boolean signatureVersion4;
        if (algorithm == null) {
            if (identity == null || signature == null) {
                throw new S3Exception(S3ErrorCode.ACCESS_DENIED);
            }
            signatureVersion4 = false;
            headerAuthorization = "AWS " + identity + ":" + signature;
        } else if (algorithm.equals("AWS4-HMAC-SHA256")) {
            if (identity == null || signature == null) {
                throw new S3Exception(S3ErrorCode.ACCESS_DENIED);
            }
            signatureVersion4 = true;
            headerAuthorization = "AWS4-HMAC-SHA256" +
                    " Credential=" + identity +
                    ", Signature=" + signature;
        } else {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        try {
            authHeader = new S3AuthorizationHeader(headerAuthorization);
        } catch (IllegalArgumentException iae) {
            throw new S3Exception(S3ErrorCode.INVALID_ARGUMENT, iae);
        }

        switch (authHeader.getAuthenticationType()) {
        case AWS_V2 -> {
            switch (authenticationType) {
            case AWS_V2, AWS_V2_OR_V4, NONE -> { }
            default -> throw new S3Exception(S3ErrorCode.ACCESS_DENIED);
            }
        }
        case AWS_V4 -> {
            switch (authenticationType) {
            case AWS_V4, AWS_V2_OR_V4, NONE -> { }
            default -> throw new S3Exception(S3ErrorCode.ACCESS_DENIED);
            }
        }
        case NONE -> { }
        default -> throw new IllegalArgumentException("Unhandled type: " +
                authHeader.getAuthenticationType());
        }

        // Locating with the bucket and key rather than with the identity alone
        // both authorizes them -- a BlobStoreLocator which scopes buckets to
        // identities answers null for one this caller may not address -- and
        // names the store to write to, which is not necessarily the default
        // one the anonymous path arrived with.
        AccessGrant grant = blobStoreLocator.locateBlobStore(
                authHeader.getIdentity(), containerName, blobName);
        if (grant == null) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            return;
        }
        Optional<String> credentialOptional = grant.credential();
        if (credentialOptional.isEmpty()) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            return;
        }
        String credential = credentialOptional.orElseThrow();

        if (signatureVersion4) {
            // V4 headers always carry these fields
            byte[] kSecret = ("AWS4" + credential).getBytes(
                    StandardCharsets.UTF_8);
            byte[] kDate = hmac("HmacSHA256",
                    requireNonNull(authHeader.getDate()).getBytes(
                            StandardCharsets.UTF_8),
                    kSecret);
            byte[] kRegion = hmac("HmacSHA256",
                    requireNonNull(authHeader.getRegion()).getBytes(
                            StandardCharsets.UTF_8),
                    kDate);
            byte[] kService = hmac("HmacSHA256",
                    requireNonNull(authHeader.getService()).getBytes(
                            StandardCharsets.UTF_8),
                    kRegion);
            byte[] kSigning = hmac("HmacSHA256",
                    "aws4_request".getBytes(StandardCharsets.UTF_8), kService);
            String expectedSignature = BaseEncoding.base16().lowerCase().encode(
                    hmac("HmacSHA256", policy, kSigning));
            if (!constantTimeEquals(signature, expectedSignature)) {
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                return;
            }
        } else {
            String expectedSignature = Base64.getEncoder().encodeToString(
                    hmac("HmacSHA1", policy,
                            credential.getBytes(StandardCharsets.UTF_8)));
            if (!constantTimeEquals(signature, expectedSignature)) {
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                return;
            }
        }

        // The signature proves only that the policy came from someone holding
        // the credential.  Whether this particular form is the one the policy
        // describes is a separate question, and asking it is the whole point
        // of the document.
        PostPolicy.parse(policy).evaluate(fields, payload.length);

        finishPostBlob(request, response, grant.blobStore(), containerName,
                blobName, contentType, fields, payload, checksum,
                checksumValue);
    }

    /**
     * Say what the multipart parser refused.  A body that outgrew a limit is
     * one the proxy will not hold, which is what MaxMessageLengthExceeded
     * says; every limit arrives as an IllegalStateException naming which.
     * Anything else it rejected is a body that is not the multipart/form-data
     * it claimed to be.  Both are the caller's own doing, and neither is the
     * 500 the unchecked exception would otherwise become.
     */
    private static S3Exception multipartParseFailure(CompletionException ce) {
        Throwable cause = ce.getCause();
        if (cause instanceof IllegalStateException) {
            return new S3Exception(S3ErrorCode.MAX_MESSAGE_LENGTH_EXCEEDED,
                    cause);
        }
        return new S3Exception(S3ErrorCode.INVALID_REQUEST,
                "The body of your POST request is not well-formed" +
                " multipart/form-data.", cause);
    }

    /**
     * Store what a form POST uploaded and answer it the way the form asked to
     * be answered.  Shared by the authenticated path and the anonymous one,
     * which differ only in whether a policy stood between them and here.
     */
    private void finishPostBlob(HttpServletRequest request,
            HttpServletResponse response, BlobStore blobStore,
            String containerName, String blobName,
            @Nullable String contentType, Map<String, String> fields,
            byte[] payload, @Nullable FlexChecksum checksum,
            @Nullable String checksumValue)
            throws IOException, S3Exception {
        if (checksum != null && checksumValue != null) {
            byte[] expected = checksum.decodeValue(checksumValue);
            byte[] actual = checksum.rawDigest(
                    checksum.hashFunction().hashBytes(payload));
            if (!java.util.Arrays.equals(expected, actual)) {
                throw new S3Exception(S3ErrorCode.BAD_DIGEST);
            }
        }

        Blob.Builder builder = Blob.builder(blobName)
                .payload(ByteSource.wrap(payload));
        if (contentType != null) {
            builder.contentType(contentType);
        }
        var userMetadata = new TreeMap<String, String>();
        for (var entry : fields.entrySet()) {
            if (entry.getKey().startsWith(USER_METADATA_PREFIX)) {
                userMetadata.put(entry.getKey().substring(
                        USER_METADATA_PREFIX.length()), entry.getValue());
            }
        }
        if (checksum != null && checksumValue != null) {
            userMetadata.put(checksum.metadataKey(), checksumValue);
        }
        if (!userMetadata.isEmpty()) {
            builder.userMetadata(userMetadata);
        }
        PutResult result = blobStore.putBlob(containerName, builder.build(),
                PutOptions.NONE);

        addCorsResponseHeader(request, response);
        if (checksum != null) {
            response.addHeader(checksum.header(), checksumValue);
        }
        String eTag = result.eTag();
        if (eTag != null) {
            response.addHeader(HttpHeaders.ETAG, maybeQuoteETag(eTag));
        }
        String versionId = result.versionId();
        if (versionId != null) {
            response.addHeader(AwsHttpHeaders.VERSION_ID, versionId);
        }

        // A browser posting a form has nowhere to display a response body, so
        // the form says where to send the user instead.  The redirect wins
        // over a status when both are present, as it does on S3.
        String redirect = fields.get("success_action_redirect");
        if (redirect == null) {
            redirect = fields.get("redirect");
        }
        if (redirect != null) {
            String location = redirect +
                    (redirect.contains("?") ? "&" : "?") +
                    "bucket=" + urlEscaper.escape(containerName) +
                    "&key=" + urlEscaper.escape(blobName) +
                    "&etag=" + urlEscaper.escape(
                            maybeQuoteETag(Strings.nullToEmpty(eTag)));
            response.setStatus(HttpServletResponse.SC_SEE_OTHER);
            response.addHeader(HttpHeaders.LOCATION, location);
            return;
        }

        // Only the three statuses S3 will send; anything else is treated as
        // unsaid rather than refused, which is what lets a form hard-code a
        // status a future version might add.
        String status = fields.get("success_action_status");
        if ("201".equals(status)) {
            response.setStatus(HttpServletResponse.SC_CREATED);
            response.setCharacterEncoding(UTF_8);
            response.setContentType(XML_CONTENT_TYPE);
            try (Writer writer = response.getWriter()) {
                XMLStreamWriter xml = xmlOutputFactory.createXMLStreamWriter(
                        writer);
                xml.writeStartDocument();
                xml.writeStartElement("PostResponse");
                writeSimpleElement(xml, "Location",
                        request.getRequestURL() + "/" +
                        urlEscaper.escape(blobName));
                writeSimpleElement(xml, "Bucket", containerName);
                writeSimpleElement(xml, "Key", blobName);
                if (eTag != null) {
                    writeSimpleElement(xml, "ETag", maybeQuoteETag(eTag));
                }
                xml.writeEndElement();
                xml.flush();
            } catch (XMLStreamException xse) {
                throw new IOException(xse);
            }
        } else if ("200".equals(status)) {
            response.setStatus(HttpServletResponse.SC_OK);
        } else {
            response.setStatus(HttpServletResponse.SC_NO_CONTENT);
        }
    }

    private void handleInitiateMultipartUpload(HttpServletRequest request,
            HttpServletResponse response, BlobStore blobStore,
            String containerName, String blobName)
            throws IOException, S3Exception {
        String checksumAlgorithm = request.getHeader(
                AwsHttpHeaders.CHECKSUM_ALGORITHM);
        FlexChecksum mpuAlgorithm = null;
        if (checksumAlgorithm != null) {
            mpuAlgorithm = FlexChecksum.fromAlgorithmName(checksumAlgorithm);
            if (mpuAlgorithm == null) {
                throw new S3Exception(S3ErrorCode.INVALID_REQUEST,
                        "Checksum algorithm provided is unsupported.");
            }
        }
        String checksumType = request.getHeader(AwsHttpHeaders.CHECKSUM_TYPE);
        boolean fullObject = false;
        if (checksumType != null) {
            if (checksumType.equalsIgnoreCase("FULL_OBJECT")) {
                if (mpuAlgorithm == null || !mpuAlgorithm.supportsFullObject()) {
                    throw new S3Exception(S3ErrorCode.INVALID_REQUEST,
                            "The checksum type full_object is not supported" +
                            " for checksum algorithm " +
                            (mpuAlgorithm == null ? "null" :
                                    mpuAlgorithm.lower()) + ".");
                }
                fullObject = true;
            } else if (!checksumType.equalsIgnoreCase("COMPOSITE")) {
                throw new S3Exception(S3ErrorCode.INVALID_REQUEST,
                        "Checksum type provided is unsupported.");
            }
        }

        ByteSource payload = ByteSource.empty();
        Blob.Builder builder = Blob.builder(blobName)
                .payload(payload);
        addContentMetadataFromHttpRequest(builder, request);
        builder.contentLength(payload.size());

        String storageClass = request.getHeader(AwsHttpHeaders.STORAGE_CLASS);
        if (storageClass == null || storageClass.equalsIgnoreCase("STANDARD")) {
            // defaults to STANDARD
        } else {
            try {
                builder.storageClass(StorageClass.valueOf(storageClass));
            } catch (IllegalArgumentException iae) {
                throw new S3Exception(S3ErrorCode.INVALID_STORAGE_CLASS, iae);
            }
        }

        String ifMatch = request.getHeader(HttpHeaders.IF_MATCH);
        String ifNoneMatch = request.getHeader(HttpHeaders.IF_NONE_MATCH);
        String blobStoreType = getBlobStoreType(blobStore);

        // Azure only supports If-None-Match: *, not If-Match: *
        // Handle If-Match: * manually for the azureblob provider.
        // Note: this is a non-atomic operation (HEAD then PUT).
        if (ifMatch != null && ifMatch.equals("*") &&
                blobStoreType.equals("azureblob")) {
            BlobMetadata metadata = blobStore.blobMetadata(containerName, blobName);
            if (metadata == null) {
                throw new S3Exception(S3ErrorCode.NO_SUCH_KEY);
            }
            ifMatch = null;
        }

        BlobAccess access;
        String cannedAcl = request.getHeader(AwsHttpHeaders.ACL);
        if (cannedAcl == null || cannedAcl.equalsIgnoreCase("private")) {
            access = BlobAccess.PRIVATE;
        } else if (cannedAcl.equalsIgnoreCase("public-read")) {
            access = BlobAccess.PUBLIC_READ;
        } else if (CANNED_ACLS.contains(cannedAcl)) {
            throw new S3Exception(S3ErrorCode.NOT_IMPLEMENTED);
        } else {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        var options = PutOptions.builder()
                .blobAccess(access)
                .ifMatch(ifMatch)
                .ifNoneMatch(ifNoneMatch)
                .build();

        MultipartUpload mpu = blobStore.initiateMultipartUpload(containerName,
                builder.build().getMetadata(), options);

        if (Quirks.MULTIPART_REQUIRES_STUB.contains(getBlobStoreType(
                blobStore))) {
            var stub = builder.name(multipartStubName(mpu.id()))
                    .payload(payload);
            if (fullObject) {
                // Remember the choice, since the completion request does not
                // reliably restate it and the two types are computed
                // differently.
                stub.userMetadata(Map.of(CHECKSUM_TYPE_METADATA_KEY,
                        FULL_OBJECT));
            }
            blobStore.putBlob(containerName, stub.build(), options);
        }

        response.setCharacterEncoding(UTF_8);
        addCorsResponseHeader(request, response);
        if (mpuAlgorithm != null) {
            response.addHeader(AwsHttpHeaders.CHECKSUM_ALGORITHM,
                    mpuAlgorithm.name());
            response.addHeader(AwsHttpHeaders.CHECKSUM_TYPE,
                    fullObject ? FULL_OBJECT : COMPOSITE);
        }
        try (Writer writer = response.getWriter()) {
            response.setContentType(XML_CONTENT_TYPE);
            XMLStreamWriter xml = xmlOutputFactory.createXMLStreamWriter(
                    writer);
            xml.writeStartDocument();
            xml.writeStartElement("InitiateMultipartUploadResult");
            xml.writeDefaultNamespace(AWS_XMLNS);

            writeSimpleElement(xml, "Bucket", containerName);
            writeSimpleElement(xml, "Key", blobName);
            writeSimpleElement(xml, "UploadId", mpu.id());

            xml.writeEndElement();
            xml.flush();
        } catch (XMLStreamException xse) {
            throw new IOException(xse);
        }
    }

    private void handleCompleteMultipartUpload(HttpServletRequest request,
            HttpServletResponse response, InputStream is,
            final BlobStore blobStore, String containerName, String blobName,
            String uploadId) throws IOException, S3Exception {
        // S3 rejects malformed checksum headers before considering their
        // meaning, even when the completion would fail for other reasons.
        validateChecksumHeaderValues(request);

        CompleteMultipartUploadRequest cmu = readXmlBody(
                is, CompleteMultipartUploadRequest.class);

        BlobMetadata metadata;
        PutOptions options;
        if (Quirks.MULTIPART_REQUIRES_STUB.contains(getBlobStoreType(
                blobStore))) {
            String stubName = multipartStubName(uploadId);
            metadata = blobStore.blobMetadata(containerName, stubName);
            if (metadata == null) {
                if (respondAlreadyCompleted(request, response, blobStore,
                        containerName, blobName, cmu)) {
                    return;
                }
                // the stub is the only record that the upload exists
                throw new S3Exception(S3ErrorCode.NO_SUCH_UPLOAD);
            }
            BlobAccess access = blobStore.getBlobAccess(containerName,
                    stubName);
            options = PutOptions.builder().blobAccess(access).build();
        } else {
            metadata = BlobMetadata.builder().name(blobName).build();
            options = PutOptions.NONE;
        }
        final MultipartUpload mpu = new MultipartUpload(containerName,
                blobName, uploadId, metadata, options);

        final List<MultipartPart> parts = new ArrayList<>();
        String blobStoreType = getBlobStoreType(blobStore);
        if (blobStoreType.equals("azureblob") ||
                blobStoreType.equals("google-cloud-storage")) {
            Map<Integer, MultipartPart> partsByListing;
            try {
                partsByListing =
                    blobStore.listMultipartUpload(mpu).stream().collect(
                            Collectors.toMap(
                                    part -> part.partNumber(),
                                    part -> part));
            } catch (KeyNotFoundException knfe) {
                // these backends recognize an upload id they never minted
                if (respondAlreadyCompleted(request, response, blobStore,
                        containerName, blobName, cmu)) {
                    return;
                }
                throw new S3Exception(S3ErrorCode.NO_SUCH_UPLOAD, knfe);
            }
            if (partsByListing.isEmpty()) {
                if (respondAlreadyCompleted(request, response, blobStore,
                        containerName, blobName, cmu)) {
                    return;
                }
                throw new S3Exception(S3ErrorCode.NO_SUCH_UPLOAD);
            }
            if (cmu.parts() != null) {
                // Sort by part number and deduplicate (last occurrence wins)
                // before validating, so a resent part is checked against the
                // ETag the client kept for its final upload.
                SortedMap<Integer, CompleteMultipartUploadRequest.Part>
                        requestParts = new TreeMap<>();
                for (CompleteMultipartUploadRequest.Part part : cmu.parts()) {
                    if (part.partNumber() < 1 || part.partNumber() > 10_000) {
                        throw new S3Exception(S3ErrorCode.INVALID_PART_ORDER,
                                "Part numbers must be positive integers.");
                    }
                    requestParts.put(part.partNumber(), part);
                }
                for (CompleteMultipartUploadRequest.Part part :
                        requestParts.values()) {
                    MultipartPart uploadedPart = partsByListing.get(
                            part.partNumber());
                    if (uploadedPart == null) {
                        throw new S3Exception(S3ErrorCode.INVALID_PART);
                    }
                    // Validate the client-supplied ETag against the uploaded
                    // part when the backend reports one (azureblob returns
                    // an empty ETag and is left unvalidated).
                    String uploadedETag = uploadedPart.partETag();
                    if (uploadedETag != null && !uploadedETag.isEmpty() &&
                            !equalsIgnoringSurroundingQuotes(
                                    uploadedETag, part.eTag())) {
                        throw new S3Exception(S3ErrorCode.INVALID_PART);
                    }
                    parts.add(uploadedPart);
                }
            }
        } else {
            var partsByListing =
                blobStore.listMultipartUpload(mpu).stream().collect(
                        Collectors.toMap(
                                part -> part.partNumber(),
                                part -> part));
            if (partsByListing.isEmpty()) {
                if (respondAlreadyCompleted(request, response, blobStore,
                        containerName, blobName, cmu)) {
                    return;
                }
                throw new S3Exception(S3ErrorCode.NO_SUCH_UPLOAD);
            }
            // use TreeMap to sort by part number and deduplicate (last wins)
            SortedMap<Integer, String> requestParts = new TreeMap<>();
            if (cmu.parts() != null) {
                for (CompleteMultipartUploadRequest.Part part : cmu.parts()) {
                    if (part.partNumber() < 1 || part.partNumber() > 10_000) {
                        throw new S3Exception(S3ErrorCode.INVALID_PART_ORDER,
                                "Part numbers must be positive integers.");
                    }
                    requestParts.put(part.partNumber(), part.eTag());
                }
            }

            for (var it = requestParts.entrySet().iterator(); it.hasNext();) {
                var entry = it.next();
                MultipartPart part = partsByListing.get(entry.getKey());
                if (part == null) {
                    throw new S3Exception(S3ErrorCode.INVALID_PART);
                }
                long partSize = part.partSize();
                if (it.hasNext() && partSize != -1 &&
                        (partSize < 5 * 1024 * 1024 || partSize <
                                blobStore.getMinimumMultipartPartSize())) {
                    throw new S3Exception(S3ErrorCode.ENTITY_TOO_SMALL);
                }
                if (part.partETag() != null &&
                        !equalsIgnoringSurroundingQuotes(part.partETag(),
                                entry.getValue())) {
                    throw new S3Exception(S3ErrorCode.INVALID_PART);
                }
                parts.add(new MultipartPart(entry.getKey(),
                        partSize, part.partETag(), part.lastModified()));
            }
        }

        if (parts.isEmpty()) {
            // Amazon requires at least one part
            throw new S3Exception(S3ErrorCode.MALFORMED_X_M_L);
        }

        // Hand the condition to the store, which resolves it as it publishes
        // the object.  Checking it here instead would only hold while nothing
        // else writes the same key, which is what the caller is guarding
        // against.  Stores that cannot answer at all say so.
        String ifMatch = request.getHeader(HttpHeaders.IF_MATCH);
        String ifNoneMatch = request.getHeader(HttpHeaders.IF_NONE_MATCH);
        if (ifMatch != null || ifNoneMatch != null) {
            if (!Quirks.NATIVE_CONDITIONAL_COMPLETE.contains(blobStoreType)) {
                throw new S3Exception(S3ErrorCode.NOT_IMPLEMENTED,
                        "Conditional writes are not supported by this" +
                        " backend.");
            }
            // S3 answers an If-Match naming a key that does not exist with
            // 404, where the stores report 412; settle that here, and once
            // existence is established If-Match: * asks nothing more.
            if (ifMatch != null) {
                if (!blobStore.blobExists(containerName, blobName)) {
                    throw new S3Exception(S3ErrorCode.NO_SUCH_KEY);
                }
                if (ifMatch.equals("*")) {
                    ifMatch = null;
                }
            }
            if (Quirks.NATIVE_IF_NONE_MATCH.contains(blobStoreType) &&
                    ifMatch != null) {
                // the nio2 stores resolve If-None-Match while writing but
                // have no compare-and-swap for an ETag, so If-Match stays a
                // check followed by a write, bounded by this process
                checkConditionalWrite(blobStore.blobMetadata(containerName,
                        blobName), ifMatch, /*ifNoneMatch=*/ null);
                ifMatch = null;
            }
        }
        final String completeIfMatch = ifMatch;
        final String completeIfNoneMatch = ifNoneMatch;

        boolean requiresStub = Quirks.MULTIPART_REQUIRES_STUB.contains(
                blobStoreType);
        MpuChecksum mpuChecksum = null;
        FlexChecksum mpuAlgorithm =
                cmu == null ? null : mpuChecksumAlgorithm(cmu);
        if (cmu != null && mpuAlgorithm != null) {
            // S3 computes the checksum from the values recorded when the
            // parts were uploaded, ignoring the ones the completion request
            // asserts beyond their presence.  Stub backends store parts as
            // hidden blobs, so recover the true per-part checksums from the
            // part content; other backends fall back to the asserted values
            // and to the part sizes the backend reports.
            Map<Integer, PartChecksum> partChecksums = requiresStub ?
                    hashMultipartPartContents(blobStore, containerName,
                            blobName, uploadId, mpuAlgorithm, cmu) :
                    null;
            var partSizes = new HashMap<Integer, Long>();
            for (MultipartPart part : parts) {
                partSizes.put(part.partNumber(), part.partSize());
            }
            mpuChecksum = computeMpuChecksum(request, cmu, mpuAlgorithm,
                    partChecksums, partSizes,
                    fullObjectUpload(metadata, request, mpuAlgorithm));
        }

        // The condition rides down with the upload, since completion is the
        // write that has to honour it.
        PutOptions completeOptions = options;
        if (completeIfMatch != null || completeIfNoneMatch != null) {
            completeOptions = (options == null ? PutOptions.builder() :
                    options.toBuilder())
                    .ifMatch(completeIfMatch)
                    .ifNoneMatch(completeIfNoneMatch)
                    .build();
        }

        // Persist the composite checksum onto the final object for stub
        // backends, which build the completed blob's metadata from the
        // MultipartUpload passed to completeMultipartUpload.
        BlobMetadata completeMetadata = metadata;
        if (mpuChecksum != null && metadata != null && requiresStub) {
            var userMetadata = new LinkedHashMap<>(metadata.userMetadata());
            // the upload's bookkeeping does not belong on the object; the
            // stored value's shape already says which type it is
            userMetadata.remove(CHECKSUM_TYPE_METADATA_KEY);
            userMetadata.put(mpuChecksum.algorithm().metadataKey(),
                    mpuChecksum.value());
            completeMetadata = metadata.toBuilder()
                    .userMetadata(userMetadata).build();
        }
        final MultipartUpload completeMpu = new MultipartUpload(containerName,
                blobName, uploadId, completeMetadata, completeOptions);

        // A conditional completion has to finish before anything is sent: the
        // store decides the outcome, and once the 200 and the XML prolog are
        // out the refusal can no longer be a status code.  That costs the
        // whitespace kept flowing during a slow completion, which matters
        // less than answering 412 where S3 answers 412.  A versioning store
        // completes synchronously for the same reason: the version it mints
        // is a response header, unsendable once the prolog is out.
        PutResult syncResult = null;
        if (completeIfMatch != null || completeIfNoneMatch != null ||
                blobStore.supportsVersioning()) {
            syncResult = blobStore.completeMultipartUpload(completeMpu, parts);
            if (Quirks.MULTIPART_REQUIRES_STUB.contains(blobStoreType)) {
                blobStore.removeBlob(containerName,
                        multipartStubName(uploadId));
            }
        }
        final PutResult completedResult = syncResult;

        response.setCharacterEncoding(UTF_8);
        addCorsResponseHeader(request, response);
        if (completedResult != null && completedResult.versionId() != null) {
            response.addHeader(AwsHttpHeaders.VERSION_ID,
                    completedResult.versionId());
        }
        try (PrintWriter writer = response.getWriter()) {
            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType(XML_CONTENT_TYPE);

            if (mpuChecksum != null) {
                response.addHeader(AwsHttpHeaders.CHECKSUM_TYPE,
                        checksumType(mpuChecksum.value()));
                response.addHeader(mpuChecksum.algorithm().header(),
                        mpuChecksum.value());
            }

            // Launch async thread to allow main thread to emit newlines to
            // the client while completeMultipartUpload processes.
            final var result = new AtomicReference<@Nullable PutResult>(
                    completedResult);
            final AtomicReference<RuntimeException> exception =
                    new AtomicReference<>();
            var thread = new Thread() {
                @Override
                public void run() {
                    try {
                        result.set(blobStore.completeMultipartUpload(
                                completeMpu, parts));
                    } catch (RuntimeException re) {
                        exception.set(re);
                    }
                }
            };
            if (completedResult == null) {
                thread.start();
            }

            XMLStreamWriter xml = xmlOutputFactory.createXMLStreamWriter(
                    writer);
            xml.writeStartDocument();
            xml.flush();

            // Emit whitespace in the prolog while completeMultipartUpload
            // runs so a slow completion does not idle the connection.  The
            // root element is written only once the outcome is known, so a
            // late failure can still be reported instead of truncating a
            // half-written success document.
            while (thread.isAlive()) {
                try {
                    thread.join(1000);
                } catch (InterruptedException ie) {
                    // ignore
                }
                writer.write("\n");
                writer.flush();
            }

            if (exception.get() != null) {
                // The 200 status and XML prolog are already sent, so the
                // failure cannot be signaled through the status code.  Write
                // an <Error> body -- as S3 does for a late completion failure
                // -- rather than truncating the response by rethrowing.
                logger.error("completeMultipartUpload failed after the " +
                        "response was committed", exception.get());
                xml.writeStartElement("Error");
                writeSimpleElement(xml, "Code",
                        S3ErrorCode.INTERNAL_ERROR.getErrorCode());
                writeSimpleElement(xml, "Message",
                        S3ErrorCode.INTERNAL_ERROR.getMessage());
                String requestId = response.getHeader(
                        AwsHttpHeaders.REQUEST_ID);
                if (requestId == null) {
                    requestId = generateRequestId();
                }
                writeSimpleElement(xml, "RequestId", requestId);
                xml.writeEndElement();
                xml.flush();
                return;
            }

            if (completedResult == null &&
                    Quirks.MULTIPART_REQUIRES_STUB.contains(
                            getBlobStoreType(blobStore))) {
                blobStore.removeBlob(containerName,
                        multipartStubName(uploadId));
            }

            xml.writeStartElement("CompleteMultipartUploadResult");
            xml.writeDefaultNamespace(AWS_XMLNS);

            // TODO: bogus value
            writeSimpleElement(xml, "Location",
                    "http://Example-Bucket.s3.amazonaws.com/" + blobName);

            writeSimpleElement(xml, "Bucket", containerName);
            writeSimpleElement(xml, "Key", blobName);

            PutResult completed = result.get();
            String completedETag = completed == null ? null : completed.eTag();
            if (completedETag != null) {
                writeSimpleElement(xml, "ETag",
                        maybeQuoteETag(completedETag));
            }

            if (mpuChecksum != null) {
                writeSimpleElement(xml, "ChecksumType",
                        checksumType(mpuChecksum.value()));
                writeSimpleElement(xml, mpuChecksum.algorithm().element(),
                        mpuChecksum.value());
            }

            xml.writeEndElement();
            xml.flush();
        } catch (XMLStreamException xse) {
            throw new IOException(xse);
        }
    }

    /**
     * Reject malformed x-amz-checksum-* request header values before
     * considering their meaning.  A valid value is either a bare base64
     * digest of the algorithm's length or a composite
     * "&lt;base64&gt;-&lt;partCount&gt;".  Base64 never contains '-', so its
     * presence always marks the composite suffix.  A digest that is not
     * valid base64 of the right length is 400 BadDigest, the same answer a
     * well formed digest that does not match the body gets; a malformed
     * part count describes the request rather than the digest and stays
     * 400 InvalidRequest.
     */
    private static void validateChecksumHeaderValues(
            HttpServletRequest request) throws S3Exception {
        for (FlexChecksum checksum : FlexChecksum.values()) {
            String value = request.getHeader(checksum.header());
            if (value == null) {
                continue;
            }
            String base64Part = value;
            int dash = value.indexOf('-');
            if (dash >= 0) {
                base64Part = value.substring(0, dash);
                int count;
                try {
                    count = Integer.parseInt(value.substring(dash + 1));
                } catch (NumberFormatException nfe) {
                    throw new S3Exception(S3ErrorCode.INVALID_REQUEST,
                            "Value for " + checksum.header() +
                            " header is invalid.", nfe, Map.of());
                }
                if (count < 1 || count > 10_000) {
                    throw new S3Exception(S3ErrorCode.INVALID_REQUEST,
                            "Value for " + checksum.header() +
                            " header is invalid.");
                }
            }
            checksum.decodeValue(base64Part);
        }
    }

    /**
     * The ETag completing {@code cmu} produces: the hex MD5 of the
     * concatenated part MD5s suffixed with the part count.  Null when a part
     * omits its ETag or carries one that is not a hex MD5, e.g. because the
     * backend does not compose ETags the way S3 does.
     */
    @Nullable
    private static String compositeETag(CompleteMultipartUploadRequest cmu) {
        if (cmu.parts() == null || cmu.parts().isEmpty()) {
            return null;
        }
        var digests = new TreeMap<Integer, byte[]>();
        for (CompleteMultipartUploadRequest.Part part : cmu.parts()) {
            String eTag = part.eTag();
            if (eTag == null) {
                return null;
            }
            eTag = eTag.replace("\"", "").toLowerCase();
            try {
                byte[] digest = BaseEncoding.base16().lowerCase().decode(eTag);
                if (digest.length != MD5.bits() / Byte.SIZE) {
                    return null;
                }
                digests.put(part.partNumber(), digest);
            } catch (IllegalArgumentException iae) {
                return null;
            }
        }
        Hasher hasher = MD5.newHasher();
        for (byte[] digest : digests.values()) {
            hasher.putBytes(digest);
        }
        return hasher.hash() + "-" + digests.size();
    }

    /**
     * Repeat the result of a multipart upload that already completed, which
     * S3 allows so a client whose response was lost can retry.  s3proxy
     * keeps no record of a finished upload, so recognize the retry by the
     * object the completion left behind carrying exactly the ETag these
     * parts compose to.  Returns false when nothing matches, leaving the
     * caller to reject the unknown upload as before.
     */
    private boolean respondAlreadyCompleted(HttpServletRequest request,
            HttpServletResponse response, BlobStore blobStore,
            String containerName, String blobName,
            CompleteMultipartUploadRequest cmu) throws IOException {
        String expected = compositeETag(cmu);
        if (expected == null) {
            return false;
        }
        BlobMetadata metadata = blobStore.blobMetadata(containerName,
                blobName);
        if (metadata == null || metadata.eTag() == null ||
                !equalsIgnoringSurroundingQuotes(expected, metadata.eTag())) {
            return false;
        }

        // Prefer the composite persisted at completion; backends that
        // cannot store it keep no record, so fall back to echoing the
        // request's own value the way the first completion did.
        FlexChecksum checksum = null;
        String checksumValue = null;
        for (var entry : metadata.userMetadata().entrySet()) {
            if (startsWithIgnoreCase(entry.getKey(),
                    CHECKSUM_METADATA_PREFIX)) {
                FlexChecksum candidate = FlexChecksum.fromMetadataKey(
                        entry.getKey());
                if (candidate != null) {
                    checksum = candidate;
                    checksumValue = entry.getValue();
                }
            }
        }
        if (checksum == null) {
            for (FlexChecksum candidate : FlexChecksum.values()) {
                String value = request.getHeader(candidate.header());
                if (value != null) {
                    checksum = candidate;
                    checksumValue = value;
                    break;
                }
            }
        }

        response.setStatus(HttpServletResponse.SC_OK);
        response.setCharacterEncoding(UTF_8);
        response.setContentType(XML_CONTENT_TYPE);
        if (checksum != null && checksumValue != null) {
            response.addHeader(AwsHttpHeaders.CHECKSUM_TYPE, "COMPOSITE");
            response.addHeader(checksum.header(), checksumValue);
        }
        try (PrintWriter writer = response.getWriter()) {
            XMLStreamWriter xml = xmlOutputFactory.createXMLStreamWriter(
                    writer);
            xml.writeStartDocument();
            xml.writeStartElement("CompleteMultipartUploadResult");
            xml.writeDefaultNamespace(AWS_XMLNS);
            // TODO: bogus value
            writeSimpleElement(xml, "Location",
                    "http://Example-Bucket.s3.amazonaws.com/" + blobName);
            writeSimpleElement(xml, "Bucket", containerName);
            writeSimpleElement(xml, "Key", blobName);
            writeSimpleElement(xml, "ETag",
                    maybeQuoteETag(metadata.eTag()));
            if (checksum != null && checksumValue != null) {
                writeSimpleElement(xml, "ChecksumType",
                        checksumType(checksumValue));
                writeSimpleElement(xml, checksum.element(), checksumValue);
            }
            xml.writeEndElement();
            xml.flush();
        } catch (XMLStreamException xse) {
            throw new IOException(xse);
        }
        return true;
    }

    /**
     * The single checksum algorithm the CompleteMultipartUpload request's
     * parts declare, null when no part carries a checksum, rejecting a mix
     * of algorithms.
     */
    @Nullable
    private static FlexChecksum mpuChecksumAlgorithm(
            CompleteMultipartUploadRequest cmu) throws S3Exception {
        if (cmu.parts() == null) {
            return null;
        }
        FlexChecksum algorithm = null;
        for (CompleteMultipartUploadRequest.Part part : cmu.parts()) {
            for (FlexChecksum candidate : FlexChecksum.values()) {
                if (candidate.value(part) != null) {
                    if (algorithm != null && algorithm != candidate) {
                        throw new S3Exception(S3ErrorCode.INVALID_REQUEST,
                                "More than one checksum algorithm was" +
                                " supplied for the parts.");
                    }
                    algorithm = candidate;
                }
            }
        }
        return algorithm;
    }

    /**
     * Compute each referenced part's true checksum by re-reading the hidden
     * part blobs that MULTIPART_REQUIRES_STUB backends store, so the result
     * matches the uploaded content no matter what per-part values the
     * completion request asserts (S3 ignores those beyond presence).  The
     * length comes back too, since combining CRCs into a full-object
     * checksum needs it.
     */
    private static Map<Integer, PartChecksum> hashMultipartPartContents(
            BlobStore blobStore, String containerName, String blobName,
            String uploadId, FlexChecksum algorithm,
            CompleteMultipartUploadRequest cmu) throws IOException {
        var digests = new HashMap<Integer, PartChecksum>();
        var partNumbers = new TreeSet<Integer>();
        for (CompleteMultipartUploadRequest.Part part : cmu.parts()) {
            partNumbers.add(part.partNumber());
        }
        for (int partNumber : partNumbers) {
            Blob blob = blobStore.getBlob(containerName,
                    AbstractNio2BlobStore.multipartPartName(uploadId,
                            blobName, partNumber), GetOptions.NONE);
            if (blob == null) {
                // a missing part is rejected elsewhere; fall back to the
                // client-asserted value
                continue;
            }
            Hasher hasher = algorithm.hashFunction().newHasher();
            long length = 0;
            try (InputStream partIs = requireNonNull(blob.getPayload())) {
                byte[] buffer = new byte[16384];
                while (true) {
                    int count = partIs.read(buffer);
                    if (count == -1) {
                        break;
                    }
                    hasher.putBytes(buffer, 0, count);
                    length += count;
                }
            }
            digests.put(partNumber, new PartChecksum(
                    algorithm.rawDigest(hasher.hash()), length));
        }
        return digests;
    }

    /**
     * Whether the upload asked for a checksum describing the whole object
     * rather than the parts.  The stub records the choice made at initiation;
     * backends without one have only the completion request to go on, where a
     * value carrying no "-<partCount>" suffix implies a full object.
     */
    private static boolean fullObjectUpload(@Nullable BlobMetadata metadata,
            HttpServletRequest request, FlexChecksum algorithm) {
        if (!algorithm.supportsFullObject()) {
            return false;
        }
        if (metadata != null) {
            String recorded = metadata.userMetadata().get(
                    CHECKSUM_TYPE_METADATA_KEY);
            if (recorded != null) {
                return recorded.equals(FULL_OBJECT);
            }
        }
        String type = request.getHeader(AwsHttpHeaders.CHECKSUM_TYPE);
        if (type != null) {
            return type.equalsIgnoreCase(FULL_OBJECT);
        }
        String provided = request.getHeader(algorithm.header());
        return provided != null && provided.indexOf('-') < 0;
    }

    /**
     * Enforce the per-part flexible checksums carried by a
     * CompleteMultipartUpload request and compute the composite checksum S3
     * returns for the finished object.  Modern AWS SDKs attach a per-part
     * checksum for every part when the upload was created with a checksum
     * algorithm; S3 rejects the completion when those checksums are missing
     * from some parts or are malformed.  Returns the composite checksum
     * (base64(hash(concatenated part digests)) plus a "-&lt;partCount&gt;"
     * suffix), preferring the true digests in {@code partDigests} over the
     * client-asserted values.
     */
    @Nullable
    private static MpuChecksum computeMpuChecksum(HttpServletRequest request,
            CompleteMultipartUploadRequest cmu, FlexChecksum algorithm,
            @Nullable Map<Integer, PartChecksum> partChecksums,
            Map<Integer, Long> partSizes, boolean fullObject)
            throws S3Exception {
        // Deduplicate by part number (last wins) and sort ascending so the
        // parts are folded together in canonical order.
        SortedMap<Integer, CompleteMultipartUploadRequest.Part> sorted =
                new TreeMap<>();
        for (CompleteMultipartUploadRequest.Part part : cmu.parts()) {
            sorted.put(part.partNumber(), part);
        }

        // Every part must supply the checksum, matching S3's requirement that
        // a checksum-initiated upload include a per-part checksum for each
        // part.  A composite hashes the concatenated part digests; a full
        // object folds the part CRCs into the CRC of the whole.
        Hasher hasher = algorithm.hashFunction().newHasher();
        byte[] combined = null;
        for (var entry : sorted.entrySet()) {
            String value = algorithm.value(entry.getValue());
            if (value == null) {
                throw new S3Exception(S3ErrorCode.INVALID_REQUEST,
                        "The upload was created using a " + algorithm.lower() +
                        " checksum. The complete request must include the" +
                        " checksum for each part. It was missing for part " +
                        entry.getKey() + " in the request.");
            }
            PartChecksum part = partChecksums != null ?
                    partChecksums.get(entry.getKey()) : null;
            byte[] digest = part != null ? part.digest() :
                    algorithm.decodeValue(value);
            if (!fullObject) {
                hasher.putBytes(digest);
                continue;
            }
            long length = part != null ? part.length() :
                    partSizes.getOrDefault(entry.getKey(), -1L);
            if (length < 0) {
                // without the part's length the CRCs cannot be folded, so
                // report no checksum rather than a wrong one
                return null;
            }
            combined = combined == null ? digest :
                    algorithm.combine(combined, digest, length);
        }

        String computed;
        if (fullObject) {
            if (combined == null) {
                return null;
            }
            computed = algorithm.encodeRaw(combined);
        } else {
            computed = algorithm.encode(hasher.hash()) + "-" + sorted.size();
        }

        // If the client asserted the expected checksum on the completion
        // request, validate our computation against it.  Only a composite
        // carries the "-<partCount>" suffix; for a composite upload a bare
        // value in this header is the SDK's request-body integrity checksum,
        // which is unrelated to the completed object.
        String provided = request.getHeader(algorithm.header());
        if (provided != null && (fullObject || provided.indexOf('-') >= 0) &&
                !provided.equals(computed)) {
            throw new S3Exception(S3ErrorCode.BAD_DIGEST);
        }

        return new MpuChecksum(algorithm, computed);
    }

    private record MpuChecksum(FlexChecksum algorithm, String value) {
    }

    /**
     * Which kind of checksum a stored value is.  Only a composite carries the
     * "-<partCount>" suffix, base64 having no use for a hyphen.
     */
    private static String checksumType(String value) {
        return value.indexOf('-') >= 0 ? COMPOSITE : FULL_OBJECT;
    }

    /** An uploaded part's true digest and length. */
    @SuppressWarnings("ArrayRecordComponent")
    private record PartChecksum(byte[] digest, long length) {
    }

    @SuppressWarnings("deprecation")
    private enum FlexChecksum {
        CRC32("crc32", "ChecksumCRC32", AwsHttpHeaders.CHECKSUM_CRC32, 4, true,
                Hashing.crc32(), 0xedb88320L),
        CRC32C("crc32c", "ChecksumCRC32C", AwsHttpHeaders.CHECKSUM_CRC32C, 4,
                true, Hashing.crc32c(), 0x82f63b78L),
        // Crc64Nvme already hashes to the big-endian wire form, unlike
        // Guava's 32-bit CRCs, so it needs no further byte swapping.
        CRC64NVME("crc64nvme", "ChecksumCRC64NVME",
                AwsHttpHeaders.CHECKSUM_CRC64NVME, 8, false,
                Crc64Nvme.INSTANCE, 0x9a6c9329ac4bc9b5L),
        SHA1("sha1", "ChecksumSHA1", AwsHttpHeaders.CHECKSUM_SHA1, 20, false,
                Hashing.sha1(), 0),
        SHA256("sha256", "ChecksumSHA256", AwsHttpHeaders.CHECKSUM_SHA256, 32,
                false, Hashing.sha256(), 0);

        private final String lower;
        private final String element;
        private final String header;
        private final int length;
        private final boolean bigEndianInt;
        private final HashFunction hashFunction;
        /** Reflected CRC polynomial, or zero for a hash that cannot combine. */
        private final long polynomial;

        FlexChecksum(String lower, String element, String header, int length,
                boolean bigEndianInt, HashFunction hashFunction,
                long polynomial) {
            this.lower = lower;
            this.element = element;
            this.header = header;
            this.length = length;
            this.bigEndianInt = bigEndianInt;
            this.hashFunction = hashFunction;
            this.polynomial = polynomial;
        }

        /**
         * Whether S3 allows this algorithm's multipart checksum to describe
         * the whole object rather than the parts, which needs the CRCs of two
         * ranges to combine into the CRC of their concatenation.
         */
        boolean supportsFullObject() {
            return polynomial != 0;
        }

        /**
         * The digest of a || b, given their digests and the length of b.
         * Only valid when {@link #supportsFullObject}.
         */
        byte[] combine(byte[] a, byte[] b, long lengthB) {
            long combined = CrcCombine.combine(toLong(a), toLong(b), lengthB,
                    polynomial, length * Byte.SIZE);
            var buffer = java.nio.ByteBuffer.allocate(length);
            if (length == Integer.BYTES) {
                buffer.putInt((int) combined);
            } else {
                buffer.putLong(combined);
            }
            return buffer.array();
        }

        /** A big-endian wire digest as an unsigned value. */
        private static long toLong(byte[] digest) {
            long value = 0;
            for (byte b : digest) {
                value = (value << Byte.SIZE) | (b & 0xffL);
            }
            return value;
        }

        String lower() {
            return lower;
        }

        String element() {
            return element;
        }

        String header() {
            return header;
        }

        boolean bigEndianInt() {
            return bigEndianInt;
        }

        HashFunction hashFunction() {
            return hashFunction;
        }

        String value(CompleteMultipartUploadRequest.Part part) {
            return switch (this) {
            case CRC32 -> part.checksumCRC32();
            case CRC32C -> part.checksumCRC32C();
            case CRC64NVME -> part.checksumCRC64NVME();
            case SHA1 -> part.checksumSHA1();
            case SHA256 -> part.checksumSHA256();
            };
        }

        /** User-metadata key persisting this checksum with the object. */
        String metadataKey() {
            return CHECKSUM_METADATA_PREFIX + lower;
        }

        /** The hash in AWS wire form (big-endian for the CRCs). */
        byte[] rawDigest(HashCode hash) {
            return bigEndianInt ?
                    java.nio.ByteBuffer.allocate(4).putInt(hash.asInt())
                            .array() :
                    hash.asBytes();
        }

        /** Base64 of the hash in AWS wire form. */
        String encode(HashCode hash) {
            return Base64.getEncoder().encodeToString(rawDigest(hash));
        }

        /** Base64 of a digest already in AWS wire form. */
        String encodeRaw(byte[] digest) {
            return Base64.getEncoder().encodeToString(digest);
        }

        /**
         * Decode a client-asserted checksum value, rejecting values that are
         * not base64 of exactly this algorithm's digest length the way S3
         * does: 400 InvalidRequest rather than a digest mismatch.
         */
        byte[] decodeValue(String value) throws S3Exception {
            byte[] decoded;
            try {
                decoded = Base64.getDecoder().decode(value);
            } catch (IllegalArgumentException iae) {
                throw new S3Exception(S3ErrorCode.BAD_DIGEST,
                        "Value for " + header + " header is invalid.", iae,
                        Map.of());
            }
            if (decoded.length != length) {
                throw new S3Exception(S3ErrorCode.BAD_DIGEST,
                        "Value for " + header + " header is invalid.");
            }
            return decoded;
        }

        @Nullable
        static FlexChecksum fromAlgorithmName(String name) {
            for (FlexChecksum checksum : values()) {
                if (checksum.name().equalsIgnoreCase(name)) {
                    return checksum;
                }
            }
            return null;
        }

        @Nullable
        static FlexChecksum fromHeaderName(String header) {
            for (FlexChecksum checksum : values()) {
                if (checksum.header().equalsIgnoreCase(header)) {
                    return checksum;
                }
            }
            return null;
        }

        @Nullable
        static FlexChecksum fromMetadataKey(String key) {
            for (FlexChecksum checksum : values()) {
                if (checksum.metadataKey().equalsIgnoreCase(key)) {
                    return checksum;
                }
            }
            return null;
        }
    }

    private void handleAbortMultipartUpload(HttpServletRequest request,
            HttpServletResponse response, BlobStore blobStore,
            String containerName, String blobName,
            String uploadId) throws IOException, S3Exception {
        if (Quirks.MULTIPART_REQUIRES_STUB.contains(getBlobStoreType(
                blobStore))) {
            String stubName = multipartStubName(uploadId);
            if (!blobStore.blobExists(containerName, stubName)) {
                throw new S3Exception(S3ErrorCode.NO_SUCH_UPLOAD);
            }

            blobStore.removeBlob(containerName, stubName);
        }

        addCorsResponseHeader(request, response);

        // TODO: how to reconstruct original mpu?
        MultipartUpload mpu = new MultipartUpload(containerName,
                blobName, uploadId, createFakeBlobMetadata(),
                PutOptions.NONE);
        try {
            blobStore.abortMultipartUpload(mpu);
        } catch (KeyNotFoundException knfe) {
            throw new S3Exception(S3ErrorCode.NO_SUCH_UPLOAD, knfe);
        }
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }

    private void handleListParts(HttpServletRequest request,
            HttpServletResponse response, BlobStore blobStore,
            String containerName, String blobName, String uploadId)
            throws IOException, S3Exception {
        // support only the no-op zero case
        String partNumberMarker = request.getParameter("part-number-marker");
        if (partNumberMarker != null && !partNumberMarker.equals("0")) {
            throw new S3Exception(S3ErrorCode.NOT_IMPLEMENTED);
        }

        // TODO: how to reconstruct original mpu?
        MultipartUpload mpu = new MultipartUpload(containerName,
                blobName, uploadId, createFakeBlobMetadata(),
                PutOptions.NONE);

        List<MultipartPart> parts = blobStore.listMultipartUpload(mpu);

        String encodingType = request.getParameter("encoding-type");

        response.setCharacterEncoding(UTF_8);
        addCorsResponseHeader(request, response);
        try (Writer writer = response.getWriter()) {
            response.setContentType(XML_CONTENT_TYPE);
            XMLStreamWriter xml = xmlOutputFactory.createXMLStreamWriter(
                    writer);
            xml.writeStartDocument();
            xml.writeStartElement("ListPartsResult");
            xml.writeDefaultNamespace(AWS_XMLNS);

            if (encodingType != null && encodingType.equals("url")) {
                writeSimpleElement(xml, "EncodingType", encodingType);
            }

            writeSimpleElement(xml, "Bucket", containerName);
            writeSimpleElement(xml, "Key", encodeBlob(
                    encodingType, blobName));
            writeSimpleElement(xml, "UploadId", uploadId);
            writeInitiatorStanza(xml);
            writeOwnerStanza(xml);
            // TODO: bogus value
            writeSimpleElement(xml, "StorageClass", "STANDARD");

            // s3proxy returns every part in a single response; marker-based
            // pagination is not implemented (a non-zero part-number-marker is
            // rejected above), so the listing is never truncated.  The S3 API
            // requires these elements -- in particular IsTruncated, whose
            // absence makes strict clients (e.g. the AWS SDK) read a null.
            writeSimpleElement(xml, "PartNumberMarker", "0");
            writeSimpleElement(xml, "NextPartNumberMarker", "0");
            writeSimpleElement(xml, "MaxParts", "1000");
            writeSimpleElement(xml, "IsTruncated", "false");

            for (MultipartPart part : parts) {
                xml.writeStartElement("Part");

                writeSimpleElement(xml, "PartNumber", String.valueOf(
                        part.partNumber()));

                Date lastModified = part.lastModified();
                if (lastModified != null) {
                    writeSimpleElement(xml, "LastModified",
                            formatDate(lastModified));
                }

                String eTag = part.partETag();
                if (eTag != null) {
                    writeSimpleElement(xml, "ETag", maybeQuoteETag(eTag));
                }

                writeSimpleElement(xml, "Size", String.valueOf(
                        part.partSize()));

                xml.writeEndElement();
            }

            xml.writeEndElement();
            xml.flush();
        } catch (XMLStreamException xse) {
            throw new IOException(xse);
        }
    }

    private void handleCopyPart(HttpServletRequest request,
            HttpServletResponse response, BlobStore blobStore,
            @Nullable String requestIdentity,
            String containerName, String blobName, String uploadId)
            throws IOException, S3Exception {
        // TODO: duplicated from handlePutBlob
        String rawCopySource = request.getHeader(AwsHttpHeaders.COPY_SOURCE);
        String sourceVersionId = parseCopySourceVersionId(rawCopySource,
                blobStore);
        String copySourceHeader = URLDecoder.decode(
                stripCopySourceQuery(rawCopySource), StandardCharsets.UTF_8);
        if (copySourceHeader.startsWith("/")) {
            // Some clients like boto do not include the leading slash
            copySourceHeader = copySourceHeader.substring(1);
        }
        String[] path = copySourceHeader.split("/", 2);
        if (path.length != 2) {
            throw new S3Exception(S3ErrorCode.INVALID_REQUEST);
        }
        String sourceContainerName = path[0];
        String sourceBlobName = path[1];
        authorizeCopySource(requestIdentity, sourceContainerName,
                sourceBlobName);

        var optionsBuilder = GetOptions.builder();
        optionsBuilder.versionId(sourceVersionId);
        String range = request.getHeader(AwsHttpHeaders.COPY_SOURCE_RANGE);
        String rawCopySourceRange = range;
        long expectedSize = -1;
        if (range != null) {
            if (!range.startsWith("bytes=") || range.indexOf(',') != -1 ||
                range.indexOf('-') == -1) {
                throw new S3Exception(S3ErrorCode.INVALID_ARGUMENT,
                    "The x-amz-copy-source-range value must be of the form " +
                    "bytes=first-last where first and last are the " +
                    "zero-based offsets of the first and last bytes to copy");
            }
            try {
                range = range.substring("bytes=".length());
                String[] ranges = range.split("-", 2);
                if (ranges[0].isEmpty()) {
                    optionsBuilder.tail(Long.parseLong(ranges[1]));
                } else if (ranges[1].isEmpty()) {
                    optionsBuilder.startAt(Long.parseLong(ranges[0]));
                } else {
                    long start = Long.parseLong(ranges[0]);
                    long end = Long.parseLong(ranges[1]);
                    if (end < start) {
                        throw new S3Exception(S3ErrorCode.INVALID_RANGE);
                    }
                    expectedSize = end - start + 1;
                    if (expectedSize > MAX_MULTIPART_COPY_SIZE) {
                        throw new S3Exception(S3ErrorCode.INVALID_REQUEST,
                                "The specified copy source is larger than" +
                                " the maximum allowable size for a copy" +
                                " source: " + MAX_MULTIPART_COPY_SIZE);
                    }
                    optionsBuilder.range(start, end);
                }
            } catch (NumberFormatException nfe) {
                throw new S3Exception(S3ErrorCode.INVALID_ARGUMENT,
                    "The x-amz-copy-source-range value must be of the form " +
                    "bytes=first-last where first and last are the " +
                    "zero-based offsets of the first and last bytes to copy",
                    nfe);
            }
        }

        String partNumberString = request.getParameter("partNumber");
        if (partNumberString == null) {
            throw new S3Exception(S3ErrorCode.INVALID_ARGUMENT);
        }
        int partNumber;
        try {
            partNumber = Integer.parseInt(partNumberString);
        } catch (NumberFormatException nfe) {
            throw new S3Exception(S3ErrorCode.INVALID_ARGUMENT,
                    "Part number must be an integer between 1 and 10000" +
                    ", inclusive", nfe, Map.of(
                            "ArgumentName", "partNumber",
                            "ArgumentValue", partNumberString));
        }
        if (partNumber < 1 || partNumber > 10_000) {
            throw new S3Exception(S3ErrorCode.INVALID_ARGUMENT,
                    "Part number must be an integer between 1 and 10000" +
                    ", inclusive", (Throwable) null, Map.of(
                            "ArgumentName", "partNumber",
                            "ArgumentValue", partNumberString));
        }

        // TODO: how to reconstruct original mpu?
        MultipartUpload mpu = new MultipartUpload(containerName,
                blobName, uploadId, createFakeBlobMetadata(),
                PutOptions.NONE);

        if (blobStore.supportsCopyMultipartPart()) {
            // Backends report overlong ranges inconsistently; enforce the
            // same InvalidRange semantics as the emulated path below, which
            // checks the size from getBlob's metadata.
            if (expectedSize != -1) {
                BlobMetadata sourceMetadata = sourceVersionId != null ?
                        blobStore.blobMetadata(sourceContainerName,
                                sourceBlobName, sourceVersionId) :
                        blobStore.blobMetadata(sourceContainerName,
                                sourceBlobName);
                if (sourceMetadata == null) {
                    throw new S3Exception(S3ErrorCode.NO_SUCH_KEY);
                }
                Long sourceSize = sourceMetadata.size();
                if (sourceSize != null && sourceSize < expectedSize) {
                    throw new S3Exception(S3ErrorCode.INVALID_RANGE);
                }
            }
            long nativeIfModifiedSince = request.getDateHeader(
                    AwsHttpHeaders.COPY_SOURCE_IF_MODIFIED_SINCE);
            long nativeIfUnmodifiedSince = request.getDateHeader(
                    AwsHttpHeaders.COPY_SOURCE_IF_UNMODIFIED_SINCE);
            MultipartPart part;
            try {
                part = blobStore.copyMultipartPart(mpu, partNumber,
                        sourceContainerName, sourceBlobName, sourceVersionId,
                        rawCopySourceRange,
                        request.getHeader(AwsHttpHeaders.COPY_SOURCE_IF_MATCH),
                        request.getHeader(
                                AwsHttpHeaders.COPY_SOURCE_IF_NONE_MATCH),
                        nativeIfModifiedSince == -1 ?
                                null : new Date(nativeIfModifiedSince),
                        nativeIfUnmodifiedSince == -1 ?
                                null : new Date(nativeIfUnmodifiedSince));
            } catch (UnsupportedOperationException uoe) {
                // The backend discovered at runtime that it cannot copy
                // server-side, e.g. Azurite lacks Put Block From URL; use
                // the streamed emulation below.
                part = null;
            }
            if (part != null) {
                writeCopyPartResponse(request, response, part);
                return;
            }
        }

        Blob blob = blobStore.getBlob(sourceContainerName, sourceBlobName,
                optionsBuilder.build());
        if (blob == null) {
            throw new S3Exception(S3ErrorCode.NO_SUCH_KEY);
        }

        BlobMetadata blobMetadata = blob.getMetadata();
        String eTag = blobMetadata.eTag();
        Date lastModified = blobMetadata.lastModified();
        try {
            // HTTP GET allow overlong ranges but S3 CopyPart does not
            Long size = blobMetadata.size();
            if (expectedSize != -1 && size != null && size < expectedSize) {
                throw new S3Exception(S3ErrorCode.INVALID_RANGE);
            }

            String ifMatch = request.getHeader(
                    AwsHttpHeaders.COPY_SOURCE_IF_MATCH);
            String ifNoneMatch = request.getHeader(
                    AwsHttpHeaders.COPY_SOURCE_IF_NONE_MATCH);
            long ifModifiedSince = request.getDateHeader(
                    AwsHttpHeaders.COPY_SOURCE_IF_MODIFIED_SINCE);
            long ifUnmodifiedSince = request.getDateHeader(
                    AwsHttpHeaders.COPY_SOURCE_IF_UNMODIFIED_SINCE);
            if (eTag != null) {
                eTag = maybeQuoteETag(eTag);
                if (ifMatch != null && !ifMatch.equals(eTag)) {
                    throw new S3Exception(S3ErrorCode.PRECONDITION_FAILED);
                }
                if (ifNoneMatch != null && ifNoneMatch.equals(eTag)) {
                    throw new S3Exception(S3ErrorCode.PRECONDITION_FAILED);
                }
            }

            if (lastModified != null) {
                if (ifModifiedSince != -1 && lastModified.compareTo(
                        new Date(ifModifiedSince)) <= 0) {
                    throw new S3Exception(S3ErrorCode.PRECONDITION_FAILED);
                }
                if (ifUnmodifiedSince != -1 && lastModified.compareTo(
                        new Date(ifUnmodifiedSince)) > 0) {
                    throw new S3Exception(S3ErrorCode.PRECONDITION_FAILED);
                }
            }
        } catch (S3Exception se) {
            // A precondition failure here would otherwise leak the source
            // payload's open backend stream; the happy-path try-with-resources
            // below closes it only once reached.
            try {
                InputStream payload = blob.getPayload();
                if (payload != null) {
                    payload.close();
                }
            } catch (IOException ioe) {
                // The stream is being abandoned; ignore close failures.
            }
            throw se;
        }

        long contentLength = requireNonNull(
                blobMetadata.contentMetadata().contentLength());

        try (InputStream is = requireNonNull(blob.getPayload())) {
            MultipartPart part = blobStore.uploadMultipartPart(mpu,
                    partNumber, is, contentLength, null);
            eTag = part.partETag();
        }

        writeCopyPartResponse(request, response,
                new MultipartPart(partNumber, contentLength, eTag,
                        lastModified, blobMetadata.versionId()));
    }

    private void writeCopyPartResponse(HttpServletRequest request,
            HttpServletResponse response, MultipartPart part)
            throws IOException {
        response.setCharacterEncoding(UTF_8);
        addCorsResponseHeader(request, response);
        String copySourceVersionId = part.copySourceVersionId();
        if (copySourceVersionId != null) {
            response.addHeader(AwsHttpHeaders.COPY_SOURCE_VERSION_ID,
                    copySourceVersionId);
        }
        try (Writer writer = response.getWriter()) {
            response.setContentType(XML_CONTENT_TYPE);
            XMLStreamWriter xml = xmlOutputFactory.createXMLStreamWriter(
                    writer);
            xml.writeStartDocument();
            xml.writeStartElement("CopyObjectResult");
            xml.writeDefaultNamespace(AWS_XMLNS);

            Date lastModified = part.lastModified();
            if (lastModified != null) {
                writeSimpleElement(xml, "LastModified",
                        formatDate(lastModified));
            }
            String eTag = part.partETag();
            if (eTag != null) {
                writeSimpleElement(xml, "ETag", maybeQuoteETag(eTag));
            }

            xml.writeEndElement();
            xml.flush();
        } catch (XMLStreamException xse) {
            throw new IOException(xse);
        }
    }

    private void handleUploadPart(HttpServletRequest request,
            HttpServletResponse response, InputStream is, BlobStore blobStore,
            String containerName, String blobName, String uploadId)
            throws IOException, S3Exception {
        // TODO: duplicated from handlePutBlob
        String contentLengthString = null;
        String decodedContentLengthString = null;
        String contentMD5String = null;
        for (String headerName : Collections.list(request.getHeaderNames())) {
            String headerValue = Strings.nullToEmpty(request.getHeader(
                    headerName));
            if (headerName.equalsIgnoreCase(HttpHeaders.CONTENT_LENGTH)) {
                contentLengthString = headerValue;
            } else if (headerName.equalsIgnoreCase(
                    AwsHttpHeaders.DECODED_CONTENT_LENGTH)) {
                decodedContentLengthString = headerValue;
            } else if (headerName.equalsIgnoreCase(HttpHeaders.CONTENT_MD5)) {
                contentMD5String = headerValue;
            }
        }
        if (decodedContentLengthString != null) {
            contentLengthString = decodedContentLengthString;
        }

        HashCode contentMD5 = null;
        if (contentMD5String != null) {
            try {
                contentMD5 = HashCode.fromBytes(
                        Base64.getDecoder().decode(contentMD5String));
            } catch (IllegalArgumentException iae) {
                throw new S3Exception(S3ErrorCode.INVALID_DIGEST, iae);
            }
            if (contentMD5.bits() != MD5.bits()) {
                throw new S3Exception(S3ErrorCode.INVALID_DIGEST);
            }
        }

        if (contentLengthString == null) {
            byte[] body = readBodyOfUnknownLength(request, is);
            is = new ByteArrayInputStream(body);
            contentLengthString = String.valueOf(body.length);
        }
        long contentLength;
        try {
            contentLength = Long.parseLong(contentLengthString);
        } catch (NumberFormatException nfe) {
            throw new S3Exception(S3ErrorCode.INVALID_ARGUMENT, nfe);
        }
        if (contentLength < 0) {
            throw new S3Exception(S3ErrorCode.INVALID_ARGUMENT);
        }
        if (decodedContentLengthString != null) {
            is = ByteStreams.limit(is, contentLength);
        }
        FlexChecksum checksum = requestChecksumHeader(request);
        String checksumValue = null;
        if (checksum != null) {
            checksumValue = request.getHeader(checksum.header());
            is = wrapChecksumValidator(is, checksum, checksumValue,
                    contentLength);
        }

        String partNumberString = request.getParameter("partNumber");
        if (partNumberString == null) {
            throw new S3Exception(S3ErrorCode.INVALID_ARGUMENT);
        }
        int partNumber;
        try {
            partNumber = Integer.parseInt(partNumberString);
        } catch (NumberFormatException nfe) {
            throw new S3Exception(S3ErrorCode.INVALID_ARGUMENT,
                    "Part number must be an integer between 1 and 10000" +
                    ", inclusive", nfe, Map.of(
                            "ArgumentName", "partNumber",
                            "ArgumentValue", partNumberString));
        }
        if (partNumber < 1 || partNumber > 10_000) {
            throw new S3Exception(S3ErrorCode.INVALID_ARGUMENT,
                    "Part number must be an integer between 1 and 10000" +
                    ", inclusive", (Throwable) null, Map.of(
                            "ArgumentName", "partNumber",
                            "ArgumentValue", partNumberString));
        }

        // TODO: how to reconstruct original mpu?
        BlobMetadata blobMetadata;
        if (Quirks.MULTIPART_REQUIRES_STUB.contains(getBlobStoreType(
                blobStore))) {
            blobMetadata = blobStore.blobMetadata(containerName,
                    multipartStubName(uploadId));
        } else {
            blobMetadata = createFakeBlobMetadata();
        }
        MultipartUpload mpu = new MultipartUpload(containerName,
                blobName, uploadId, blobMetadata, PutOptions.NONE);

        MultipartPart part = blobStore.uploadMultipartPart(mpu, partNumber,
                is, contentLength, contentMD5);

        if (part.partETag() != null) {
            response.addHeader(HttpHeaders.ETAG,
                    maybeQuoteETag(part.partETag()));
        }
        if (checksum != null) {
            response.addHeader(checksum.header(), checksumValue);
        }

        addCorsResponseHeader(request, response);
    }

    private static void addResponseHeaderWithOverride(
            HttpServletRequest request, HttpServletResponse response,
            String headerName, String overrideHeaderName,
            @Nullable String value) {
        String override = request.getParameter(overrideHeaderName);

        override = (override != null) ? override : value;

        if (override != null) {
            response.addHeader(headerName, override);
        }
    }

    private static void addMetadataToResponse(HttpServletRequest request,
            HttpServletResponse response,
            BlobMetadata metadata,
            boolean partialContent) {
        ContentMetadata contentMetadata =
                metadata.contentMetadata();
        addResponseHeaderWithOverride(request, response,
                HttpHeaders.CACHE_CONTROL, "response-cache-control",
                contentMetadata.cacheControl());
        addResponseHeaderWithOverride(request, response,
                HttpHeaders.CONTENT_ENCODING, "response-content-encoding",
                contentMetadata.contentEncoding());
        addResponseHeaderWithOverride(request, response,
                HttpHeaders.CONTENT_LANGUAGE, "response-content-language",
                contentMetadata.contentLanguage());
        addResponseHeaderWithOverride(request, response,
                HttpHeaders.CONTENT_DISPOSITION, "response-content-disposition",
                contentMetadata.contentDisposition());
        Long contentLength = contentMetadata.contentLength();
        if (contentLength != null) {
            response.addHeader(HttpHeaders.CONTENT_LENGTH,
                    contentLength.toString());
        }
        String overrideContentType = request.getParameter(
                "response-content-type");
        String contentType = overrideContentType != null ?
                overrideContentType : contentMetadata.contentType();
        // S3 names a type for every object, so one a backend reports none for
        // -- written around S3Proxy, or by a client of a backend that does not
        // require one -- answers with the default rather than with no
        // Content-Type at all.
        response.setContentType(contentType != null ? contentType :
                ContentMetadata.DEFAULT_CONTENT_TYPE);
        String eTag = metadata.eTag();
        if (eTag != null) {
            response.addHeader(HttpHeaders.ETAG, maybeQuoteETag(eTag));
        }
        String overrideExpires = request.getParameter("response-expires");
        if (overrideExpires != null) {
            response.addHeader(HttpHeaders.EXPIRES, overrideExpires);
        } else {
            Date expires = contentMetadata.expires();
            if (expires != null) {
                response.addDateHeader(HttpHeaders.EXPIRES, expires.getTime());
            }
        }
        Date lastModified = metadata.lastModified();
        if (lastModified != null) {
            response.addDateHeader(HttpHeaders.LAST_MODIFIED,
                    lastModified.getTime());
        }
        String versionId = metadata.versionId();
        if (versionId != null) {
            response.addHeader(AwsHttpHeaders.VERSION_ID, versionId);
        }
        StorageClass storageClass = metadata.storageClass();
        if (storageClass != null) {
            response.addHeader(AwsHttpHeaders.STORAGE_CLASS,
                    storageClass.toString());
        }
        FlexChecksum storedChecksum = null;
        String storedChecksumValue = null;
        for (var entry : metadata.userMetadata().entrySet()) {
            String key = entry.getKey();
            if (startsWithIgnoreCase(key, CHECKSUM_METADATA_PREFIX)) {
                FlexChecksum candidate = FlexChecksum.fromMetadataKey(key);
                if (candidate != null) {
                    storedChecksum = candidate;
                    storedChecksumValue = entry.getValue();
                }
                // reserved internal state, never exposed as x-amz-meta-
                continue;
            }
            response.addHeader(USER_METADATA_PREFIX + key, entry.getValue());
        }
        // S3 omits the whole-object checksum from a ranged response since it
        // does not describe the bytes actually returned.
        if (storedChecksum != null && storedChecksumValue != null &&
                !partialContent &&
                "ENABLED".equalsIgnoreCase(
                        request.getHeader(AwsHttpHeaders.CHECKSUM_MODE))) {
            response.addHeader(storedChecksum.header(), storedChecksumValue);
            response.addHeader(AwsHttpHeaders.CHECKSUM_TYPE,
                    checksumType(storedChecksumValue));
        }
    }

    /**
     * Whether a URI addresses a bucket and no key, without the trailing slash
     * that clients canonicalize such a request with, e.g. "/bucket" but
     * neither "/" nor "/bucket/" nor "/bucket/key".
     */
    private static boolean isBucketRootUri(String uri) {
        return uri.length() > 1 && uri.charAt(0) == '/' &&
                uri.indexOf('/', 1) == -1;
    }

    /** Parse ISO 8601 timestamp into seconds since 1970. */
    private static long parseIso8601(String date) {
        var formatter = new SimpleDateFormat(
                "yyyyMMdd'T'HHmmss'Z'");
        formatter.setTimeZone(TimeZone.getTimeZone("UTC"));
        try {
            return formatter.parse(date).getTime() / 1000;
        } catch (ParseException pe) {
            throw new IllegalArgumentException(pe);
        }
    }

    private void isTimeSkewed(
            long date, boolean isPresigned) throws S3Exception  {
        if (date < 0) {
            throw new S3Exception(S3ErrorCode.ACCESS_DENIED);
        }
        long now = System.currentTimeMillis() / 1000;
        if (isPresigned) {
            if (now + maximumTimeSkew < date) {
                logger.debug("request is not valid yet {} {}", date, now);
                throw new S3Exception(S3ErrorCode.ACCESS_DENIED);
            }
        } else {
            if (now + maximumTimeSkew < date || now - maximumTimeSkew > date) {
                logger.debug("time skewed {} {}", date, now);
                throw new S3Exception(S3ErrorCode.REQUEST_TIME_TOO_SKEWED);
            }
        }
    }

    // cannot call BlobStore.getContext().utils().date().iso8601DateFormat since
    // it has unwanted millisecond precision
    static String generateRequestId() {
        return "%016X".formatted(ThreadLocalRandom.current().nextLong());
    }

    private static String formatDate(Date date) {
        var formatter = new SimpleDateFormat(
                "yyyy-MM-dd'T'HH:mm:ss'Z'");
        formatter.setTimeZone(TimeZone.getTimeZone("GMT"));
        return formatter.format(date);
    }

    protected final void sendSimpleErrorResponse(
            HttpServletRequest request, HttpServletResponse response,
            S3ErrorCode code, String message,
            Map<String, String> elements) throws IOException {
        logger.debug("sendSimpleErrorResponse: {} {}", code, elements);

        if (response.isCommitted()) {
            // Another handler already opened and closed the writer.
            return;
        }

        // Errors triggered by request-body validation may have left the body
        // partially unread (e.g. the client declared Content-Length=N but
        // sent N+k bytes; we read exactly N per the HTTP framing rules and
        // the leftover k bytes would corrupt the next request on a keep-
        // alive connection).  Close the connection on those cases so the
        // client retries on a fresh socket.
        if (code == S3ErrorCode.BAD_DIGEST ||
                code == S3ErrorCode.INVALID_DIGEST ||
                code == S3ErrorCode.INVALID_REQUEST ||
                code == S3ErrorCode.MAX_MESSAGE_LENGTH_EXCEEDED ||
                code == S3ErrorCode.X_AMZ_CONTENT_S_H_A_256_MISMATCH) {
            response.setHeader(HttpHeaders.CONNECTION, "close");
        }

        // A read that found nothing missed an absent object rather than a
        // delete marker; no unversioned key resolves to one.  Set this
        // centrally because some backends raise NoSuchKey from the blobstore
        // instead of reporting absence.  A versioning backend that did find
        // a marker has already said so; do not contradict it.
        if (code == S3ErrorCode.NO_SUCH_KEY &&
                !response.containsHeader(AwsHttpHeaders.DELETE_MARKER) &&
                (request.getMethod().equals("GET") ||
                        request.getMethod().equals("HEAD"))) {
            response.addHeader(AwsHttpHeaders.DELETE_MARKER, "false");
        }

        // A browser refuses any cross-origin response that does not name its
        // origin, whatever the response says, so an error without these
        // headers reaches the page as "No 'Access-Control-Allow-Origin' header
        // is present on the requested resource" and the Code and Message
        // written below are never read.  Every failure then looks like a CORS
        // misconfiguration rather than the expired URL, wrong key or absent
        // object it was.
        //
        // Not for a preflight: answering one without them is how the browser
        // is told the real request may not proceed, and naming an allowed
        // origin while refusing only muddles that.  Nor when a handler emitted
        // them before failing -- a second copy is precisely what browsers
        // reject.  addCorsResponseHeader writes Vary first and nothing else
        // writes it, so its presence says the headers are already there.
        if (!request.getMethod().equals("OPTIONS") &&
                !response.containsHeader(HttpHeaders.VARY)) {
            addCorsResponseHeader(request, response);
        }

        response.setStatus(code.getHttpStatusCode());

        if (request.getMethod().equals("HEAD")) {
            // The HEAD method is identical to GET except that the server MUST
            // NOT return a message-body in the response.
            return;
        }

        response.setCharacterEncoding(UTF_8);
        try (Writer writer = response.getWriter()) {
            response.setContentType(XML_CONTENT_TYPE);
            XMLStreamWriter xml = xmlOutputFactory.createXMLStreamWriter(
                    writer);
            xml.writeStartDocument();
            xml.writeStartElement("Error");

            writeSimpleElement(xml, "Code", code.getErrorCode());
            writeSimpleElement(xml, "Message", message);

            for (var entry : elements.entrySet()) {
                writeSimpleElement(xml, entry.getKey(), entry.getValue());
            }

            String requestId = response.getHeader(AwsHttpHeaders.REQUEST_ID);
            if (requestId == null) {
                requestId = generateRequestId();
            }
            writeSimpleElement(xml, "RequestId", requestId);

            xml.writeEndElement();
            xml.flush();
        } catch (XMLStreamException xse) {
            throw new IOException(xse);
        }
    }

    private void addCorsResponseHeader(HttpServletRequest request,
          HttpServletResponse response) {
        if (!corsRules.isEnabled()) {
            return;
        }
        // Whether the headers below appear at all, and which origin they name,
        // depends on the Origin request header, so a shared cache must key on
        // it.  Without this a cache can hand one origin's response -- or a
        // no-Origin response carrying no CORS headers -- to a different
        // origin.  handleOptionsBlob sets the same header for preflights.
        response.addHeader(HttpHeaders.VARY, HttpHeaders.ORIGIN);
        String corsOrigin = request.getHeader(HttpHeaders.ORIGIN);
        if (!Strings.isNullOrEmpty(corsOrigin) &&
                corsRules.isOriginAllowed(corsOrigin)) {
            response.addHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN,
                    corsRules.getAllowedOrigin(corsOrigin));
            response.addHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS,
                    corsRules.getAllowedMethods());
            response.addHeader(HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS,
                    corsRules.getExposedHeaders());
            if (corsRules.isAllowCredentials()) {
                response.addHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS,
                        "true");
            }
        }
    }

    private static void addContentMetadataFromHttpRequest(
            Blob.Builder builder,
            HttpServletRequest request) {
        addContentMetadataFromHttpRequest(builder, request, null, null);
    }

    private static void addContentMetadataFromHttpRequest(
            Blob.Builder builder,
            HttpServletRequest request,
            @Nullable FlexChecksum checksum,
            @Nullable String checksumValue) {
        var userMetadata = ImmutableMap.<String, String>builder();
        for (String headerName : Collections.list(request.getHeaderNames())) {
            if (startsWithIgnoreCase(headerName, USER_METADATA_PREFIX)) {
                String key = headerName.substring(
                        USER_METADATA_PREFIX.length());
                // reserved for the validated checksum persisted below
                if (startsWithIgnoreCase(key, CHECKSUM_METADATA_PREFIX)) {
                    continue;
                }
                userMetadata.put(key,
                        Strings.nullToEmpty(request.getHeader(headerName)));
            }
        }
        if (checksum != null && checksumValue != null) {
            userMetadata.put(checksum.metadataKey(), checksumValue);
        }
        String contentEncoding = request.getHeader(
                HttpHeaders.CONTENT_ENCODING);
        if (contentEncoding != null) {
            contentEncoding = stripAwsChunked(contentEncoding);
            if (contentEncoding.isEmpty()) {
                contentEncoding = null;
            }
        }
        builder.cacheControl(request.getHeader(
                        HttpHeaders.CACHE_CONTROL))
                .contentDisposition(request.getHeader(
                        HttpHeaders.CONTENT_DISPOSITION))
                .contentEncoding(contentEncoding)
                .contentLanguage(request.getHeader(
                        HttpHeaders.CONTENT_LANGUAGE))
                .userMetadata(userMetadata.build());
        String contentType = request.getContentType();
        if (contentType != null) {
            builder.contentType(contentType);
        }
        long expires = request.getDateHeader(HttpHeaders.EXPIRES);
        if (expires != -1) {
            builder.expires(new Date(expires));
        }
    }

    // TODO: bogus values
    private static void writeInitiatorStanza(XMLStreamWriter xml)
            throws XMLStreamException {
        xml.writeStartElement("Initiator");

        writeSimpleElement(xml, "ID", FAKE_INITIATOR_ID);
        writeSimpleElement(xml, "DisplayName",
                FAKE_INITIATOR_DISPLAY_NAME);

        xml.writeEndElement();
    }

    // TODO: bogus values
    private static void writeOwnerStanza(XMLStreamWriter xml)
            throws XMLStreamException {
        xml.writeStartElement("Owner");

        writeSimpleElement(xml, "ID", FAKE_OWNER_ID);
        writeSimpleElement(xml, "DisplayName", FAKE_OWNER_DISPLAY_NAME);

        xml.writeEndElement();
    }

    private static void writeOwnerFullControlGrant(XMLStreamWriter xml)
            throws XMLStreamException {
        xml.writeStartElement("Grant");

        xml.writeStartElement("Grantee");
        xml.writeNamespace("xsi", "http://www.w3.org/2001/XMLSchema-instance");
        xml.writeAttribute("xsi:type", "CanonicalUser");

        writeSimpleElement(xml, "ID", FAKE_OWNER_ID);
        writeSimpleElement(xml, "DisplayName", FAKE_OWNER_DISPLAY_NAME);

        xml.writeEndElement();

        writeSimpleElement(xml, "Permission", "FULL_CONTROL");

        xml.writeEndElement();
    }

    private static void writeAllUsersReadGrant(XMLStreamWriter xml)
            throws XMLStreamException {
        xml.writeStartElement("Grant");

        xml.writeStartElement("Grantee");
        xml.writeNamespace("xsi", "http://www.w3.org/2001/XMLSchema-instance");
        xml.writeAttribute("xsi:type", "Group");

        writeSimpleElement(xml, "URI",
                "http://acs.amazonaws.com/groups/global/AllUsers");

        xml.writeEndElement();

        writeSimpleElement(xml, "Permission", "READ");

        xml.writeEndElement();
    }

    private static void writeSimpleElement(XMLStreamWriter xml,
            String elementName, String characters) throws XMLStreamException {
        xml.writeStartElement(elementName);
        xml.writeCharacters(characters);
        xml.writeEndElement();
    }

    private static BlobMetadata createFakeBlobMetadata() {
        return Blob.builder("fake-name")
                .build()
                .getMetadata();
    }

    private static boolean equalsIgnoringSurroundingQuotes(String s1,
            String s2) {
        if (s1.length() >= 2 && s1.startsWith("\"") && s1.endsWith("\"")) {
            s1 = s1.substring(1, s1.length() - 1);
        }
        if (s2.length() >= 2 && s2.startsWith("\"") && s2.endsWith("\"")) {
            s2 = s2.substring(1, s2.length() - 1);
        }
        return s1.equals(s2);
    }

    private static String maybeQuoteETag(String eTag) {
        if (!eTag.startsWith("\"") && !eTag.endsWith("\"")) {
            eTag = "\"" + eTag + "\"";
        }
        return eTag;
    }

    private static String unquoteETag(String eTag) {
        return CharMatcher.is('"').trimFrom(eTag);
    }

    /**
     * Evaluate If-Match and If-None-Match against the object a write is about
     * to replace.  Note the asymmetry S3 has here: an If-Match naming a key
     * that does not exist is a 404 rather than a 412, including If-Match: *,
     * since there is nothing to have matched.
     *
     * @param metadata the destination object, or null if it does not exist
     */
    private static void checkConditionalWrite(@Nullable BlobMetadata metadata,
            @Nullable String ifMatch, @Nullable String ifNoneMatch)
            throws S3Exception {
        if (ifMatch != null) {
            if (metadata == null) {
                throw new S3Exception(S3ErrorCode.NO_SUCH_KEY);
            }
            if (!ifMatch.equals("*")) {
                String eTag = metadata.eTag();
                if (eTag == null || !equalsIgnoringSurroundingQuotes(ifMatch,
                        maybeQuoteETag(eTag))) {
                    throw new S3Exception(S3ErrorCode.PRECONDITION_FAILED);
                }
            }
        }

        if (ifNoneMatch != null && metadata != null) {
            if (ifNoneMatch.equals("*")) {
                throw new S3Exception(S3ErrorCode.PRECONDITION_FAILED);
            }
            String eTag = metadata.eTag();
            if (eTag != null && equalsIgnoringSurroundingQuotes(ifNoneMatch,
                    maybeQuoteETag(eTag))) {
                throw new S3Exception(S3ErrorCode.PRECONDITION_FAILED);
            }
        }
    }

    private static boolean startsWithIgnoreCase(String string, String prefix) {
        return string.toLowerCase().startsWith(prefix.toLowerCase());
    }

    /**
     * Reads the body of an upload that declared no length, so that the length
     * is known before a backend is asked to store it.  S3 accepts an upload
     * framed with Transfer-Encoding: chunked, but most backends need a size
     * before they can stream one on, and a chunked body says nothing about how
     * large it will turn out to be -- hence the same bound, and the same
     * error beyond it, that a SigV4 request whose payload must be digested
     * already carries.  An upload that framed its body neither way is the one
     * S3 answers 411 to.
     */
    private byte[] readBodyOfUnknownLength(HttpServletRequest request,
            InputStream is) throws IOException, S3Exception {
        String transferEncoding = request.getHeader(
                HttpHeaders.TRANSFER_ENCODING);
        if (transferEncoding == null ||
                !transferEncoding.toLowerCase().contains("chunked")) {
            throw new S3Exception(S3ErrorCode.MISSING_CONTENT_LENGTH);
        }
        byte[] body = ByteStreams.limit(is, v4MaxNonChunkedRequestSize + 1)
                .readAllBytes();
        if (body.length == v4MaxNonChunkedRequestSize + 1) {
            throw new S3Exception(S3ErrorCode.MAX_MESSAGE_LENGTH_EXCEEDED);
        }
        return body;
    }

    /**
     * Remove the transport-only "aws-chunked" token from a Content-Encoding
     * value, returning whatever real encodings remain.  Modern AWS SDKs send
     * Content-Encoding: aws-chunked when uploading via aws-chunked, but the
     * proxy decodes the body before storing, so the token must not be carried
     * forward as object metadata.
     */
    private static String stripAwsChunked(String contentEncoding) {
        var parts = new ArrayList<String>();
        boolean removed = false;
        for (String part : Splitter.on(',').split(contentEncoding)) {
            String trimmed = part.trim();
            if (trimmed.equalsIgnoreCase("aws-chunked") || trimmed.isEmpty()) {
                removed = true;
            } else {
                parts.add(trimmed);
            }
        }
        // S3 echoes Content-Encoding verbatim, so only rewrite the value when
        // there was something to remove.
        return removed ? String.join(", ", parts) : contentEncoding;
    }

    private static byte[] hmac(String algorithm, byte[] data, byte[] key) {
        try {
            Mac mac = Mac.getInstance(algorithm);
            mac.init(new SecretKeySpec(key, algorithm));
            return mac.doFinal(data);
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    // Encode blob name if client requests it.  This allows for characters
    // which XML 1.0 cannot represent.
    private static String encodeBlob(String encodingType, String blobName) {
        if (encodingType != null && encodingType.equals("url")) {
            return urlEscaper.escape(blobName);
        } else {
            return blobName;
        }
    }

    public final BlobStoreLocator getBlobStoreLocator() {
        return blobStoreLocator;
    }

    public final void setBlobStoreLocator(BlobStoreLocator locator) {
        this.blobStoreLocator = locator;
    }

    private static boolean validateIpAddress(String string) {
        List<String> parts = Splitter.on('.').splitToList(string);
        if (parts.size() != 4) {
            return false;
        }
        for (String part : parts) {
            try {
                int num = Integer.parseInt(part);
                if (num < 0 || num > 255) {
                    return false;
                }
            } catch (NumberFormatException nfe) {
                return false;
            }
        }
        return true;
    }

    /**
     * Refuse a presigned URL whose window has closed, or one naming a window
     * longer than S3 will sign.  Answer AccessDenied for values that do not
     * parse rather than letting the numeric exception escape as a 500.
     *
     * <p>The query string carrying these is unauthenticated -- the signature
     * over it is checked afterwards, and not at all when the proxy runs
     * without authorization -- so this bounds how long a URL works rather than
     * establishing who may use it.
     */
    private static void checkPresignedExpiry(HttpServletRequest request)
            throws S3Exception {
        String expiresString = request.getParameter("Expires");
        if (expiresString != null) { // v2 query
            long expires;
            try {
                expires = Long.parseLong(expiresString);
            } catch (NumberFormatException nfe) {
                throw new S3Exception(S3ErrorCode.ACCESS_DENIED, nfe);
            }
            long nowSeconds = System.currentTimeMillis() / 1000;
            if (nowSeconds >= expires) {
                throw new S3Exception(S3ErrorCode.ACCESS_DENIED,
                        "Request has expired");
            }
            if (expires - nowSeconds > TimeUnit.DAYS.toSeconds(365)) {
                throw new S3Exception(S3ErrorCode.ACCESS_DENIED);
            }
        }

        String dateString = request.getParameter("X-Amz-Date");
        //from para v4 query
        expiresString = request.getParameter("X-Amz-Expires");
        if (dateString != null && expiresString != null) { //v4 query
            long date;
            long expires;
            try {
                date = parseIso8601(dateString);
                expires = Long.parseLong(expiresString);
            } catch (IllegalArgumentException iae) {
                throw new S3Exception(S3ErrorCode.ACCESS_DENIED, iae);
            }
            long nowSeconds = System.currentTimeMillis() / 1000;
            if (nowSeconds >= date + expires) {
                throw new S3Exception(S3ErrorCode.ACCESS_DENIED,
                        "Request has expired");
            }
            if (expires > TimeUnit.DAYS.toSeconds(7)) {
                throw new S3Exception(S3ErrorCode.ACCESS_DENIED);
            }
        }
    }

    private static boolean constantTimeEquals(String x, String y) {
        return MessageDigest.isEqual(x.getBytes(StandardCharsets.UTF_8),
                y.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Report a signature mismatch the way S3 does, quoting the strings the
     * proxy signed.  A bare Forbidden gives the caller nothing to act on --
     * a stale clock, a rewritten Host, an unrepeated signed header and a
     * wrong secret all look identical from outside -- while the canonical
     * request shows which line diverged from the one it signed.  None of it
     * is secret: it is the caller's own request as the proxy parsed it, and
     * turning it into a signature still needs the credential.
     */
    private static S3Exception signatureDoesNotMatch(
            HttpServletRequest request, S3AuthorizationHeader authHeader,
            AwsSignature.@Nullable SignatureDetail detail,
            boolean presignedUrl) {
        // Ordered as S3 orders them, less the StringToSignBytes and
        // CanonicalRequestBytes hex dumps, which say nothing the text does
        // not once buildCanonicalHeaders has folded the whitespace.
        var elements = new LinkedHashMap<String, String>();
        String identity = authHeader.getIdentity();
        if (identity != null) {
            elements.put("AWSAccessKeyId", identity);
        }
        if (detail != null) {
            elements.put("StringToSign", xmlSafe(detail.stringToSign()));
        }
        String provided = authHeader.getSignature();
        if (provided != null) {
            elements.put("SignatureProvided", provided);
        }
        if (detail != null) {
            String canonicalRequest = detail.canonicalRequest();
            if (canonicalRequest != null) {
                elements.put("CanonicalRequest", xmlSafe(canonicalRequest));
            }
        }

        var message = new StringBuilder("The request signature we calculated" +
                " does not match the signature you provided. Check your key" +
                " and signing method.");
        List<String> missing = AwsSignature.missingSignedHeaders(request,
                presignedUrl);
        if (!missing.isEmpty()) {
            // The likeliest cause by far, and the one the canonical request
            // states only implicitly, as a header line with nothing after the
            // colon.
            message.append(" The request omits headers it declares as signed: ")
                    .append(String.join(", ", missing)).append('.');
        }
        return new S3Exception(S3ErrorCode.SIGNATURE_DOES_NOT_MATCH,
                message.toString(), /*cause=*/ null, elements);
    }

    /**
     * Drop what XML cannot carry, so echoing a request back to its sender
     * cannot turn a 403 into an unserializable response.
     */
    private static String xmlSafe(String s) {
        var builder = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); ++i) {
            char c = s.charAt(i);
            builder.append(c == 0x9 || c == 0xa || c == 0xd ||
                    (c >= 0x20 && c <= 0xd7ff) ||
                    (c >= 0xe000 && c <= 0xfffd) ? c : '�');
        }
        return builder.toString();
    }
}
