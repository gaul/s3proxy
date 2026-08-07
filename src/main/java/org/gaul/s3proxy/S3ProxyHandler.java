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
import java.util.HexFormat;
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
import java.util.function.Supplier;
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
import org.gaul.s3proxy.blobstore.ContentMetadata;
import org.gaul.s3proxy.blobstore.S3Exceptions;
import org.gaul.s3proxy.blobstore.SdkResponses;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.gaul.s3proxy.nio2blob.AbstractNio2BlobStore;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.checksums.DefaultChecksumAlgorithm;
import software.amazon.awssdk.checksums.SdkChecksum;
import software.amazon.awssdk.checksums.spi.ChecksumAlgorithm;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.services.s3.model.Bucket;
import software.amazon.awssdk.services.s3.model.BucketCannedACL;
import software.amazon.awssdk.services.s3.model.BucketVersioningStatus;
import software.amazon.awssdk.services.s3.model.CommonPrefix;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.CompletedMultipartUpload;
import software.amazon.awssdk.services.s3.model.CompletedPart;
import software.amazon.awssdk.services.s3.model.CopyObjectRequest;
import software.amazon.awssdk.services.s3.model.CopyObjectResponse;
import software.amazon.awssdk.services.s3.model.CreateBucketRequest;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.DeleteMarkerEntry;
import software.amazon.awssdk.services.s3.model.DeleteObjectResponse;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.HeadObjectRequest;
import software.amazon.awssdk.services.s3.model.HeadObjectResponse;
import software.amazon.awssdk.services.s3.model.ListObjectVersionsRequest;
import software.amazon.awssdk.services.s3.model.ListObjectVersionsResponse;
import software.amazon.awssdk.services.s3.model.ListObjectsRequest;
import software.amazon.awssdk.services.s3.model.ListObjectsResponse;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Response;
import software.amazon.awssdk.services.s3.model.MetadataDirective;
import software.amazon.awssdk.services.s3.model.NoSuchBucketException;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.s3.model.NoSuchUploadException;
import software.amazon.awssdk.services.s3.model.ObjectCannedACL;
import software.amazon.awssdk.services.s3.model.ObjectVersion;
import software.amazon.awssdk.services.s3.model.Part;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.awssdk.services.s3.model.S3Error;
import software.amazon.awssdk.services.s3.model.S3Object;
import software.amazon.awssdk.services.s3.model.StorageClass;
import software.amazon.awssdk.services.s3.model.UploadPartCopyRequest;
import software.amazon.awssdk.services.s3.model.UploadPartCopyResponse;
import software.amazon.awssdk.services.s3.model.UploadPartResponse;
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
    private <T> T readXmlBody(InputStream is, Class<T> type) {
        try {
            return mapper.readValue(is, type);
        } catch (StreamReadException | DatabindException e) {
            throw new S3ProxyException(S3ErrorCode.MALFORMED_X_M_L, e);
        }
    }

    private <T> T readXmlBody(byte[] body, Class<T> type) {
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
            throws IOException {
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
        // -- or store it, where a bucket grants AllUsers WRITE
        if (!anonymousIdentity &&
                (method.equals("GET") || method.equals("HEAD") ||
                method.equals("POST") || method.equals("OPTIONS") ||
                method.equals("PUT") || method.equals("DELETE")) &&
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
            throw new S3ProxyException(S3ErrorCode.ACCESS_DENIED,
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
                    throw new S3ProxyException(S3ErrorCode.INVALID_ARGUMENT, iae);
                }
            }
            if (authHeader == null) {
                String algorithm = request.getParameter("X-Amz-Algorithm");
                if (algorithm == null) { //v2 query
                    String identity = request.getParameter("AWSAccessKeyId");
                    String signature = request.getParameter("Signature");
                    if (identity == null || signature == null) {
                        throw new S3ProxyException(S3ErrorCode.ACCESS_DENIED);
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
                        throw new S3ProxyException(S3ErrorCode.ACCESS_DENIED);
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
                    throw new S3ProxyException(S3ErrorCode.INVALID_ARGUMENT, iae);
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
                throw new S3ProxyException(S3ErrorCode.ACCESS_DENIED);
            }

            // An x-amz-date that is present but unparseable -- empty or
            // malformed -- carries no time to compare against.  Answer
            // AccessDenied the way S3 does, rather than deferring to the
            // signature comparison below, which fails for an unrelated reason
            // and reports a misleading SignatureDoesNotMatch.
            String xAmzDate = request.getHeader(AwsHttpHeaders.DATE);
            if (xAmzDate != null) { //format diff between v2 and v4
                if (xAmzDate.isBlank()) {
                    throw new S3ProxyException(S3ErrorCode.ACCESS_DENIED,
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
                    throw new S3ProxyException(S3ErrorCode.ACCESS_DENIED,
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
                        throw new S3ProxyException(S3ErrorCode.ACCESS_DENIED, iae);
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
                throw new S3ProxyException(S3ErrorCode.NOT_IMPLEMENTED);
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
                throw new S3ProxyException(S3ErrorCode.NOT_IMPLEMENTED);
            }
        }

        AccessGrant grant = blobStoreLocator.locateBlobStore(
                requestIdentity, path.length > 1 ? path[1] : null,
                path.length > 2 ? path[2] : null);
        if (anonymousIdentity) {
            if (grant == null) {
                throw new S3ProxyException(S3ErrorCode.ACCESS_DENIED);
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
            throw new S3ProxyException(S3ErrorCode.ACCESS_DENIED);
        } else {
            if (grant == null) {
                throw new S3ProxyException(S3ErrorCode.INVALID_ACCESS_KEY_ID);
            }
            // non-anonymous requests always parse an Authorization header
            requireNonNull(authHeader);

            String credential = grant.credential().orElseThrow(
                    () -> new S3ProxyException(S3ErrorCode.INVALID_ACCESS_KEY_ID));
            blobStore = grant.blobStore();

            checkPresignedExpiry(request);
            // The aim ?
            switch (authHeader.getAuthenticationType()) {
            case AWS_V2 -> {
                switch (authenticationType) {
                case AWS_V2, AWS_V2_OR_V4, NONE -> { }
                default -> throw new S3ProxyException(S3ErrorCode.ACCESS_DENIED);
                }
            }
            case AWS_V4 -> {
                switch (authenticationType) {
                case AWS_V4, AWS_V2_OR_V4, NONE -> { }
                default -> throw new S3ProxyException(S3ErrorCode.ACCESS_DENIED);
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
                // The header value once the buffered payload has hashed to
                // it, letting the canonical request reuse the digest rather
                // than hash the body a second time.  Stays null on the paths
                // that never verify the body against the header.
                String verifiedContentSha256 = null;
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
                            throw new S3ProxyException(
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
                                throw new S3ProxyException(
                                        S3ErrorCode
                                        .MAX_MESSAGE_LENGTH_EXCEEDED);
                            }
                        }

                        // maybe we should check this when signing,
                        // a lot of dup code with aws sign code.
                        MessageDigest md = MessageDigest.getInstance(
                            authHeader.getHashAlgorithm());
                        byte[] hash = md.digest(payload);
                        if (!HexFormat.of().formatHex(hash)
                                .equals(contentSha256)) {
                            throw new S3ProxyException(
                                    S3ErrorCode
                                    .X_AMZ_CONTENT_S_H_A_256_MISMATCH);
                        }
                        verifiedContentSha256 = contentSha256;
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
                            credential, presignedUrl, pinnedSha256,
                            verifiedContentSha256);
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
                                credential, presignedUrl, /*pinnedHash=*/ null,
                                verifiedContentSha256);
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
                    throw new S3ProxyException(S3ErrorCode.INVALID_ARGUMENT, e);
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
                is = new ChecksumValidatingInputStream(is,
                        FlexChecksum.SHA256.newChecksum(),
                        HexFormat.of().parseHex(pinnedSha256),
                        request.getContentLengthLong(),
                        S3ErrorCode.X_AMZ_CONTENT_S_H_A_256_MISMATCH);
            }
        }

        // Validate container name
        if (!uri.equals("/") && !isValidContainer(path[1])) {
            if (method.equals("PUT") &&
                    (path.length <= 2 || path[2].isEmpty()) &&
                    !"".equals(request.getParameter("acl")))  {
                throw new S3ProxyException(S3ErrorCode.INVALID_BUCKET_NAME);
            } else {
                throw new S3ProxyException(S3ErrorCode.NO_SUCH_BUCKET);
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
                    throw new S3ProxyException(S3ErrorCode.NOT_IMPLEMENTED);
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
        throw new S3ProxyException(S3ErrorCode.NOT_IMPLEMENTED);
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
            HttpServletRequest request) {
        for (String parameter : RESPONSE_HEADER_OVERRIDES) {
            if (request.getParameter(parameter) != null) {
                throw new S3ProxyException(S3ErrorCode.INVALID_REQUEST,
                        "Request specific response headers cannot be used for" +
                        " anonymous GET requests.");
            }
        }
    }

    private static boolean checkPublicAccess(BlobStore blobStore,
            String containerName, String blobName) {
        String blobStoreType = getBlobStoreType(blobStore);
        try {
            if (Quirks.NO_BLOB_ACCESS_CONTROL.contains(blobStoreType)) {
                BucketCannedACL access = blobStore.getContainerAccess(
                        containerName);
                return access == BucketCannedACL.PUBLIC_READ ||
                        access == BucketCannedACL.PUBLIC_READ_WRITE;
            }
            ObjectCannedACL access = blobStore.getBlobAccess(containerName,
                    blobName);
            return access == ObjectCannedACL.PUBLIC_READ;
        } catch (NoSuchBucketException e) {
            throw new S3ProxyException(S3ErrorCode.NO_SUCH_BUCKET, e);
        } catch (NoSuchKeyException e) {
            throw new S3ProxyException(S3ErrorCode.NO_SUCH_KEY, e);
        }
    }

    /**
     * Refuse an anonymous write unless the bucket grants AllUsers WRITE --
     * the one grant S3 answers an unsigned write from.
     */
    private static void checkPublicWriteAccess(BlobStore blobStore,
            String containerName) {
        BucketCannedACL access;
        try {
            access = blobStore.getContainerAccess(containerName);
        } catch (NoSuchBucketException e) {
            throw new S3ProxyException(S3ErrorCode.NO_SUCH_BUCKET, e);
        }
        if (access != BucketCannedACL.PUBLIC_READ_WRITE) {
            throw new S3ProxyException(S3ErrorCode.ACCESS_DENIED);
        }
    }

    private void doHandleAnonymous(HttpServletRequest request,
            HttpServletResponse response, InputStream is, String uri,
            String[] path, BlobStore blobStore, @Nullable RequestContext ctx)
            throws IOException {
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
            throw new S3ProxyException(S3ErrorCode.NO_SUCH_BUCKET);
        }

        if (method.equals("GET") || method.equals("HEAD")) {
            checkNoResponseHeaderOverrides(request);
        }

        checkVersionId(request, blobStore);

        switch (method) {
        case "GET" -> {
            if (uri.equals("/")) {
                setOperation(ctx, S3Operation.LIST_BUCKETS);
                throw new S3ProxyException(S3ErrorCode.ACCESS_DENIED);
            } else if (path.length <= 2 || path[2].isEmpty()) {
                String containerName = path[1];
                BucketCannedACL access = blobStore.getContainerAccess(
                        containerName);
                if (access == BucketCannedACL.PRIVATE) {
                    setOperation(ctx, S3Operation.LIST_OBJECTS_V2);
                    throw new S3ProxyException(S3ErrorCode.ACCESS_DENIED);
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
                    throw new S3ProxyException(S3ErrorCode.ACCESS_DENIED);
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
                BucketCannedACL access = blobStore.getContainerAccess(
                        containerName);
                if (access == BucketCannedACL.PRIVATE) {
                    setOperation(ctx, S3Operation.HEAD_BUCKET);
                    throw new S3ProxyException(S3ErrorCode.ACCESS_DENIED);
                }
                setOperation(ctx, S3Operation.HEAD_BUCKET);
                if (!blobStore.containerExists(containerName)) {
                    throw new S3ProxyException(S3ErrorCode.NO_SUCH_BUCKET);
                }
            } else {
                String containerName = path[1];
                String blobName = path[2];
                if (!checkPublicAccess(blobStore, containerName, blobName)) {
                    setOperation(ctx, S3Operation.HEAD_OBJECT);
                    throw new S3ProxyException(S3ErrorCode.ACCESS_DENIED);
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
                handlePostBlob(request, response, is, blobStore, path[1]);
                return;
            }
        }
        case "PUT" -> {
            // Only a plain object write: bucket creation, ACLs, copies, and
            // multipart parts stay authenticated, since bucket WRITE grants
            // none of them.
            if (path.length > 2 && !path[2].isEmpty() &&
                    request.getParameter("uploadId") == null &&
                    request.getParameter("acl") == null &&
                    request.getHeader(AwsHttpHeaders.COPY_SOURCE) == null) {
                String containerName = path[1];
                String blobName = path[2];
                setOperation(ctx, S3Operation.PUT_OBJECT);
                checkPublicWriteAccess(blobStore, containerName);
                handlePutBlob(request, response, is, blobStore, containerName,
                        blobName);
                return;
            }
            setOperation(ctx, S3Operation.PUT_OBJECT);
            throw new S3ProxyException(S3ErrorCode.ACCESS_DENIED);
        }
        case "DELETE" -> {
            if (path.length > 2 && !path[2].isEmpty() &&
                    request.getParameter("uploadId") == null) {
                String containerName = path[1];
                String blobName = path[2];
                setOperation(ctx, S3Operation.DELETE_OBJECT);
                checkPublicWriteAccess(blobStore, containerName);
                handleBlobRemove(request, response, blobStore, containerName,
                        blobName);
                return;
            }
            setOperation(ctx, S3Operation.DELETE_OBJECT);
            throw new S3ProxyException(S3ErrorCode.ACCESS_DENIED);
        }
        case "OPTIONS" -> {
            if (uri.equals("/")) {
                setOperation(ctx, S3Operation.OPTIONS_OBJECT);
                throw new S3ProxyException(S3ErrorCode.ACCESS_DENIED);
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
        throw new S3ProxyException(S3ErrorCode.NOT_IMPLEMENTED);
    }

    private void handleGetContainerAcl(HttpServletRequest request,
            HttpServletResponse response, BlobStore blobStore,
            String containerName) throws IOException {
        if (!blobStore.containerExists(containerName)) {
            throw new S3ProxyException(S3ErrorCode.NO_SUCH_BUCKET);
        }
        BucketCannedACL access = blobStore.getContainerAccess(containerName);

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

            // S3 lists the group grants ahead of the owner's, which clients
            // rely on to tell the two apart without inspecting every grantee.
            if (access == BucketCannedACL.PUBLIC_READ ||
                    access == BucketCannedACL.PUBLIC_READ_WRITE) {
                writeAllUsersGrant(xml, "READ");
            }
            if (access == BucketCannedACL.PUBLIC_READ_WRITE) {
                writeAllUsersGrant(xml, "WRITE");
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
            String containerName) throws IOException {
        BucketCannedACL access;

        String cannedAcl = request.getHeader(AwsHttpHeaders.ACL);
        if (cannedAcl == null || "private".equalsIgnoreCase(cannedAcl)) {
            access = BucketCannedACL.PRIVATE;
        } else if ("public-read".equalsIgnoreCase(cannedAcl)) {
            access = BucketCannedACL.PUBLIC_READ;
        } else if ("public-read-write".equalsIgnoreCase(cannedAcl)) {
            access = BucketCannedACL.PUBLIC_READ_WRITE;
        } else if (CANNED_ACLS.contains(cannedAcl)) {
            throw new S3ProxyException(S3ErrorCode.NOT_IMPLEMENTED);
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
                access = BucketCannedACL.PRIVATE;
            } else if (accessString.equals("public-read")) {
                access = BucketCannedACL.PUBLIC_READ;
            } else if (accessString.equals("public-read-write")) {
                access = BucketCannedACL.PUBLIC_READ_WRITE;
            } else {
                throw new S3ProxyException(S3ErrorCode.NOT_IMPLEMENTED);
            }
        }

        blobStore.setContainerAccess(containerName, access);
        addCorsResponseHeader(request, response);
    }

    private void handleGetBlobAcl(HttpServletRequest request,
            HttpServletResponse response, BlobStore blobStore,
            String containerName, String blobName)
            throws IOException {
        // Resolves only the current object; ignoring a versionId would
        // answer with the wrong version's ACL.
        checkVersionId(request);

        ObjectCannedACL access = blobStore.getBlobAccess(containerName, blobName);

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

            if (access == ObjectCannedACL.PUBLIC_READ) {
                writeAllUsersGrant(xml, "READ");
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
            throws IOException {
        // Resolves only the current object; ignoring a versionId would
        // change the wrong version's ACL.
        checkVersionId(request);

        ObjectCannedACL access;

        String cannedAcl = request.getHeader(AwsHttpHeaders.ACL);
        if (cannedAcl == null || "private".equalsIgnoreCase(cannedAcl)) {
            access = ObjectCannedACL.PRIVATE;
        } else if ("public-read".equalsIgnoreCase(cannedAcl)) {
            access = ObjectCannedACL.PUBLIC_READ;
        } else if (CANNED_ACLS.contains(cannedAcl)) {
            throw new S3ProxyException(S3ErrorCode.NOT_IMPLEMENTED);
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
                access = ObjectCannedACL.PRIVATE;
            } else if (accessString.equals("public-read")) {
                access = ObjectCannedACL.PUBLIC_READ;
            } else {
                throw new S3ProxyException(S3ErrorCode.NOT_IMPLEMENTED);
            }
        }

        blobStore.setBlobAccess(containerName, blobName, access);
        addCorsResponseHeader(request, response);
    }

    /** Map XML ACLs to a canned policy if an exact transformation exists. */
    private static String mapXmlAclsToCannedPolicy(
            AccessControlPolicy policy) {
        if (!policy.owner().id().equals(FAKE_OWNER_ID)) {
            throw new S3ProxyException(S3ErrorCode.NOT_IMPLEMENTED);
        }

        boolean ownerFullControl = false;
        boolean allUsersRead = false;
        boolean allUsersWrite = false;
        // grants() is null when the document holds an empty
        // <AccessControlList/>, which is how a client revokes every grant;
        // answer NotImplemented like any other ACL without a canned
        // spelling rather than 500, which the client retries with backoff.
        if (policy.aclList() != null && policy.aclList().grants() != null) {
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
                } else if (grant.grantee().type().equals("Group") &&
                        grant.grantee().uri().equals("http://acs.amazonaws.com/" +
                                "groups/global/AllUsers") &&
                        grant.permission().equals("WRITE")) {
                    allUsersWrite = true;
                } else {
                    throw new S3ProxyException(S3ErrorCode.NOT_IMPLEMENTED);
                }
            }
        }

        if (ownerFullControl) {
            if (allUsersRead && allUsersWrite) {
                return "public-read-write";
            }
            if (allUsersWrite) {
                // no canned ACL says write-without-read
                throw new S3ProxyException(S3ErrorCode.NOT_IMPLEMENTED);
            }
            if (allUsersRead) {
                return "public-read";
            }
            return "private";
        } else {
            throw new S3ProxyException(S3ErrorCode.NOT_IMPLEMENTED);
        }
    }

    private void handleContainerList(HttpServletRequest request,
            HttpServletResponse response, BlobStore blobStore)
            throws IOException {
        // S3 lists buckets ordered by name; the backends promise no order of
        // their own, and paginating an unstable one would drop or repeat
        // buckets between pages.
        var buckets = new ArrayList<Bucket>(blobStore.list().buckets());
        buckets.sort(Comparator.comparing(Bucket::name));

        int maxBuckets = MAX_BUCKETS;
        String maxBucketsString = request.getParameter("max-buckets");
        if (maxBucketsString != null) {
            try {
                maxBuckets = Integer.parseInt(maxBucketsString);
            } catch (NumberFormatException nfe) {
                throw new S3ProxyException(S3ErrorCode.INVALID_ARGUMENT, nfe);
            }
            if (maxBuckets < 1 || maxBuckets > MAX_BUCKETS) {
                throw new S3ProxyException(S3ErrorCode.INVALID_ARGUMENT);
            }
        }
        // the token names the last bucket the previous page returned
        String continuationToken = request.getParameter("continuation-token");
        String prefix = request.getParameter("prefix");

        var page = new ArrayList<Bucket>();
        String nextContinuationToken = null;
        for (Bucket bucket : buckets) {
            String name = bucket.name();
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
            page.add(bucket);
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
            for (Bucket bucket : page) {
                xml.writeStartElement("Bucket");

                writeSimpleElement(xml, "Name", bucket.name());

                Date creationDate = bucket.creationDate() == null ? null :
                        Date.from(bucket.creationDate());
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
            String containerName) {
        if (!blobStore.containerExists(containerName)) {
            throw new S3ProxyException(S3ErrorCode.NO_SUCH_BUCKET);
        }
        throw new S3ProxyException(S3ErrorCode.NO_SUCH_POLICY);
    }

    /**
     * GetBucketVersioning.  A store without versioning still answers: its
     * buckets have never been versioned, which S3 spells as a configuration
     * with no Status element.
     */
    private void handleGetBucketVersioning(HttpServletRequest request,
            HttpServletResponse response, BlobStore blobStore,
            String containerName) throws IOException {
        BucketVersioningStatus status;
        if (blobStore.supportsVersioning()) {
            status = blobStore.getContainerVersioning(containerName);
        } else {
            if (!blobStore.containerExists(containerName)) {
                throw new S3ProxyException(S3ErrorCode.NO_SUCH_BUCKET);
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
                writeSimpleElement(xml, "Status", status.toString());
            }
            xml.writeEndElement();
            xml.flush();
        } catch (XMLStreamException xse) {
            throw new IOException(xse);
        }
    }

    private void handleSetBucketVersioning(HttpServletRequest request,
            HttpServletResponse response, InputStream is, BlobStore blobStore,
            String containerName) throws IOException {
        if (!blobStore.supportsVersioning()) {
            throw new S3ProxyException(S3ErrorCode.NOT_IMPLEMENTED,
                    "Versioning is not supported.");
        }

        // Bound the buffered body: the configuration is a few elements, but
        // the request is otherwise attacker-controlled.
        byte[] body = ByteStreams.limit(is, v4MaxNonChunkedRequestSize + 1)
                .readAllBytes();
        if (body.length == v4MaxNonChunkedRequestSize + 1) {
            throw new S3ProxyException(S3ErrorCode.MAX_MESSAGE_LENGTH_EXCEEDED);
        }
        VersioningConfigurationRequest vcr = readXmlBody(body,
                VersioningConfigurationRequest.class);
        if (vcr.mfaDelete() != null) {
            throw new S3ProxyException(S3ErrorCode.NOT_IMPLEMENTED,
                    "MFA delete is not supported.");
        }
        BucketVersioningStatus status = vcr.status() == null ? null :
                BucketVersioningStatus.fromValue(vcr.status());
        if (status == null ||
                status == BucketVersioningStatus.UNKNOWN_TO_SDK_VERSION) {
            throw new S3ProxyException(S3ErrorCode.MALFORMED_X_M_L);
        }

        blobStore.setContainerVersioning(containerName, status);
        addCorsResponseHeader(request, response);
    }

    /**
     * One row of the interleaved versions listing: an object version, or a
     * delete marker when {@code deleteMarker} is set.
     */
    private record VersionEntry(String name, String versionId, boolean latest,
            boolean deleteMarker, @Nullable String eTag,
            @Nullable Date lastModified, @Nullable Long size,
            @Nullable String storageClass) {
        static VersionEntry of(ObjectVersion version) {
            return new VersionEntry(version.key(), version.versionId(),
                    Boolean.TRUE.equals(version.isLatest()),
                    /*deleteMarker=*/ false, version.eTag(),
                    version.lastModified() == null ? null :
                            Date.from(version.lastModified()),
                    version.size(),
                    version.storageClassAsString() == null ?
                            StorageClass.STANDARD.toString() :
                            version.storageClassAsString());
        }

        static VersionEntry of(DeleteMarkerEntry marker) {
            return new VersionEntry(marker.key(), marker.versionId(),
                    Boolean.TRUE.equals(marker.isLatest()),
                    /*deleteMarker=*/ true, /*eTag=*/ null,
                    marker.lastModified() == null ? null :
                            Date.from(marker.lastModified()),
                    /*size=*/ null, /*storageClass=*/ null);
        }

        /** S3 listing order: keys ascending, then newest first. */
        static int compareOrder(VersionEntry left, VersionEntry right) {
            int compare = left.name().compareTo(right.name());
            if (compare != 0) {
                return compare;
            }
            var leftModified = left.lastModified();
            var rightModified = right.lastModified();
            return Long.compare(
                    rightModified == null ? 0 : rightModified.getTime(),
                    leftModified == null ? 0 : leftModified.getTime());
        }
    }

    private void handleListObjectVersions(HttpServletRequest request,
            HttpServletResponse response, BlobStore blobStore,
            String containerName) throws IOException {
        if (!blobStore.supportsVersioning()) {
            throw new S3ProxyException(S3ErrorCode.NOT_IMPLEMENTED,
                    "Versioning is not supported.");
        }

        String encodingType = request.getParameter("encoding-type");
        var versionsRequest = ListObjectVersionsRequest.builder()
                .bucket(containerName);
        String prefix = request.getParameter("prefix");
        if (prefix != null && !prefix.isEmpty()) {
            versionsRequest.prefix(prefix);
        }
        String delimiter = request.getParameter("delimiter");
        if (delimiter != null && !delimiter.isEmpty()) {
            versionsRequest.delimiter(delimiter);
        }
        String keyMarker = request.getParameter("key-marker");
        if (keyMarker != null) {
            versionsRequest.keyMarker(keyMarker);
        }
        String versionIdMarker = request.getParameter("version-id-marker");
        if (versionIdMarker != null) {
            versionsRequest.versionIdMarker(versionIdMarker);
        }

        int maxKeys = 1000;
        String maxKeysString = request.getParameter("max-keys");
        if (maxKeysString != null) {
            try {
                maxKeys = Integer.parseInt(maxKeysString);
            } catch (NumberFormatException nfe) {
                throw new S3ProxyException(S3ErrorCode.INVALID_ARGUMENT, nfe);
            }
            if (maxKeys < 0) {
                throw new S3ProxyException(S3ErrorCode.INVALID_ARGUMENT);
            }
            if (maxKeys > 1000) {
                maxKeys = 1000;
            }
        }
        versionsRequest.maxKeys(maxKeys);

        ListObjectVersionsResponse page = blobStore.listVersions(
                versionsRequest.build());

        // The service interleaves Version and DeleteMarker elements in one
        // ordered document, but the SDK models them as two lists, each still
        // in that order.  Merge them back by S3's order -- keys ascending,
        // then newest first -- which recovers the original sequence except
        // for a version and a marker of the same key stamped in the same
        // millisecond.
        var versionEntries = page.versions().stream()
                .map(VersionEntry::of)
                .toList();
        var markerEntries = page.deleteMarkers().stream()
                .map(VersionEntry::of)
                .toList();
        var merged = new ArrayList<VersionEntry>(
                versionEntries.size() + markerEntries.size());
        int vi = 0;
        int mi = 0;
        while (vi < versionEntries.size() || mi < markerEntries.size()) {
            boolean takeVersion;
            if (vi == versionEntries.size()) {
                takeVersion = false;
            } else if (mi == markerEntries.size()) {
                takeVersion = true;
            } else {
                takeVersion = VersionEntry.compareOrder(versionEntries.get(vi),
                        markerEntries.get(mi)) <= 0;
            }
            merged.add(takeVersion ?
                    versionEntries.get(vi++) : markerEntries.get(mi++));
        }

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

            for (VersionEntry version : merged) {
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

                String storageClass = version.storageClass();
                if (!version.deleteMarker() && storageClass != null) {
                    writeSimpleElement(xml, "StorageClass", storageClass);
                }

                xml.writeEndElement();
            }

            for (CommonPrefix commonPrefix : page.commonPrefixes()) {
                xml.writeStartElement("CommonPrefixes");
                writeSimpleElement(xml, "Prefix", encodeBlob(encodingType,
                        commonPrefix.prefix()));
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
            String container) throws IOException {
        String delimiter = request.getParameter("delimiter");
        if (delimiter != null && !delimiter.isEmpty() &&
                !delimiter.equals("/")) {
            throw new S3ProxyException(S3ErrorCode.NOT_IMPLEMENTED);
        }
        String keyMarker = request.getParameter("key-marker");
        String uploadIdMarker = request.getParameter("upload-id-marker");

        int maxUploads = 1000;
        String maxUploadsString = request.getParameter("max-uploads");
        if (maxUploadsString != null) {
            try {
                maxUploads = Integer.parseInt(maxUploadsString);
            } catch (NumberFormatException nfe) {
                throw new S3ProxyException(S3ErrorCode.INVALID_ARGUMENT, nfe);
            }
            if (maxUploads < 0) {
                throw new S3ProxyException(S3ErrorCode.INVALID_ARGUMENT);
            }
            if (maxUploads > 1000) {
                maxUploads = 1000;
            }
        }

        String encodingType = request.getParameter("encoding-type");
        String prefix = request.getParameter("prefix");

        var uploads = blobStore.listMultipartUploads(
                container);

        var filtered = uploads.stream()
                .filter(u -> prefix == null || u.key().startsWith(prefix))
                .filter(u -> {
                    if (keyMarker == null) {
                        return true;
                    }
                    int cmp = u.key().compareTo(keyMarker);
                    if (cmp > 0) {
                        return true;
                    }
                    if (cmp == 0 && uploadIdMarker != null) {
                        return u.uploadId().compareTo(uploadIdMarker) > 0;
                    }
                    return false;
                })
                .sorted(Comparator.comparing(
                        software.amazon.awssdk.services.s3.model
                                .MultipartUpload::key)
                        .thenComparing(software.amazon.awssdk.services.s3
                                .model.MultipartUpload::uploadId))
                .collect(Collectors.toList());

        boolean isTruncated = filtered.size() > maxUploads;
        var page = isTruncated ?
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
                var last = page.get(page.size() - 1);
                writeSimpleElement(xml, "NextKeyMarker", encodeBlob(
                        encodingType, last.key()));
                writeSimpleElement(xml, "NextUploadIdMarker",
                        last.uploadId());
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

            for (var upload : page) {
                xml.writeStartElement("Upload");

                writeSimpleElement(xml, "Key", encodeBlob(
                        encodingType, upload.key()));
                writeSimpleElement(xml, "UploadId", upload.uploadId());
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
            String containerName) throws IOException {
        if (!blobStore.containerExists(containerName)) {
            throw new S3ProxyException(S3ErrorCode.NO_SUCH_BUCKET);
        }
        addCorsResponseHeader(request, response);
    }

    private void handleContainerCreate(HttpServletRequest request,
            HttpServletResponse response, InputStream is, BlobStore blobStore,
            String containerName) throws IOException {
        if (containerName.isEmpty()) {
            throw new S3ProxyException(S3ErrorCode.METHOD_NOT_ALLOWED);
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
            throw new S3ProxyException(S3ErrorCode.NOT_IMPLEMENTED);
        }

        String contentLengthString = request.getHeader(
                HttpHeaders.CONTENT_LENGTH);
        if (contentLengthString != null) {
            long contentLength;
            try {
                contentLength = Long.parseLong(contentLengthString);
            } catch (NumberFormatException nfe) {
                throw new S3ProxyException(S3ErrorCode.INVALID_ARGUMENT, nfe);
            }
            if (contentLength < 0) {
                throw new S3ProxyException(S3ErrorCode.INVALID_ARGUMENT);
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
                org.gaul.s3proxy.CreateBucketRequest cbr = readXmlBody(
                        pis, org.gaul.s3proxy.CreateBucketRequest.class);
                locationString = cbr.locationConstraint();
            }
        }

        // The backend determines the region; clients sending a
        // LocationConstraint other than the backend's region get no special
        // handling.
        logger.debug("Creating bucket with location: {}", locationString);

        // public-read-write grants AllUsers read as well as write.  A
        // BucketCannedACL says only whether a container is readable, so the
        // write half is dropped -- but dropping the read half too left a
        // bucket created for anonymous use answering AccessDenied to the
        // anonymous reads its own ACL had allowed.
        String acl = request.getHeader(AwsHttpHeaders.ACL);
        var createRequest = CreateBucketRequest.builder()
                .bucket(containerName);
        if ("public-read".equalsIgnoreCase(acl)) {
            createRequest.acl(BucketCannedACL.PUBLIC_READ);
        } else if ("public-read-write".equalsIgnoreCase(acl)) {
            createRequest.acl(BucketCannedACL.PUBLIC_READ_WRITE);
        }

        boolean created = blobStore.createContainer(createRequest.build());
        if (!created) {
            throw new S3ProxyException(S3ErrorCode.BUCKET_ALREADY_OWNED_BY_YOU,
                    S3ErrorCode.BUCKET_ALREADY_OWNED_BY_YOU.getMessage(),
                    null, Map.of("BucketName", containerName));
        }

        response.addHeader(HttpHeaders.LOCATION, "/" + containerName);
        addCorsResponseHeader(request, response);
    }

    private void handleContainerDelete(HttpServletRequest request,
            HttpServletResponse response, BlobStore blobStore,
            String containerName) throws IOException {
        if (!blobStore.containerExists(containerName)) {
            throw new S3ProxyException(S3ErrorCode.NO_SUCH_BUCKET);
        }

        if (!blobStore.deleteContainerIfEmpty(containerName)) {
            throw new S3ProxyException(S3ErrorCode.BUCKET_NOT_EMPTY);
        }

        addCorsResponseHeader(request, response);
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }

    private void handleBlobList(HttpServletRequest request,
            HttpServletResponse response, BlobStore blobStore,
            String containerName) throws IOException {
        String blobStoreType = getBlobStoreType(blobStore);
        String encodingType = request.getParameter("encoding-type");
        String delimiter = request.getParameter("delimiter");
        String prefix = request.getParameter("prefix");
        if (prefix != null && prefix.isEmpty()) {
            prefix = null;
        }

        boolean isListV2 = false;
        String marker;
        String listType = request.getParameter("list-type");
        // S3 treats an empty continuation-token or start-after as absent
        // rather than refusing it; a native store would reject the empty
        // string as a malformed token.
        String continuationToken = Strings.emptyToNull(
                request.getParameter("continuation-token"));
        String startAfter = Strings.emptyToNull(
                request.getParameter("start-after"));
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
            throw new S3ProxyException(S3ErrorCode.NOT_IMPLEMENTED);
        }
        boolean opaqueMarkers = Quirks.OPAQUE_MARKERS.contains(
                blobStoreType);
        if (marker != null && opaqueMarkers) {
            String realMarker = lastKeyToMarker.getIfPresent(
                    Map.entry(containerName, marker));
            if (realMarker != null) {
                marker = realMarker;
            }
        }

        boolean fetchOwner = !isListV2 ||
                "true".equals(request.getParameter("fetch-owner"));

        int maxKeys = 1000;
        String maxKeysString = request.getParameter("max-keys");
        if (maxKeysString != null) {
            try {
                maxKeys = Integer.parseInt(maxKeysString);
            } catch (NumberFormatException nfe) {
                throw new S3ProxyException(S3ErrorCode.INVALID_ARGUMENT, nfe);
            }
            if (maxKeys < 0) {
                throw new S3ProxyException(S3ErrorCode.INVALID_ARGUMENT);
            }
            if (maxKeys > 1000) {
                maxKeys = 1000;
            }
        }

        // V2 rides the store's own continuation tokens; V1 pages by keys,
        // which the default listV1 bridge serves over the V2 listing.
        List<S3Object> contents;
        List<CommonPrefix> prefixList;
        String nextToken;
        if (isListV2) {
            var listRequest = ListObjectsV2Request.builder()
                    .bucket(containerName)
                    .prefix(prefix)
                    .delimiter(delimiter)
                    .maxKeys(maxKeys);
            // marker carries the continuation token, or start-after when no
            // token was sent -- possibly cache-mapped to the store's opaque
            // token, in which case it must ride as a token either way.
            if (continuationToken != null || opaqueMarkers) {
                listRequest.continuationToken(marker);
            } else {
                listRequest.startAfter(marker);
            }
            ListObjectsV2Response set = blobStore.list(listRequest.build());
            contents = set.contents();
            prefixList = set.commonPrefixes();
            nextToken = set.nextContinuationToken();
        } else {
            ListObjectsResponse set = blobStore.listV1(
                    ListObjectsRequest.builder()
                            .bucket(containerName)
                            .prefix(prefix)
                            .delimiter(delimiter)
                            .maxKeys(maxKeys)
                            .marker(marker)
                            .build());
            contents = set.contents();
            prefixList = set.commonPrefixes();
            nextToken = set.nextMarker();
            if (nextToken == null &&
                    Boolean.TRUE.equals(set.isTruncated()) &&
                    !contents.isEmpty()) {
                nextToken = contents.get(contents.size() - 1).key();
            }
        }

        boolean filterStub = Quirks.MULTIPART_REQUIRES_STUB.contains(
                blobStoreType);
        int filteredCount = prefixList.size();
        for (S3Object object : contents) {
            if (!filterStub ||
                    !object.key().startsWith(MULTIPART_STUB_PREFIX)) {
                filteredCount++;
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
                    // A token is opaque: encoding-type applies to the
                    // key-shaped fields only, and a client does not decode
                    // this one.
                    writeSimpleElement(xml, "ContinuationToken",
                            continuationToken);
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

            String nextMarker = nextToken;
            if (nextMarker != null) {
                writeSimpleElement(xml, "IsTruncated", "true");
                if (isListV2) {
                    // opaque, so never encoding-type encoded: a client sends
                    // it back exactly as written
                    writeSimpleElement(xml, "NextContinuationToken",
                            nextMarker);
                } else {
                    writeSimpleElement(xml, "NextMarker",
                            encodeBlob(encodingType, nextMarker));
                }
                if (Quirks.OPAQUE_MARKERS.contains(blobStoreType)) {
                    // A caller may page with the last key it was given rather
                    // than the marker, which S3 allows and which a store with
                    // opaque markers rejects.  Remember which marker produced
                    // that key so the next request can present it instead.
                    // Keyed on the name as the store spells it, since the
                    // marker is read back from the query string already
                    // decoded.  A caller echoing the marker needs no entry:
                    // one this cache does not know passes through untouched,
                    // which is what the store wants anyway.  The last name
                    // the caller sees is the greater of the final key and
                    // the final prefix, each list being in listing order.
                    String lastKey = Streams.findLast(contents.stream())
                            .map(S3Object::key).orElse(null);
                    String lastPrefix = Streams.findLast(prefixList.stream())
                            .map(CommonPrefix::prefix).orElse(null);
                    String lastName = lastPrefix == null ? lastKey :
                            lastKey == null ||
                                    lastKey.compareTo(lastPrefix) < 0 ?
                            lastPrefix : lastKey;
                    if (lastName != null) {
                        lastKeyToMarker.put(
                                Map.entry(containerName, lastName),
                                nextMarker);
                    }
                }
            } else {
                writeSimpleElement(xml, "IsTruncated", "false");
            }

            for (S3Object object : contents) {
                if (filterStub && object.key().startsWith(
                        MULTIPART_STUB_PREFIX)) {
                    continue;
                }

                xml.writeStartElement("Contents");

                writeSimpleElement(xml, "Key", encodeBlob(encodingType,
                        object.key()));

                if (object.lastModified() != null) {
                    writeSimpleElement(xml, "LastModified",
                            formatDate(Date.from(object.lastModified())));
                }

                String eTag = object.eTag();
                if (eTag != null) {
                    writeSimpleElement(xml, "ETag", maybeQuoteETag(eTag));
                }

                Long size = object.size();
                if (size != null) {
                    writeSimpleElement(xml, "Size", String.valueOf(size));
                }

                String storageClass = object.storageClassAsString();
                if (storageClass != null) {
                    writeSimpleElement(xml, "StorageClass", storageClass);
                }

                if (fetchOwner) {
                    writeOwnerStanza(xml);
                }

                xml.writeEndElement();
            }

            Set<String> commonPrefixes = new TreeSet<>();
            for (CommonPrefix entry : prefixList) {
                commonPrefixes.add(entry.prefix());
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
            throws IOException {
        // Only directory buckets delete conditionally.  Reject the condition
        // rather than honor the delete and discard it, which would report
        // success for a delete the caller asked not to happen.  The
        // x-amz-if-match-size and x-amz-if-match-last-modified-time forms
        // are already refused as unknown x-amz- headers.
        if (request.getHeader(HttpHeaders.IF_MATCH) != null) {
            throw new S3ProxyException(S3ErrorCode.NOT_IMPLEMENTED);
        }
        if (blobStore.supportsVersioning()) {
            DeleteObjectResponse result = blobStore.removeBlob(
                    containerName, blobName,
                    request.getParameter("versionId"));
            String versionId = result.versionId();
            if (versionId != null) {
                response.addHeader(AwsHttpHeaders.VERSION_ID, versionId);
            }
            if (Boolean.TRUE.equals(result.deleteMarker())) {
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
            HttpServletRequest request, byte[] body) {
        String contentMD5 = request.getHeader(HttpHeaders.CONTENT_MD5);
        if (contentMD5 != null) {
            HashCode expected;
            try {
                expected = HashCode.fromBytes(
                        Base64.getDecoder().decode(contentMD5));
            } catch (IllegalArgumentException iae) {
                throw new S3ProxyException(S3ErrorCode.INVALID_DIGEST, iae);
            }
            if (expected.bits() != MD5.bits()) {
                throw new S3ProxyException(S3ErrorCode.INVALID_DIGEST);
            }
            if (!expected.equals(MD5.hashBytes(body))) {
                throw new S3ProxyException(S3ErrorCode.BAD_DIGEST);
            }
            return;
        }
        // Match modern AWS SDKs that send a flexible checksum header in
        // place of Content-MD5.  Try each algorithm we recognise; the SDK
        // sends only one.
        for (FlexChecksum checksum : FlexChecksum.values()) {
            if (validateChecksumHeader(request, body, checksum)) {
                return;
            }
        }
        throw new S3ProxyException(S3ErrorCode.INVALID_REQUEST,
                "Missing required header for this request: Content-Md5");
    }

    private static boolean validateChecksumHeader(HttpServletRequest request,
            byte[] body, FlexChecksum checksum) {
        String value = request.getHeader(checksum.header());
        if (value == null) {
            return false;
        }
        byte[] expected;
        try {
            expected = Base64.getDecoder().decode(value);
        } catch (IllegalArgumentException iae) {
            throw new S3ProxyException(S3ErrorCode.INVALID_DIGEST, iae);
        }
        SdkChecksum digest = checksum.newChecksum();
        digest.update(body);
        if (!java.util.Arrays.equals(expected, digest.getChecksumBytes())) {
            throw new S3ProxyException(S3ErrorCode.BAD_DIGEST);
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
            HttpServletRequest request) {
        FlexChecksum found = null;
        for (FlexChecksum candidate : FlexChecksum.values()) {
            if (request.getHeader(candidate.header()) != null) {
                if (found != null) {
                    throw new S3ProxyException(S3ErrorCode.INVALID_REQUEST,
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
            FlexChecksum checksum, String expectedBase64, long contentLength) {
        return new ChecksumValidatingInputStream(is, checksum.newChecksum(),
                checksum.decodeValue(expectedBase64), contentLength);
    }

    private void handleMultiBlobRemove(HttpServletRequest request,
            HttpServletResponse response, InputStream is,
            BlobStore blobStore, String containerName)
            throws IOException {
        // Bound the buffered body: a MultiObjectDelete is limited to 1000
        // keys, but the request is otherwise attacker-controlled, so read at
        // most one byte past the limit and reject rather than exhaust the heap.
        byte[] body = ByteStreams.limit(is, v4MaxNonChunkedRequestSize + 1)
                .readAllBytes();
        if (body.length == v4MaxNonChunkedRequestSize + 1) {
            throw new S3ProxyException(S3ErrorCode.MAX_MESSAGE_LENGTH_EXCEEDED);
        }
        validateMultiBlobRemoveChecksum(request, body);
        DeleteMultipleObjectsRequest dmor = readXmlBody(
                body, DeleteMultipleObjectsRequest.class);
        if (dmor.objects() == null) {
            throw new S3ProxyException(S3ErrorCode.MALFORMED_X_M_L);
        }

        if (dmor.objects().size() > 1_000) {
            throw new S3ProxyException(S3ErrorCode.INVALID_ARGUMENT);
        }

        boolean supportsVersioning = blobStore.supportsVersioning();
        boolean anyVersion = false;
        Collection<String> blobNames = new ArrayList<>();
        for (DeleteMultipleObjectsRequest.S3Object s3Object :
                dmor.objects()) {
            if (Strings.isNullOrEmpty(s3Object.key())) {
                throw new S3ProxyException(S3ErrorCode.MALFORMED_X_M_L);
            }
            if (s3Object.hasCondition()) {
                throw new S3ProxyException(S3ErrorCode.NOT_IMPLEMENTED);
            }
            // On a versioning store even the literal "null" names a version
            // -- the one written while the bucket was unversioned -- so any
            // VersionId element routes the delete through the versioned path.
            if (s3Object.versionId() != null && supportsVersioning) {
                anyVersion = true;
            } else if (s3Object.hasVersion()) {
                throw new S3ProxyException(S3ErrorCode.NOT_IMPLEMENTED,
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
                    DeleteObjectResponse result = blobStore.removeBlob(
                            containerName, s3Object.key(),
                            s3Object.versionId());
                    results.add(new DeletedObjectResult(s3Object.key(),
                            s3Object.versionId(), result, null));
                } catch (AwsServiceException e) {
                    if (!"NoSuchVersion".equals(S3Exceptions.errorCode(e))) {
                        throw e;
                    }
                    results.add(new DeletedObjectResult(s3Object.key(),
                            s3Object.versionId(), null,
                            S3Error.builder()
                                    .key(s3Object.key())
                                    .versionId(s3Object.versionId())
                                    .code("NoSuchVersion")
                                    .message("The specified version does" +
                                            " not exist.")
                                    .build()));
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
                    S3Error error = result.error();
                    if (error != null) {
                        xml.writeStartElement("Error");
                        writeSimpleElement(xml, "Key", error.key());
                        if (error.versionId() != null) {
                            writeSimpleElement(xml, "VersionId",
                                    error.versionId());
                        }
                        writeSimpleElement(xml, "Code", error.code());
                        writeSimpleElement(xml, "Message", error.message());
                        xml.writeEndElement();
                    } else if (!dmor.quiet()) {
                        xml.writeStartElement("Deleted");
                        writeSimpleElement(xml, "Key", result.key());
                        String versionId = result.requestedVersionId();
                        if (versionId != null) {
                            writeSimpleElement(xml, "VersionId", versionId);
                        }
                        DeleteObjectResponse removed = result.result();
                        if (removed != null &&
                                Boolean.TRUE.equals(removed.deleteMarker())) {
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
            @Nullable DeleteObjectResponse result,
            @Nullable S3Error error) {
    }

    private void handleBlobMetadata(HttpServletRequest request,
            HttpServletResponse response,
            BlobStore blobStore, String containerName,
            String blobName) throws IOException {
        var headRequest = HeadObjectRequest.builder()
                .bucket(containerName)
                .key(blobName);
        if (blobStore.supportsVersioning()) {
            headRequest.versionId(request.getParameter("versionId"));
        }
        HeadObjectResponse metadata = blobStore.blobMetadata(
                headRequest.build());
        if (metadata == null) {
            throw new S3ProxyException(S3ErrorCode.NO_SUCH_KEY);
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

    /**
     * The multipart carrier's view of a stub blob's HEAD: the create-time
     * request reconstructed from what the stub persisted, so a store that
     * assembles the final object itself can write its metadata.
     */
    private static CreateMultipartUploadRequest.Builder toCarrierRequest(
            String containerName, String blobName, HeadObjectResponse head) {
        return CreateMultipartUploadRequest.builder()
                .bucket(containerName)
                .key(blobName)
                .metadata(head.metadata())
                .cacheControl(head.cacheControl())
                .contentDisposition(head.contentDisposition())
                .contentEncoding(head.contentEncoding())
                .contentLanguage(head.contentLanguage())
                .contentType(head.contentType());
    }

    /** The carrier for an upload known only by its id and target. */
    private static MultipartUpload reconstructedMpu(String containerName,
            String blobName, String uploadId) {
        return new MultipartUpload(uploadId,
                CreateMultipartUploadRequest.builder()
                        .bucket(containerName)
                        .key(blobName)
                        .build());
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
            BlobStore blobStore) {
        if (!blobStore.supportsVersioning()) {
            checkVersionId(request);
        }
    }

    /** Vet a versionId for an operation that cannot resolve one. */
    private static void checkVersionId(HttpServletRequest request) {
        String versionId = request.getParameter("versionId");
        if (versionId != null && !versionId.equals("null")) {
            throw new S3ProxyException(S3ErrorCode.NOT_IMPLEMENTED,
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
            @Nullable HeadObjectResponse metadata) {
        String value = request.getParameter("partNumber");
        if (value == null || metadata == null) {
            return;
        }
        int partNumber;
        try {
            partNumber = Integer.parseInt(value);
        } catch (NumberFormatException nfe) {
            throw new S3ProxyException(S3ErrorCode.INVALID_ARGUMENT, nfe);
        }
        if (partNumber < 1 || partNumber > 10_000) {
            throw new S3ProxyException(S3ErrorCode.INVALID_ARGUMENT);
        }
        if (eTagPartCount(metadata.eTag()) > 1) {
            throw new S3ProxyException(S3ErrorCode.NOT_IMPLEMENTED,
                    "Reading one part of a multipart object is not" +
                    " supported.");
        }
        if (partNumber > 1) {
            // one part, so anything past it does not exist
            throw new S3ProxyException(S3ErrorCode.INVALID_PART);
        }
    }

    /**
     * Evaluate the conditional request headers for an operation that reads
     * only metadata, which BlobStore.blobMetadata cannot express as
     * GetOptions.  Returns true when the response is already complete, i.e.
     * the caller's copy is unchanged.
     */
    private static boolean checkConditionalHeaders(HttpServletRequest request,
            HttpServletResponse response, HeadObjectResponse metadata) {
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
                throw new S3ProxyException(S3ErrorCode.PRECONDITION_FAILED);
            }
            if (ifNoneMatch != null && ifNoneMatch.equals(eTag)) {
                response.setStatus(HttpServletResponse.SC_NOT_MODIFIED);
                return true;
            }
        }

        Date lastModified = metadata.lastModified() == null ? null :
                Date.from(metadata.lastModified());
        if (lastModified != null) {
            if (ifModifiedSince != -1 && lastModified.compareTo(
                    new Date(ifModifiedSince)) <= 0) {
                response.setStatus(HttpServletResponse.SC_NOT_MODIFIED);
                return true;
            }
            if (ifUnmodifiedSince != -1 && lastModified.compareTo(
                    new Date(ifUnmodifiedSince)) > 0) {
                throw new S3ProxyException(S3ErrorCode.PRECONDITION_FAILED);
            }
        }
        return false;
    }

    private void handleGetObjectAttributes(HttpServletRequest request,
            HttpServletResponse response, BlobStore blobStore,
            String containerName, String blobName)
            throws IOException {
        // Resolves only the current object; ignoring a versionId would
        // answer with the wrong version's attributes.
        checkVersionId(request);
        Set<String> attributes = requestedObjectAttributes(request);

        HeadObjectResponse metadata = blobStore.blobMetadata(containerName,
                blobName);
        if (metadata == null) {
            throw new S3ProxyException(S3ErrorCode.NO_SUCH_KEY);
        }
        if (checkConditionalHeaders(request, response, metadata)) {
            return;
        }

        var lastModified = metadata.lastModified();
        if (lastModified != null) {
            response.addDateHeader(HttpHeaders.LAST_MODIFIED,
                    lastModified.toEpochMilli());
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
                String storageClass = metadata.storageClassAsString();
                writeSimpleElement(xml, "StorageClass", storageClass == null ?
                        StorageClass.STANDARD.toString() : storageClass);
            }

            Long size = metadata.contentLength();
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
            HttpServletRequest request) {
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
            throw new S3ProxyException(S3ErrorCode.INVALID_REQUEST,
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
            HeadObjectResponse metadata) throws XMLStreamException {
        for (var entry : metadata.metadata().entrySet()) {
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
            String containerName) throws IOException {
        if (!blobStore.containerExists(containerName)) {
            // Don't leak internal information, although authenticated
            throw new S3ProxyException(S3ErrorCode.ACCESS_DENIED);
        }

        String corsOrigin = request.getHeader(HttpHeaders.ORIGIN);
        if (Strings.isNullOrEmpty(corsOrigin)) {
            throw new S3ProxyException(S3ErrorCode.INVALID_CORS_ORIGIN);
        }
        if (!corsRules.isOriginAllowed(corsOrigin)) {
            throw new S3ProxyException(S3ErrorCode.ACCESS_DENIED);
        }

        String corsMethod = request.getHeader(
                HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD);
        if (!corsRules.isMethodAllowed(corsMethod)) {
            throw new S3ProxyException(S3ErrorCode.INVALID_CORS_METHOD);
        }

        String corsHeaders = request.getHeader(
                HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS);
        if (!Strings.isNullOrEmpty(corsHeaders)) {
            if (corsRules.isEveryHeaderAllowed(corsHeaders)) {
                response.addHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS,
                        corsHeaders);
            } else {
                throw new S3ProxyException(S3ErrorCode.ACCESS_DENIED);
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
            throws IOException {
        if (request.getParameter("partNumber") != null) {
            // needs the ETag to tell a multipart object apart, and the body
            // must not be fetched only to be thrown away on the error path
            checkPartNumber(request,
                    blobStore.blobMetadata(containerName, blobName));
        }

        int status = HttpServletResponse.SC_OK;
        var getRequest = GetObjectRequest.builder()
                .bucket(containerName)
                .key(blobName);

        if (blobStore.supportsVersioning()) {
            getRequest.versionId(request.getParameter("versionId"));
        }

        getRequest.ifMatch(request.getHeader(HttpHeaders.IF_MATCH));
        getRequest.ifNoneMatch(request.getHeader(HttpHeaders.IF_NONE_MATCH));

        long ifModifiedSince = request.getDateHeader(
                HttpHeaders.IF_MODIFIED_SINCE);
        if (ifModifiedSince != -1) {
            getRequest.ifModifiedSince(Instant.ofEpochMilli(ifModifiedSince));
        }

        long ifUnmodifiedSince = request.getDateHeader(
                HttpHeaders.IF_UNMODIFIED_SINCE);
        if (ifUnmodifiedSince != -1) {
            getRequest.ifUnmodifiedSince(
                    Instant.ofEpochMilli(ifUnmodifiedSince));
        }

        String range = request.getHeader(HttpHeaders.RANGE);
        if (range != null && range.startsWith("bytes=") &&
                // ignore multiple ranges
                range.indexOf(',') == -1 &&
                // ignore malformed ranges missing the hyphen
                range.indexOf('-') != -1) {
            String[] ranges = range.substring("bytes=".length())
                    .split("-", 2);
            try {
                if (ranges[0].isEmpty()) {
                    long tail = Long.parseLong(ranges[1]);
                    if (tail < 0) {
                        throw new S3ProxyException(S3ErrorCode.INVALID_RANGE);
                    }
                } else if (ranges[1].isEmpty()) {
                    long startAt = Long.parseLong(ranges[0]);
                    if (startAt < 0) {
                        throw new S3ProxyException(S3ErrorCode.INVALID_RANGE);
                    }
                } else {
                    long start = Long.parseLong(ranges[0]);
                    long end = Long.parseLong(ranges[1]);
                    if (start < 0 || end < start) {
                        throw new S3ProxyException(S3ErrorCode.INVALID_RANGE);
                    }
                }
            } catch (NumberFormatException nfe) {
                throw new S3ProxyException(S3ErrorCode.INVALID_ARGUMENT, nfe);
            }
            // pass the validated single range through verbatim
            getRequest.range(range);
            status = HttpServletResponse.SC_PARTIAL_CONTENT;
        }

        ResponseInputStream<GetObjectResponse> blob = blobStore.getBlob(
                getRequest.build());
        if (blob == null) {
            throw new S3ProxyException(S3ErrorCode.NO_SUCH_KEY);
        }

        response.setStatus(status);

        addCorsResponseHeader(request, response);

        addMetadataToResponse(request, response,
                SdkResponses.toHead(blob.response()),
                status == HttpServletResponse.SC_PARTIAL_CONTENT);

        // TODO: handles only a single range due to blobstore API limitations
        String contentRange = blob.response().contentRange();
        if (contentRange != null) {
            response.addHeader(HttpHeaders.CONTENT_RANGE, contentRange);
            response.addHeader(HttpHeaders.ACCEPT_RANGES, "bytes");
        }

        try (InputStream is = blob;
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
            BlobStore blobStore) {
        int query = rawCopySource.indexOf('?');
        if (query == -1) {
            return null;
        }
        String queryString = rawCopySource.substring(query + 1);
        if (!queryString.startsWith("versionId=")) {
            throw new S3ProxyException(S3ErrorCode.INVALID_ARGUMENT);
        }
        String versionId = URLDecoder.decode(
                queryString.substring("versionId=".length()),
                StandardCharsets.UTF_8);
        if (versionId.isEmpty()) {
            throw new S3ProxyException(S3ErrorCode.INVALID_ARGUMENT);
        }
        if (!blobStore.supportsVersioning()) {
            if (!versionId.equals("null")) {
                throw new S3ProxyException(S3ErrorCode.NOT_IMPLEMENTED,
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
            String sourceContainerName, String sourceBlobName) {
        if (blobStoreLocator.locateBlobStore(requestIdentity,
                sourceContainerName, sourceBlobName) == null) {
            throw new S3ProxyException(S3ErrorCode.ACCESS_DENIED);
        }
    }

    private void handleCopyBlob(HttpServletRequest request,
            HttpServletResponse response, BlobStore blobStore,
            @Nullable String requestIdentity,
            String destContainerName, String destBlobName)
            throws IOException {
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
            throw new S3ProxyException(S3ErrorCode.INVALID_REQUEST);
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
            throw new S3ProxyException(S3ErrorCode.INVALID_REQUEST);
        }

        var copyRequest = CopyObjectRequest.builder()
                .sourceBucket(sourceContainerName)
                .sourceKey(sourceBlobName)
                .sourceVersionId(sourceVersionId)
                .destinationBucket(destContainerName)
                .destinationKey(destBlobName);

        // The access rides down with the copy so that the store applies it as
        // it creates the object, rather than a PutObjectAcl afterwards whose
        // failure would leave the copy readable to nobody who asked for it.
        String cannedAcl = request.getHeader(AwsHttpHeaders.ACL);
        if (cannedAcl != null && !"private".equalsIgnoreCase(cannedAcl)) {
            if ("public-read".equalsIgnoreCase(cannedAcl)) {
                copyRequest.acl(ObjectCannedACL.PUBLIC_READ);
            } else if (CANNED_ACLS.contains(cannedAcl)) {
                throw new S3ProxyException(S3ErrorCode.NOT_IMPLEMENTED);
            } else {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST);
                return;
            }
        }

        copyRequest.copySourceIfMatch(
                request.getHeader(AwsHttpHeaders.COPY_SOURCE_IF_MATCH));
        copyRequest.copySourceIfNoneMatch(
                request.getHeader(AwsHttpHeaders.COPY_SOURCE_IF_NONE_MATCH));
        long ifModifiedSince = request.getDateHeader(
                AwsHttpHeaders.COPY_SOURCE_IF_MODIFIED_SINCE);
        if (ifModifiedSince != -1) {
            copyRequest.copySourceIfModifiedSince(
                    Instant.ofEpochMilli(ifModifiedSince));
        }
        long ifUnmodifiedSince = request.getDateHeader(
                AwsHttpHeaders.COPY_SOURCE_IF_UNMODIFIED_SINCE);
        if (ifUnmodifiedSince != -1) {
            copyRequest.copySourceIfUnmodifiedSince(
                    Instant.ofEpochMilli(ifUnmodifiedSince));
        }

        if (replaceMetadata) {
            copyRequest.metadataDirective(MetadataDirective.REPLACE);
            var userMetadata = ImmutableMap.<String, String>builder();
            for (String headerName : Collections.list(
                    request.getHeaderNames())) {
                String headerValue = Strings.nullToEmpty(request.getHeader(
                        headerName));
                if (headerName.equalsIgnoreCase(
                        HttpHeaders.CACHE_CONTROL)) {
                    copyRequest.cacheControl(headerValue);
                } else if (headerName.equalsIgnoreCase(
                        HttpHeaders.CONTENT_DISPOSITION)) {
                    copyRequest.contentDisposition(headerValue);
                } else if (headerName.equalsIgnoreCase(
                        HttpHeaders.CONTENT_ENCODING)) {
                    String stripped = stripAwsChunked(headerValue);
                    if (!stripped.isEmpty()) {
                        copyRequest.contentEncoding(stripped);
                    }
                } else if (headerName.equalsIgnoreCase(
                        HttpHeaders.CONTENT_LANGUAGE)) {
                    copyRequest.contentLanguage(headerValue);
                } else if (headerName.equalsIgnoreCase(
                        HttpHeaders.CONTENT_TYPE)) {
                    copyRequest.contentType(headerValue);
                } else if (startsWithIgnoreCase(headerName,
                        USER_METADATA_PREFIX)) {
                    userMetadata.put(
                            headerName.substring(USER_METADATA_PREFIX.length()),
                            headerValue);
                }
                // TODO: Expires
            }
            copyRequest.metadata(userMetadata.build());
        }

        CopyObjectResponse copyResult;
        try {
            copyResult = blobStore.copyBlob(copyRequest.build());
        } catch (NoSuchKeyException nske) {
            throw new S3ProxyException(S3ErrorCode.NO_SUCH_KEY, nske);
        }

        HeadObjectResponse blobMetadata = blobStore.blobMetadata(
                destContainerName, destBlobName);
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
                        formatDate(Date.from(lastModified)));
            }

            String eTag = copyResult.copyObjectResult() == null ?
                    null : copyResult.copyObjectResult().eTag();
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
            throws IOException {
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
                throw new S3ProxyException(S3ErrorCode.INVALID_DIGEST, iae);
            }
            if (contentMD5.bits() != MD5.bits()) {
                throw new S3ProxyException(S3ErrorCode.INVALID_DIGEST);
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
            throw new S3ProxyException(S3ErrorCode.INVALID_ARGUMENT, nfe);
        }
        if (contentLength < 0) {
            throw new S3ProxyException(S3ErrorCode.INVALID_ARGUMENT);
        }
        if (contentLength > maxSinglePartObjectSize) {
            throw new S3ProxyException(S3ErrorCode.ENTITY_TOO_LARGE);
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
            throw new S3ProxyException(S3ErrorCode.NOT_IMPLEMENTED,
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
                throw new S3ProxyException(S3ErrorCode.NO_SUCH_KEY);
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

        ObjectCannedACL access;
        String cannedAcl = request.getHeader(AwsHttpHeaders.ACL);
        if (cannedAcl == null || cannedAcl.equalsIgnoreCase("private")) {
            access = ObjectCannedACL.PRIVATE;
        } else if (cannedAcl.equalsIgnoreCase("public-read")) {
            access = ObjectCannedACL.PUBLIC_READ;
        } else if (CANNED_ACLS.contains(cannedAcl)) {
            throw new S3ProxyException(S3ErrorCode.NOT_IMPLEMENTED);
        } else {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        var putRequest = PutObjectRequest.builder()
                .bucket(containerName)
                .key(blobName)
                .contentLength(contentLength)
                .ifMatch(ifMatch)
                .ifNoneMatch(ifNoneMatch);
        if (access == ObjectCannedACL.PUBLIC_READ) {
            putRequest.acl(ObjectCannedACL.PUBLIC_READ);
        }

        String storageClass = request.getHeader(AwsHttpHeaders.STORAGE_CLASS);
        if (storageClass == null || storageClass.equalsIgnoreCase("STANDARD")) {
            // defaults to STANDARD
        } else {
            try {
                putRequest.storageClass(StorageClass.valueOf(storageClass));
            } catch (IllegalArgumentException iae) {
                throw new S3ProxyException(S3ErrorCode.INVALID_STORAGE_CLASS, iae);
            }
        }

        var contentHeaders = parseContentMetadata(request, checksum,
                checksumValue);
        putRequest.cacheControl(contentHeaders.cacheControl())
                .contentDisposition(contentHeaders.contentDisposition())
                .contentEncoding(contentHeaders.contentEncoding())
                .contentLanguage(contentHeaders.contentLanguage())
                .contentType(contentHeaders.contentType())
                .expires(contentHeaders.expires())
                .metadata(contentHeaders.userMetadata());
        if (contentMD5 != null) {
            putRequest.contentMD5(Base64.getEncoder().encodeToString(
                    contentMD5.asBytes()));
        }

        PutObjectResponse result = blobStore.putBlob(putRequest.build(), is);

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
            BlobStore anonymousBlobStore, String containerName)
            throws IOException {
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
        // A fallback should the bounds below ever diverge; no part reaches it
        // while they agree.
        parser.setFilesDirectory(java.nio.file.Path.of(
                System.getProperty("java.io.tmpdir")));
        // Jetty bounds the number of parts and nothing else, so say how large
        // a body may be.  Nothing has authorized this one -- a form POST
        // carries no Authorization header, and the policy that speaks for it
        // is inside the body still being read -- so an unbounded body is one
        // anyone who can reach the proxy may send.  Bound it where the other
        // body read into memory is bounded, and hold parts in memory up to
        // the same bound rather than Jetty's default of writing every file
        // part to disk: the payload is about to be buffered whole anyway, and
        // the write turns a read-only temporary directory into a baffling 400
        // for every form upload.
        parser.setMaxLength(v4MaxNonChunkedRequestSize);
        parser.setMaxMemoryFileSize(v4MaxNonChunkedRequestSize);
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
                        throw new S3ProxyException(S3ErrorCode.INVALID_REQUEST,
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
        // without one here -- so either the policy or the bucket's own
        // permissions must say the caller may write.  A form carrying no
        // policy is answered as S3 answers it: the upload proceeds only when
        // the bucket grants AllUsers WRITE, and is refused otherwise.
        if (policy == null && signature == null && identity == null) {
            checkPublicWriteAccess(anonymousBlobStore, containerName);
            finishPostBlob(request, response, anonymousBlobStore,
                    containerName, blobName, contentType, fields, payload,
                    checksum, checksumValue);
            return;
        }
        // Carrying some but not all of them is a form built wrong rather than
        // one that meant to go unsigned, and saying so beats reporting it as a
        // refusal the caller cannot act on.
        if (policy == null || signature == null) {
            throw new S3ProxyException(S3ErrorCode.INVALID_ARGUMENT,
                    "Bucket POST must contain both 'policy' and a signature" +
                    " when it is authenticated.");
        }

        String headerAuthorization = null;
        S3AuthorizationHeader authHeader = null;
        boolean signatureVersion4;
        if (algorithm == null) {
            if (identity == null || signature == null) {
                throw new S3ProxyException(S3ErrorCode.ACCESS_DENIED);
            }
            signatureVersion4 = false;
            headerAuthorization = "AWS " + identity + ":" + signature;
        } else if (algorithm.equals("AWS4-HMAC-SHA256")) {
            if (identity == null || signature == null) {
                throw new S3ProxyException(S3ErrorCode.ACCESS_DENIED);
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
            throw new S3ProxyException(S3ErrorCode.INVALID_ARGUMENT, iae);
        }

        switch (authHeader.getAuthenticationType()) {
        case AWS_V2 -> {
            switch (authenticationType) {
            case AWS_V2, AWS_V2_OR_V4, NONE -> { }
            default -> throw new S3ProxyException(S3ErrorCode.ACCESS_DENIED);
            }
        }
        case AWS_V4 -> {
            switch (authenticationType) {
            case AWS_V4, AWS_V2_OR_V4, NONE -> { }
            default -> throw new S3ProxyException(S3ErrorCode.ACCESS_DENIED);
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
            String expectedSignature = HexFormat.of().formatHex(
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
    private static S3ProxyException multipartParseFailure(
            CompletionException ce) {
        Throwable cause = ce.getCause();
        if (cause instanceof IllegalStateException) {
            return new S3ProxyException(S3ErrorCode.MAX_MESSAGE_LENGTH_EXCEEDED,
                    cause);
        }
        return new S3ProxyException(S3ErrorCode.INVALID_REQUEST,
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
            throws IOException {
        if (checksum != null && checksumValue != null) {
            byte[] expected = checksum.decodeValue(checksumValue);
            SdkChecksum digest = checksum.newChecksum();
            digest.update(payload);
            byte[] actual = digest.getChecksumBytes();
            if (!java.util.Arrays.equals(expected, actual)) {
                throw new S3ProxyException(S3ErrorCode.BAD_DIGEST);
            }
        }

        var putRequest = PutObjectRequest.builder()
                .bucket(containerName)
                .key(blobName)
                .contentLength((long) payload.length);
        if (contentType != null) {
            putRequest.contentType(contentType);
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
            putRequest.metadata(userMetadata);
        }
        PutObjectResponse result = blobStore.putBlob(putRequest.build(),
                new ByteArrayInputStream(payload));

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
            throws IOException {
        String checksumAlgorithm = request.getHeader(
                AwsHttpHeaders.CHECKSUM_ALGORITHM);
        FlexChecksum mpuAlgorithm = null;
        if (checksumAlgorithm != null) {
            mpuAlgorithm = FlexChecksum.fromAlgorithmName(checksumAlgorithm);
            if (mpuAlgorithm == null) {
                throw new S3ProxyException(S3ErrorCode.INVALID_REQUEST,
                        "Checksum algorithm provided is unsupported.");
            }
        }
        String checksumType = request.getHeader(AwsHttpHeaders.CHECKSUM_TYPE);
        boolean fullObject = false;
        if (checksumType != null) {
            if (checksumType.equalsIgnoreCase("FULL_OBJECT")) {
                if (mpuAlgorithm == null || !mpuAlgorithm.supportsFullObject()) {
                    throw new S3ProxyException(S3ErrorCode.INVALID_REQUEST,
                            "The checksum type full_object is not supported" +
                            " for checksum algorithm " +
                            (mpuAlgorithm == null ? "null" :
                                    mpuAlgorithm.lower()) + ".");
                }
                fullObject = true;
            } else if (!checksumType.equalsIgnoreCase("COMPOSITE")) {
                throw new S3ProxyException(S3ErrorCode.INVALID_REQUEST,
                        "Checksum type provided is unsupported.");
            }
        }

        var contentHeaders = parseContentMetadata(request, null, null);
        var createRequest = CreateMultipartUploadRequest.builder()
                .bucket(containerName)
                .key(blobName)
                .cacheControl(contentHeaders.cacheControl())
                .contentDisposition(contentHeaders.contentDisposition())
                .contentEncoding(contentHeaders.contentEncoding())
                .contentLanguage(contentHeaders.contentLanguage())
                .contentType(contentHeaders.contentType())
                .expires(contentHeaders.expires())
                .metadata(contentHeaders.userMetadata());

        StorageClass parsedStorageClass = null;
        String storageClass = request.getHeader(AwsHttpHeaders.STORAGE_CLASS);
        if (storageClass == null || storageClass.equalsIgnoreCase("STANDARD")) {
            // defaults to STANDARD
        } else {
            try {
                parsedStorageClass = StorageClass.valueOf(storageClass);
                createRequest.storageClass(parsedStorageClass);
            } catch (IllegalArgumentException iae) {
                throw new S3ProxyException(S3ErrorCode.INVALID_STORAGE_CLASS, iae);
            }
        }

        String ifMatch = request.getHeader(HttpHeaders.IF_MATCH);
        String blobStoreType = getBlobStoreType(blobStore);

        // Azure only supports If-None-Match: *, not If-Match: *
        // Handle If-Match: * manually for the azureblob provider.
        // Note: this is a non-atomic operation (HEAD then PUT).
        if (ifMatch != null && ifMatch.equals("*") &&
                blobStoreType.equals("azureblob")) {
            if (blobStore.blobMetadata(containerName, blobName) == null) {
                throw new S3ProxyException(S3ErrorCode.NO_SUCH_KEY);
            }
        }

        ObjectCannedACL access;
        String cannedAcl = request.getHeader(AwsHttpHeaders.ACL);
        if (cannedAcl == null || cannedAcl.equalsIgnoreCase("private")) {
            access = ObjectCannedACL.PRIVATE;
        } else if (cannedAcl.equalsIgnoreCase("public-read")) {
            access = ObjectCannedACL.PUBLIC_READ;
        } else if (CANNED_ACLS.contains(cannedAcl)) {
            throw new S3ProxyException(S3ErrorCode.NOT_IMPLEMENTED);
        } else {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }
        if (access == ObjectCannedACL.PUBLIC_READ) {
            createRequest.acl(ObjectCannedACL.PUBLIC_READ);
        }

        MultipartUpload mpu = blobStore.initiateMultipartUpload(
                createRequest.build());

        if (Quirks.MULTIPART_REQUIRES_STUB.contains(getBlobStoreType(
                blobStore))) {
            var stubMetadata = new LinkedHashMap<>(
                    contentHeaders.userMetadata());
            if (fullObject) {
                // Remember the choice, since the completion request does not
                // reliably restate it and the two types are computed
                // differently.
                stubMetadata.put(CHECKSUM_TYPE_METADATA_KEY, FULL_OBJECT);
            }
            var stub = PutObjectRequest.builder()
                    .bucket(containerName)
                    .key(multipartStubName(mpu.id()))
                    .contentLength(0L)
                    .cacheControl(contentHeaders.cacheControl())
                    .contentDisposition(contentHeaders.contentDisposition())
                    .contentEncoding(contentHeaders.contentEncoding())
                    .contentLanguage(contentHeaders.contentLanguage())
                    .contentType(contentHeaders.contentType())
                    .expires(contentHeaders.expires())
                    .metadata(stubMetadata);
            if (parsedStorageClass != null) {
                stub.storageClass(parsedStorageClass);
            }
            if (access == ObjectCannedACL.PUBLIC_READ) {
                stub.acl(ObjectCannedACL.PUBLIC_READ);
            }
            blobStore.putBlob(stub.build(),
                    new ByteArrayInputStream(new byte[0]));
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
            String uploadId) throws IOException {
        // S3 rejects malformed checksum headers before considering their
        // meaning, even when the completion would fail for other reasons.
        validateChecksumHeaderValues(request);

        CompleteMultipartUploadRequest cmu = readXmlBody(
                is, CompleteMultipartUploadRequest.class);

        CreateMultipartUploadRequest carrierRequest;
        if (Quirks.MULTIPART_REQUIRES_STUB.contains(getBlobStoreType(
                blobStore))) {
            String stubName = multipartStubName(uploadId);
            HeadObjectResponse stubHead = blobStore.blobMetadata(
                    containerName, stubName);
            if (stubHead == null) {
                if (respondAlreadyCompleted(request, response, blobStore,
                        containerName, blobName, cmu)) {
                    return;
                }
                // the stub is the only record that the upload exists
                throw new S3ProxyException(S3ErrorCode.NO_SUCH_UPLOAD);
            }
            ObjectCannedACL access = blobStore.getBlobAccess(containerName,
                    stubName);
            carrierRequest = toCarrierRequest(containerName, blobName,
                    stubHead)
                    .acl(access)
                    .build();
        } else {
            carrierRequest = CreateMultipartUploadRequest.builder()
                    .bucket(containerName)
                    .key(blobName)
                    .build();
        }
        final MultipartUpload mpu = new MultipartUpload(uploadId,
                carrierRequest);

        final List<CompletedPart> parts = new ArrayList<>();
        var listedPartSizes = new HashMap<Integer, Long>();
        String blobStoreType = getBlobStoreType(blobStore);
        if (blobStoreType.equals("azureblob") ||
                blobStoreType.equals("google-cloud-storage")) {
            Map<Integer, Part> partsByListing;
            try {
                partsByListing =
                    blobStore.listMultipartUpload(mpu).stream().collect(
                            Collectors.toMap(
                                    part -> part.partNumber(),
                                    part -> part));
            } catch (NoSuchKeyException | NoSuchUploadException e) {
                // these backends recognize an upload id they never minted
                if (respondAlreadyCompleted(request, response, blobStore,
                        containerName, blobName, cmu)) {
                    return;
                }
                throw new S3ProxyException(S3ErrorCode.NO_SUCH_UPLOAD, e);
            }
            if (partsByListing.isEmpty()) {
                if (respondAlreadyCompleted(request, response, blobStore,
                        containerName, blobName, cmu)) {
                    return;
                }
                throw new S3ProxyException(S3ErrorCode.NO_SUCH_UPLOAD);
            }
            if (cmu.parts() != null) {
                // Sort by part number and deduplicate (last occurrence wins)
                // before validating, so a resent part is checked against the
                // ETag the client kept for its final upload.
                SortedMap<Integer, CompleteMultipartUploadRequest.Part>
                        requestParts = new TreeMap<>();
                for (CompleteMultipartUploadRequest.Part part : cmu.parts()) {
                    if (part.partNumber() < 1 || part.partNumber() > 10_000) {
                        throw new S3ProxyException(S3ErrorCode.INVALID_PART_ORDER,
                                "Part numbers must be positive integers.");
                    }
                    requestParts.put(part.partNumber(), part);
                }
                for (CompleteMultipartUploadRequest.Part part :
                        requestParts.values()) {
                    Part uploadedPart = partsByListing.get(
                            part.partNumber());
                    if (uploadedPart == null) {
                        throw new S3ProxyException(S3ErrorCode.INVALID_PART);
                    }
                    // Validate the client-supplied ETag against the uploaded
                    // part when the backend reports one (azureblob returns
                    // an empty ETag and is left unvalidated).
                    String uploadedETag = uploadedPart.eTag();
                    if (uploadedETag != null && !uploadedETag.isEmpty() &&
                            !equalsIgnoringSurroundingQuotes(
                                    uploadedETag, part.eTag())) {
                        throw new S3ProxyException(S3ErrorCode.INVALID_PART);
                    }
                    listedPartSizes.put(uploadedPart.partNumber(),
                            uploadedPart.size());
                    parts.add(CompletedPart.builder()
                            .partNumber(uploadedPart.partNumber())
                            .eTag(uploadedPart.eTag())
                            .build());
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
                throw new S3ProxyException(S3ErrorCode.NO_SUCH_UPLOAD);
            }
            // use TreeMap to sort by part number and deduplicate (last wins)
            SortedMap<Integer, String> requestParts = new TreeMap<>();
            if (cmu.parts() != null) {
                for (CompleteMultipartUploadRequest.Part part : cmu.parts()) {
                    if (part.partNumber() < 1 || part.partNumber() > 10_000) {
                        throw new S3ProxyException(S3ErrorCode.INVALID_PART_ORDER,
                                "Part numbers must be positive integers.");
                    }
                    requestParts.put(part.partNumber(), part.eTag());
                }
            }

            for (var it = requestParts.entrySet().iterator(); it.hasNext();) {
                var entry = it.next();
                Part part = partsByListing.get(entry.getKey());
                if (part == null) {
                    throw new S3ProxyException(S3ErrorCode.INVALID_PART);
                }
                Long partSize = part.size();
                if (it.hasNext() && partSize != null && partSize != -1 &&
                        (partSize < 5 * 1024 * 1024 || partSize <
                                blobStore.getMinimumMultipartPartSize())) {
                    throw new S3ProxyException(S3ErrorCode.ENTITY_TOO_SMALL);
                }
                if (part.eTag() != null &&
                        !equalsIgnoringSurroundingQuotes(part.eTag(),
                                entry.getValue())) {
                    throw new S3ProxyException(S3ErrorCode.INVALID_PART);
                }
                listedPartSizes.put(entry.getKey(), partSize);
                parts.add(CompletedPart.builder()
                        .partNumber(entry.getKey())
                        .eTag(part.eTag())
                        .build());
            }
        }

        if (parts.isEmpty()) {
            // Amazon requires at least one part
            throw new S3ProxyException(S3ErrorCode.MALFORMED_X_M_L);
        }

        // Hand the condition to the store, which resolves it as it publishes
        // the object.  Checking it here instead would only hold while nothing
        // else writes the same key, which is what the caller is guarding
        // against.  Stores that cannot answer at all say so.
        String ifMatch = request.getHeader(HttpHeaders.IF_MATCH);
        String ifNoneMatch = request.getHeader(HttpHeaders.IF_NONE_MATCH);
        if (ifMatch != null || ifNoneMatch != null) {
            if (!Quirks.NATIVE_CONDITIONAL_COMPLETE.contains(blobStoreType)) {
                throw new S3ProxyException(S3ErrorCode.NOT_IMPLEMENTED,
                        "Conditional writes are not supported by this" +
                        " backend.");
            }
            // S3 answers an If-Match naming a key that does not exist with
            // 404, where the stores report 412; settle that here, and once
            // existence is established If-Match: * asks nothing more.
            if (ifMatch != null) {
                if (!blobStore.blobExists(containerName, blobName)) {
                    throw new S3ProxyException(S3ErrorCode.NO_SUCH_KEY);
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
            mpuChecksum = computeMpuChecksum(request, cmu, mpuAlgorithm,
                    partChecksums, listedPartSizes,
                    fullObjectUpload(carrierRequest.metadata(), request,
                            mpuAlgorithm));
        }

        // Persist the composite checksum onto the final object for stub
        // backends, which build the completed blob's metadata from the
        // MultipartUpload passed to completeMultipartUpload.
        CreateMultipartUploadRequest completeCarrier = carrierRequest;
        if (mpuChecksum != null && requiresStub) {
            var userMetadata = new LinkedHashMap<>(carrierRequest.metadata());
            // the upload's bookkeeping does not belong on the object; the
            // stored value's shape already says which type it is
            userMetadata.remove(CHECKSUM_TYPE_METADATA_KEY);
            userMetadata.put(mpuChecksum.algorithm().metadataKey(),
                    mpuChecksum.value());
            completeCarrier = carrierRequest.toBuilder()
                    .metadata(userMetadata).build();
        }
        final MultipartUpload completeMpu = new MultipartUpload(uploadId,
                completeCarrier);

        // The condition rides on the completion request, since completion is
        // the write that has to honour it.
        final var sdkComplete = software.amazon.awssdk.services.s3.model.CompleteMultipartUploadRequest
                .builder()
                .bucket(containerName)
                .key(blobName)
                .uploadId(uploadId)
                .multipartUpload(CompletedMultipartUpload.builder()
                        .parts(parts)
                        .build())
                .ifMatch(completeIfMatch)
                .ifNoneMatch(completeIfNoneMatch)
                .build();

        // A conditional completion has to finish before anything is sent: the
        // store decides the outcome, and once the 200 and the XML prolog are
        // out the refusal can no longer be a status code.  That costs the
        // whitespace kept flowing during a slow completion, which matters
        // less than answering 412 where S3 answers 412.  A versioning store
        // completes synchronously for the same reason: the version it mints
        // is a response header, unsendable once the prolog is out.
        CompleteMultipartUploadResponse syncResult = null;
        if (completeIfMatch != null || completeIfNoneMatch != null ||
                blobStore.supportsVersioning()) {
            syncResult = blobStore.completeMultipartUpload(completeMpu,
                    sdkComplete);
            if (Quirks.MULTIPART_REQUIRES_STUB.contains(blobStoreType)) {
                blobStore.removeBlob(containerName,
                        multipartStubName(uploadId));
            }
        }
        final CompleteMultipartUploadResponse completedResult =
                syncResult;

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
            final var result =
                    new AtomicReference<@Nullable CompleteMultipartUploadResponse>(
                    completedResult);
            final AtomicReference<RuntimeException> exception =
                    new AtomicReference<>();
            var thread = new Thread() {
                @Override
                public void run() {
                    try {
                        result.set(blobStore.completeMultipartUpload(
                                completeMpu, sdkComplete));
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

            CompleteMultipartUploadResponse completed = result.get();
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
            HttpServletRequest request) {
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
                    throw new S3ProxyException(S3ErrorCode.INVALID_REQUEST,
                            "Value for " + checksum.header() +
                            " header is invalid.", nfe, Map.of());
                }
                if (count < 1 || count > 10_000) {
                    throw new S3ProxyException(S3ErrorCode.INVALID_REQUEST,
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
                byte[] digest = HexFormat.of().parseHex(eTag);
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
        HeadObjectResponse metadata = blobStore.blobMetadata(containerName,
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
        for (var entry : metadata.metadata().entrySet()) {
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
            CompleteMultipartUploadRequest cmu) {
        if (cmu.parts() == null) {
            return null;
        }
        FlexChecksum algorithm = null;
        for (CompleteMultipartUploadRequest.Part part : cmu.parts()) {
            for (FlexChecksum candidate : FlexChecksum.values()) {
                if (candidate.value(part) != null) {
                    if (algorithm != null && algorithm != candidate) {
                        throw new S3ProxyException(S3ErrorCode.INVALID_REQUEST,
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
            var blob = blobStore.getBlob(containerName,
                    AbstractNio2BlobStore.multipartPartName(uploadId,
                            blobName, partNumber));
            if (blob == null) {
                // a missing part is rejected elsewhere; fall back to the
                // client-asserted value
                continue;
            }
            SdkChecksum digest = algorithm.newChecksum();
            long length = 0;
            try (InputStream partIs = blob) {
                byte[] buffer = new byte[16384];
                while (true) {
                    int count = partIs.read(buffer);
                    if (count == -1) {
                        break;
                    }
                    digest.update(buffer, 0, count);
                    length += count;
                }
            }
            digests.put(partNumber, new PartChecksum(
                    digest.getChecksumBytes(), length));
        }
        return digests;
    }

    /**
     * Whether the upload asked for a checksum describing the whole object
     * rather than the parts.  The stub records the choice made at initiation;
     * backends without one have only the completion request to go on, where a
     * value carrying no "-<partCount>" suffix implies a full object.
     */
    private static boolean fullObjectUpload(
            Map<String, String> recordedMetadata,
            HttpServletRequest request, FlexChecksum algorithm) {
        if (!algorithm.supportsFullObject()) {
            return false;
        }
        String recorded = recordedMetadata.get(CHECKSUM_TYPE_METADATA_KEY);
        if (recorded != null) {
            return recorded.equals(FULL_OBJECT);
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
            Map<Integer, Long> partSizes, boolean fullObject) {
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
        SdkChecksum composite = algorithm.newChecksum();
        byte[] combined = null;
        for (var entry : sorted.entrySet()) {
            String value = algorithm.value(entry.getValue());
            if (value == null) {
                throw new S3ProxyException(S3ErrorCode.INVALID_REQUEST,
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
                composite.update(digest);
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
            computed = algorithm.encodeRaw(composite.getChecksumBytes()) +
                    "-" + sorted.size();
        }

        // If the client asserted the expected checksum on the completion
        // request, validate our computation against it.  Only a composite
        // carries the "-<partCount>" suffix; for a composite upload a bare
        // value in this header is the SDK's request-body integrity checksum,
        // which is unrelated to the completed object.
        String provided = request.getHeader(algorithm.header());
        if (provided != null && (fullObject || provided.indexOf('-') >= 0) &&
                !provided.equals(computed)) {
            throw new S3ProxyException(S3ErrorCode.BAD_DIGEST);
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

    // The suppliers are stateless singletons or method references; the
    // accumulators they hand out are the mutable part.
    @SuppressWarnings("ImmutableEnumChecker")
    enum FlexChecksum {
        CRC32("crc32", "ChecksumCRC32", AwsHttpHeaders.CHECKSUM_CRC32, 4,
                sdk(DefaultChecksumAlgorithm.CRC32), 0xedb88320L),
        CRC32C("crc32c", "ChecksumCRC32C", AwsHttpHeaders.CHECKSUM_CRC32C, 4,
                sdk(DefaultChecksumAlgorithm.CRC32C), 0x82f63b78L),
        // The SDK names CRC64NVME but computes it only through the optional
        // aws-crt native module; Crc64Nvme supplies it instead.
        CRC64NVME("crc64nvme", "ChecksumCRC64NVME",
                AwsHttpHeaders.CHECKSUM_CRC64NVME, 8,
                Crc64Nvme::new, 0x9a6c9329ac4bc9b5L),
        SHA1("sha1", "ChecksumSHA1", AwsHttpHeaders.CHECKSUM_SHA1, 20,
                sdk(DefaultChecksumAlgorithm.SHA1), 0),
        SHA256("sha256", "ChecksumSHA256", AwsHttpHeaders.CHECKSUM_SHA256, 32,
                sdk(DefaultChecksumAlgorithm.SHA256), 0);

        private final String lower;
        private final String element;
        private final String header;
        private final int length;
        private final Supplier<SdkChecksum> checksums;
        /** Reflected CRC polynomial, or zero for a hash that cannot combine. */
        private final long polynomial;

        FlexChecksum(String lower, String element, String header, int length,
                Supplier<SdkChecksum> checksums, long polynomial) {
            this.lower = lower;
            this.element = element;
            this.header = header;
            this.length = length;
            this.checksums = checksums;
            this.polynomial = polynomial;
        }

        private static Supplier<SdkChecksum> sdk(ChecksumAlgorithm algorithm) {
            return () -> SdkChecksum.forAlgorithm(algorithm);
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

        /**
         * A fresh accumulator for this algorithm.  Its getChecksumBytes
         * answers in the wire byte order S3 base64-encodes, for the CRCs as
         * well as the SHAs, so nothing downstream reorders bytes.
         */
        SdkChecksum newChecksum() {
            return checksums.get();
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

        /** Base64 of a digest already in AWS wire form. */
        String encodeRaw(byte[] digest) {
            return Base64.getEncoder().encodeToString(digest);
        }

        /**
         * Decode a client-asserted checksum value, rejecting values that are
         * not base64 of exactly this algorithm's digest length the way S3
         * does: 400 InvalidRequest rather than a digest mismatch.
         */
        byte[] decodeValue(String value) {
            byte[] decoded;
            try {
                decoded = Base64.getDecoder().decode(value);
            } catch (IllegalArgumentException iae) {
                throw new S3ProxyException(S3ErrorCode.BAD_DIGEST,
                        "Value for " + header + " header is invalid.", iae,
                        Map.of());
            }
            if (decoded.length != length) {
                throw new S3ProxyException(S3ErrorCode.BAD_DIGEST,
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
            String uploadId) throws IOException {
        if (Quirks.MULTIPART_REQUIRES_STUB.contains(getBlobStoreType(
                blobStore))) {
            String stubName = multipartStubName(uploadId);
            if (!blobStore.blobExists(containerName, stubName)) {
                throw new S3ProxyException(S3ErrorCode.NO_SUCH_UPLOAD);
            }

            blobStore.removeBlob(containerName, stubName);
        }

        addCorsResponseHeader(request, response);

        MultipartUpload mpu = reconstructedMpu(containerName, blobName,
                uploadId);
        try {
            blobStore.abortMultipartUpload(mpu);
        } catch (NoSuchKeyException | NoSuchUploadException e) {
            throw new S3ProxyException(S3ErrorCode.NO_SUCH_UPLOAD, e);
        }
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }

    private void handleListParts(HttpServletRequest request,
            HttpServletResponse response, BlobStore blobStore,
            String containerName, String blobName, String uploadId)
            throws IOException {
        // support only the no-op zero case
        String partNumberMarker = request.getParameter("part-number-marker");
        if (partNumberMarker != null && !partNumberMarker.equals("0")) {
            throw new S3ProxyException(S3ErrorCode.NOT_IMPLEMENTED);
        }

        MultipartUpload mpu = reconstructedMpu(containerName, blobName,
                uploadId);

        List<Part> parts = blobStore.listMultipartUpload(mpu);

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

            for (Part part : parts) {
                xml.writeStartElement("Part");

                writeSimpleElement(xml, "PartNumber", String.valueOf(
                        part.partNumber()));

                if (part.lastModified() != null) {
                    writeSimpleElement(xml, "LastModified",
                            formatDate(Date.from(part.lastModified())));
                }

                String eTag = part.eTag();
                if (eTag != null) {
                    writeSimpleElement(xml, "ETag", maybeQuoteETag(eTag));
                }

                writeSimpleElement(xml, "Size", String.valueOf(
                        part.size()));

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
            throws IOException {
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
            throw new S3ProxyException(S3ErrorCode.INVALID_REQUEST);
        }
        String sourceContainerName = path[0];
        String sourceBlobName = path[1];
        authorizeCopySource(requestIdentity, sourceContainerName,
                sourceBlobName);

        var getRequest = GetObjectRequest.builder()
                .bucket(sourceContainerName)
                .key(sourceBlobName)
                .versionId(sourceVersionId);
        String range = request.getHeader(AwsHttpHeaders.COPY_SOURCE_RANGE);
        String rawCopySourceRange = range;
        long expectedSize = -1;
        if (range != null) {
            if (!range.startsWith("bytes=") || range.indexOf(',') != -1 ||
                range.indexOf('-') == -1) {
                throw new S3ProxyException(S3ErrorCode.INVALID_ARGUMENT,
                    "The x-amz-copy-source-range value must be of the form " +
                    "bytes=first-last where first and last are the " +
                    "zero-based offsets of the first and last bytes to copy");
            }
            try {
                String[] ranges = range.substring("bytes=".length())
                        .split("-", 2);
                if (!ranges[0].isEmpty() && !ranges[1].isEmpty()) {
                    long start = Long.parseLong(ranges[0]);
                    long end = Long.parseLong(ranges[1]);
                    if (end < start) {
                        throw new S3ProxyException(S3ErrorCode.INVALID_RANGE);
                    }
                    expectedSize = end - start + 1;
                    if (expectedSize > MAX_MULTIPART_COPY_SIZE) {
                        throw new S3ProxyException(S3ErrorCode.INVALID_REQUEST,
                                "The specified copy source is larger than" +
                                " the maximum allowable size for a copy" +
                                " source: " + MAX_MULTIPART_COPY_SIZE);
                    }
                } else {
                    // parse for validation only
                    Long.parseLong(ranges[0].isEmpty() ?
                            ranges[1] : ranges[0]);
                }
                getRequest.range(range);
            } catch (NumberFormatException nfe) {
                throw new S3ProxyException(S3ErrorCode.INVALID_ARGUMENT,
                    "The x-amz-copy-source-range value must be of the form " +
                    "bytes=first-last where first and last are the " +
                    "zero-based offsets of the first and last bytes to copy",
                    nfe);
            }
        }

        String partNumberString = request.getParameter("partNumber");
        if (partNumberString == null) {
            throw new S3ProxyException(S3ErrorCode.INVALID_ARGUMENT);
        }
        int partNumber;
        try {
            partNumber = Integer.parseInt(partNumberString);
        } catch (NumberFormatException nfe) {
            throw new S3ProxyException(S3ErrorCode.INVALID_ARGUMENT,
                    "Part number must be an integer between 1 and 10000" +
                    ", inclusive", nfe, Map.of(
                            "ArgumentName", "partNumber",
                            "ArgumentValue", partNumberString));
        }
        if (partNumber < 1 || partNumber > 10_000) {
            throw new S3ProxyException(S3ErrorCode.INVALID_ARGUMENT,
                    "Part number must be an integer between 1 and 10000" +
                    ", inclusive", (Throwable) null, Map.of(
                            "ArgumentName", "partNumber",
                            "ArgumentValue", partNumberString));
        }

        MultipartUpload mpu = reconstructedMpu(containerName, blobName,
                uploadId);

        if (blobStore.supportsCopyMultipartPart()) {
            // Backends report overlong ranges inconsistently; enforce the
            // same InvalidRange semantics as the emulated path below, which
            // checks the size from getBlob's metadata.
            if (expectedSize != -1) {
                HeadObjectResponse sourceMetadata = blobStore.blobMetadata(
                        HeadObjectRequest.builder()
                                .bucket(sourceContainerName)
                                .key(sourceBlobName)
                                .versionId(sourceVersionId)
                                .build());
                if (sourceMetadata == null) {
                    throw new S3ProxyException(S3ErrorCode.NO_SUCH_KEY);
                }
                Long sourceSize = sourceMetadata.contentLength();
                if (sourceSize != null && sourceSize < expectedSize) {
                    throw new S3ProxyException(S3ErrorCode.INVALID_RANGE);
                }
            }
            long nativeIfModifiedSince = request.getDateHeader(
                    AwsHttpHeaders.COPY_SOURCE_IF_MODIFIED_SINCE);
            long nativeIfUnmodifiedSince = request.getDateHeader(
                    AwsHttpHeaders.COPY_SOURCE_IF_UNMODIFIED_SINCE);
            var partCopyRequest = UploadPartCopyRequest.builder()
                    .sourceBucket(sourceContainerName)
                    .sourceKey(sourceBlobName)
                    .sourceVersionId(sourceVersionId)
                    .destinationBucket(containerName)
                    .destinationKey(blobName)
                    .uploadId(uploadId)
                    .partNumber(partNumber)
                    .copySourceRange(rawCopySourceRange)
                    .copySourceIfMatch(request.getHeader(
                            AwsHttpHeaders.COPY_SOURCE_IF_MATCH))
                    .copySourceIfNoneMatch(request.getHeader(
                            AwsHttpHeaders.COPY_SOURCE_IF_NONE_MATCH))
                    .copySourceIfModifiedSince(nativeIfModifiedSince == -1 ?
                            null : Instant.ofEpochMilli(nativeIfModifiedSince))
                    .copySourceIfUnmodifiedSince(
                            nativeIfUnmodifiedSince == -1 ? null :
                            Instant.ofEpochMilli(nativeIfUnmodifiedSince))
                    .build();
            UploadPartCopyResponse part;
            try {
                part = blobStore.copyMultipartPart(mpu, partCopyRequest);
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

        var blob = blobStore.getBlob(getRequest.build());
        if (blob == null) {
            throw new S3ProxyException(S3ErrorCode.NO_SUCH_KEY);
        }

        GetObjectResponse blobMetadata = blob.response();
        String eTag = blobMetadata.eTag();
        Date lastModified = blobMetadata.lastModified() == null ? null :
                Date.from(blobMetadata.lastModified());
        try {
            // HTTP GET allow overlong ranges but S3 CopyPart does not
            Long size = blobMetadata.contentLength();
            if (expectedSize != -1 && size != null && size < expectedSize) {
                throw new S3ProxyException(S3ErrorCode.INVALID_RANGE);
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
                    throw new S3ProxyException(S3ErrorCode.PRECONDITION_FAILED);
                }
                if (ifNoneMatch != null && ifNoneMatch.equals(eTag)) {
                    throw new S3ProxyException(S3ErrorCode.PRECONDITION_FAILED);
                }
            }

            if (lastModified != null) {
                if (ifModifiedSince != -1 && lastModified.compareTo(
                        new Date(ifModifiedSince)) <= 0) {
                    throw new S3ProxyException(S3ErrorCode.PRECONDITION_FAILED);
                }
                if (ifUnmodifiedSince != -1 && lastModified.compareTo(
                        new Date(ifUnmodifiedSince)) > 0) {
                    throw new S3ProxyException(S3ErrorCode.PRECONDITION_FAILED);
                }
            }
        } catch (S3ProxyException se) {
            // A precondition failure here would otherwise leak the source
            // payload's open backend stream; the happy-path try-with-resources
            // below closes it only once reached.
            try {
                blob.close();
            } catch (IOException ioe) {
                // The stream is being abandoned; ignore close failures.
            }
            throw se;
        }

        long contentLength = requireNonNull(blobMetadata.contentLength());

        try (InputStream is = blob) {
            UploadPartResponse part = blobStore.uploadMultipartPart(mpu,
                    partNumber, is, contentLength, null);
            eTag = part.eTag();
        }

        writeCopyPartResponse(request, response,
                SdkResponses.copiedPart(eTag, lastModified,
                        blobMetadata.versionId()));
    }

    private void writeCopyPartResponse(HttpServletRequest request,
            HttpServletResponse response, UploadPartCopyResponse part)
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

            var result = part.copyPartResult();
            if (result != null && result.lastModified() != null) {
                writeSimpleElement(xml, "LastModified",
                        formatDate(Date.from(result.lastModified())));
            }
            String eTag = result == null ? null : result.eTag();
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
            throws IOException {
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
                throw new S3ProxyException(S3ErrorCode.INVALID_DIGEST, iae);
            }
            if (contentMD5.bits() != MD5.bits()) {
                throw new S3ProxyException(S3ErrorCode.INVALID_DIGEST);
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
            throw new S3ProxyException(S3ErrorCode.INVALID_ARGUMENT, nfe);
        }
        if (contentLength < 0) {
            throw new S3ProxyException(S3ErrorCode.INVALID_ARGUMENT);
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
            throw new S3ProxyException(S3ErrorCode.INVALID_ARGUMENT);
        }
        int partNumber;
        try {
            partNumber = Integer.parseInt(partNumberString);
        } catch (NumberFormatException nfe) {
            throw new S3ProxyException(S3ErrorCode.INVALID_ARGUMENT,
                    "Part number must be an integer between 1 and 10000" +
                    ", inclusive", nfe, Map.of(
                            "ArgumentName", "partNumber",
                            "ArgumentValue", partNumberString));
        }
        if (partNumber < 1 || partNumber > 10_000) {
            throw new S3ProxyException(S3ErrorCode.INVALID_ARGUMENT,
                    "Part number must be an integer between 1 and 10000" +
                    ", inclusive", (Throwable) null, Map.of(
                            "ArgumentName", "partNumber",
                            "ArgumentValue", partNumberString));
        }

        MultipartUpload mpu = reconstructedMpu(containerName, blobName,
                uploadId);

        UploadPartResponse part = blobStore.uploadMultipartPart(mpu,
                partNumber, is, contentLength, contentMD5);

        if (part.eTag() != null) {
            response.addHeader(HttpHeaders.ETAG,
                    maybeQuoteETag(part.eTag()));
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

    @SuppressWarnings("deprecation")
    private static void addMetadataToResponse(HttpServletRequest request,
            HttpServletResponse response,
            HeadObjectResponse metadata,
            boolean partialContent) {
        addResponseHeaderWithOverride(request, response,
                HttpHeaders.CACHE_CONTROL, "response-cache-control",
                metadata.cacheControl());
        addResponseHeaderWithOverride(request, response,
                HttpHeaders.CONTENT_ENCODING, "response-content-encoding",
                metadata.contentEncoding());
        addResponseHeaderWithOverride(request, response,
                HttpHeaders.CONTENT_LANGUAGE, "response-content-language",
                metadata.contentLanguage());
        addResponseHeaderWithOverride(request, response,
                HttpHeaders.CONTENT_DISPOSITION, "response-content-disposition",
                metadata.contentDisposition());
        Long contentLength = metadata.contentLength();
        if (contentLength != null) {
            response.addHeader(HttpHeaders.CONTENT_LENGTH,
                    contentLength.toString());
        }
        String overrideContentType = request.getParameter(
                "response-content-type");
        String contentType = overrideContentType != null ?
                overrideContentType : metadata.contentType();
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
            var expires = metadata.expires();
            if (expires != null) {
                response.addDateHeader(HttpHeaders.EXPIRES,
                        expires.toEpochMilli());
            }
        }
        var lastModified = metadata.lastModified();
        if (lastModified != null) {
            response.addDateHeader(HttpHeaders.LAST_MODIFIED,
                    lastModified.toEpochMilli());
        }
        String versionId = metadata.versionId();
        if (versionId != null) {
            response.addHeader(AwsHttpHeaders.VERSION_ID, versionId);
        }
        String storageClass = metadata.storageClassAsString();
        if (storageClass != null) {
            response.addHeader(AwsHttpHeaders.STORAGE_CLASS, storageClass);
        }
        FlexChecksum storedChecksum = null;
        String storedChecksumValue = null;
        for (var entry : metadata.metadata().entrySet()) {
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
            long date, boolean isPresigned) {
        if (date < 0) {
            throw new S3ProxyException(S3ErrorCode.ACCESS_DENIED);
        }
        long now = System.currentTimeMillis() / 1000;
        if (isPresigned) {
            if (now + maximumTimeSkew < date) {
                logger.debug("request is not valid yet {} {}", date, now);
                throw new S3ProxyException(S3ErrorCode.ACCESS_DENIED);
            }
        } else {
            if (now + maximumTimeSkew < date || now - maximumTimeSkew > date) {
                logger.debug("time skewed {} {}", date, now);
                throw new S3ProxyException(S3ErrorCode.REQUEST_TIME_TOO_SKEWED);
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
        sendSimpleErrorResponse(request, response, code.getErrorCode(),
                code.getHttpStatusCode(), message, elements);
    }

    /**
     * Renders an S3 error document from a raw error code and status, e.g.
     * one a backend's service reported, which need not name an {@link
     * S3ErrorCode} entry.
     */
    protected final void sendSimpleErrorResponse(
            HttpServletRequest request, HttpServletResponse response,
            String code, int httpStatusCode, String message,
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
        if (code.equals(S3ErrorCode.BAD_DIGEST.getErrorCode()) ||
                code.equals(S3ErrorCode.INVALID_DIGEST.getErrorCode()) ||
                code.equals(S3ErrorCode.INVALID_REQUEST.getErrorCode()) ||
                code.equals(S3ErrorCode.MAX_MESSAGE_LENGTH_EXCEEDED
                        .getErrorCode()) ||
                code.equals(S3ErrorCode.X_AMZ_CONTENT_S_H_A_256_MISMATCH
                        .getErrorCode())) {
            response.setHeader(HttpHeaders.CONNECTION, "close");
        }

        // A read that found nothing missed an absent object rather than a
        // delete marker; no unversioned key resolves to one.  Set this
        // centrally because some backends raise NoSuchKey from the blobstore
        // instead of reporting absence.  A versioning backend that did find
        // a marker has already said so; do not contradict it.
        if (code.equals(S3ErrorCode.NO_SUCH_KEY.getErrorCode()) &&
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

        response.setStatus(httpStatusCode);

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

            writeSimpleElement(xml, "Code", code);
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

    /** The content headers and x-amz-meta-* pairs a write request carries. */
    private record RequestContentMetadata(
            Map<String, String> userMetadata,
            @Nullable String cacheControl,
            @Nullable String contentDisposition,
            @Nullable String contentEncoding,
            @Nullable String contentLanguage,
            @Nullable String contentType,
            @Nullable Instant expires) {
    }

    private static RequestContentMetadata parseContentMetadata(
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
        long expires = request.getDateHeader(HttpHeaders.EXPIRES);
        return new RequestContentMetadata(
                userMetadata.build(),
                request.getHeader(HttpHeaders.CACHE_CONTROL),
                request.getHeader(HttpHeaders.CONTENT_DISPOSITION),
                contentEncoding,
                request.getHeader(HttpHeaders.CONTENT_LANGUAGE),
                request.getContentType(),
                expires == -1 ? null : Instant.ofEpochMilli(expires));
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

    private static void writeAllUsersGrant(XMLStreamWriter xml,
            String permission) throws XMLStreamException {
        xml.writeStartElement("Grant");

        xml.writeStartElement("Grantee");
        xml.writeNamespace("xsi", "http://www.w3.org/2001/XMLSchema-instance");
        xml.writeAttribute("xsi:type", "Group");

        writeSimpleElement(xml, "URI",
                "http://acs.amazonaws.com/groups/global/AllUsers");

        xml.writeEndElement();

        writeSimpleElement(xml, "Permission", permission);

        xml.writeEndElement();
    }

    private static void writeSimpleElement(XMLStreamWriter xml,
            String elementName, String characters) throws XMLStreamException {
        xml.writeStartElement(elementName);
        xml.writeCharacters(characters);
        xml.writeEndElement();
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
    private static void checkConditionalWrite(
            @Nullable HeadObjectResponse metadata,
            @Nullable String ifMatch, @Nullable String ifNoneMatch) {
        if (ifMatch != null) {
            if (metadata == null) {
                throw new S3ProxyException(S3ErrorCode.NO_SUCH_KEY);
            }
            if (!ifMatch.equals("*")) {
                String eTag = metadata.eTag();
                if (eTag == null || !equalsIgnoringSurroundingQuotes(ifMatch,
                        maybeQuoteETag(eTag))) {
                    throw new S3ProxyException(S3ErrorCode.PRECONDITION_FAILED);
                }
            }
        }

        if (ifNoneMatch != null && metadata != null) {
            if (ifNoneMatch.equals("*")) {
                throw new S3ProxyException(S3ErrorCode.PRECONDITION_FAILED);
            }
            String eTag = metadata.eTag();
            if (eTag != null && equalsIgnoringSurroundingQuotes(ifNoneMatch,
                    maybeQuoteETag(eTag))) {
                throw new S3ProxyException(S3ErrorCode.PRECONDITION_FAILED);
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
            InputStream is) throws IOException {
        String transferEncoding = request.getHeader(
                HttpHeaders.TRANSFER_ENCODING);
        if (transferEncoding == null ||
                !transferEncoding.toLowerCase().contains("chunked")) {
            throw new S3ProxyException(S3ErrorCode.MISSING_CONTENT_LENGTH);
        }
        byte[] body = ByteStreams.limit(is, v4MaxNonChunkedRequestSize + 1)
                .readAllBytes();
        if (body.length == v4MaxNonChunkedRequestSize + 1) {
            throw new S3ProxyException(S3ErrorCode.MAX_MESSAGE_LENGTH_EXCEEDED);
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
    private static void checkPresignedExpiry(HttpServletRequest request) {
        String expiresString = request.getParameter("Expires");
        if (expiresString != null) { // v2 query
            long expires;
            try {
                expires = Long.parseLong(expiresString);
            } catch (NumberFormatException nfe) {
                throw new S3ProxyException(S3ErrorCode.ACCESS_DENIED, nfe);
            }
            long nowSeconds = System.currentTimeMillis() / 1000;
            if (nowSeconds >= expires) {
                throw new S3ProxyException(S3ErrorCode.ACCESS_DENIED,
                        "Request has expired");
            }
            if (expires - nowSeconds > TimeUnit.DAYS.toSeconds(365)) {
                throw new S3ProxyException(S3ErrorCode.ACCESS_DENIED);
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
                throw new S3ProxyException(S3ErrorCode.ACCESS_DENIED, iae);
            }
            long nowSeconds = System.currentTimeMillis() / 1000;
            if (nowSeconds >= date + expires) {
                throw new S3ProxyException(S3ErrorCode.ACCESS_DENIED,
                        "Request has expired");
            }
            if (expires > TimeUnit.DAYS.toSeconds(7)) {
                throw new S3ProxyException(S3ErrorCode.ACCESS_DENIED);
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
    private static S3ProxyException signatureDoesNotMatch(
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
        return new S3ProxyException(S3ErrorCode.SIGNATURE_DOES_NOT_MATCH,
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
