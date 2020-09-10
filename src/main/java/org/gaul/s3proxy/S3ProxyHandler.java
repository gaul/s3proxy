/*
 * Copyright 2014-2020 Andrew Gaul <andrew@gaul.org>
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
import java.io.ByteArrayOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.PushbackInputStream;
import java.io.Writer;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.AccessDeniedException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedMap;
import java.util.TimeZone;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import javax.annotation.Nullable;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.dataformat.xml.XmlMapper;
import com.google.common.base.CharMatcher;
import com.google.common.base.Optional;
import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Iterables;
import com.google.common.collect.Maps;
import com.google.common.escape.Escaper;
import com.google.common.hash.HashCode;
import com.google.common.hash.HashFunction;
import com.google.common.hash.Hashing;
import com.google.common.hash.HashingInputStream;
import com.google.common.io.BaseEncoding;
import com.google.common.io.ByteSource;
import com.google.common.io.ByteStreams;
import com.google.common.net.HostAndPort;
import com.google.common.net.HttpHeaders;
import com.google.common.net.PercentEscaper;

import org.apache.commons.fileupload.MultipartStream;
import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.KeyNotFoundException;
import org.jclouds.blobstore.domain.Blob;
import org.jclouds.blobstore.domain.BlobAccess;
import org.jclouds.blobstore.domain.BlobBuilder;
import org.jclouds.blobstore.domain.BlobMetadata;
import org.jclouds.blobstore.domain.ContainerAccess;
import org.jclouds.blobstore.domain.MultipartPart;
import org.jclouds.blobstore.domain.MultipartUpload;
import org.jclouds.blobstore.domain.PageSet;
import org.jclouds.blobstore.domain.StorageMetadata;
import org.jclouds.blobstore.domain.Tier;
import org.jclouds.blobstore.domain.internal.MutableBlobMetadataImpl;
import org.jclouds.blobstore.options.CopyOptions;
import org.jclouds.blobstore.options.CreateContainerOptions;
import org.jclouds.blobstore.options.GetOptions;
import org.jclouds.blobstore.options.ListContainerOptions;
import org.jclouds.blobstore.options.PutOptions;
import org.jclouds.domain.Location;
import org.jclouds.io.ContentMetadata;
import org.jclouds.io.ContentMetadataBuilder;
import org.jclouds.io.Payload;
import org.jclouds.io.Payloads;
import org.jclouds.rest.AuthorizationException;
import org.jclouds.s3.domain.ObjectMetadata.StorageClass;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** HTTP server-independent handler for S3 requests. */
public class S3ProxyHandler {
    private static final Logger logger = LoggerFactory.getLogger(
            S3ProxyHandler.class);
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
    private static final String FAKE_REQUEST_ID = "4442587FB7D0A2F9";
    private static final CharMatcher VALID_BUCKET_FIRST_CHAR =
            CharMatcher.inRange('a', 'z')
                    .or(CharMatcher.inRange('A', 'Z'))
                    .or(CharMatcher.inRange('0', '9'));
    private static final CharMatcher VALID_BUCKET =
            VALID_BUCKET_FIRST_CHAR
                    .or(CharMatcher.is('.'))
                    .or(CharMatcher.is('_'))
                    .or(CharMatcher.is('-'));
    private static final Set<String> UNSUPPORTED_PARAMETERS = ImmutableSet.of(
            "accelerate",
            "analytics",
            "cors",
            "inventory",
            "lifecycle",
            "logging",
            "metrics",
            "notification",
            "replication",
            "requestPayment",
            "restore",
            "tagging",
            "torrent",
            "versioning",
            "versions",
            "website"
    );
    /** All supported x-amz- headers, except for x-amz-meta- user metadata. */
    private static final Set<String> SUPPORTED_X_AMZ_HEADERS = ImmutableSet.of(
            AwsHttpHeaders.ACL,
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
            AwsHttpHeaders.STORAGE_CLASS
    );
    private static final Set<String> CANNED_ACLS = ImmutableSet.of(
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
    /** URLEncoder escapes / which we do not want. */
    private static final Escaper urlEscaper = new PercentEscaper(
            "*-./_", /*plusForSpace=*/ false);
    @SuppressWarnings("deprecation")
    private static final HashFunction MD5 = Hashing.md5();

    private final boolean anonymousIdentity;
    private final AuthenticationType authenticationType;
    private final Optional<String> virtualHost;
    private final long v4MaxNonChunkedRequestSize;
    private final boolean ignoreUnknownHeaders;
    private final CrossOriginResourceSharing corsRules;
    private final String servicePath;
    private final int maximumTimeSkew;
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
            .expireAfterWrite(10, TimeUnit.MINUTES)
            .build();

    public S3ProxyHandler(final BlobStore blobStore,
            AuthenticationType authenticationType, final String identity,
            final String credential, @Nullable String virtualHost,
            long v4MaxNonChunkedRequestSize, boolean ignoreUnknownHeaders,
            CrossOriginResourceSharing corsRules, final String servicePath,
            int maximumTimeSkew) {
        if (authenticationType != AuthenticationType.NONE) {
            anonymousIdentity = false;
            blobStoreLocator = new BlobStoreLocator() {
                @Nullable
                @Override
                public Map.Entry<String, BlobStore> locateBlobStore(
                        String identityArg, String container, String blob) {
                    if (!identity.equals(identityArg)) {
                        return null;
                    }
                    return Maps.immutableEntry(credential, blobStore);
                }
            };
        } else {
            anonymousIdentity = true;
            final Map.Entry<String, BlobStore> anonymousBlobStore =
                    Maps.immutableEntry(null, blobStore);
            blobStoreLocator = new BlobStoreLocator() {
                @Override
                public Map.Entry<String, BlobStore> locateBlobStore(
                        String identityArg, String container, String blob) {
                    return anonymousBlobStore;
                }
            };
        }
        this.authenticationType = authenticationType;
        this.virtualHost = Optional.fromNullable(virtualHost);
        this.v4MaxNonChunkedRequestSize = v4MaxNonChunkedRequestSize;
        this.ignoreUnknownHeaders = ignoreUnknownHeaders;
        this.corsRules = corsRules;
        this.defaultBlobStore = blobStore;
        xmlOutputFactory.setProperty("javax.xml.stream.isRepairingNamespaces",
                Boolean.FALSE);
        this.servicePath = Strings.nullToEmpty(servicePath);
        this.maximumTimeSkew = maximumTimeSkew;
    }

    private static String getBlobStoreType(BlobStore blobStore) {
        return blobStore.getContext().unwrap().getProviderMetadata().getId();
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
            InputStream is) throws IOException, S3Exception {
        String method = request.getMethod();
        String uri = request.getRequestURI();
        String originalUri = request.getRequestURI();

        if (!this.servicePath.isEmpty()) {
            if (uri.length() > this.servicePath.length()) {
                uri = uri.substring(this.servicePath.length());
            }
        }

        logger.debug("request: {}", request);
        String hostHeader = request.getHeader(HttpHeaders.HOST);
        if (hostHeader != null && virtualHost.isPresent()) {
            hostHeader = HostAndPort.fromString(hostHeader).getHost();
            String virtualHostSuffix = "." + virtualHost.get();
            if (!hostHeader.equals(virtualHost.get())) {
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

        // TODO: fake
        response.addHeader(AwsHttpHeaders.REQUEST_ID, FAKE_REQUEST_ID);

        boolean hasDateHeader = false;
        boolean hasXAmzDateHeader = false;
        for (String headerName : Collections.list(request.getHeaderNames())) {
            for (String headerValue : Collections.list(request.getHeaders(
                    headerName))) {
                logger.debug("header: {}: {}", headerName,
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
            doHandleAnonymous(request, response, is, uri, defaultBlobStore);
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
            if (headerAuthorization == null) {
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
            }

            try {
                authHeader = new S3AuthorizationHeader(headerAuthorization);
                //whether v2 or v4 (normal header and query)
            } catch (IllegalArgumentException iae) {
                throw new S3Exception(S3ErrorCode.INVALID_ARGUMENT, iae);
            }
            requestIdentity = authHeader.identity;
        }

        long dateSkew = 0; //date for timeskew check

        //v2 GET /s3proxy-1080747708/foo?AWSAccessKeyId=local-identity&Expires=
        //1510322602&Signature=UTyfHY1b1Wgr5BFEn9dpPlWdtFE%3D)
        //have no date

        if (!anonymousIdentity) {
            boolean haveDate = true;

            AuthenticationType finalAuthType = null;
            if (authHeader.authenticationType == AuthenticationType.AWS_V2 &&
                    (authenticationType == AuthenticationType.AWS_V2 ||
                    authenticationType == AuthenticationType.AWS_V2_OR_V4)) {
                finalAuthType = AuthenticationType.AWS_V2;
            } else if (
                authHeader.authenticationType == AuthenticationType.AWS_V4 &&
                        (authenticationType == AuthenticationType.AWS_V4 ||
                    authenticationType == AuthenticationType.AWS_V2_OR_V4)) {
                finalAuthType = AuthenticationType.AWS_V4;
            } else if (authenticationType != AuthenticationType.NONE) {
                throw new S3Exception(S3ErrorCode.ACCESS_DENIED);
            }

            if (hasXAmzDateHeader) { //format diff between v2 and v4
                if (finalAuthType == AuthenticationType.AWS_V2) {
                    dateSkew = request.getDateHeader(AwsHttpHeaders.DATE);
                    dateSkew /= 1000;
                    //case sensetive?
                } else if (finalAuthType == AuthenticationType.AWS_V4) {
                    dateSkew = parseIso8601(request.getHeader(
                            AwsHttpHeaders.DATE));
                }
            } else if (request.getParameter("X-Amz-Date") != null) { // v4 query
                String dateString = request.getParameter("X-Amz-Date");
                dateSkew = parseIso8601(dateString);
            } else if (hasDateHeader) {
                try {
                    dateSkew = request.getDateHeader(HttpHeaders.DATE);
                } catch (IllegalArgumentException iae) {
                    throw new S3Exception(S3ErrorCode.ACCESS_DENIED, iae);
                }
                dateSkew /= 1000;

            } else {
                haveDate = false;
            }
            if (haveDate) {
                isTimeSkewed(dateSkew);
            }
        }


        String[] path = uri.split("/", 3);
        for (int i = 0; i < path.length; i++) {
            path[i] = URLDecoder.decode(path[i], UTF_8);
        }

        Map.Entry<String, BlobStore> provider =
                blobStoreLocator.locateBlobStore(
                        requestIdentity, path.length > 1 ? path[1] : null,
                        path.length > 2 ? path[2] : null);
        if (anonymousIdentity) {
            blobStore = provider.getValue();
            String contentSha256 = request.getHeader(
                    AwsHttpHeaders.CONTENT_SHA256);
            if ("STREAMING-AWS4-HMAC-SHA256-PAYLOAD".equals(contentSha256)) {
                is = new ChunkedInputStream(is);
            }
        } else if (requestIdentity == null) {
            throw new S3Exception(S3ErrorCode.ACCESS_DENIED);
        } else {
            if (provider == null) {
                throw new S3Exception(S3ErrorCode.INVALID_ACCESS_KEY_ID);
            }

            String credential = provider.getKey();
            blobStore = provider.getValue();

            String expiresString = request.getParameter("Expires");
            if (expiresString != null) { // v2 query
                long expires = Long.parseLong(expiresString);
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
                long date = parseIso8601(dateString);
                long expires = Long.parseLong(expiresString);
                long nowSeconds = System.currentTimeMillis() / 1000;
                if (nowSeconds >= date + expires) {
                    throw new S3Exception(S3ErrorCode.ACCESS_DENIED,
                            "Request has expired");
                }
                if (expires > TimeUnit.DAYS.toSeconds(7)) {
                    throw new S3Exception(S3ErrorCode.ACCESS_DENIED);
                }
            }
            // The aim ?
            switch (authHeader.authenticationType) {
            case AWS_V2:
                switch (authenticationType) {
                case AWS_V2:
                case AWS_V2_OR_V4:
                case NONE:
                    break;
                default:
                    throw new S3Exception(S3ErrorCode.ACCESS_DENIED);
                }
                break;
            case AWS_V4:
                switch (authenticationType) {
                case AWS_V4:
                case AWS_V2_OR_V4:
                case NONE:
                    break;
                default:
                    throw new S3Exception(S3ErrorCode.ACCESS_DENIED);
                }
                break;
            case NONE:
                break;
            default:
                throw new IllegalArgumentException("Unhandled type: " +
                        authHeader.authenticationType);
            }

            String expectedSignature = null;

            if (authHeader.hmacAlgorithm == null) { //v2
                // When presigned url is generated, it doesn't consider
                // service path
                String uriForSigning = presignedUrl ? uri : this.servicePath +
                        uri;
                expectedSignature = AwsSignature.createAuthorizationSignature(
                        request, uriForSigning, credential, presignedUrl,
                        haveBothDateHeader);
            } else {
                String contentSha256 = request.getHeader(
                        AwsHttpHeaders.CONTENT_SHA256);
                try {
                    byte[] payload;
                    if (request.getParameter("X-Amz-Algorithm") != null) {
                        payload = new byte[0];
                    } else if ("STREAMING-AWS4-HMAC-SHA256-PAYLOAD".equals(
                            contentSha256)) {
                        payload = new byte[0];
                        is = new ChunkedInputStream(is);
                    } else if ("UNSIGNED-PAYLOAD".equals(contentSha256)) {
                        payload = new byte[0];
                    } else {
                        // buffer the entire stream to calculate digest
                        // why input stream read contentlength of header?
                        payload = ByteStreams.toByteArray(ByteStreams.limit(
                                is, v4MaxNonChunkedRequestSize + 1));
                        if (payload.length == v4MaxNonChunkedRequestSize + 1) {
                            throw new S3Exception(
                                    S3ErrorCode.MAX_MESSAGE_LENGTH_EXCEEDED);
                        }

                        // maybe we should check this when signing,
                        // a lot of dup code with aws sign code.
                        MessageDigest md = MessageDigest.getInstance(
                            authHeader.hashAlgorithm);
                        byte[] hash = md.digest(payload);
                        if  (!contentSha256.equals(
                              BaseEncoding.base16().lowerCase()
                              .encode(hash))) {
                            throw new S3Exception(
                                    S3ErrorCode
                                    .X_AMZ_CONTENT_S_H_A_256_MISMATCH);
                        }
                        is = new ByteArrayInputStream(payload);
                    }

                    String uriForSigning = presignedUrl ? originalUri :
                            this.servicePath + originalUri;
                    expectedSignature = AwsSignature
                            .createAuthorizationSignatureV4(// v4 sign
                            baseRequest, authHeader, payload, uriForSigning,
                            credential);
                } catch (InvalidKeyException | NoSuchAlgorithmException e) {
                    throw new S3Exception(S3ErrorCode.INVALID_ARGUMENT, e);
                }
            }

            if (!constantTimeEquals(expectedSignature, authHeader.signature)) {
                throw new S3Exception(S3ErrorCode.SIGNATURE_DOES_NOT_MATCH);
            }
        }

        for (String parameter : Collections.list(
                request.getParameterNames())) {
            if (UNSUPPORTED_PARAMETERS.contains(parameter)) {
                logger.error("Unknown parameters {} with URI {}",
                        parameter, request.getRequestURI());
                throw new S3Exception(S3ErrorCode.NOT_IMPLEMENTED);
            }
        }

        // emit NotImplemented for unknown x-amz- headers
        for (String headerName : Collections.list(request.getHeaderNames())) {
            if (ignoreUnknownHeaders) {
                continue;
            }
            if (!headerName.startsWith("x-amz-")) {
                continue;
            }
            if (headerName.startsWith(USER_METADATA_PREFIX)) {
                continue;
            }
            if (!SUPPORTED_X_AMZ_HEADERS.contains(headerName.toLowerCase())) {
                logger.error("Unknown header {} with URI {}",
                        headerName, request.getRequestURI());
                throw new S3Exception(S3ErrorCode.NOT_IMPLEMENTED);
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

        String uploadId = request.getParameter("uploadId");
        switch (method) {
        case "DELETE":
            if (path.length <= 2 || path[2].isEmpty()) {
                handleContainerDelete(response, blobStore, path[1]);
                return;
            } else if (uploadId != null) {
                handleAbortMultipartUpload(request, response, blobStore,
                        path[1], path[2], uploadId);
                return;
            } else {
                handleBlobRemove(response, blobStore, path[1], path[2]);
                return;
            }
        case "GET":
            if (uri.equals("/")) {
                handleContainerList(response, blobStore);
                return;
            } else if (path.length <= 2 || path[2].isEmpty()) {
                if ("".equals(request.getParameter("acl"))) {
                    handleGetContainerAcl(response, blobStore, path[1]);
                    return;
                } else if ("".equals(request.getParameter("location"))) {
                    handleContainerLocation(response);
                    return;
                } else if ("".equals(request.getParameter("policy"))) {
                    handleBucketPolicy(blobStore, path[1]);
                    return;
                } else if ("".equals(request.getParameter("uploads"))) {
                    handleListMultipartUploads(request, response, blobStore,
                            path[1]);
                    return;
                }
                handleBlobList(request, response, blobStore, path[1]);
                return;
            } else {
                if ("".equals(request.getParameter("acl"))) {
                    handleGetBlobAcl(response, blobStore, path[1],
                            path[2]);
                    return;
                } else if (uploadId != null) {
                    handleListParts(request, response, blobStore, path[1],
                            path[2], uploadId);
                    return;
                }
                handleGetBlob(request, response, blobStore, path[1],
                        path[2]);
                return;
            }
        case "HEAD":
            if (path.length <= 2 || path[2].isEmpty()) {
                handleContainerExists(blobStore, path[1]);
                return;
            } else {
                handleBlobMetadata(request, response, blobStore, path[1],
                        path[2]);
                return;
            }
        case "POST":
            if ("".equals(request.getParameter("delete"))) {
                handleMultiBlobRemove(response, is, blobStore, path[1]);
                return;
            } else if ("".equals(request.getParameter("uploads"))) {
                handleInitiateMultipartUpload(request, response, blobStore,
                        path[1], path[2]);
                return;
            } else if (uploadId != null &&
                    request.getParameter("partNumber") == null) {
                handleCompleteMultipartUpload(request, response, is, blobStore,
                        path[1], path[2], uploadId);
                return;
            }
            break;
        case "PUT":
            if (path.length <= 2 || path[2].isEmpty()) {
                if ("".equals(request.getParameter("acl"))) {
                    handleSetContainerAcl(request, response, is, blobStore,
                            path[1]);
                    return;
                }
                handleContainerCreate(request, response, is, blobStore,
                        path[1]);
                return;
            } else if (uploadId != null) {
                if (request.getHeader(AwsHttpHeaders.COPY_SOURCE) != null) {
                    handleCopyPart(request, response, blobStore, path[1],
                            path[2], uploadId);
                } else {
                    handleUploadPart(request, response, is, blobStore, path[1],
                            path[2], uploadId);
                }
                return;
            } else if (request.getHeader(AwsHttpHeaders.COPY_SOURCE) != null) {
                handleCopyBlob(request, response, is, blobStore, path[1],
                        path[2]);
                return;
            } else {
                if ("".equals(request.getParameter("acl"))) {
                    handleSetBlobAcl(request, response, is, blobStore, path[1],
                            path[2]);
                    return;
                }
                handlePutBlob(request, response, is, blobStore, path[1],
                        path[2]);
                return;
            }
        case "OPTIONS":
            handleOptionsBlob(request, response, blobStore, path[1]);
            return;
        default:
            break;
        }
        logger.error("Unknown method {} with URI {}",
                method, request.getRequestURI());
        throw new S3Exception(S3ErrorCode.NOT_IMPLEMENTED);
    }

    private static boolean checkPublicAccess(BlobStore blobStore,
            String containerName, String blobName) {
        String blobStoreType = getBlobStoreType(blobStore);
        if (Quirks.NO_BLOB_ACCESS_CONTROL.contains(blobStoreType)) {
            ContainerAccess access = blobStore.getContainerAccess(
                    containerName);
            return access == ContainerAccess.PUBLIC_READ;
        } else {
            BlobAccess access = blobStore.getBlobAccess(containerName,
                    blobName);
            return access == BlobAccess.PUBLIC_READ;
        }
    }

    private void doHandleAnonymous(HttpServletRequest request,
            HttpServletResponse response, InputStream is, String uri,
            BlobStore blobStore)
            throws IOException, S3Exception {
        String method = request.getMethod();
        String[] path = uri.split("/", 3);
        switch (method) {
        case "GET":
            if (uri.equals("/")) {
                throw new S3Exception(S3ErrorCode.ACCESS_DENIED);
            } else if (path.length <= 2 || path[2].isEmpty()) {
                String containerName = path[1];
                ContainerAccess access = blobStore.getContainerAccess(
                        containerName);
                if (access == ContainerAccess.PRIVATE) {
                    throw new S3Exception(S3ErrorCode.ACCESS_DENIED);
                }
                handleBlobList(request, response, blobStore, containerName);
                return;
            } else {
                String containerName = path[1];
                String blobName = path[2];
                if (!checkPublicAccess(blobStore, containerName, blobName)) {
                    throw new S3Exception(S3ErrorCode.ACCESS_DENIED);
                }
                handleGetBlob(request, response, blobStore, containerName,
                        blobName);
                return;
            }
        case "HEAD":
            if (path.length <= 2 || path[2].isEmpty()) {
                String containerName = path[1];
                ContainerAccess access = blobStore.getContainerAccess(
                        containerName);
                if (access == ContainerAccess.PRIVATE) {
                    throw new S3Exception(S3ErrorCode.ACCESS_DENIED);
                }
                if (!blobStore.containerExists(containerName)) {
                    throw new S3Exception(S3ErrorCode.NO_SUCH_BUCKET);
                }
            } else {
                String containerName = path[1];
                String blobName = path[2];
                if (!checkPublicAccess(blobStore, containerName, blobName)) {
                    throw new S3Exception(S3ErrorCode.ACCESS_DENIED);
                }
                handleBlobMetadata(request, response, blobStore, containerName,
                        blobName);
            }
            return;
        case "POST":
            if (path.length <= 2 || path[2].isEmpty()) {
                handlePostBlob(request, response, is, blobStore, path[1]);
                return;
            }
            break;
        case "OPTIONS":
            if (uri.equals("/")) {
                throw new S3Exception(S3ErrorCode.ACCESS_DENIED);
            } else {
                String containerName = path[1];
                /*
                 * Only check access on bucket level. The preflight request
                 * might be for a PUT, so the object is not yet there.
                 */
                ContainerAccess access = blobStore.getContainerAccess(
                        containerName);
                if (access == ContainerAccess.PRIVATE) {
                    throw new S3Exception(S3ErrorCode.ACCESS_DENIED);
                }
                handleOptionsBlob(request, response, blobStore, containerName);
                return;
            }
        default:
            break;
        }
        logger.error("Unknown method {} with URI {}",
                method, request.getRequestURI());
        throw new S3Exception(S3ErrorCode.NOT_IMPLEMENTED);
    }

    private void handleGetContainerAcl(HttpServletResponse response,
            BlobStore blobStore, String containerName)
            throws IOException, S3Exception {
        if (!blobStore.containerExists(containerName)) {
            throw new S3Exception(S3ErrorCode.NO_SUCH_BUCKET);
        }
        ContainerAccess access = blobStore.getContainerAccess(containerName);

        response.setCharacterEncoding(UTF_8);
        try (Writer writer = response.getWriter()) {
            response.setContentType(XML_CONTENT_TYPE);
            XMLStreamWriter xml = xmlOutputFactory.createXMLStreamWriter(
                    writer);
            xml.writeStartDocument();
            xml.writeStartElement("AccessControlPolicy");
            xml.writeDefaultNamespace(AWS_XMLNS);

            writeOwnerStanza(xml);

            xml.writeStartElement("AccessControlList");

            xml.writeStartElement("Grant");

            xml.writeStartElement("Grantee");
            xml.writeNamespace("xsi",
                    "http://www.w3.org/2001/XMLSchema-instance");
            xml.writeAttribute("xsi:type", "CanonicalUser");

            writeSimpleElement(xml, "ID", FAKE_OWNER_ID);
            writeSimpleElement(xml, "DisplayName",
                    FAKE_OWNER_DISPLAY_NAME);

            xml.writeEndElement();

            writeSimpleElement(xml, "Permission", "FULL_CONTROL");

            xml.writeEndElement();

            if (access == ContainerAccess.PUBLIC_READ) {
                xml.writeStartElement("Grant");

                xml.writeStartElement("Grantee");
                xml.writeNamespace("xsi",
                        "http://www.w3.org/2001/XMLSchema-instance");
                xml.writeAttribute("xsi:type", "Group");

                writeSimpleElement(xml, "URI",
                        "http://acs.amazonaws.com/groups/global/AllUsers");

                xml.writeEndElement();

                writeSimpleElement(xml, "Permission", "READ");

                xml.writeEndElement();
            }

            xml.writeEndElement();

            xml.writeEndElement();
            xml.flush();
        } catch (XMLStreamException xse) {
            throw new IOException(xse);
        }
    }

    private static void handleSetContainerAcl(HttpServletRequest request,
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

        PushbackInputStream pis = new PushbackInputStream(is);
        int ch = pis.read();
        if (ch != -1) {
            pis.unread(ch);
            AccessControlPolicy policy = new XmlMapper().readValue(
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
    }

    private void handleGetBlobAcl(HttpServletResponse response,
            BlobStore blobStore, String containerName,
            String blobName) throws IOException {
        BlobAccess access = blobStore.getBlobAccess(containerName, blobName);

        response.setCharacterEncoding(UTF_8);
        try (Writer writer = response.getWriter()) {
            response.setContentType(XML_CONTENT_TYPE);
            XMLStreamWriter xml = xmlOutputFactory.createXMLStreamWriter(
                    writer);
            xml.writeStartDocument();
            xml.writeStartElement("AccessControlPolicy");
            xml.writeDefaultNamespace(AWS_XMLNS);

            writeOwnerStanza(xml);

            xml.writeStartElement("AccessControlList");

            xml.writeStartElement("Grant");

            xml.writeStartElement("Grantee");
            xml.writeNamespace("xsi",
                    "http://www.w3.org/2001/XMLSchema-instance");
            xml.writeAttribute("xsi:type", "CanonicalUser");

            writeSimpleElement(xml, "ID", FAKE_OWNER_ID);
            writeSimpleElement(xml, "DisplayName",
                    FAKE_OWNER_DISPLAY_NAME);

            xml.writeEndElement();

            writeSimpleElement(xml, "Permission", "FULL_CONTROL");

            xml.writeEndElement();

            if (access == BlobAccess.PUBLIC_READ) {
                xml.writeStartElement("Grant");

                xml.writeStartElement("Grantee");
                xml.writeNamespace("xsi",
                        "http://www.w3.org/2001/XMLSchema-instance");
                xml.writeAttribute("xsi:type", "Group");

                writeSimpleElement(xml, "URI",
                        "http://acs.amazonaws.com/groups/global/AllUsers");

                xml.writeEndElement();

                writeSimpleElement(xml, "Permission", "READ");

                xml.writeEndElement();
            }

            xml.writeEndElement();

            xml.writeEndElement();
            xml.flush();
        } catch (XMLStreamException xse) {
            throw new IOException(xse);
        }
    }

    private static void handleSetBlobAcl(HttpServletRequest request,
            HttpServletResponse response, InputStream is, BlobStore blobStore,
            String containerName, String blobName)
            throws IOException, S3Exception {
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

        PushbackInputStream pis = new PushbackInputStream(is);
        int ch = pis.read();
        if (ch != -1) {
            pis.unread(ch);
            AccessControlPolicy policy = new XmlMapper().readValue(
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
    }

    /** Map XML ACLs to a canned policy if an exact tranformation exists. */
    private static String mapXmlAclsToCannedPolicy(
            AccessControlPolicy policy) throws S3Exception {
        if (!policy.owner.id.equals(FAKE_OWNER_ID)) {
            throw new S3Exception(S3ErrorCode.NOT_IMPLEMENTED);
        }

        boolean ownerFullControl = false;
        boolean allUsersRead = false;
        if (policy.aclList != null) {
            for (AccessControlPolicy.AccessControlList.Grant grant :
                    policy.aclList.grants) {
                if (grant.grantee.type.equals("CanonicalUser") &&
                        grant.grantee.id.equals(FAKE_OWNER_ID) &&
                        grant.permission.equals("FULL_CONTROL")) {
                    ownerFullControl = true;
                } else if (grant.grantee.type.equals("Group") &&
                        grant.grantee.uri.equals("http://acs.amazonaws.com/" +
                                "groups/global/AllUsers") &&
                        grant.permission.equals("READ")) {
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

    private void handleContainerList(HttpServletResponse response,
            BlobStore blobStore) throws IOException {
        PageSet<? extends StorageMetadata> buckets = blobStore.list();

        response.setCharacterEncoding(UTF_8);
        try (Writer writer = response.getWriter()) {
            response.setContentType(XML_CONTENT_TYPE);
            XMLStreamWriter xml = xmlOutputFactory.createXMLStreamWriter(
                    writer);
            xml.writeStartDocument();
            xml.writeStartElement("ListAllMyBucketsResult");
            xml.writeDefaultNamespace(AWS_XMLNS);

            writeOwnerStanza(xml);

            xml.writeStartElement("Buckets");
            for (StorageMetadata metadata : buckets) {
                xml.writeStartElement("Bucket");

                writeSimpleElement(xml, "Name", metadata.getName());

                Date creationDate = metadata.getCreationDate();
                if (creationDate == null) {
                    // Some providers, e.g., Swift, do not provide container
                    // creation date.  Emit a bogus one to satisfy clients like
                    // s3cmd which require one.
                    creationDate = new Date(0);
                }
                writeSimpleElement(xml, "CreationDate",
                        blobStore.getContext().utils().date()
                                .iso8601DateFormat(creationDate).trim());

                xml.writeEndElement();
            }
            xml.writeEndElement();

            xml.writeEndElement();
            xml.flush();
        } catch (XMLStreamException xse) {
            throw new IOException(xse);
        }
    }

    private void handleContainerLocation(HttpServletResponse response)
            throws IOException {
        response.setCharacterEncoding(UTF_8);
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

    private void handleListMultipartUploads(HttpServletRequest request,
            HttpServletResponse response, BlobStore blobStore,
            String container) throws IOException, S3Exception {
        if (request.getParameter("delimiter") != null ||
                request.getParameter("prefix") != null ||
                request.getParameter("max-uploads") != null ||
                request.getParameter("key-marker") != null ||
                request.getParameter("upload-id-marker") != null) {
            throw new UnsupportedOperationException();
        }

        List<MultipartUpload> uploads = blobStore.listMultipartUploads(
                container);

        response.setCharacterEncoding(UTF_8);
        try (Writer writer = response.getWriter()) {
            response.setContentType(XML_CONTENT_TYPE);
            XMLStreamWriter xml = xmlOutputFactory.createXMLStreamWriter(
                    writer);
            xml.writeStartDocument();
            xml.writeStartElement("ListMultipartUploadsResult");
            xml.writeDefaultNamespace(AWS_XMLNS);

            writeSimpleElement(xml, "Bucket", container);

            // TODO: bogus values
            xml.writeEmptyElement("KeyMarker");
            xml.writeEmptyElement("UploadIdMarker");
            xml.writeEmptyElement("NextKeyMarker");
            xml.writeEmptyElement("NextUploadIdMarker");
            xml.writeEmptyElement("Delimiter");
            xml.writeEmptyElement("Prefix");
            writeSimpleElement(xml, "MaxUploads", "1000");
            writeSimpleElement(xml, "IsTruncated", "false");

            for (MultipartUpload upload : uploads) {
                xml.writeStartElement("Upload");

                writeSimpleElement(xml, "Key", upload.blobName());
                writeSimpleElement(xml, "UploadId", upload.id());
                writeInitiatorStanza(xml);
                writeOwnerStanza(xml);
                // TODO: bogus value
                writeSimpleElement(xml, "StorageClass", "STANDARD");

                // TODO: bogus value
                writeSimpleElement(xml, "Initiated",
                        blobStore.getContext().utils().date()
                                .iso8601DateFormat(new Date()));

                xml.writeEndElement();
            }

            // TODO: CommonPrefixes

            xml.writeEndElement();

            xml.flush();
        } catch (XMLStreamException xse) {
            throw new IOException(xse);
        }
    }

    private static void handleContainerExists(BlobStore blobStore,
            String containerName) throws IOException, S3Exception {
        if (!blobStore.containerExists(containerName)) {
            throw new S3Exception(S3ErrorCode.NO_SUCH_BUCKET);
        }
    }

    private static void handleContainerCreate(HttpServletRequest request,
            HttpServletResponse response, InputStream is, BlobStore blobStore,
            String containerName) throws IOException, S3Exception {
        if (containerName.isEmpty()) {
            throw new S3Exception(S3ErrorCode.METHOD_NOT_ALLOWED);
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
                CreateBucketRequest cbr = new XmlMapper().readValue(
                        pis, CreateBucketRequest.class);
                locationString = cbr.locationConstraint;
            }
        }

        Location location = null;
        if (locationString != null) {
            for (Location loc : blobStore.listAssignableLocations()) {
                if (loc.getId().equalsIgnoreCase(locationString)) {
                    location = loc;
                    break;
                }
            }
            if (location == null) {
                throw new S3Exception(S3ErrorCode.INVALID_LOCATION_CONSTRAINT);
            }
        }
        logger.debug("Creating bucket with location: {}", location);

        CreateContainerOptions options = new CreateContainerOptions();
        String acl = request.getHeader(AwsHttpHeaders.ACL);
        if ("public-read".equalsIgnoreCase(acl)) {
            options.publicRead();
        }

        boolean created;
        try {
            created = blobStore.createContainerInLocation(location,
                    containerName, options);
        } catch (AuthorizationException ae) {
            if (ae.getCause() instanceof AccessDeniedException) {
                throw new S3Exception(S3ErrorCode.ACCESS_DENIED,
                        "Could not create bucket", ae);
            }
            throw new S3Exception(S3ErrorCode.BUCKET_ALREADY_EXISTS, ae);
        }
        if (!created) {
            throw new S3Exception(S3ErrorCode.BUCKET_ALREADY_OWNED_BY_YOU,
                    S3ErrorCode.BUCKET_ALREADY_OWNED_BY_YOU.getMessage(),
                    null, ImmutableMap.of("BucketName", containerName));
        }

        response.addHeader(HttpHeaders.LOCATION, "/" + containerName);
    }

    private static void handleContainerDelete(HttpServletResponse response,
            BlobStore blobStore, String containerName)
            throws IOException, S3Exception {
        if (!blobStore.containerExists(containerName)) {
            throw new S3Exception(S3ErrorCode.NO_SUCH_BUCKET);
        }

        String blobStoreType = getBlobStoreType(blobStore);
        if (blobStoreType.equals("b2")) {
            // S3 allows deleting a container with in-progress MPU while B2 does
            // not.  Explicitly cancel uploads for B2.
            for (MultipartUpload mpu : blobStore.listMultipartUploads(
                    containerName)) {
                blobStore.abortMultipartUpload(mpu);
            }
        }

        if (!blobStore.deleteContainerIfEmpty(containerName)) {
            throw new S3Exception(S3ErrorCode.BUCKET_NOT_EMPTY);
        }

        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }

    private void handleBlobList(HttpServletRequest request,
            HttpServletResponse response, BlobStore blobStore,
            String containerName) throws IOException, S3Exception {
        String blobStoreType = getBlobStoreType(blobStore);
        ListContainerOptions options = new ListContainerOptions();
        String encodingType = request.getParameter("encoding-type");
        String delimiter = request.getParameter("delimiter");
        if (delimiter != null) {
            options.delimiter(delimiter);
        } else {
            options.recursive();
        }
        String prefix = request.getParameter("prefix");
        if (prefix != null && !prefix.isEmpty()) {
            options.prefix(prefix);
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
            if (continuationToken != null && startAfter != null) {
                throw new S3Exception(S3ErrorCode.INVALID_ARGUMENT);
            }
            if (continuationToken != null) {
                marker = continuationToken;
            } else {
                marker = startAfter;
            }
        } else {
            throw new S3Exception(S3ErrorCode.NOT_IMPLEMENTED);
        }
        if (marker != null) {
            if (Quirks.OPAQUE_MARKERS.contains(blobStoreType)) {
                String realMarker = lastKeyToMarker.getIfPresent(
                        Maps.immutableEntry(containerName, marker));
                if (realMarker != null) {
                    marker = realMarker;
                }
            }
            options.afterMarker(marker);
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
            if (maxKeys > 1000) {
                maxKeys = 1000;
            }
        }
        options.maxResults(maxKeys);

        PageSet<? extends StorageMetadata> set = blobStore.list(containerName,
                options);

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
                writeSimpleElement(xml, "KeyCount", String.valueOf(set.size()));
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

            String nextMarker = set.getNextMarker();
            if (nextMarker != null) {
                writeSimpleElement(xml, "IsTruncated", "true");
                writeSimpleElement(xml,
                        isListV2 ? "NextContinuationToken" : "NextMarker",
                        encodeBlob(encodingType, nextMarker));
                if (Quirks.OPAQUE_MARKERS.contains(blobStoreType)) {
                    StorageMetadata sm = Iterables.getLast(set, null);
                    if (sm != null) {
                        lastKeyToMarker.put(Maps.immutableEntry(containerName,
                                sm.getName()), nextMarker);
                    }
                }
            } else {
                writeSimpleElement(xml, "IsTruncated", "false");
            }

            Set<String> commonPrefixes = new TreeSet<>();
            for (StorageMetadata metadata : set) {
                switch (metadata.getType()) {
                case FOLDER:
                    // fallthrough
                case RELATIVE_PATH:
                    commonPrefixes.add(metadata.getName());
                    continue;
                default:
                    break;
                }

                xml.writeStartElement("Contents");

                writeSimpleElement(xml, "Key", encodeBlob(encodingType,
                        metadata.getName()));

                Date lastModified = metadata.getLastModified();
                if (lastModified != null) {
                    writeSimpleElement(xml, "LastModified",
                            formatDate(lastModified));
                }

                String eTag = metadata.getETag();
                if (eTag != null) {
                    writeSimpleElement(xml, "ETag", maybeQuoteETag(eTag));
                }

                writeSimpleElement(xml, "Size",
                        String.valueOf(metadata.getSize()));
                writeSimpleElement(xml, "StorageClass",
                        StorageClass.fromTier(metadata.getTier()).toString());

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

    private static void handleBlobRemove(HttpServletResponse response,
            BlobStore blobStore, String containerName,
            String blobName) throws IOException, S3Exception {
        blobStore.removeBlob(containerName, blobName);
        response.sendError(HttpServletResponse.SC_NO_CONTENT);
    }

    private void handleMultiBlobRemove(HttpServletResponse response,
            InputStream is, BlobStore blobStore, String containerName)
            throws IOException, S3Exception {
        DeleteMultipleObjectsRequest dmor = new XmlMapper().readValue(
                is, DeleteMultipleObjectsRequest.class);
        if (dmor.objects == null) {
            throw new S3Exception(S3ErrorCode.MALFORMED_X_M_L);
        }

        Collection<String> blobNames = new ArrayList<>();
        for (DeleteMultipleObjectsRequest.S3Object s3Object :
                dmor.objects) {
            blobNames.add(s3Object.key);
        }

        blobStore.removeBlobs(containerName, blobNames);

        response.setCharacterEncoding(UTF_8);
        try (Writer writer = response.getWriter()) {
            response.setContentType(XML_CONTENT_TYPE);
            XMLStreamWriter xml = xmlOutputFactory.createXMLStreamWriter(
                    writer);
            xml.writeStartDocument();
            xml.writeStartElement("DeleteResult");
            xml.writeDefaultNamespace(AWS_XMLNS);

            if (!dmor.quiet) {
                for (String blobName : blobNames) {
                    xml.writeStartElement("Deleted");

                    writeSimpleElement(xml, "Key", blobName);

                    xml.writeEndElement();
                }
            }

            // TODO: emit error stanza
            xml.writeEndElement();
            xml.flush();
        } catch (XMLStreamException xse) {
            throw new IOException(xse);
        }
    }

    private static void handleBlobMetadata(HttpServletRequest request,
            HttpServletResponse response,
            BlobStore blobStore, String containerName,
            String blobName) throws IOException, S3Exception {
        BlobMetadata metadata = blobStore.blobMetadata(containerName, blobName);
        if (metadata == null) {
            throw new S3Exception(S3ErrorCode.NO_SUCH_KEY);
        }

        // BlobStore.blobMetadata does not support GetOptions so we emulate
        // conditional requests.
        String ifMatch = request.getHeader(HttpHeaders.IF_MATCH);
        String ifNoneMatch = request.getHeader(HttpHeaders.IF_NONE_MATCH);
        long ifModifiedSince = request.getDateHeader(
                HttpHeaders.IF_MODIFIED_SINCE);
        long ifUnmodifiedSince = request.getDateHeader(
                HttpHeaders.IF_UNMODIFIED_SINCE);

        String eTag = metadata.getETag();
        if (eTag != null) {
            eTag = maybeQuoteETag(eTag);
            if (ifMatch != null && !ifMatch.equals(eTag)) {
                throw new S3Exception(S3ErrorCode.PRECONDITION_FAILED);
            }
            if (ifNoneMatch != null && ifNoneMatch.equals(eTag)) {
                response.setStatus(HttpServletResponse.SC_NOT_MODIFIED);
                return;
            }
        }

        Date lastModified = metadata.getLastModified();
        if (lastModified != null) {
            if (ifModifiedSince != -1 && lastModified.compareTo(
                    new Date(ifModifiedSince)) <= 0) {
                throw new S3Exception(S3ErrorCode.PRECONDITION_FAILED);
            }
            if (ifUnmodifiedSince != -1 && lastModified.compareTo(
                    new Date(ifUnmodifiedSince)) >= 0) {
                response.setStatus(HttpServletResponse.SC_NOT_MODIFIED);
                return;
            }
        }

        response.setStatus(HttpServletResponse.SC_OK);
        addMetadataToResponse(request, response, metadata);
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

        response.addHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, corsOrigin);
        response.addHeader(HttpHeaders.VARY, HttpHeaders.ORIGIN);
        response.addHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS,
                corsRules.getAllowedMethods());

        response.setStatus(HttpServletResponse.SC_OK);
    }

    private void handleGetBlob(HttpServletRequest request,
            HttpServletResponse response, BlobStore blobStore,
            String containerName, String blobName)
            throws IOException, S3Exception {
        int status = HttpServletResponse.SC_OK;
        GetOptions options = new GetOptions();

        String ifMatch = request.getHeader(HttpHeaders.IF_MATCH);
        if (ifMatch != null) {
            options.ifETagMatches(ifMatch);
        }

        String ifNoneMatch = request.getHeader(HttpHeaders.IF_NONE_MATCH);
        if (ifNoneMatch != null) {
            options.ifETagDoesntMatch(ifNoneMatch);
        }

        long ifModifiedSince = request.getDateHeader(
                HttpHeaders.IF_MODIFIED_SINCE);
        if (ifModifiedSince != -1) {
            options.ifModifiedSince(new Date(ifModifiedSince));
        }

        long ifUnmodifiedSince = request.getDateHeader(
                HttpHeaders.IF_UNMODIFIED_SINCE);
        if (ifUnmodifiedSince != -1) {
            options.ifUnmodifiedSince(new Date(ifUnmodifiedSince));
        }

        String range = request.getHeader(HttpHeaders.RANGE);
        if (range != null && range.startsWith("bytes=") &&
                // ignore multiple ranges
                range.indexOf(',') == -1) {
            range = range.substring("bytes=".length());
            String[] ranges = range.split("-", 2);
            if (ranges[0].isEmpty()) {
                options.tail(Long.parseLong(ranges[1]));
            } else if (ranges[1].isEmpty()) {
                options.startAt(Long.parseLong(ranges[0]));
            } else {
                options.range(Long.parseLong(ranges[0]),
                        Long.parseLong(ranges[1]));
            }
            status = HttpServletResponse.SC_PARTIAL_CONTENT;
        }

        Blob blob = blobStore.getBlob(containerName, blobName, options);
        if (blob == null) {
            throw new S3Exception(S3ErrorCode.NO_SUCH_KEY);
        }

        response.setStatus(status);

        addCorsResponseHeader(request, response);

        addMetadataToResponse(request, response, blob.getMetadata());
        // TODO: handles only a single range due to jclouds limitations
        Collection<String> contentRanges =
                blob.getAllHeaders().get(HttpHeaders.CONTENT_RANGE);
        if (!contentRanges.isEmpty()) {
            response.addHeader(HttpHeaders.CONTENT_RANGE,
                    contentRanges.iterator().next());
            response.addHeader(HttpHeaders.ACCEPT_RANGES,
                    "bytes");
        }

        try (InputStream is = blob.getPayload().openStream();
             OutputStream os = response.getOutputStream()) {
            ByteStreams.copy(is, os);
            os.flush();
        }
    }

    private void handleCopyBlob(HttpServletRequest request,
            HttpServletResponse response, InputStream is, BlobStore blobStore,
            String destContainerName, String destBlobName)
            throws IOException, S3Exception {
        String copySourceHeader = request.getHeader(AwsHttpHeaders.COPY_SOURCE);
        copySourceHeader = URLDecoder.decode(copySourceHeader, UTF_8);
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
        boolean replaceMetadata = "REPLACE".equalsIgnoreCase(request.getHeader(
                AwsHttpHeaders.METADATA_DIRECTIVE));

        if (sourceContainerName.equals(destContainerName) &&
                sourceBlobName.equals(destBlobName) &&
                !replaceMetadata) {
            throw new S3Exception(S3ErrorCode.INVALID_REQUEST);
        }

        CopyOptions.Builder options = CopyOptions.builder();

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
            ContentMetadataBuilder contentMetadata =
                    ContentMetadataBuilder.create();
            ImmutableMap.Builder<String, String> userMetadata =
                    ImmutableMap.builder();
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
                    contentMetadata.contentEncoding(headerValue);
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

        String eTag;
        try {
            eTag = blobStore.copyBlob(
                    sourceContainerName, sourceBlobName,
                    destContainerName, destBlobName, options.build());
        } catch (KeyNotFoundException knfe) {
            throw new S3Exception(S3ErrorCode.NO_SUCH_KEY, knfe);
        }

        // TODO: jclouds should include this in CopyOptions
        String cannedAcl = request.getHeader(AwsHttpHeaders.ACL);
        if (cannedAcl != null && !cannedAcl.equalsIgnoreCase("private")) {
            handleSetBlobAcl(request, response, is, blobStore,
                    destContainerName, destBlobName);
        }

        BlobMetadata blobMetadata = blobStore.blobMetadata(destContainerName,
                destBlobName);
        response.setCharacterEncoding(UTF_8);
        try (Writer writer = response.getWriter()) {
            response.setContentType(XML_CONTENT_TYPE);
            XMLStreamWriter xml = xmlOutputFactory.createXMLStreamWriter(
                    writer);
            xml.writeStartDocument();
            xml.writeStartElement("CopyObjectResult");
            xml.writeDefaultNamespace(AWS_XMLNS);

            writeSimpleElement(xml, "LastModified",
                    formatDate(blobMetadata.getLastModified()));
            writeSimpleElement(xml, "ETag", maybeQuoteETag(eTag));

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
                        BaseEncoding.base64().decode(contentMD5String));
            } catch (IllegalArgumentException iae) {
                throw new S3Exception(S3ErrorCode.INVALID_DIGEST, iae);
            }
            if (contentMD5.bits() != MD5.bits()) {
                throw new S3Exception(S3ErrorCode.INVALID_DIGEST);
            }
        }

        if (contentLengthString == null) {
            throw new S3Exception(S3ErrorCode.MISSING_CONTENT_LENGTH);
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

        PutOptions options = new PutOptions().setBlobAccess(access);

        String blobStoreType = getBlobStoreType(blobStore);
        if (blobStoreType.equals("azureblob") &&
                contentLength > 256 * 1024 * 1024) {
            options.multipart(true);
        }

        String eTag;
        BlobBuilder.PayloadBlobBuilder builder = blobStore
                .blobBuilder(blobName)
                .payload(is)
                .contentLength(contentLength);

        String storageClass = request.getHeader(AwsHttpHeaders.STORAGE_CLASS);
        if (storageClass == null || storageClass.equalsIgnoreCase("STANDARD")) {
            // defaults to STANDARD
        } else {
            builder.tier(StorageClass.valueOf(storageClass).toTier());
        }

        addContentMetdataFromHttpRequest(builder, request);
        if (contentMD5 != null) {
            builder = builder.contentMD5(contentMD5);
        }

        eTag = blobStore.putBlob(containerName, builder.build(),
                options);

        addCorsResponseHeader(request, response);

        response.addHeader(HttpHeaders.ETAG, maybeQuoteETag(eTag));
    }

    private void handlePostBlob(HttpServletRequest request,
            HttpServletResponse response, InputStream is, BlobStore blobStore,
            String containerName)
            throws IOException, S3Exception {
        String boundaryHeader = request.getHeader(HttpHeaders.CONTENT_TYPE);
        if (boundaryHeader == null ||
                !boundaryHeader.startsWith("multipart/form-data; boundary=")) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }
        String boundary =
                boundaryHeader.substring(boundaryHeader.indexOf('=') + 1);

        String blobName = null;
        String contentType = null;
        String identity = null;
        // TODO: handle policy
        byte[] policy = null;
        String signature = null;
        String algorithm = null;
        byte[] payload = null;
        MultipartStream multipartStream = new MultipartStream(is,
                boundary.getBytes(StandardCharsets.UTF_8), 4096, null);
        boolean nextPart = multipartStream.skipPreamble();
        while (nextPart) {
            String header = multipartStream.readHeaders();
            try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
                multipartStream.readBodyData(baos);
                if (isField(header, "acl")) {
                    // TODO: acl
                } else if (isField(header, "AWSAccessKeyId") ||
                        isField(header, "X-Amz-Credential")) {
                    identity = new String(baos.toByteArray());
                } else if (isField(header, "Content-Type")) {
                    contentType = new String(baos.toByteArray());
                } else if (isField(header, "file")) {
                    // TODO: buffers entire payload
                    payload = baos.toByteArray();
                } else if (isField(header, "key")) {
                    blobName = new String(baos.toByteArray());
                } else if (isField(header, "policy")) {
                    policy = baos.toByteArray();
                } else if (isField(header, "signature") ||
                        isField(header, "X-Amz-Signature")) {
                    signature = new String(baos.toByteArray());
                } else if (isField(header, "X-Amz-Algorithm")) {
                    algorithm = new String(baos.toByteArray());
                }
            }
            nextPart = multipartStream.readBoundary();
        }


        if (blobName == null || policy == null) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
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

        switch (authHeader.authenticationType) {
        case AWS_V2:
            switch (authenticationType) {
            case AWS_V2:
            case AWS_V2_OR_V4:
            case NONE:
                break;
            default:
                throw new S3Exception(S3ErrorCode.ACCESS_DENIED);
            }
            break;
        case AWS_V4:
            switch (authenticationType) {
            case AWS_V4:
            case AWS_V2_OR_V4:
            case NONE:
                break;
            default:
                throw new S3Exception(S3ErrorCode.ACCESS_DENIED);
            }
            break;
        case NONE:
            break;
        default:
            throw new IllegalArgumentException("Unhandled type: " +
                    authHeader.authenticationType);
        }

        Map.Entry<String, BlobStore> provider =
                blobStoreLocator.locateBlobStore(authHeader.identity, null,
                        null);
        if (provider == null) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            return;
        }
        String credential = provider.getKey();

        if (signatureVersion4) {
            byte[] kSecret = ("AWS4" + credential).getBytes(
                    StandardCharsets.UTF_8);
            byte[] kDate = hmac("HmacSHA256",
                    authHeader.date.getBytes(StandardCharsets.UTF_8), kSecret);
            byte[] kRegion = hmac("HmacSHA256",
                    authHeader.region.getBytes(StandardCharsets.UTF_8), kDate);
            byte[] kService = hmac("HmacSHA256", authHeader.service.getBytes(
                    StandardCharsets.UTF_8), kRegion);
            byte[] kSigning = hmac("HmacSHA256",
                    "aws4_request".getBytes(StandardCharsets.UTF_8), kService);
            String expectedSignature = BaseEncoding.base16().lowerCase().encode(
                    hmac("HmacSHA256", policy, kSigning));
            if (!constantTimeEquals(signature, expectedSignature)) {
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                return;
            }
        } else {
            String expectedSignature = BaseEncoding.base64().encode(
                    hmac("HmacSHA1", policy,
                            credential.getBytes(StandardCharsets.UTF_8)));
            if (!constantTimeEquals(signature, expectedSignature)) {
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                return;
            }
        }

        BlobBuilder.PayloadBlobBuilder builder = blobStore
                .blobBuilder(blobName)
                .payload(payload);
        if (contentType != null) {
            builder.contentType(contentType);
        }
        Blob blob = builder.build();
        blobStore.putBlob(containerName, blob);

        response.setStatus(HttpServletResponse.SC_NO_CONTENT);

        addCorsResponseHeader(request, response);
    }

    private void handleInitiateMultipartUpload(HttpServletRequest request,
            HttpServletResponse response, BlobStore blobStore,
            String containerName, String blobName)
            throws IOException, S3Exception {
        ByteSource payload = ByteSource.empty();
        BlobBuilder.PayloadBlobBuilder builder = blobStore
                .blobBuilder(blobName)
                .payload(payload);
        addContentMetdataFromHttpRequest(builder, request);
        builder.contentLength(payload.size());

        String storageClass = request.getHeader(AwsHttpHeaders.STORAGE_CLASS);
        if (storageClass == null || storageClass.equalsIgnoreCase("STANDARD")) {
            // defaults to STANDARD
        } else {
            builder.tier(StorageClass.valueOf(storageClass).toTier());
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
        PutOptions options = new PutOptions().setBlobAccess(access);

        MultipartUpload mpu = blobStore.initiateMultipartUpload(containerName,
                builder.build().getMetadata(), options);

        if (Quirks.MULTIPART_REQUIRES_STUB.contains(getBlobStoreType(
                blobStore))) {
            blobStore.putBlob(containerName, builder.name(mpu.id()).build(),
                    options);
        }

        response.setCharacterEncoding(UTF_8);
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

        addCorsResponseHeader(request, response);
    }

    private void handleCompleteMultipartUpload(HttpServletRequest request,
            HttpServletResponse response, InputStream is,
            final BlobStore blobStore, String containerName, String blobName,
            String uploadId) throws IOException, S3Exception {
        final MultipartUpload mpu;
        if (Quirks.MULTIPART_REQUIRES_STUB.contains(getBlobStoreType(
                blobStore))) {
            Blob stubBlob = blobStore.getBlob(containerName, uploadId);
            BlobAccess access = blobStore.getBlobAccess(containerName,
                    uploadId);
            mpu = MultipartUpload.create(containerName,
                    blobName, uploadId, stubBlob.getMetadata(),
                    new PutOptions().setBlobAccess(access));
        } else {
            mpu = MultipartUpload.create(containerName,
                    blobName, uploadId, new MutableBlobMetadataImpl(),
                    new PutOptions());
        }

        // List parts to get part sizes and to map multiple Azure parts
        // into single parts.
        ImmutableMap.Builder<Integer, MultipartPart> builder =
                ImmutableMap.builder();
        for (MultipartPart part : blobStore.listMultipartUpload(mpu)) {
            builder.put(part.partNumber(), part);
        }
        ImmutableMap<Integer, MultipartPart> partsByListing = builder.build();

        final List<MultipartPart> parts = new ArrayList<>();
        String blobStoreType = getBlobStoreType(blobStore);
        if (blobStoreType.equals("azureblob")) {
            // TODO: how to sanity check parts?
            for (MultipartPart part : blobStore.listMultipartUpload(mpu)) {
                parts.add(part);
            }
        } else {
            CompleteMultipartUploadRequest cmu;
            try {
                cmu = new XmlMapper().readValue(
                        is, CompleteMultipartUploadRequest.class);
            } catch (JsonParseException jpe) {
                throw new S3Exception(S3ErrorCode.MALFORMED_X_M_L, jpe);
            }

            // use TreeMap to allow runt last part
            SortedMap<Integer, String> requestParts = new TreeMap<>();
            if (cmu.parts != null) {
                for (CompleteMultipartUploadRequest.Part part : cmu.parts) {
                    requestParts.put(part.partNumber, part.eTag);
                }
            }
            for (Iterator<Map.Entry<Integer, String>> it =
                    requestParts.entrySet().iterator(); it.hasNext();) {
                Map.Entry<Integer, String> entry = it.next();
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
                parts.add(MultipartPart.create(entry.getKey(),
                        partSize, part.partETag(), part.lastModified()));
            }
        }

        if (parts.isEmpty()) {
            // Amazon requires at least one part
            throw new S3Exception(S3ErrorCode.MALFORMED_X_M_L);
        }

        response.setCharacterEncoding(UTF_8);
        try (PrintWriter writer = response.getWriter()) {
            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType(XML_CONTENT_TYPE);

            // Launch async thread to allow main thread to emit newlines to
            // the client while completeMultipartUpload processes.
            final AtomicReference<String> eTag = new AtomicReference<>();
            final AtomicReference<RuntimeException> exception =
                    new AtomicReference<>();
            Thread thread = new Thread() {
                @Override
                public void run() {
                    try {
                        eTag.set(blobStore.completeMultipartUpload(mpu, parts));
                    } catch (RuntimeException re) {
                        exception.set(re);
                    }
                }
            };
            thread.start();

            XMLStreamWriter xml = xmlOutputFactory.createXMLStreamWriter(
                    writer);
            xml.writeStartDocument();
            xml.writeStartElement("CompleteMultipartUploadResult");
            xml.writeDefaultNamespace(AWS_XMLNS);
            xml.flush();

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
                throw exception.get();
            }

            if (Quirks.MULTIPART_REQUIRES_STUB.contains(getBlobStoreType(
                    blobStore))) {
                blobStore.removeBlob(containerName, uploadId);
            }

            // TODO: bogus value
            writeSimpleElement(xml, "Location",
                    "http://Example-Bucket.s3.amazonaws.com/" + blobName);

            writeSimpleElement(xml, "Bucket", containerName);
            writeSimpleElement(xml, "Key", blobName);

            if (eTag != null) {
                writeSimpleElement(xml, "ETag", maybeQuoteETag(eTag.get()));
            }

            xml.writeEndElement();
            xml.flush();
        } catch (XMLStreamException xse) {
            throw new IOException(xse);
        }

        addCorsResponseHeader(request, response);
    }

    private void handleAbortMultipartUpload(HttpServletRequest request,
            HttpServletResponse response, BlobStore blobStore,
            String containerName, String blobName,
            String uploadId) throws IOException, S3Exception {
        if (Quirks.MULTIPART_REQUIRES_STUB.contains(getBlobStoreType(
                blobStore))) {
            if (!blobStore.blobExists(containerName, uploadId)) {
                throw new S3Exception(S3ErrorCode.NO_SUCH_UPLOAD);
            }

            blobStore.removeBlob(containerName, uploadId);
        }


        addCorsResponseHeader(request, response);

        // TODO: how to reconstruct original mpu?
        MultipartUpload mpu = MultipartUpload.create(containerName,
                blobName, uploadId, createFakeBlobMetadata(blobStore),
                new PutOptions());
        blobStore.abortMultipartUpload(mpu);
        response.sendError(HttpServletResponse.SC_NO_CONTENT);
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
        MultipartUpload mpu = MultipartUpload.create(containerName,
                blobName, uploadId, createFakeBlobMetadata(blobStore),
                new PutOptions());

        List<MultipartPart> parts;
        if (getBlobStoreType(blobStore).equals("azureblob")) {
            // map Azure subparts back into S3 parts
            SortedMap<Integer, Long> map = new TreeMap<>();
            for (MultipartPart part : blobStore.listMultipartUpload(mpu)) {
                int virtualPartNumber = part.partNumber() / 10_000;
                Long size = map.get(virtualPartNumber);
                map.put(virtualPartNumber,
                        (size == null ? 0L : (long) size) + part.partSize());
            }
            parts = new ArrayList<>();
            for (Map.Entry<Integer, Long> entry : map.entrySet()) {
                String eTag = "";  // TODO: bogus value
                Date lastModified = null;  // TODO: bogus value
                parts.add(MultipartPart.create(entry.getKey(),
                        entry.getValue(), eTag, lastModified));
            }
        } else {
            parts = blobStore.listMultipartUpload(mpu);
        }

        String encodingType = request.getParameter("encoding-type");

        response.setCharacterEncoding(UTF_8);
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

            // TODO: pagination
/*
            writeSimpleElement(xml, "PartNumberMarker", "1");
            writeSimpleElement(xml, "NextPartNumberMarker", "3");
            writeSimpleElement(xml, "MaxParts", "2");
            writeSimpleElement(xml, "IsTruncated", "true");
*/

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

        addCorsResponseHeader(request, response);
    }

    private void handleCopyPart(HttpServletRequest request,
            HttpServletResponse response, BlobStore blobStore,
            String containerName, String blobName, String uploadId)
            throws IOException, S3Exception {
        // TODO: duplicated from handlePutBlob
        String copySourceHeader = request.getHeader(AwsHttpHeaders.COPY_SOURCE);
        copySourceHeader = URLDecoder.decode(copySourceHeader, UTF_8);
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

        GetOptions options = new GetOptions();
        String range = request.getHeader(AwsHttpHeaders.COPY_SOURCE_RANGE);
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
                    options.tail(Long.parseLong(ranges[1]));
                } else if (ranges[1].isEmpty()) {
                    options.startAt(Long.parseLong(ranges[0]));
                } else {
                    long start = Long.parseLong(ranges[0]);
                    long end = Long.parseLong(ranges[1]);
                    expectedSize = end - start + 1;
                    options.range(start, end);
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
                    ", inclusive", nfe, ImmutableMap.of(
                            "ArgumentName", "partNumber",
                            "ArgumentValue", partNumberString));
        }
        if (partNumber < 1 || partNumber > 10_000) {
            throw new S3Exception(S3ErrorCode.INVALID_ARGUMENT,
                    "Part number must be an integer between 1 and 10000" +
                    ", inclusive", (Throwable) null, ImmutableMap.of(
                            "ArgumentName", "partNumber",
                            "ArgumentValue", partNumberString));
        }

        // TODO: how to reconstruct original mpu?
        MultipartUpload mpu = MultipartUpload.create(containerName,
                blobName, uploadId, createFakeBlobMetadata(blobStore),
                new PutOptions());

        Blob blob = blobStore.getBlob(sourceContainerName, sourceBlobName,
                options);
        if (blob == null) {
            throw new S3Exception(S3ErrorCode.NO_SUCH_KEY);
        }

        BlobMetadata blobMetadata = blob.getMetadata();
        // HTTP GET allow overlong ranges but S3 CopyPart does not
        if (expectedSize != -1 && blobMetadata.getSize() < expectedSize) {
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
        String eTag = blobMetadata.getETag();
        if (eTag != null) {
            eTag = maybeQuoteETag(eTag);
            if (ifMatch != null && !ifMatch.equals(eTag)) {
                throw new S3Exception(S3ErrorCode.PRECONDITION_FAILED);
            }
            if (ifNoneMatch != null && ifNoneMatch.equals(eTag)) {
                throw new S3Exception(S3ErrorCode.PRECONDITION_FAILED);
            }
        }

        Date lastModified = blobMetadata.getLastModified();
        if (lastModified != null) {
            if (ifModifiedSince != -1 && lastModified.compareTo(
                    new Date(ifModifiedSince)) <= 0) {
                throw new S3Exception(S3ErrorCode.PRECONDITION_FAILED);
            }
            if (ifUnmodifiedSince != -1 && lastModified.compareTo(
                    new Date(ifUnmodifiedSince)) >= 0) {
                throw new S3Exception(S3ErrorCode.PRECONDITION_FAILED);
            }
        }

        long contentLength =
                blobMetadata.getContentMetadata().getContentLength();

        String blobStoreType = getBlobStoreType(blobStore);
        try (InputStream is = blob.getPayload().openStream()) {
            if (blobStoreType.equals("azureblob")) {
                // Azure has a smaller maximum part size than S3.  Split a
                // single S3 part multiple Azure parts.
                long azureMaximumMultipartPartSize =
                        blobStore.getMaximumMultipartPartSize();
                HashingInputStream his = new HashingInputStream(MD5, is);
                int subPartNumber = 0;
                for (long offset = 0; offset < contentLength;
                        offset += azureMaximumMultipartPartSize,
                        ++subPartNumber) {
                    Payload payload = Payloads.newInputStreamPayload(
                            new UncloseableInputStream(ByteStreams.limit(his,
                                    azureMaximumMultipartPartSize)));
                    payload.getContentMetadata().setContentLength(
                            Math.min(azureMaximumMultipartPartSize,
                                    contentLength - offset));
                    blobStore.uploadMultipartPart(mpu,
                            10_000 * partNumber + subPartNumber, payload);
                }
                eTag = BaseEncoding.base16().lowerCase().encode(
                        his.hash().asBytes());
            } else {
                Payload payload = Payloads.newInputStreamPayload(is);
                payload.getContentMetadata().setContentLength(contentLength);

                MultipartPart part = blobStore.uploadMultipartPart(mpu,
                        partNumber, payload);
                eTag = part.partETag();
            }
        }

        response.setCharacterEncoding(UTF_8);
        try (Writer writer = response.getWriter()) {
            response.setContentType(XML_CONTENT_TYPE);
            XMLStreamWriter xml = xmlOutputFactory.createXMLStreamWriter(
                    writer);
            xml.writeStartDocument();
            xml.writeStartElement("CopyObjectResult");
            xml.writeDefaultNamespace(AWS_XMLNS);

            writeSimpleElement(xml, "LastModified", formatDate(lastModified));
            if (eTag != null) {
                writeSimpleElement(xml, "ETag", maybeQuoteETag(eTag));
            }

            xml.writeEndElement();
            xml.flush();
        } catch (XMLStreamException xse) {
            throw new IOException(xse);
        }

        addCorsResponseHeader(request, response);
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
                        BaseEncoding.base64().decode(contentMD5String));
            } catch (IllegalArgumentException iae) {
                throw new S3Exception(S3ErrorCode.INVALID_DIGEST, iae);
            }
            if (contentMD5.bits() != MD5.bits()) {
                throw new S3Exception(S3ErrorCode.INVALID_DIGEST);
            }
        }

        if (contentLengthString == null) {
            throw new S3Exception(S3ErrorCode.MISSING_CONTENT_LENGTH);
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
                    ", inclusive", nfe, ImmutableMap.of(
                            "ArgumentName", "partNumber",
                            "ArgumentValue", partNumberString));
        }
        if (partNumber < 1 || partNumber > 10_000) {
            throw new S3Exception(S3ErrorCode.INVALID_ARGUMENT,
                    "Part number must be an integer between 1 and 10000" +
                    ", inclusive", (Throwable) null, ImmutableMap.of(
                            "ArgumentName", "partNumber",
                            "ArgumentValue", partNumberString));
        }

        // TODO: how to reconstruct original mpu?
        BlobMetadata blobMetadata;
        if (Quirks.MULTIPART_REQUIRES_STUB.contains(getBlobStoreType(
                blobStore))) {
            blobMetadata = blobStore.blobMetadata(containerName, uploadId);
        } else {
            blobMetadata = createFakeBlobMetadata(blobStore);
        }
        MultipartUpload mpu = MultipartUpload.create(containerName,
                blobName, uploadId, blobMetadata, new PutOptions());

        if (getBlobStoreType(blobStore).equals("azureblob")) {
            // Azure has a smaller maximum part size than S3.  Split a single
            // S3 part multiple Azure parts.
            long azureMaximumMultipartPartSize =
                        blobStore.getMaximumMultipartPartSize();
            HashingInputStream his = new HashingInputStream(MD5, is);
            int subPartNumber = 0;
            for (long offset = 0; offset < contentLength;
                    offset += azureMaximumMultipartPartSize,
                    ++subPartNumber) {
                Payload payload = Payloads.newInputStreamPayload(
                        ByteStreams.limit(his,
                                azureMaximumMultipartPartSize));
                payload.getContentMetadata().setContentLength(
                        Math.min(azureMaximumMultipartPartSize,
                                contentLength - offset));
                blobStore.uploadMultipartPart(mpu,
                        10_000 * partNumber + subPartNumber, payload);
            }
            response.addHeader(HttpHeaders.ETAG, maybeQuoteETag(
                    BaseEncoding.base16().lowerCase().encode(
                            his.hash().asBytes())));
        } else {
            MultipartPart part;
            Payload payload = Payloads.newInputStreamPayload(is);
            payload.getContentMetadata().setContentLength(contentLength);
            if (contentMD5 != null) {
                payload.getContentMetadata().setContentMD5(contentMD5);
            }

            part = blobStore.uploadMultipartPart(mpu, partNumber, payload);

            if (part.partETag() != null) {
                response.addHeader(HttpHeaders.ETAG,
                        maybeQuoteETag(part.partETag()));
            }
        }

        addCorsResponseHeader(request, response);
    }

    private static void addResponseHeaderWithOverride(
            HttpServletRequest request, HttpServletResponse response,
            String headerName, String overrideHeaderName, String value) {
        String override = request.getParameter(overrideHeaderName);

        // NPE in if value is null
        override = (override != null) ? override : value;

        if (override != null) {
            response.addHeader(headerName, override);
        }
    }

    private static void addMetadataToResponse(HttpServletRequest request,
            HttpServletResponse response,
            BlobMetadata metadata) {
        ContentMetadata contentMetadata =
                metadata.getContentMetadata();
        addResponseHeaderWithOverride(request, response,
                HttpHeaders.CACHE_CONTROL, "response-cache-control",
                contentMetadata.getCacheControl());
        addResponseHeaderWithOverride(request, response,
                HttpHeaders.CONTENT_ENCODING, "response-content-encoding",
                contentMetadata.getContentEncoding());
        addResponseHeaderWithOverride(request, response,
                HttpHeaders.CONTENT_LANGUAGE, "response-content-language",
                contentMetadata.getContentLanguage());
        addResponseHeaderWithOverride(request, response,
                HttpHeaders.CONTENT_DISPOSITION, "response-content-disposition",
                contentMetadata.getContentDisposition());
        response.addHeader(HttpHeaders.CONTENT_LENGTH,
                contentMetadata.getContentLength().toString());
        String overrideContentType = request.getParameter(
                "response-content-type");
        response.setContentType(overrideContentType != null ?
                overrideContentType : contentMetadata.getContentType());
        String eTag = metadata.getETag();
        if (eTag != null) {
            response.addHeader(HttpHeaders.ETAG, maybeQuoteETag(eTag));
        }
        String overrideExpires = request.getParameter("response-expires");
        if (overrideExpires != null) {
            response.addHeader(HttpHeaders.EXPIRES, overrideExpires);
        } else {
            Date expires = contentMetadata.getExpires();
            if (expires != null) {
                response.addDateHeader(HttpHeaders.EXPIRES, expires.getTime());
            }
        }
        response.addDateHeader(HttpHeaders.LAST_MODIFIED,
                metadata.getLastModified().getTime());
        Tier tier = metadata.getTier();
        if (tier != null) {
            response.addHeader(AwsHttpHeaders.STORAGE_CLASS,
                    StorageClass.fromTier(tier).toString());
        }
        for (Map.Entry<String, String> entry :
                metadata.getUserMetadata().entrySet()) {
            response.addHeader(USER_METADATA_PREFIX + entry.getKey(),
                    entry.getValue());
        }
    }

    /** Parse ISO 8601 timestamp into seconds since 1970. */
    private static long parseIso8601(String date) {
        SimpleDateFormat formatter = new SimpleDateFormat(
                "yyyyMMdd'T'HHmmss'Z'");
        formatter.setTimeZone(TimeZone.getTimeZone("UTC"));
        try {
            return formatter.parse(date).getTime() / 1000;
        } catch (ParseException pe) {
            throw new IllegalArgumentException(pe);
        }
    }

    private void isTimeSkewed(long date) throws S3Exception  {
        if (date < 0) {
            throw new S3Exception(S3ErrorCode.ACCESS_DENIED);
        }
        long now = System.currentTimeMillis() / 1000;
        if (now + maximumTimeSkew < date || now - maximumTimeSkew > date) {
            logger.debug("time skewed {} {}", date, now);
            throw new S3Exception(S3ErrorCode.REQUEST_TIME_TOO_SKEWED);
        }
    }

    // cannot call BlobStore.getContext().utils().date().iso8601DateFormatsince
    // it has unwanted millisecond precision
    private static String formatDate(Date date) {
        SimpleDateFormat formatter = new SimpleDateFormat(
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

            for (Map.Entry<String, String> entry : elements.entrySet()) {
                writeSimpleElement(xml, entry.getKey(), entry.getValue());
            }

            writeSimpleElement(xml, "RequestId", FAKE_REQUEST_ID);

            xml.writeEndElement();
            xml.flush();
        } catch (XMLStreamException xse) {
            throw new IOException(xse);
        }
    }

    private void addCorsResponseHeader(HttpServletRequest request,
          HttpServletResponse response) {
        String corsOrigin = request.getHeader(HttpHeaders.ORIGIN);
        if (!Strings.isNullOrEmpty(corsOrigin) &&
                corsRules.isOriginAllowed(corsOrigin)) {
            response.addHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN,
                    corsOrigin);
            response.addHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS,
                    request.getMethod());
        }
    }

    private static void addContentMetdataFromHttpRequest(
            BlobBuilder.PayloadBlobBuilder builder,
            HttpServletRequest request) {
        ImmutableMap.Builder<String, String> userMetadata =
                ImmutableMap.builder();
        for (String headerName : Collections.list(request.getHeaderNames())) {
            if (startsWithIgnoreCase(headerName, USER_METADATA_PREFIX)) {
                userMetadata.put(
                        headerName.substring(USER_METADATA_PREFIX.length()),
                        Strings.nullToEmpty(request.getHeader(headerName)));
            }
        }
        builder.cacheControl(request.getHeader(
                        HttpHeaders.CACHE_CONTROL))
                .contentDisposition(request.getHeader(
                        HttpHeaders.CONTENT_DISPOSITION))
                .contentEncoding(request.getHeader(
                        HttpHeaders.CONTENT_ENCODING))
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

    private static void writeSimpleElement(XMLStreamWriter xml,
            String elementName, String characters) throws XMLStreamException {
        xml.writeStartElement(elementName);
        xml.writeCharacters(characters);
        xml.writeEndElement();
    }

    private static BlobMetadata createFakeBlobMetadata(BlobStore blobStore) {
        return blobStore.blobBuilder("fake-name")
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

    private static boolean startsWithIgnoreCase(String string, String prefix) {
        return string.toLowerCase().startsWith(prefix.toLowerCase());
    }

    private static boolean isField(String string, String field) {
        return startsWithIgnoreCase(string,
                "Content-Disposition: form-data; name=\"" + field + "\"");
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

    private static final class UncloseableInputStream
            extends FilterInputStream {
        UncloseableInputStream(InputStream is) {
            super(is);
        }

        @Override
        public void close() throws IOException {
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

    private static boolean constantTimeEquals(String x, String y) {
        return MessageDigest.isEqual(x.getBytes(StandardCharsets.UTF_8),
                y.getBytes(StandardCharsets.UTF_8));
    }
}
