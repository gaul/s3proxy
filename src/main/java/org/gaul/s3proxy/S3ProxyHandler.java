/*
 * Copyright 2014-2016 Andrew Gaul <andrew@gaul.org>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
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
import java.io.ByteArrayOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PushbackInputStream;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.regex.Pattern;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;

import com.fasterxml.jackson.dataformat.xml.XmlMapper;
import com.google.common.base.Joiner;
import com.google.common.base.Objects;
import com.google.common.base.Optional;
import com.google.common.base.Strings;
import com.google.common.base.Throwables;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Iterables;
import com.google.common.collect.Maps;
import com.google.common.collect.SortedSetMultimap;
import com.google.common.collect.TreeMultimap;
import com.google.common.hash.HashCode;
import com.google.common.hash.Hashing;
import com.google.common.hash.HashingInputStream;
import com.google.common.io.BaseEncoding;
import com.google.common.io.ByteSource;
import com.google.common.io.ByteStreams;
import com.google.common.io.FileBackedOutputStream;
import com.google.common.net.HostAndPort;
import com.google.common.net.HttpHeaders;
import com.google.common.net.PercentEscaper;

import org.apache.commons.fileupload.MultipartStream;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.ContainerNotFoundException;
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
import org.jclouds.blobstore.options.CopyOptions;
import org.jclouds.blobstore.options.CreateContainerOptions;
import org.jclouds.blobstore.options.GetOptions;
import org.jclouds.blobstore.options.ListContainerOptions;
import org.jclouds.blobstore.options.PutOptions;
import org.jclouds.domain.Location;
import org.jclouds.http.HttpResponse;
import org.jclouds.http.HttpResponseException;
import org.jclouds.io.ContentMetadata;
import org.jclouds.io.ContentMetadataBuilder;
import org.jclouds.io.Payload;
import org.jclouds.io.Payloads;
import org.jclouds.rest.AuthorizationException;
import org.jclouds.util.Throwables2;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

final class S3ProxyHandler extends AbstractHandler {
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
    private static final Pattern VALID_BUCKET_PATTERN =
            Pattern.compile("[a-zA-Z0-9._-]+");
    private static final Set<String> SIGNED_SUBRESOURCES = ImmutableSet.of(
            "acl", "delete", "lifecycle", "location", "logging", "notification",
            "partNumber", "policy", "requestPayment", "torrent", "uploadId",
            "uploads", "versionId", "versioning", "versions", "website"
    );
    private static final Set<String> SUPPORTED_PARAMETERS = ImmutableSet.of(
            "acl",
            "AWSAccessKeyId",
            "delete",
            "delimiter",
            "encoding-type",
            "Expires",
            "location",
            "marker",
            "max-keys",
            "partNumber",
            "prefix",
            "response-cache-control",
            "response-content-disposition",
            "response-content-encoding",
            "response-content-language",
            "response-content-type",
            "response-expires",
            "Signature",
            "uploadId",
            "uploads",
            "X-Amz-Expires"
    );
    /** All supported x-amz- headers, except for x-amz-meta- user metadata. */
    private static final Set<String> SUPPORTED_X_AMZ_HEADERS = ImmutableSet.of(
            "x-amz-acl",
            "x-amz-content-sha256",
            "x-amz-copy-source",
            "x-amz-copy-source-if-match",
            "x-amz-copy-source-if-modified-since",
            "x-amz-copy-source-if-none-match",
            "x-amz-copy-source-if-unmodified-since",
            "x-amz-copy-source-range",
            "x-amz-date",
            "x-amz-decoded-content-length",
            "x-amz-metadata-directive",
            "x-amz-storage-class"  // ignored
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
    private static final PercentEscaper AWS_URL_PARAMETER_ESCAPER =
            new PercentEscaper("-_.~", false);
    // TODO: configurable fileThreshold
    private static final int B2_PUT_BLOB_BUFFER_SIZE = 1024 * 1024;

    private final boolean anonymousIdentity;
    private final Optional<String> virtualHost;
    private final long v4MaxNonChunkedRequestSize;
    private final boolean ignoreUnknownHeaders;
    private final boolean corsAllowAll;
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

    S3ProxyHandler(final BlobStore blobStore, final String identity,
            final String credential, Optional<String> virtualHost,
            long v4MaxNonChunkedRequestSize, boolean ignoreUnknownHeaders,
            boolean corsAllowAll) {
        if (identity != null) {
            anonymousIdentity = false;
            blobStoreLocator = new BlobStoreLocator() {
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
        this.virtualHost = requireNonNull(virtualHost);
        this.v4MaxNonChunkedRequestSize = v4MaxNonChunkedRequestSize;
        this.ignoreUnknownHeaders = ignoreUnknownHeaders;
        this.corsAllowAll = corsAllowAll;
        this.defaultBlobStore = blobStore;
        xmlOutputFactory.setProperty("javax.xml.stream.isRepairingNamespaces",
                Boolean.FALSE);
    }

    private static String getBlobStoreType(BlobStore blobStore) {
        return blobStore.getContext().unwrap().getProviderMetadata().getId();
    }

    @Override
    public void handle(String target, Request baseRequest,
            HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        try (InputStream is = request.getInputStream()) {
            doHandle(baseRequest, request, response, is);
            baseRequest.setHandled(true);
        } catch (ContainerNotFoundException cnfe) {
            S3ErrorCode code = S3ErrorCode.NO_SUCH_BUCKET;
            sendSimpleErrorResponse(request, response, code, code.getMessage(),
                    ImmutableMap.<String, String>of());
            baseRequest.setHandled(true);
            return;
        } catch (HttpResponseException hre) {
            HttpResponse httpResponse = hre.getResponse();
            response.sendError(httpResponse == null ?
                    HttpServletResponse.SC_INTERNAL_SERVER_ERROR :
                    httpResponse.getStatusCode());
            baseRequest.setHandled(true);
            return;
        } catch (IllegalArgumentException iae) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST);
            baseRequest.setHandled(true);
            return;
        } catch (KeyNotFoundException knfe) {
            S3ErrorCode code = S3ErrorCode.NO_SUCH_KEY;
            sendSimpleErrorResponse(request, response, code, code.getMessage(),
                    ImmutableMap.<String, String>of());
            baseRequest.setHandled(true);
            return;
        } catch (S3Exception se) {
            sendSimpleErrorResponse(request, response, se.getError(),
                    se.getMessage(), se.getElements());
            baseRequest.setHandled(true);
            return;
        } catch (UnsupportedOperationException uoe) {
            response.sendError(HttpServletResponse.SC_NOT_IMPLEMENTED);
            baseRequest.setHandled(true);
            return;
        } catch (Throwable throwable) {
            if (Throwables2.getFirstThrowableOfType(throwable,
                    AuthorizationException.class) != null) {
                S3ErrorCode code = S3ErrorCode.ACCESS_DENIED;
                sendSimpleErrorResponse(request, response, code,
                        code.getMessage(), ImmutableMap.<String, String>of());
                baseRequest.setHandled(true);
                return;
            } else if (Throwables2.getFirstThrowableOfType(throwable,
                    TimeoutException.class) != null) {
                S3ErrorCode code = S3ErrorCode.REQUEST_TIMEOUT;
                sendSimpleErrorResponse(request, response, code,
                        code.getMessage(), ImmutableMap.<String, String>of());
                baseRequest.setHandled(true);
                return;
            } else {
                throw throwable;
            }
        }
    }

    private void doHandle(Request baseRequest, HttpServletRequest request,
            HttpServletResponse response, InputStream is)
            throws IOException, S3Exception {
        String method = request.getMethod();
        String uri = request.getRequestURI();
        logger.debug("request: {}", request);
        String hostHeader = request.getHeader(HttpHeaders.HOST);
        if (hostHeader != null && virtualHost.isPresent()) {
            hostHeader = HostAndPort.fromString(hostHeader).getHostText();
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
            } else if (headerName.equalsIgnoreCase("x-amz-date")) {
                hasXAmzDateHeader = true;
            }
        }

        // when access information is not provided in request header,
        // treat it as anonymous, return all public accessible information
        if (!anonymousIdentity &&
                (method.equals("GET") || method.equals("HEAD") ||
                method.equals("POST")) &&
                request.getHeader(HttpHeaders.AUTHORIZATION) == null &&
                request.getParameter("AWSAccessKeyId") == null &&
                defaultBlobStore != null) {
            doHandleAnonymous(request, response, is, uri, defaultBlobStore);
            return;
        }

        if (!anonymousIdentity && !hasDateHeader && !hasXAmzDateHeader &&
                request.getParameter("Expires") == null &&
                request.getParameter("X-Amz-Expires") == null) {
            throw new S3Exception(S3ErrorCode.ACCESS_DENIED,
                    "AWS authentication requires a valid Date or" +
                    " x-amz-date header");
        }

        // TODO: apply sanity checks to X-Amz-Date
        if (hasDateHeader) {
            long date;
            try {
                date = request.getDateHeader(HttpHeaders.DATE);
            } catch (IllegalArgumentException iae) {
                throw new S3Exception(S3ErrorCode.ACCESS_DENIED, iae);
            }
            if (date < 0) {
                throw new S3Exception(S3ErrorCode.ACCESS_DENIED);
            }
            long now = System.currentTimeMillis();
            if (now + TimeUnit.DAYS.toMillis(1) < date ||
                    now - TimeUnit.DAYS.toMillis(1) > date) {
                throw new S3Exception(S3ErrorCode.REQUEST_TIME_TOO_SKEWED);
            }
        }

        BlobStore blobStore;
        String requestIdentity = null;
        String headerAuthorization = request.getHeader(
                HttpHeaders.AUTHORIZATION);
        S3AuthorizationHeader authHeader = null;

        if (!anonymousIdentity) {
            if (headerAuthorization == null) {
                String identity = request.getParameter("AWSAccessKeyId");
                String signature = request.getParameter("Signature");
                if (identity == null || signature == null) {
                    throw new S3Exception(S3ErrorCode.ACCESS_DENIED);
                }
                headerAuthorization = "AWS " + identity + ":" + signature;
            }

            try {
                authHeader = new S3AuthorizationHeader(headerAuthorization);
            } catch (IllegalArgumentException e) {
                throw new S3Exception(S3ErrorCode.INVALID_ARGUMENT);
            }
            requestIdentity = authHeader.identity;
        }

        String[] path = uri.split("/", 3);
        for (int i = 0; i < path.length; i++) {
            path[i] = URLDecoder.decode(path[i], "UTF-8");
        }

        Map.Entry<String, BlobStore> provider =
                blobStoreLocator.locateBlobStore(
                        requestIdentity, path.length > 1 ? path[1] : null,
                        path.length > 2 ? path[2] : null);
        if (anonymousIdentity) {
            blobStore = provider.getValue();
        } else if (requestIdentity == null) {
            throw new S3Exception(S3ErrorCode.ACCESS_DENIED);
        } else {
            if (provider == null) {
                throw new S3Exception(S3ErrorCode.INVALID_ACCESS_KEY_ID);
            }

            String credential = provider.getKey();
            blobStore = provider.getValue();

            String expiresString =
                    Optional.fromNullable(request.getParameter("Expires"))
                    .or(Optional.fromNullable(
                            request.getParameter("X-Amz-Expires")))
                    .orNull();
            if (expiresString != null) {
                long expires = Long.parseLong(expiresString);
                long nowSeconds = System.currentTimeMillis() / 1000;
                if (nowSeconds > expires) {
                    throw new S3Exception(S3ErrorCode.ACCESS_DENIED);
                }
            }

            String expectedSignature = null;
            if (authHeader.hmacAlgorithm == null) {
                expectedSignature = createAuthorizationSignature(request,
                        uri, requestIdentity, credential);
            } else {
                try {
                    byte[] payload;
                    if ("STREAMING-AWS4-HMAC-SHA256-PAYLOAD".equals(
                            request.getHeader("x-amz-content-sha256"))) {
                        payload = new byte[0];
                        is = new ChunkedInputStream(is);
                    } else {
                        // buffer the entire stream to calculate digest
                        payload = ByteStreams.toByteArray(ByteStreams.limit(
                                is, v4MaxNonChunkedRequestSize + 1));
                        if (payload.length == v4MaxNonChunkedRequestSize + 1) {
                            throw new S3Exception(
                                    S3ErrorCode.MAX_MESSAGE_LENGTH_EXCEEDED);
                        }
                        is = new ByteArrayInputStream(payload);
                    }
                    expectedSignature = createAuthorizationSignatureV4(
                            baseRequest, payload, uri, credential);
                } catch (InvalidKeyException | NoSuchAlgorithmException e) {
                    throw new S3Exception(S3ErrorCode.INVALID_ARGUMENT);
                }
            }

            if (!expectedSignature.equals(authHeader.signature)) {
                throw new S3Exception(S3ErrorCode.SIGNATURE_DOES_NOT_MATCH);
            }
        }

        // emit NotImplemented for unknown parameters
        for (String parameter : Collections.list(
                request.getParameterNames())) {
            if (!SUPPORTED_PARAMETERS.contains(parameter)) {
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
            if (headerName.startsWith("x-amz-meta-")) {
                continue;
            }
            if (!SUPPORTED_X_AMZ_HEADERS.contains(headerName.toLowerCase())) {
                logger.error("Unknown header {} with URI {}",
                        headerName, request.getRequestURI());
                throw new S3Exception(S3ErrorCode.NOT_IMPLEMENTED);
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
                    handleContainerLocation(response, blobStore, path[1]);
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
                handleContainerExists(response, blobStore, path[1]);
                return;
            } else {
                handleBlobMetadata(request, response, blobStore, path[1],
                        path[2]);
                return;
            }
        case "POST":
            if ("".equals(request.getParameter("delete"))) {
                handleMultiBlobRemove(request, response, is, blobStore,
                        path[1]);
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
                if (request.getHeader("x-amz-copy-source") != null) {
                    handleCopyPart(request, response, blobStore, path[1],
                            path[2], uploadId);
                } else {
                    handleUploadPart(request, response, is, blobStore, path[1],
                            path[2], uploadId);
                }
                return;
            } else if (request.getHeader("x-amz-copy-source") != null) {
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
        default:
            break;
        }
        logger.error("Unknown method {} with URI {}",
                method, request.getRequestURI());
        throw new S3Exception(S3ErrorCode.NOT_IMPLEMENTED);
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
                handleContainerList(response, blobStore);
                return;
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
                BlobAccess access = blobStore.getBlobAccess(containerName,
                        blobName);
                if (access != BlobAccess.PUBLIC_READ) {
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
                BlobAccess access = blobStore.getBlobAccess(containerName,
                        blobName);
                if (access != BlobAccess.PUBLIC_READ) {
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
        default:
            break;
        }
        logger.error("Unknown method {} with URI {}",
                method, request.getRequestURI());
        throw new S3Exception(S3ErrorCode.NOT_IMPLEMENTED);
    }

    private void handleGetContainerAcl(HttpServletResponse response,
            BlobStore blobStore, String containerName) throws IOException {
        ContainerAccess access = blobStore.getContainerAccess(containerName);

        try (Writer writer = response.getWriter()) {
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

    private void handleSetContainerAcl(HttpServletRequest request,
            HttpServletResponse response, InputStream is, BlobStore blobStore,
            String containerName) throws IOException, S3Exception {
        ContainerAccess access;

        String cannedAcl = request.getHeader("x-amz-acl");
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

        try (Writer writer = response.getWriter()) {
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

    private void handleSetBlobAcl(HttpServletRequest request,
            HttpServletResponse response, InputStream is, BlobStore blobStore,
            String containerName, String blobName)
            throws IOException, S3Exception {
        BlobAccess access;

        String cannedAcl = request.getHeader("x-amz-acl");
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

        try (Writer writer = response.getWriter()) {
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

    private void handleContainerLocation(HttpServletResponse response,
            BlobStore blobStore, String containerName) throws IOException {
        try (Writer writer = response.getWriter()) {
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

        try (Writer writer = response.getWriter()) {
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

    private void handleContainerExists(HttpServletResponse response,
            BlobStore blobStore, String containerName)
            throws IOException, S3Exception {
        if (!blobStore.containerExists(containerName)) {
            throw new S3Exception(S3ErrorCode.NO_SUCH_BUCKET);
        }
    }

    private void handleContainerCreate(HttpServletRequest request,
            HttpServletResponse response, InputStream is, BlobStore blobStore,
            String containerName) throws IOException, S3Exception {
        if (containerName.isEmpty()) {
            throw new S3Exception(S3ErrorCode.METHOD_NOT_ALLOWED);
        }
        if (containerName.length() < 3 || containerName.length() > 255 ||
                !VALID_BUCKET_PATTERN.matcher(containerName).matches()) {
            throw new S3Exception(S3ErrorCode.INVALID_BUCKET_NAME);
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
        String acl = request.getHeader("x-amz-acl");
        if ("public-read".equalsIgnoreCase(acl)) {
            options.publicRead();
        }

        boolean created;
        try {
            created = blobStore.createContainerInLocation(location,
                    containerName, options);
        } catch (AuthorizationException ae) {
            throw new S3Exception(S3ErrorCode.BUCKET_ALREADY_EXISTS, ae);
        }
        if (!created) {
            throw new S3Exception(S3ErrorCode.BUCKET_ALREADY_OWNED_BY_YOU,
                    null, null, ImmutableMap.of("BucketName", containerName));
        }
    }

    private void handleContainerDelete(HttpServletResponse response,
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
        String marker = request.getParameter("marker");
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
        int maxKeys = 1000;
        String maxKeysString = request.getParameter("max-keys");
        if (maxKeysString != null) {
            try {
                maxKeys = Integer.parseInt(maxKeysString);
            } catch (NumberFormatException nfe) {
                throw new S3Exception(S3ErrorCode.INVALID_ARGUMENT, nfe);
            }
        }
        options.maxResults(maxKeys);

        response.setCharacterEncoding("UTF-8");

        PageSet<? extends StorageMetadata> set = blobStore.list(containerName,
                options);

        try (Writer writer = response.getWriter()) {
            response.setStatus(HttpServletResponse.SC_OK);
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

            writeSimpleElement(xml, "MaxKeys", String.valueOf(maxKeys));

            if (marker == null) {
                xml.writeEmptyElement("Marker");
            } else {
                writeSimpleElement(xml, "Marker", encodeBlob(
                        encodingType, marker));
            }

            if (delimiter != null) {
                writeSimpleElement(xml, "Delimiter", encodeBlob(
                        encodingType, delimiter));
            }

            if (encodingType != null && encodingType.equals("url")) {
                writeSimpleElement(xml, "EncodingType", encodingType);
            }

            String nextMarker = set.getNextMarker();
            if (nextMarker != null) {
                writeSimpleElement(xml, "IsTruncated", "true");
                writeSimpleElement(xml, "NextMarker", encodeBlob(
                        encodingType, nextMarker));
                if (Quirks.OPAQUE_MARKERS.contains(blobStoreType)) {
                    lastKeyToMarker.put(Maps.immutableEntry(containerName,
                            Iterables.getLast(set).getName()), nextMarker);
                }
            } else {
                writeSimpleElement(xml, "IsTruncated", "false");
            }

            Set<String> commonPrefixes = new TreeSet<>();
            for (StorageMetadata metadata : set) {
                switch (metadata.getType()) {
                case FOLDER:
                    continue;
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
                            blobStore.getContext().utils().date()
                                    .iso8601DateFormat(lastModified));
                }

                String eTag = metadata.getETag();
                if (eTag != null) {
                    writeSimpleElement(xml, "ETag", maybeQuoteETag(eTag));
                }

                writeSimpleElement(xml, "Size",
                        String.valueOf(metadata.getSize()));
                writeSimpleElement(xml, "StorageClass", "STANDARD");

                writeOwnerStanza(xml);

                xml.writeEndElement();
            }

            for (String commonPrefix : commonPrefixes) {
                xml.writeStartElement("CommonPrefixes");

                writeSimpleElement(xml, "Prefix", commonPrefix);

                xml.writeEndElement();
            }

            xml.writeEndElement();
            xml.flush();
        } catch (XMLStreamException xse) {
            throw new IOException(xse);
        }
    }

    private void handleBlobRemove(HttpServletResponse response,
            BlobStore blobStore, String containerName,
            String blobName) throws IOException, S3Exception {
        blobStore.removeBlob(containerName, blobName);
        response.sendError(HttpServletResponse.SC_NO_CONTENT);
    }

    private void handleMultiBlobRemove(HttpServletRequest request,
            HttpServletResponse response, InputStream is, BlobStore blobStore,
            String containerName) throws IOException {
        DeleteMultipleObjectsRequest dmor = new XmlMapper().readValue(
                is, DeleteMultipleObjectsRequest.class);
        Collection<String> blobNames = new ArrayList<>();
        for (DeleteMultipleObjectsRequest.S3Object s3Object :
                dmor.objects) {
            blobNames.add(s3Object.key);
        }

        blobStore.removeBlobs(containerName, blobNames);

        try (Writer writer = response.getWriter()) {
            XMLStreamWriter xml = xmlOutputFactory.createXMLStreamWriter(
                    writer);
            xml.writeStartDocument();
            xml.writeStartElement("DeleteResult");
            xml.writeDefaultNamespace(AWS_XMLNS);
            for (String blobName : blobNames) {
                xml.writeStartElement("Deleted");

                writeSimpleElement(xml, "Key", blobName);

                xml.writeEndElement();
            }
            // TODO: emit error stanza
            xml.writeEndElement();
            xml.flush();
        } catch (XMLStreamException xse) {
            throw new IOException(xse);
        }
    }

    private void handleBlobMetadata(HttpServletRequest request,
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

        Blob blob;
        try {
            blob = blobStore.getBlob(containerName, blobName, options);
        } catch (IllegalArgumentException iae) {
            throw new S3Exception(S3ErrorCode.INVALID_RANGE);
        }
        if (blob == null) {
            throw new S3Exception(S3ErrorCode.NO_SUCH_KEY);
        }

        response.setStatus(status);

        if (corsAllowAll) {
            response.addHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "*");
        }

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
        String copySourceHeader = request.getHeader("x-amz-copy-source");
        copySourceHeader = URLDecoder.decode(copySourceHeader, "UTF-8");
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
                "x-amz-metadata-directive"));

        if (sourceContainerName.equals(destContainerName) &&
                sourceBlobName.equals(destBlobName) &&
                !replaceMetadata) {
            throw new S3Exception(S3ErrorCode.INVALID_REQUEST);
        }

        CopyOptions.Builder options = CopyOptions.builder();

        String ifMatch = request.getHeader("x-amz-copy-source-if-match");
        if (ifMatch != null) {
            options.ifMatch(ifMatch);
        }
        String ifNoneMatch = request.getHeader(
                "x-amz-copy-source-if-none-match");
        if (ifNoneMatch != null) {
            options.ifNoneMatch(ifNoneMatch);
        }
        long ifModifiedSince = request.getDateHeader(
                "x-amz-copy-source-if-modified-since");
        if (ifModifiedSince != -1) {
            options.ifModifiedSince(new Date(ifModifiedSince));
        }
        long ifUnmodifiedSince = request.getDateHeader(
                "x-amz-copy-source-if-unmodified-since");
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
        String cannedAcl = request.getHeader("x-amz-acl");
        if (cannedAcl != null && !cannedAcl.equalsIgnoreCase("private")) {
            handleSetBlobAcl(request, response, is, blobStore,
                    destContainerName, destBlobName);
        }

        BlobMetadata blobMetadata = blobStore.blobMetadata(destContainerName,
                destBlobName);
        try (Writer writer = response.getWriter()) {
            XMLStreamWriter xml = xmlOutputFactory.createXMLStreamWriter(
                    writer);
            xml.writeStartDocument();
            xml.writeStartElement("CopyObjectResult");
            xml.writeDefaultNamespace(AWS_XMLNS);

            writeSimpleElement(xml, "LastModified",
                    blobStore.getContext().utils().date()
                            .iso8601DateFormat(blobMetadata.getLastModified()));
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
                    "x-amz-decoded-content-length")) {
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
            if (contentMD5.bits() != Hashing.md5().bits()) {
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
        String cannedAcl = request.getHeader("x-amz-acl");
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
                contentLength > 64 * 1024 * 1024) {
            options.multipart(true);
        }

        FileBackedOutputStream fbos = null;
        String eTag;
        try {
            BlobBuilder.PayloadBlobBuilder builder;
            if (blobStoreType.equals("b2")) {
                // B2 requires a repeatable payload to calculate the SHA1 hash
                fbos = new FileBackedOutputStream(B2_PUT_BLOB_BUFFER_SIZE);
                ByteStreams.copy(is, fbos);
                fbos.close();
                builder = blobStore.blobBuilder(blobName)
                        .payload(fbos.asByteSource());
            } else {
                builder = blobStore.blobBuilder(blobName)
                        .payload(is);
            }

            builder.contentLength(contentLength);

            addContentMetdataFromHttpRequest(builder, request);
            if (contentMD5 != null) {
                builder = builder.contentMD5(contentMD5);
            }

            eTag = blobStore.putBlob(containerName, builder.build(),
                    options);
        } catch (HttpResponseException hre) {
            HttpResponse hr = hre.getResponse();
            if (hr == null) {
                return;
            }
            int status = hr.getStatusCode();
            switch (status) {
            case HttpServletResponse.SC_BAD_REQUEST:
            case 422:  // Swift returns 422 Unprocessable Entity
                throw new S3Exception(S3ErrorCode.BAD_DIGEST);
            default:
                // TODO: emit hre.getContent() ?
                response.sendError(status);
                break;
            }
            return;
        } finally {
            if (fbos != null) {
                fbos.reset();
            }
        }

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
        byte[] payload = null;
        MultipartStream multipartStream = new MultipartStream(is,
                boundary.getBytes(StandardCharsets.UTF_8), 4096, null);
        boolean nextPart = multipartStream.skipPreamble();
        while (nextPart) {
            String header = multipartStream.readHeaders();
            try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
                multipartStream.readBodyData(baos);
                if (startsWithIgnoreCase(header,
                        "Content-Disposition: form-data;" +
                        " name=\"acl\"")) {
                    // TODO: acl
                } else if (startsWithIgnoreCase(header,
                        "Content-Disposition: form-data;" +
                        " name=\"AWSAccessKeyId\"")) {
                    identity = new String(baos.toByteArray());
                } else if (startsWithIgnoreCase(header,
                        "Content-Disposition: form-data;" +
                        " name=\"Content-Type\"")) {
                    contentType = new String(baos.toByteArray());
                } else if (startsWithIgnoreCase(header,
                        "Content-Disposition: form-data;" +
                        " name=\"file\"")) {
                    // TODO: buffers entire payload
                    payload = baos.toByteArray();
                } else if (startsWithIgnoreCase(header,
                        "Content-Disposition: form-data;" +
                        " name=\"key\"")) {
                    blobName = new String(baos.toByteArray());
                } else if (startsWithIgnoreCase(header,
                        "Content-Disposition: form-data;" +
                        " name=\"policy\"")) {
                    policy = baos.toByteArray();
                } else if (startsWithIgnoreCase(header,
                        "Content-Disposition: form-data;" +
                        " name=\"signature\"")) {
                    signature = new String(baos.toByteArray());
                }
            }
            nextPart = multipartStream.readBoundary();
        }

        if (identity == null || signature == null || blobName == null ||
                policy == null) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        Map.Entry<String, BlobStore> provider =
                blobStoreLocator.locateBlobStore(identity, null, null);
        if (provider == null) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            return;
        }
        String credential = provider.getKey();

        Mac mac;
        try {
            mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(credential.getBytes(
                    StandardCharsets.UTF_8), "HmacSHA1"));
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            throw Throwables.propagate(e);
        }
        String expectedSignature = BaseEncoding.base64().encode(
                mac.doFinal(policy));
        if (!signature.equals(expectedSignature)) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            return;
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

        BlobAccess access;
        String cannedAcl = request.getHeader("x-amz-acl");
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

        // S3 requires blob metadata during the initiate call while Azure and
        // Swift require it in the complete call.  Store a stub blob which
        // allows reproducing this metadata later.
        blobStore.putBlob(containerName, builder.name(mpu.id()).build(),
                options);

        try (Writer writer = response.getWriter()) {
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
            HttpServletResponse response, InputStream is, BlobStore blobStore,
            String containerName, String blobName, String uploadId)
            throws IOException, S3Exception {
        Blob stubBlob = blobStore.getBlob(containerName, uploadId);
        BlobAccess access = blobStore.getBlobAccess(containerName, uploadId);
        MultipartUpload mpu = MultipartUpload.create(containerName,
                blobName, uploadId, stubBlob.getMetadata(),
                new PutOptions().setBlobAccess(access));

        // List parts to get part sizes and to map multiple Azure parts
        // into single parts.
        ImmutableMap.Builder<Integer, MultipartPart> builder =
                ImmutableMap.builder();
        for (MultipartPart part : blobStore.listMultipartUpload(mpu)) {
            builder.put(part.partNumber(), part);
        }
        ImmutableMap<Integer, MultipartPart> partsByListing = builder.build();

        List<MultipartPart> parts = new ArrayList<>();
        String blobStoreType = getBlobStoreType(blobStore);
        if (blobStoreType.equals("azureblob")) {
            // TODO: how to sanity check parts?
            for (MultipartPart part : blobStore.listMultipartUpload(mpu)) {
                parts.add(part);
            }
        } else {
            CompleteMultipartUploadRequest cmu = new XmlMapper().readValue(
                    is, CompleteMultipartUploadRequest.class);
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
                if (partSize < blobStore.getMinimumMultipartPartSize() &&
                        partSize != -1 && it.hasNext()) {
                    throw new S3Exception(S3ErrorCode.ENTITY_TOO_SMALL);
                }
                if (part.partETag() != null &&
                        !equalsIgnoringSurroundingQuotes(part.partETag(),
                                entry.getValue())) {
                    throw new S3Exception(S3ErrorCode.INVALID_PART);
                }
                parts.add(MultipartPart.create(entry.getKey(),
                        partSize, part.partETag()));
            }
        }

        if (parts.isEmpty()) {
            // Amazon requires at least one part
            throw new S3Exception(S3ErrorCode.MALFORMED_X_M_L);
        }

        String eTag = blobStore.completeMultipartUpload(mpu, parts);

        blobStore.removeBlob(containerName, stubBlob.getMetadata().getName());

        try (Writer writer = response.getWriter()) {
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

            if (eTag != null) {
                writeSimpleElement(xml, "ETag", maybeQuoteETag(eTag));
            }

            xml.writeEndElement();
            xml.flush();
        } catch (XMLStreamException xse) {
            throw new IOException(xse);
        }
    }

    private void handleAbortMultipartUpload(HttpServletRequest request,
            HttpServletResponse response, BlobStore blobStore,
            String containerName, String blobName, String uploadId)
            throws IOException, S3Exception {
        if (!blobStore.blobExists(containerName, uploadId)) {
            throw new S3Exception(S3ErrorCode.NO_SUCH_UPLOAD);
        }

        blobStore.removeBlob(containerName, uploadId);

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
            throws IOException {
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
                parts.add(MultipartPart.create(entry.getKey(),
                        entry.getValue(), eTag));
            }
        } else {
            parts = blobStore.listMultipartUpload(mpu);
        }

        String encodingType = request.getParameter("encoding-type");

        try (Writer writer = response.getWriter()) {
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

                Date lastModified = null;  // TODO: not part of MultipartPart
                if (lastModified != null) {
                    writeSimpleElement(xml, "LastModified",
                            blobStore.getContext().utils().date()
                                    .iso8601DateFormat(lastModified));
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
            String containerName, String blobName, String uploadId)
            throws IOException, S3Exception {
        // TODO: duplicated from handlePutBlob
        String copySourceHeader = request.getHeader("x-amz-copy-source");
        copySourceHeader = URLDecoder.decode(copySourceHeader, "UTF-8");
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
        String range = request.getHeader("x-amz-copy-source-range");
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

        String ifMatch = request.getHeader(
                "x-amz-copy-source-if-match");
        String ifNoneMatch = request.getHeader(
                "x-amz-copy-source-if-modified-since");
        long ifModifiedSince = request.getDateHeader(
                "x-amz-copy-source-if-none-match");
        long ifUnmodifiedSince = request.getDateHeader(
                "x-amz-copy-source-if-unmodified-since");
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
        FileBackedOutputStream fbos = null;
        try (InputStream is = blob.getPayload().openStream()) {
            if (blobStoreType.equals("azureblob")) {
                // Azure has a maximum part size of 4 MB while S3 has a minimum
                // part size of 5 MB and a maximum of 5 GB.  Split a single S3
                // part multiple Azure parts.
                long azureMaximumMultipartPartSize = 4 * 1024 * 1024;
                HashingInputStream his = new HashingInputStream(Hashing.md5(),
                        is);
                for (int offset = 0, subPartNumber = 0; offset < contentLength;
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
                Payload payload;
                if (blobStoreType.equals("b2")) {
                    // B2 requires a repeatable payload to calculate the SHA1
                    // hash
                    fbos = new FileBackedOutputStream(B2_PUT_BLOB_BUFFER_SIZE);
                    ByteStreams.copy(is, fbos);
                    fbos.close();
                    payload = Payloads.newByteSourcePayload(
                            fbos.asByteSource());
                } else {
                    payload = Payloads.newInputStreamPayload(is);
                }

                payload.getContentMetadata().setContentLength(contentLength);

                MultipartPart part = blobStore.uploadMultipartPart(mpu,
                        partNumber, payload);
                eTag = part.partETag();
            }
        } finally {
            if (fbos != null) {
                fbos.reset();
            }
        }

        try (Writer writer = response.getWriter()) {
            XMLStreamWriter xml = xmlOutputFactory.createXMLStreamWriter(
                    writer);
            xml.writeStartDocument();
            xml.writeStartElement("CopyObjectResult");
            xml.writeDefaultNamespace(AWS_XMLNS);

            writeSimpleElement(xml, "LastModified",
                    blobStore.getContext().utils().date()
                            .iso8601DateFormat(blobMetadata.getLastModified()));
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
                    "x-amz-decoded-content-length")) {
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
            if (contentMD5.bits() != Hashing.md5().bits()) {
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
        MultipartUpload mpu = MultipartUpload.create(containerName,
                blobName, uploadId, createFakeBlobMetadata(blobStore),
                new PutOptions());

        if (getBlobStoreType(blobStore).equals("azureblob")) {
            // Azure has a maximum part size of 4 MB while S3 has a minimum
            // part size of 5 MB and a maximum of 5 GB.  Split a single S3
            // part multiple Azure parts.
            long azureMaximumMultipartPartSize = 4 * 1024 * 1024;
            HashingInputStream his = new HashingInputStream(Hashing.md5(),
                    is);
            for (int offset = 0, subPartNumber = 0; offset < contentLength;
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
            Payload payload;
            FileBackedOutputStream fbos = null;
            try {
                String blobStoreType = getBlobStoreType(blobStore);
                if (blobStoreType.equals("b2")) {
                    // B2 requires a repeatable payload to calculate the SHA1
                    // hash
                    fbos = new FileBackedOutputStream(B2_PUT_BLOB_BUFFER_SIZE);
                    ByteStreams.copy(is, fbos);
                    fbos.close();
                    payload = Payloads.newByteSourcePayload(
                            fbos.asByteSource());
                } else {
                    payload = Payloads.newInputStreamPayload(is);
                }
                payload.getContentMetadata().setContentLength(contentLength);
                if (contentMD5 != null) {
                    payload.getContentMetadata().setContentMD5(contentMD5);
                }

                part = blobStore.uploadMultipartPart(mpu, partNumber, payload);
            } finally {
                if (fbos != null) {
                    fbos.reset();
                }
            }

            if (part.partETag() != null) {
                response.addHeader(HttpHeaders.ETAG,
                        maybeQuoteETag(part.partETag()));
            }
        }
    }

    private static void addResponseHeaderWithOverride(
            HttpServletRequest request, HttpServletResponse response,
            String headerName, String overrideHeaderName, String value) {
        String override = request.getParameter(overrideHeaderName);
        response.addHeader(headerName, override != null ? override : value);
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
        for (Map.Entry<String, String> entry :
                metadata.getUserMetadata().entrySet()) {
            response.addHeader(USER_METADATA_PREFIX + entry.getKey(),
                    entry.getValue());
        }
    }

    private void sendSimpleErrorResponse(
            HttpServletRequest request, HttpServletResponse response,
            S3ErrorCode code, String message,
            Map<String, String> elements) throws IOException {
        logger.debug("{} {}", code, elements);

        response.setStatus(code.getHttpStatusCode());

        if (request.getMethod().equals("HEAD")) {
            // The HEAD method is identical to GET except that the server MUST
            // NOT return a message-body in the response.
            return;
        }

        try (Writer writer = response.getWriter()) {
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

    public void setBlobStoreLocator(BlobStoreLocator locator) {
        this.blobStoreLocator = locator;
    }

    @SuppressWarnings("serial")
    static final class S3Exception extends Exception {
        private final S3ErrorCode error;
        private final Map<String, String> elements;

        S3Exception(S3ErrorCode error) {
            this(error, error.getMessage(), (Throwable) null,
                    ImmutableMap.<String, String>of());
        }

        S3Exception(S3ErrorCode error, String message) {
            this(error, message, (Throwable) null,
                    ImmutableMap.<String, String>of());
        }

        S3Exception(S3ErrorCode error, Throwable cause) {
            this(error, error.getMessage(), cause,
                    ImmutableMap.<String, String>of());
        }

        S3Exception(S3ErrorCode error, String message, Throwable cause,
                Map<String, String> elements) {
            super(message, cause);
            this.error = requireNonNull(error);
            this.elements = ImmutableMap.copyOf(elements);
        }

        S3ErrorCode getError() {
            return error;
        }

        Map<String, String> getElements() {
            return elements;
        }
    }

    /**
     * Create Amazon V2 signature.  Reference:
     * http://docs.aws.amazon.com/general/latest/gr/signature-version-2.html
     */
    private static String createAuthorizationSignature(
            HttpServletRequest request, String uri, String identity,
            String credential) {
        // sort Amazon headers
        SortedSetMultimap<String, String> canonicalizedHeaders =
                TreeMultimap.create();
        for (String headerName : Collections.list(request.getHeaderNames())) {
            Collection<String> headerValues = Collections.list(
                    request.getHeaders(headerName));
            headerName = headerName.toLowerCase();
            if (!headerName.startsWith("x-amz-")) {
                continue;
            }
            if (headerValues.isEmpty()) {
                canonicalizedHeaders.put(headerName, "");
            }
            for (String headerValue : headerValues) {
                canonicalizedHeaders.put(headerName,
                        Strings.nullToEmpty(headerValue));
            }
        }

        // build string to sign
        StringBuilder builder = new StringBuilder()
                .append(request.getMethod())
                .append('\n')
                .append(Strings.nullToEmpty(request.getHeader(
                        HttpHeaders.CONTENT_MD5)))
                .append('\n')
                .append(Strings.nullToEmpty(request.getHeader(
                        HttpHeaders.CONTENT_TYPE)))
                .append('\n');
        String expires =
                Optional.fromNullable(request.getParameter("Expires"))
                .or(Optional.fromNullable(
                        request.getParameter("X-Amz-Expires")))
                .orNull();
        if (expires != null) {
            builder.append(expires);
        } else if (!canonicalizedHeaders.containsKey("x-amz-date")) {
            builder.append(request.getHeader(HttpHeaders.DATE));
        }
        builder.append('\n');
        for (Map.Entry<String, String> entry : canonicalizedHeaders.entries()) {
            builder.append(entry.getKey()).append(':')
                    .append(entry.getValue()).append('\n');
        }
        builder.append(uri);

        char separator = '?';
        List<String> subresources = Collections.list(
                request.getParameterNames());
        Collections.sort(subresources);
        for (String subresource : subresources) {
            if (SIGNED_SUBRESOURCES.contains(subresource)) {
                builder.append(separator).append(subresource);

                String value = request.getParameter(subresource);
                if (!"".equals(value)) {
                    builder.append('=').append(value);
                }
                separator = '&';
            }
        }

        String stringToSign = builder.toString();
        logger.trace("stringToSign: {}", stringToSign);

        // sign string
        Mac mac;
        try {
            mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(credential.getBytes(
                    StandardCharsets.UTF_8), "HmacSHA1"));
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            throw Throwables.propagate(e);
        }
        return BaseEncoding.base64().encode(mac.doFinal(
                stringToSign.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * Create v4 signature.  Reference:
     * http://docs.aws.amazon.com/general/latest/gr/signature-version-4.html
     */
    private static String createAuthorizationSignatureV4(Request request,
            byte[] payload, String uri, String credential)
            throws InvalidKeyException, IOException, NoSuchAlgorithmException,
            S3Exception {
        S3AuthorizationHeader authHeader = new S3AuthorizationHeader(
                request.getHeader("Authorization"));
        String canonicalRequest = createCanonicalRequest(request, uri, payload,
                authHeader.hashAlgorithm);
        String algorithm = authHeader.hmacAlgorithm;
        byte[] dateKey = signMessage(
                authHeader.date.getBytes(StandardCharsets.UTF_8),
                ("AWS4" + credential).getBytes(StandardCharsets.UTF_8),
                algorithm);
        byte[] dateRegionKey = signMessage(
                authHeader.region.getBytes(StandardCharsets.UTF_8), dateKey,
                algorithm);
        byte[] dateRegionServiceKey = signMessage(
                authHeader.service.getBytes(StandardCharsets.UTF_8),
                dateRegionKey, algorithm);
        byte[] signingKey = signMessage(
                "aws4_request".getBytes(StandardCharsets.UTF_8),
                dateRegionServiceKey, algorithm);
        String signatureString = "AWS4-HMAC-SHA256\n" +
                request.getHeader("x-amz-date") + "\n" +
                authHeader.date + "/" + authHeader.region +
                        "/s3/aws4_request\n" +
                canonicalRequest;
        byte[] signature = signMessage(
                signatureString.getBytes(StandardCharsets.UTF_8),
                signingKey, algorithm);
        return BaseEncoding.base16().lowerCase().encode(signature);
    }

    private static byte[] signMessage(byte[] data, byte[] key, String algorithm)
            throws InvalidKeyException, NoSuchAlgorithmException {
        Mac mac = Mac.getInstance(algorithm);
        mac.init(new SecretKeySpec(key, algorithm));
        return mac.doFinal(data);
    }

    private static String createCanonicalRequest(Request request, String uri,
            byte[] payload, String hashAlgorithm) throws IOException,
            NoSuchAlgorithmException {
        String authorizationHeader = request.getHeader("Authorization");
        String xAmzContentSha256 = request.getHeader("x-amz-content-sha256");
        String digest;
        if ("STREAMING-AWS4-HMAC-SHA256-PAYLOAD".equals(xAmzContentSha256)) {
            digest = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";
        } else {
            digest = getMessageDigest(payload, hashAlgorithm);
        }
        String[] signedHeaders = extractSignedHeaders(authorizationHeader);
        String canonicalRequest = Joiner.on("\n").join(
                request.getMethod(),
                uri,
                buildCanonicalQueryString(request),
                buildCanonicalHeaders(request, signedHeaders) + "\n",
                Joiner.on(';').join(signedHeaders),
                digest);
        return getMessageDigest(
                canonicalRequest.getBytes(StandardCharsets.UTF_8),
                hashAlgorithm);
    }

    private static String getMessageDigest(byte[] payload, String algorithm)
            throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        byte[] hash = md.digest(payload);
        return BaseEncoding.base16().lowerCase().encode(hash);
    }

    private static String[] extractSignedHeaders(String authorization) {
        int index = authorization.indexOf("SignedHeaders=");
        if (index < 0) {
            return null;
        }
        int endSigned = authorization.indexOf(',', index);
        if (endSigned < 0) {
            return null;
        }
        int startHeaders = authorization.indexOf('=', index);
        return authorization.substring(startHeaders + 1, endSigned).split(";");
    }

    private static String buildCanonicalHeaders(Request request,
            String[] signedHeaders) {
        List<String> headers = new ArrayList<>();
        for (String header : signedHeaders) {
            headers.add(header.toLowerCase());
        }
        Collections.sort(headers);
        List<String> headersWithValues = new ArrayList<>();
        for (String header : headers) {
            List<String> values = new ArrayList<>();
            StringBuilder headerWithValue = new StringBuilder();
            headerWithValue.append(header);
            headerWithValue.append(":");
            for (String value : Collections.list(request.getHeaders(header))) {
                value = value.trim();
                if (!value.startsWith("\"")) {
                    value = value.replaceAll("\\s+", " ");
                }
                values.add(value);
            }
            headerWithValue.append(Joiner.on(",").join(values));
            headersWithValues.add(headerWithValue.toString());
        }

        return Joiner.on("\n").join(headersWithValues);
    }

    private static String buildCanonicalQueryString(Request request)
            throws UnsupportedEncodingException {
        // The parameters are required to be sorted
        List<String> parameters = Collections.list(request.getParameterNames());
        Collections.sort(parameters);
        List<String> queryParameters = new ArrayList<>();
        String charsetName = Objects.firstNonNull(request.getQueryEncoding(),
                "UTF-8");
        for (String key : parameters) {
            // re-encode keys and values in AWS normalized form
            String value = request.getParameter(key);
            queryParameters.add(AWS_URL_PARAMETER_ESCAPER.escape(key) +
                    "=" + AWS_URL_PARAMETER_ESCAPER.escape(value));
        }
        return Joiner.on("&").join(queryParameters);
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

    // Encode blob name if client requests it.  This allows for characters
    // which XML 1.0 cannot represent.
    private static String encodeBlob(String encodingType, String blobName) {
        if (encodingType != null && encodingType.equals("url")) {
            try {
                return URLEncoder.encode(blobName, "UTF-8");
            } catch (UnsupportedEncodingException e) {
                throw Throwables.propagate(e);
            }
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
}
