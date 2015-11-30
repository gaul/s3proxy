/*
 * Copyright 2014-2015 Andrew Gaul <andrew@gaul.org>
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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PushbackInputStream;
import java.io.Writer;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
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
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;

import com.google.common.base.Optional;
import com.google.common.base.Strings;
import com.google.common.base.Throwables;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableMultimap;
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
import com.google.common.net.HostAndPort;
import com.google.common.net.HttpHeaders;

import org.apache.commons.fileupload.MultipartStream;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.jclouds.blobstore.BlobRequestSigner;
import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.ContainerNotFoundException;
import org.jclouds.blobstore.KeyNotFoundException;
import org.jclouds.blobstore.LocalBlobRequestSigner;
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
import org.jclouds.http.HttpRequest;
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
            "Expires",
            "location",
            "marker",
            "max-keys",
            "partNumber",
            "prefix",
            "Signature",
            "uploadId",
            "uploads"
    );
    /** All supported x-amz- headers, except for x-amz-meta- user metadata. */
    private static final Set<String> SUPPORTED_X_AMZ_HEADERS = ImmutableSet.of(
            "x-amz-acl",
            "x-amz-copy-source",
            "x-amz-copy-source-range",
            "x-amz-date",
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
    /** Blobstores with opaque markers. */
    private static final Set<String> BLOBSTORE_OPAQUE_MARKERS = ImmutableSet.of(
            "azureblob",
            "google-cloud-storage"
    );

    private final boolean anonymousIdentity;
    private final Optional<String> virtualHost;
    private final XMLInputFactory xmlInputFactory =
            XMLInputFactory.newInstance();
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
                   final String credential, Optional<String> virtualHost) {
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
        try {
            doHandle(request, response);
            baseRequest.setHandled(true);
        } catch (ContainerNotFoundException cnfe) {
            S3ErrorCode code = S3ErrorCode.NO_SUCH_BUCKET;
            sendSimpleErrorResponse(request, response, code, code.getMessage(),
                    ImmutableMap.<String, String>of());
            baseRequest.setHandled(true);
            return;
        } catch (HttpResponseException hre) {
            response.sendError(hre.getResponse().getStatusCode());
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
        }
    }

    private void doHandle(HttpServletRequest request,
            HttpServletResponse response) throws IOException, S3Exception {
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
            doHandleAnonymous(request, response, uri, defaultBlobStore);
            return;
        }

        if (!anonymousIdentity && !hasDateHeader && !hasXAmzDateHeader &&
                request.getParameter("Expires") == null) {
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
        String requestSignature = null;
        String headerAuthorization = request.getHeader(
                HttpHeaders.AUTHORIZATION);

        if (!anonymousIdentity) {
            if (headerAuthorization != null) {
                if (headerAuthorization.startsWith("AWS ")) {
                    int colon = headerAuthorization.lastIndexOf(':',
                            headerAuthorization.length() - 2);
                    if (colon < 4) {
                        throw new S3Exception(S3ErrorCode.INVALID_ARGUMENT);
                    }
                    requestIdentity = headerAuthorization.substring(4, colon);
                    requestSignature = headerAuthorization.substring(colon + 1);
                } else if (headerAuthorization.startsWith(
                        "AWS4-HMAC-SHA256 ")) {
                    // Fail V4 signature requests to allow clients to retry
                    // with V2.
                    throw new S3Exception(S3ErrorCode.INVALID_ARGUMENT);
                }
            } else {
                requestIdentity = request.getParameter("AWSAccessKeyId");
                requestSignature = request.getParameter("Signature");
            }
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

            String expectedSignature = createAuthorizationSignature(request,
                    uri, requestIdentity, provider.getKey());
            if (!expectedSignature.equals(requestSignature)) {
                throw new S3Exception(S3ErrorCode.SIGNATURE_DOES_NOT_MATCH);
            }

            blobStore = provider.getValue();

            String expiresString = request.getParameter("Expires");
            if (expiresString != null) {
                long expires = Long.parseLong(expiresString);
                long nowSeconds = System.currentTimeMillis() / 1000;
                if (nowSeconds > expires) {
                    throw new S3Exception(S3ErrorCode.ACCESS_DENIED);
                }
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
            if (!headerName.startsWith("x-amz-")) {
                continue;
            }
            if (headerName.startsWith("x-amz-meta-")) {
                continue;
            }
            if (headerName.startsWith("x-amz-content-")) {
                continue;
            }
            if (!SUPPORTED_X_AMZ_HEADERS.contains(headerName)) {
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
                    handleListMultipartUploads(response, blobStore,
                            uploadId);
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
                handleBlobMetadata(response, blobStore, path[1], path[2]);
                return;
            }
        case "POST":
            if ("".equals(request.getParameter("delete"))) {
                handleMultiBlobRemove(request, response, blobStore, path[1]);
                return;
            } else if ("".equals(request.getParameter("uploads"))) {
                handleInitiateMultipartUpload(request, response, blobStore,
                        path[1], path[2]);
                return;
            } else if (uploadId != null &&
                    request.getParameter("partNumber") == null) {
                handleCompleteMultipartUpload(request, response, blobStore,
                        path[1], path[2], uploadId);
                return;
            }
            break;
        case "PUT":
            if (path.length <= 2 || path[2].isEmpty()) {
                if ("".equals(request.getParameter("acl"))) {
                    handleSetContainerAcl(request, response, blobStore,
                            path[1]);
                    return;
                }
                handleContainerCreate(request, response, blobStore, path[1]);
                return;
            } else if (uploadId != null) {
                if (request.getHeader("x-amz-copy-source") != null) {
                    handleCopyPart(request, response, blobStore, path[1],
                            path[2], uploadId);
                } else {
                    handleUploadPart(request, response, blobStore, path[1],
                            path[2], uploadId);
                }
                return;
            } else if (request.getHeader("x-amz-copy-source") != null) {
                handleCopyBlob(request, response, blobStore, path[1], path[2]);
                return;
            } else {
                if ("".equals(request.getParameter("acl"))) {
                    handleSetBlobAcl(request, response, blobStore, path[1],
                            path[2]);
                    return;
                }
                handlePutBlob(request, response, blobStore, path[1], path[2]);
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
            HttpServletResponse response, String uri, BlobStore blobStore)
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
            }

            BlobRequestSigner signer = blobStore
                    .getContext()
                    .getSigner();
            if (signer instanceof LocalBlobRequestSigner) {
                // Local blobstores do not have an HTTP server --
                // must handle these calls directly.
                Blob blob = blobStore.getBlob(path[1], path[2]);
                if (blob == null) {
                    // TODO: NO_SUCH_BUCKET
                    throw new S3Exception(S3ErrorCode.NO_SUCH_KEY);
                }
                // TODO: getBlob should return BlobAccess
                BlobAccess access = blobStore.getBlobAccess(path[1],
                        path[2]);
                if (access != BlobAccess.PUBLIC_READ) {
                    throw new S3Exception(S3ErrorCode.ACCESS_DENIED);
                }
                try (InputStream payload = blob.getPayload().openStream();
                        OutputStream os = response.getOutputStream()) {
                    ByteStreams.copy(payload, os);
                }
            } else {
                HttpRequest anonymousRequest = signer
                        .signGetBlob(path[1], path[2])
                        .toBuilder()
                        .headers(ImmutableMultimap.<String, String>of())
                        // TODO: replace parameters?
                        .build();
                logger.debug("issuing anonymous request: {}", anonymousRequest);
                HttpResponse anonymousResponse = blobStore
                        .getContext()
                        .utils()
                        .http()
                        .invoke(anonymousRequest);
                try (InputStream payload =
                        anonymousResponse.getPayload().openStream();
                        OutputStream os = response.getOutputStream()) {
                    ByteStreams.copy(payload, os);
                }
            }
            return;
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
                return;
            }
            break;
        case "POST":
            if (path.length <= 2 || path[2].isEmpty()) {
                handlePostBlob(request, response, blobStore, path[1]);
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
            HttpServletResponse response, BlobStore blobStore,
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
            HttpServletResponse response, BlobStore blobStore,
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

        blobStore.setBlobAccess(containerName, blobName, access);
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

    private void handleListMultipartUploads(HttpServletResponse response,
            BlobStore blobStore, String uploadId)
            throws IOException, S3Exception {
        // TODO: list all blobs starting with uploadId
        throw new S3Exception(S3ErrorCode.NOT_IMPLEMENTED);
    }

    private void handleContainerExists(HttpServletResponse response,
            BlobStore blobStore, String containerName)
            throws IOException, S3Exception {
        if (!blobStore.containerExists(containerName)) {
            throw new S3Exception(S3ErrorCode.NO_SUCH_BUCKET);
        }
    }

    private void handleContainerCreate(HttpServletRequest request,
            HttpServletResponse response, BlobStore blobStore,
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

        Collection<String> locations;
        try (PushbackInputStream pis = new PushbackInputStream(
                request.getInputStream())) {
            int ch = pis.read();
            if (ch == -1) {
                // handle empty bodies
                locations = new ArrayList<>();
            } else {
                pis.unread(ch);
                locations = parseSimpleXmlElements(pis,
                        "LocationConstraint");
            }
        }

        Location location = null;
        if (locations.size() == 1) {
            String locationString = locations.iterator().next();
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
            if (BLOBSTORE_OPAQUE_MARKERS.contains(blobStoreType)) {
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
                writeSimpleElement(xml, "Prefix", prefix);
            }

            writeSimpleElement(xml, "MaxKeys", String.valueOf(maxKeys));

            if (marker == null) {
                xml.writeEmptyElement("Marker");
            } else {
                writeSimpleElement(xml, "Marker", marker);
            }

            if (delimiter != null) {
                writeSimpleElement(xml, "Delimiter", delimiter);
            }

            String nextMarker = set.getNextMarker();
            if (nextMarker != null) {
                writeSimpleElement(xml, "IsTruncated", "true");
                writeSimpleElement(xml, "NextMarker", nextMarker);
                if (BLOBSTORE_OPAQUE_MARKERS.contains(blobStoreType)) {
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

                writeSimpleElement(xml, "Key", metadata.getName());

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
            HttpServletResponse response, BlobStore blobStore,
            String containerName) throws IOException {
        Collection<String> blobNames;
        try (InputStream is = request.getInputStream()) {
            blobNames = parseSimpleXmlElements(is, "Key");
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

    private void handleBlobMetadata(HttpServletResponse response,
            BlobStore blobStore, String containerName,
            String blobName) throws IOException, S3Exception {
        BlobMetadata metadata = blobStore.blobMetadata(containerName, blobName);
        if (metadata == null) {
            throw new S3Exception(S3ErrorCode.NO_SUCH_KEY);
        }

        response.setStatus(HttpServletResponse.SC_OK);
        addMetadataToResponse(response, metadata);
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

        addMetadataToResponse(response, blob.getMetadata());
        Collection<String> contentRanges =
                blob.getAllHeaders().get(HttpHeaders.CONTENT_RANGE);
        if (!contentRanges.isEmpty()) {
            response.addHeader(HttpHeaders.CONTENT_RANGE,
                    contentRanges.iterator().next());
        }

        try (InputStream is = blob.getPayload().openStream();
             OutputStream os = response.getOutputStream()) {
            ByteStreams.copy(is, os);
            os.flush();
        }
    }

    private void handleCopyBlob(HttpServletRequest request,
            HttpServletResponse response, BlobStore blobStore,
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
                } else if (headerName.toLowerCase().startsWith(
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
            handleSetBlobAcl(request, response, blobStore, destContainerName,
                    destBlobName);
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
            HttpServletResponse response, BlobStore blobStore,
            String containerName, String blobName)
            throws IOException, S3Exception {
        // Flag headers present since HttpServletResponse.getHeader returns
        // null for empty headers values.
        String contentLengthString = null;
        String contentMD5String = null;
        for (String headerName : Collections.list(request.getHeaderNames())) {
            String headerValue = Strings.nullToEmpty(request.getHeader(
                    headerName));
            if (headerName.equalsIgnoreCase(HttpHeaders.CONTENT_LENGTH)) {
                contentLengthString = headerValue;
            } else if (headerName.equalsIgnoreCase(HttpHeaders.CONTENT_MD5)) {
                contentMD5String = headerValue;
            }
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

        try (InputStream is = request.getInputStream()) {
            BlobBuilder.PayloadBlobBuilder builder = blobStore
                    .blobBuilder(blobName)
                    .payload(is)
                    .contentLength(request.getContentLength());
            addContentMetdataFromHttpRequest(builder, request);
            if (contentMD5 != null) {
                builder = builder.contentMD5(contentMD5);
            }

            PutOptions options = new PutOptions();
            String blobStoreType = getBlobStoreType(blobStore);
            if (blobStoreType.equals("azureblob") &&
                    contentLength > 64 * 1024 * 1024) {
                options.multipart(true);
            }
            String eTag;
            try {
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
            } catch (RuntimeException re) {
                if (Throwables2.getFirstThrowableOfType(re,
                        TimeoutException.class) != null) {
                    throw new S3Exception(S3ErrorCode.REQUEST_TIMEOUT, re);
                } else {
                    throw re;
                }
            }

            if (blobStoreType.equals("azureblob")) {
                eTag = BaseEncoding.base16().lowerCase()
                        .encode(BaseEncoding.base64().decode(contentMD5String));
            }
            response.addHeader(HttpHeaders.ETAG, maybeQuoteETag(eTag));
        }

        // TODO: jclouds should include this in PutOptions
        String cannedAcl = request.getHeader("x-amz-acl");
        if (cannedAcl != null && !cannedAcl.equalsIgnoreCase("private")) {
            handleSetBlobAcl(request, response, blobStore, containerName,
                    blobName);
        }
    }

    private void handlePostBlob(HttpServletRequest request,
            HttpServletResponse response, BlobStore blobStore,
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
        try (InputStream is = request.getInputStream()) {
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
            String containerName, String blobName) throws IOException {
        ByteSource payload = ByteSource.empty();
        BlobBuilder.PayloadBlobBuilder builder = blobStore
                .blobBuilder(blobName)
                .payload(payload);
        addContentMetdataFromHttpRequest(builder, request);
        builder.contentLength(payload.size());
        Blob blob = builder.build();

        // S3 requires blob metadata during the initiate call while Azure and
        // Swift require it in the complete call.  Store a stub blob which
        // allows reproducing this metadata later.
        blobStore.putBlob(containerName, blob);

        MultipartUpload mpu = blobStore.initiateMultipartUpload(containerName,
                blob.getMetadata());

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
            HttpServletResponse response, BlobStore blobStore,
            String containerName, String blobName, String uploadId)
            throws IOException, S3Exception {
        Blob stubBlob = blobStore.getBlob(containerName, blobName);
        MultipartUpload mpu = MultipartUpload.create(containerName,
                blobName, uploadId, stubBlob.getMetadata());

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
            try (InputStream is = request.getInputStream()) {
                for (Iterator<Map.Entry<Integer, String>> it =
                        parseCompleteMultipartUpload(is).entrySet().iterator();
                        it.hasNext();) {
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
                    if (!equalsIgnoringSurroundingQuotes(part.partETag(),
                            entry.getValue())) {
                        throw new S3Exception(S3ErrorCode.INVALID_PART);
                    }
                    parts.add(MultipartPart.create(entry.getKey(),
                            partSize, part.partETag()));
                }
            }
        }

        if (parts.isEmpty()) {
            // Amazon requires at least one part
            throw new S3Exception(S3ErrorCode.MALFORMED_X_M_L);
        }

        String eTag = blobStore.completeMultipartUpload(mpu, parts);

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
        if (!blobStore.blobExists(containerName, blobName)) {
            throw new S3Exception(S3ErrorCode.NO_SUCH_UPLOAD);
        }

        blobStore.removeBlob(containerName, blobName);

        // TODO: how to reconstruct original mpu?
        MultipartUpload mpu = MultipartUpload.create(containerName,
                blobName, uploadId, createFakeBlobMetadata(blobStore));
        blobStore.abortMultipartUpload(mpu);
        response.sendError(HttpServletResponse.SC_NO_CONTENT);
    }

    private void handleListParts(HttpServletRequest request,
            HttpServletResponse response, BlobStore blobStore,
            String containerName, String blobName, String uploadId)
            throws IOException {
        // TODO: how to reconstruct original mpu?
        MultipartUpload mpu = MultipartUpload.create(containerName,
                blobName, uploadId, createFakeBlobMetadata(blobStore));

        List<MultipartPart> parts = blobStore.listMultipartUpload(mpu);

        try (Writer writer = response.getWriter()) {
            XMLStreamWriter xml = xmlOutputFactory.createXMLStreamWriter(
                    writer);
            xml.writeStartDocument();
            xml.writeStartElement("ListPartsResult");
            xml.writeDefaultNamespace(AWS_XMLNS);

            writeSimpleElement(xml, "Bucket", containerName);
            writeSimpleElement(xml, "Key", blobName);
            writeSimpleElement(xml, "UploadId", uploadId);

            // TODO: bogus values
            xml.writeStartElement("Initiator");

            writeSimpleElement(xml, "ID", FAKE_INITIATOR_ID);
            writeSimpleElement(xml, "DisplayName",
                    FAKE_INITIATOR_DISPLAY_NAME);

            xml.writeEndElement();

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
                blobName, uploadId, createFakeBlobMetadata(blobStore));

        Blob blob = blobStore.getBlob(sourceContainerName, sourceBlobName,
                options);
        if (blob == null) {
            throw new S3Exception(S3ErrorCode.NO_SUCH_KEY);
        }

        BlobMetadata blobMetadata = blob.getMetadata();
        long contentLength =
                blobMetadata.getContentMetadata().getContentLength();
        String eTag;

        try (InputStream is = blob.getPayload().openStream()) {
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

    private void handleUploadPart(HttpServletRequest request,
            HttpServletResponse response, BlobStore blobStore,
            String containerName, String blobName, String uploadId)
            throws IOException, S3Exception {
        // TODO: duplicated from handlePutBlob
        String contentLengthString = null;
        String contentMD5String = null;
        for (String headerName : Collections.list(request.getHeaderNames())) {
            String headerValue = Strings.nullToEmpty(request.getHeader(
                    headerName));
            if (headerName.equalsIgnoreCase(HttpHeaders.CONTENT_LENGTH)) {
                contentLengthString = headerValue;
            } else if (headerName.equalsIgnoreCase(HttpHeaders.CONTENT_MD5)) {
                contentMD5String = headerValue;
            }
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
                blobName, uploadId, createFakeBlobMetadata(blobStore));

        try (InputStream is = request.getInputStream()) {
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
                Payload payload = Payloads.newInputStreamPayload(is);
                payload.getContentMetadata().setContentLength(contentLength);
                if (contentMD5 != null) {
                    payload.getContentMetadata().setContentMD5(contentMD5);
                }

                MultipartPart part = blobStore.uploadMultipartPart(mpu,
                        partNumber, payload);
                response.addHeader(HttpHeaders.ETAG,
                        maybeQuoteETag(part.partETag()));
            }
        }
    }

    private static void addMetadataToResponse(HttpServletResponse response,
            BlobMetadata metadata) {
        ContentMetadata contentMetadata =
                metadata.getContentMetadata();
        response.addHeader(HttpHeaders.CONTENT_DISPOSITION,
                contentMetadata.getContentDisposition());
        response.addHeader(HttpHeaders.CONTENT_ENCODING,
                contentMetadata.getContentEncoding());
        response.addHeader(HttpHeaders.CONTENT_LANGUAGE,
                contentMetadata.getContentLanguage());
        response.addHeader(HttpHeaders.CONTENT_LENGTH,
                contentMetadata.getContentLength().toString());
        response.setContentType(contentMetadata.getContentType());
        HashCode contentMd5 = contentMetadata.getContentMD5AsHashCode();
        if (contentMd5 != null) {
            byte[] contentMd5Bytes = contentMd5.asBytes();
            response.addHeader(HttpHeaders.CONTENT_MD5,
                    BaseEncoding.base64().encode(contentMd5Bytes));
            response.addHeader(HttpHeaders.ETAG, maybeQuoteETag(
                    BaseEncoding.base16().lowerCase().encode(contentMd5Bytes)));
        }
        Date expires = contentMetadata.getExpires();
        if (expires != null) {
            response.addDateHeader(HttpHeaders.EXPIRES, expires.getTime());
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
     * http://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html
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
        String expires = request.getParameter("Expires");
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

    private Collection<String> parseSimpleXmlElements(InputStream is,
            String tagName) throws IOException {
        Collection<String> elements = new ArrayList<>();
        try {
            XMLStreamReader reader = xmlInputFactory.createXMLStreamReader(is);
            String startTag = null;
            StringBuilder characters = new StringBuilder();

            while (reader.hasNext()) {
                switch (reader.getEventType()) {
                case XMLStreamConstants.START_ELEMENT:
                    startTag = reader.getLocalName();
                    characters.setLength(0);
                    break;
                case XMLStreamConstants.CHARACTERS:
                    characters.append(reader.getTextCharacters(),
                            reader.getTextStart(), reader.getTextLength());
                    break;
                case XMLStreamConstants.END_ELEMENT:
                    if (startTag != null && startTag.equals(tagName)) {
                        elements.add(characters.toString());
                    }
                    startTag = null;
                    characters.setLength(0);
                    break;
                default:
                    break;
                }
                reader.next();
            }
        } catch (XMLStreamException xse) {
            throw new IOException(xse);
        }
        return elements;
    }

    private SortedMap<Integer, String> parseCompleteMultipartUpload(
            InputStream is) throws IOException {
        SortedMap<Integer, String> parts = new TreeMap<>();
        try {
            XMLStreamReader reader = xmlInputFactory.createXMLStreamReader(is);
            int partNumber = -1;
            String eTag = null;
            StringBuilder characters = new StringBuilder();

            while (reader.hasNext()) {
                switch (reader.getEventType()) {
                case XMLStreamConstants.CHARACTERS:
                    characters.append(reader.getTextCharacters(),
                            reader.getTextStart(), reader.getTextLength());
                    break;
                case XMLStreamConstants.END_ELEMENT:
                    String tag = reader.getLocalName();
                    if (tag.equalsIgnoreCase("PartNumber")) {
                        partNumber = Integer.parseInt(
                                characters.toString().trim());
                    } else if (tag.equalsIgnoreCase("ETag")) {
                        eTag = characters.toString().trim();
                    } else if (tag.equalsIgnoreCase("Part")) {
                        parts.put(partNumber, eTag);
                        partNumber = -1;
                        eTag = null;
                    }
                    characters.setLength(0);
                    break;
                default:
                    break;
                }
                reader.next();
            }
        } catch (XMLStreamException xse) {
            throw new IOException(xse);
        }
        return parts;
    }

    private static void addContentMetdataFromHttpRequest(
            BlobBuilder.PayloadBlobBuilder builder,
            HttpServletRequest request) {
        ImmutableMap.Builder<String, String> userMetadata =
                ImmutableMap.builder();
        for (String headerName : Collections.list(request.getHeaderNames())) {
            if (headerName.toLowerCase().startsWith(USER_METADATA_PREFIX)) {
                userMetadata.put(
                        headerName.substring(USER_METADATA_PREFIX.length()),
                        Strings.nullToEmpty(request.getHeader(headerName)));
            }
        }
        builder.contentDisposition(request.getHeader(
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
}
