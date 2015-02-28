/*
 * Copyright 2014 Andrew Gaul <andrew@gaul.org>
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

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
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
import java.util.TreeSet;
import java.util.UUID;
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
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
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

import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.ContainerNotFoundException;
import org.jclouds.blobstore.domain.Blob;
import org.jclouds.blobstore.domain.BlobAccess;
import org.jclouds.blobstore.domain.BlobBuilder;
import org.jclouds.blobstore.domain.BlobMetadata;
import org.jclouds.blobstore.domain.ContainerAccess;
import org.jclouds.blobstore.domain.PageSet;
import org.jclouds.blobstore.domain.StorageMetadata;
import org.jclouds.blobstore.options.CreateContainerOptions;
import org.jclouds.blobstore.options.GetOptions;
import org.jclouds.blobstore.options.ListContainerOptions;
import org.jclouds.blobstore.options.PutOptions;
import org.jclouds.domain.Location;
import org.jclouds.http.HttpResponse;
import org.jclouds.http.HttpResponseException;
import org.jclouds.io.ContentMetadata;
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
    private static final String FAKE_UPLOAD_ID =
            "EXAMPLEJZ6e0YupT2h66iePQCc9IEbYbDUy4RTpMeoSMLPRp8Z5o1u8feSRo" +
            "npvnWsKKG35tI2LB9VDPiCgTy.Gq2VxQLYjrue4Nq.NBdqI-";
    private static final long MINIMUM_MULTIPART_PART_SIZE = 5 * 1024 * 1024;
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
    private static final Set<String> CANNED_ACLS = ImmutableSet.of(
            "private",
            "public-read",
            "public-read-write",
            "authenticated-read",
            "bucket-owner-read",
            "bucket-owner-full-control",
            "log-delivery-write"
    );

    private final BlobStore blobStore;
    private final String blobStoreType;
    private final String identity;
    private final String credential;
    private final boolean forceMultiPartUpload;
    private final Optional<String> virtualHost;
    private final XMLInputFactory xmlInputFactory =
            XMLInputFactory.newInstance();
    private final XMLOutputFactory xmlOutputFactory =
            XMLOutputFactory.newInstance();

    S3ProxyHandler(BlobStore blobStore, String identity, String credential,
            boolean forceMultiPartUpload, Optional<String> virtualHost) {
        this.blobStore = checkNotNull(blobStore);
        this.blobStoreType =
                blobStore.getContext().unwrap().getProviderMetadata().getId();
        this.identity = identity;
        this.credential = credential;
        this.forceMultiPartUpload = forceMultiPartUpload;
        this.virtualHost = checkNotNull(virtualHost);
        xmlOutputFactory.setProperty("javax.xml.stream.isRepairingNamespaces",
                Boolean.FALSE);
    }

    @Override
    public void handle(String target, Request baseRequest,
            HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        try {
            doHandle(target, baseRequest, request, response);
        } catch (S3Exception se) {
            sendSimpleErrorResponse(response, se.getError());
            baseRequest.setHandled(true);
            return;
        }
    }

    private void doHandle(String target, Request baseRequest,
            HttpServletRequest request, HttpServletResponse response)
            throws IOException, S3Exception {
        String method = request.getMethod();
        String uri = request.getRequestURI();
        logger.debug("request: {}", request);
        String hostHeader = request.getHeader(HttpHeaders.HOST);
        if (hostHeader != null && virtualHost.isPresent()) {
            hostHeader = HostAndPort.fromString(hostHeader).getHostText();
            String virtualHostSuffix = "." + virtualHost.get();
            if (hostHeader.endsWith(virtualHostSuffix)) {
                String bucket = hostHeader.substring(0,
                        hostHeader.length() - virtualHostSuffix.length());
                uri = "/" + bucket + uri;
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

        if (identity != null && !hasDateHeader && !hasXAmzDateHeader &&
                request.getParameter("Expires") == null) {
            sendSimpleErrorResponse(response, S3ErrorCode.ACCESS_DENIED,
                    "AWS authentication requires a valid Date or" +
                    " x-amz-date header", null, null);
            baseRequest.setHandled(true);
            return;
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

        if (identity != null) {
            String expectedSignature = createAuthorizationSignature(request,
                    uri, identity, credential);
            String headerAuthorization = request.getHeader(
                    HttpHeaders.AUTHORIZATION);
            String headerIdentity = null;
            String headerSignature = null;
            if (headerAuthorization != null &&
                    headerAuthorization.startsWith("AWS ")) {
                String[] values =
                        headerAuthorization.substring(4).split(":", 2);
                if (values.length != 2) {
                    throw new S3Exception(S3ErrorCode.INVALID_ARGUMENT);
                }
                headerIdentity = values[0];
                headerSignature = values[1];
            } else if (headerAuthorization != null &&
                    headerAuthorization.startsWith("AWS4-HMAC-SHA256 ")) {
                // Fail V4 signature requests to allow clients to retry with V2.
                throw new S3Exception(S3ErrorCode.INVALID_ARGUMENT);
            }
            String parameterIdentity = request.getParameter("AWSAccessKeyId");
            String parameterSignature = request.getParameter("Signature");

            if (headerIdentity != null && headerSignature != null) {
                if (!identity.equals(headerIdentity)) {
                    throw new S3Exception(S3ErrorCode.INVALID_ACCESS_KEY_ID);
                } else if (!expectedSignature.equals(headerSignature)) {
                    throw new S3Exception(S3ErrorCode.SIGNATURE_DOES_NOT_MATCH);
                }
            } else if (parameterIdentity != null &&
                    parameterSignature != null) {
                if (!identity.equals(parameterIdentity)) {
                    throw new S3Exception(S3ErrorCode.INVALID_ACCESS_KEY_ID);
                } else if (!expectedSignature.equals(parameterSignature)) {
                    throw new S3Exception(S3ErrorCode.SIGNATURE_DOES_NOT_MATCH);
                }

                String expiresString = request.getParameter("Expires");
                if (expiresString != null) {
                    long expires = Long.parseLong(expiresString);
                    long nowSeconds = System.currentTimeMillis() / 1000;
                    if (nowSeconds > expires) {
                        throw new S3Exception(S3ErrorCode.ACCESS_DENIED);
                    }
                }
            } else {
                throw new S3Exception(S3ErrorCode.ACCESS_DENIED);
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

        String[] path = uri.split("/", 3);
        for (int i = 0; i < path.length; i++) {
            path[i] = URLDecoder.decode(path[i], "UTF-8");
        }
        String uploadId = request.getParameter("uploadId");
        switch (method) {
        case "DELETE":
            if (path.length <= 2 || path[2].isEmpty()) {
                handleContainerDelete(response, path[1]);
                baseRequest.setHandled(true);
                return;
            } else if (uploadId != null) {
                handleAbortMultipartUpload(request, response, path[1], path[2],
                        uploadId);
                baseRequest.setHandled(true);
                return;
            } else {
                handleBlobRemove(response, path[1], path[2]);
                baseRequest.setHandled(true);
                return;
            }
        case "GET":
            if (uri.equals("/")) {
                handleContainerList(response);
                baseRequest.setHandled(true);
                return;
            } else if (path.length <= 2 || path[2].isEmpty()) {
                if ("".equals(request.getParameter("acl"))) {
                    handleGetContainerAcl(response, path[1]);
                    baseRequest.setHandled(true);
                    return;
                } else if ("".equals(request.getParameter("location"))) {
                    handleContainerLocation(response, path[1]);
                    baseRequest.setHandled(true);
                    return;
                } else if ("".equals(request.getParameter("uploads"))) {
                    handleListMultipartUploads(response, uploadId);
                    baseRequest.setHandled(true);
                    return;
                }
                handleBlobList(request, response, path[1]);
                baseRequest.setHandled(true);
                return;
            } else {
                if ("".equals(request.getParameter("acl"))) {
                    handleGetBlobAcl(response, path[1], path[2]);
                    baseRequest.setHandled(true);
                    return;
                } else if (uploadId != null) {
                    handleListParts(request, response, path[1], path[2],
                            uploadId);
                    baseRequest.setHandled(true);
                    return;
                }
                handleGetBlob(request, response, path[1], path[2]);
                baseRequest.setHandled(true);
                return;
            }
        case "HEAD":
            if (path.length <= 2 || path[2].isEmpty()) {
                handleContainerExists(response, path[1]);
                baseRequest.setHandled(true);
                return;
            } else {
                handleBlobMetadata(response, path[1], path[2]);
                baseRequest.setHandled(true);
                return;
            }
        case "POST":
            if ("".equals(request.getParameter("delete"))) {
                handleMultiBlobRemove(request, response, path[1]);
                baseRequest.setHandled(true);
                return;
            } else if ("".equals(request.getParameter("uploads"))) {
                handleInitiateMultipartUpload(request, response, path[1],
                        path[2]);
                baseRequest.setHandled(true);
                return;
            } else if (uploadId != null) {
                handleCompleteMultipartUpload(request, response, path[1],
                        path[2], uploadId);
                baseRequest.setHandled(true);
                return;
            }
            break;
        case "PUT":
            if (path.length <= 2 || path[2].isEmpty()) {
                if ("".equals(request.getParameter("acl"))) {
                    handleSetContainerAcl(request, response, path[1]);
                    baseRequest.setHandled(true);
                    return;
                }
                handleContainerCreate(request, response, path[1]);
                baseRequest.setHandled(true);
                return;
            } else if (uploadId != null) {
                handleUploadPart(request, response, path[1], path[2],
                        uploadId);
                baseRequest.setHandled(true);
                return;
            } else if (request.getHeader("x-amz-copy-source") != null) {
                handleCopyBlob(request, response, path[1], path[2]);
                baseRequest.setHandled(true);
                return;
            } else {
                if ("".equals(request.getParameter("acl"))) {
                    handleSetBlobAcl(request, response, path[1], path[2]);
                    baseRequest.setHandled(true);
                    return;
                }
                handlePutBlob(request, response, path[1], path[2]);
                baseRequest.setHandled(true);
                return;
            }
        default:
            logger.error("Unknown method {} with URI {}",
                    method, request.getRequestURI());
            throw new S3Exception(S3ErrorCode.NOT_IMPLEMENTED);
        }
    }

    private void handleGetContainerAcl(HttpServletResponse response,
            String containerName) throws IOException {
        ContainerAccess access;
        if (blobStoreType.equals("filesystem") ||
                blobStoreType.equals("transient")) {
            access = ContainerAccess.PRIVATE;
        } else {
            access = blobStore.getContainerAccess(containerName);
        }

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

            xml.writeStartElement("ID");
            xml.writeCharacters(FAKE_OWNER_ID);
            xml.writeEndElement();

            xml.writeStartElement("DisplayName");
            xml.writeCharacters(FAKE_OWNER_DISPLAY_NAME);
            xml.writeEndElement();

            xml.writeEndElement();

            xml.writeStartElement("Permission");
            xml.writeCharacters("FULL_CONTROL");
            xml.writeEndElement();

            xml.writeEndElement();

            if (access == ContainerAccess.PUBLIC_READ) {
                xml.writeStartElement("Grant");

                xml.writeStartElement("Grantee");
                xml.writeNamespace("xsi",
                        "http://www.w3.org/2001/XMLSchema-instance");
                xml.writeAttribute("xsi:type", "Group");

                xml.writeStartElement("URI");
                xml.writeCharacters(
                        "http://acs.amazonaws.com/groups/global/AllUsers");
                xml.writeEndElement();

                xml.writeEndElement();

                xml.writeStartElement("Permission");
                xml.writeCharacters("READ");
                xml.writeEndElement();

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
            HttpServletResponse response, String containerName)
            throws IOException, S3Exception {
        ContainerAccess access;

        String cannedAcl = request.getHeader("x-amz-acl");
        if ("private".equals(cannedAcl)) {
            access = ContainerAccess.PRIVATE;
        } else if ("public-read".equals(cannedAcl)) {
            access = ContainerAccess.PUBLIC_READ;
        } else if (cannedAcl == null || CANNED_ACLS.contains(cannedAcl)) {
            throw new S3Exception(S3ErrorCode.NOT_IMPLEMENTED);
        } else {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        if (!(blobStoreType.equals("filesystem") ||
                blobStoreType.equals("transient"))) {
            blobStore.setContainerAccess(containerName, access);
        }
    }

    private void handleGetBlobAcl(HttpServletResponse response,
            String containerName, String blobName) throws IOException {
        BlobAccess access;
        if (blobStoreType.equals("filesystem") ||
                blobStoreType.equals("transient")) {
            access = BlobAccess.PRIVATE;
        } else {
            access = blobStore.getBlobAccess(containerName, blobName);
        }

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

            xml.writeStartElement("ID");
            xml.writeCharacters(FAKE_OWNER_ID);
            xml.writeEndElement();

            xml.writeStartElement("DisplayName");
            xml.writeCharacters(FAKE_OWNER_DISPLAY_NAME);
            xml.writeEndElement();

            xml.writeEndElement();

            xml.writeStartElement("Permission");
            xml.writeCharacters("FULL_CONTROL");
            xml.writeEndElement();

            xml.writeEndElement();

            if (access == BlobAccess.PUBLIC_READ) {
                xml.writeStartElement("Grant");

                xml.writeStartElement("Grantee");
                xml.writeNamespace("xsi",
                        "http://www.w3.org/2001/XMLSchema-instance");
                xml.writeAttribute("xsi:type", "Group");

                xml.writeStartElement("URI");
                xml.writeCharacters(
                        "http://acs.amazonaws.com/groups/global/AllUsers");
                xml.writeEndElement();

                xml.writeEndElement();

                xml.writeStartElement("Permission");
                xml.writeCharacters("READ");
                xml.writeEndElement();

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
            HttpServletResponse response, String containerName,
            String blobName) throws IOException, S3Exception {
        BlobAccess access;

        String cannedAcl = request.getHeader("x-amz-acl");
        if ("private".equals(cannedAcl)) {
            access = BlobAccess.PRIVATE;
        } else if ("public-read".equals(cannedAcl)) {
            access = BlobAccess.PUBLIC_READ;
        } else if (cannedAcl == null || CANNED_ACLS.contains(cannedAcl)) {
            throw new S3Exception(S3ErrorCode.NOT_IMPLEMENTED);
        } else {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        if (!(blobStoreType.equals("filesystem") ||
                blobStoreType.equals("transient"))) {
            blobStore.setBlobAccess(containerName, blobName, access);
        }
    }

    private void handleContainerList(HttpServletResponse response)
            throws IOException {
        try (Writer writer = response.getWriter()) {
            XMLStreamWriter xml = xmlOutputFactory.createXMLStreamWriter(
                    writer);
            xml.writeStartDocument();
            xml.writeStartElement("ListAllMyBucketsResult");
            xml.writeDefaultNamespace(AWS_XMLNS);

            writeOwnerStanza(xml);

            xml.writeStartElement("Buckets");
            for (StorageMetadata metadata : blobStore.list()) {
                xml.writeStartElement("Bucket");

                xml.writeStartElement("Name");
                xml.writeCharacters(metadata.getName());
                xml.writeEndElement();

                Date creationDate = metadata.getCreationDate();
                if (creationDate == null) {
                    // Some providers, e.g., Swift, do not provide container
                    // creation date.  Emit a bogus one to satisfy clients like
                    // s3cmd which require one.
                    creationDate = new Date(0);
                }
                xml.writeStartElement("CreationDate");
                xml.writeCharacters(blobStore.getContext().utils().date()
                        .iso8601DateFormat(creationDate).trim());
                xml.writeEndElement();
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
            String containerName) throws IOException {
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
            String uploadId) throws IOException, S3Exception {
        // TODO: list all blobs starting with uploadId
        throw new S3Exception(S3ErrorCode.NOT_IMPLEMENTED);
    }

    private void handleContainerExists(HttpServletResponse response,
            String containerName) throws IOException, S3Exception {
        if (!blobStore.containerExists(containerName)) {
            throw new S3Exception(S3ErrorCode.NO_SUCH_BUCKET);
        }
    }

    private void handleContainerCreate(HttpServletRequest request,
            HttpServletResponse response, String containerName)
            throws IOException, S3Exception {
        if (containerName.isEmpty()) {
            throw new S3Exception(S3ErrorCode.METHOD_NOT_ALLOWED);
        }
        if (containerName.length() < 3 || containerName.length() > 255 ||
                !VALID_BUCKET_PATTERN.matcher(containerName).matches()) {
            throw new S3Exception(S3ErrorCode.INVALID_BUCKET_NAME);
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
        if ("public-read".equals(acl)) {
            options.publicRead();
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

        try {
            if (blobStore.createContainerInLocation(location, containerName,
                    options)) {
                return;
            }
            S3ErrorCode errorCode = S3ErrorCode.BUCKET_ALREADY_OWNED_BY_YOU;
            sendSimpleErrorResponse(response,
                    errorCode, errorCode.getMessage(), "BucketName",
                    containerName);
        } catch (AuthorizationException ae) {
            throw new S3Exception(S3ErrorCode.BUCKET_ALREADY_EXISTS, ae);
        }
    }

    private void handleContainerDelete(HttpServletResponse response,
            String containerName) throws IOException, S3Exception {
        if (!blobStore.containerExists(containerName)) {
            throw new S3Exception(S3ErrorCode.NO_SUCH_BUCKET);
        }
        if (!blobStore.deleteContainerIfEmpty(containerName)) {
            throw new S3Exception(S3ErrorCode.BUCKET_NOT_EMPTY);
        }
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }

    private void handleBlobList(HttpServletRequest request,
            HttpServletResponse response, String containerName)
            throws IOException, S3Exception {
        ListContainerOptions options = new ListContainerOptions();
        String delimiter = request.getParameter("delimiter");
        if (!(delimiter != null && delimiter.equals("/"))) {
            options = options.recursive();
        }
        String prefix = request.getParameter("prefix");
        if (prefix != null) {
            options = options.inDirectory(prefix);
        }
        String marker = request.getParameter("marker");
        if (marker != null) {
            options = options.afterMarker(request.getParameter("marker"));
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
        options = options.maxResults(maxKeys);

        PageSet<? extends StorageMetadata> set;
        try {
            set = blobStore.list(containerName, options);
        } catch (ContainerNotFoundException cnfe) {
            throw new S3Exception(S3ErrorCode.NO_SUCH_BUCKET, cnfe);
        }

        try (Writer writer = new OutputStreamWriter(response.getOutputStream(),
                StandardCharsets.UTF_8)) {
            response.setStatus(HttpServletResponse.SC_OK);
            XMLStreamWriter xml = xmlOutputFactory.createXMLStreamWriter(
                    writer);
            xml.writeStartDocument();
            xml.writeStartElement("ListBucketResult");
            xml.writeDefaultNamespace(AWS_XMLNS);

            xml.writeStartElement("Name");
            xml.writeCharacters(containerName);
            xml.writeEndElement();

            if (prefix == null) {
                xml.writeEmptyElement("Prefix");
            } else {
                xml.writeStartElement("Prefix");
                xml.writeCharacters(prefix);
                xml.writeEndElement();
            }

            xml.writeStartElement("MaxKeys");
            xml.writeCharacters(String.valueOf(maxKeys));
            xml.writeEndElement();

            if (marker == null) {
                xml.writeEmptyElement("Marker");
            } else {
                xml.writeStartElement("Marker");
                xml.writeCharacters(marker);
                xml.writeEndElement();
            }

            if (delimiter != null) {
                xml.writeStartElement("Delimiter");
                xml.writeCharacters(delimiter);
                xml.writeEndElement();
            }

            String nextMarker = set.getNextMarker();
            if (nextMarker != null) {
                xml.writeStartElement("IsTruncated");
                xml.writeCharacters("true");
                xml.writeEndElement();

                xml.writeStartElement("NextMarker");
                xml.writeCharacters(nextMarker);
                xml.writeEndElement();
            } else {
                xml.writeStartElement("IsTruncated");
                xml.writeCharacters("false");
                xml.writeEndElement();
            }

            Set<String> commonPrefixes = new TreeSet<>();
            for (StorageMetadata metadata : set) {
                switch (metadata.getType()) {
                case FOLDER:
                    continue;
                case RELATIVE_PATH:
                    String name = metadata.getName();
                    if (delimiter != null) {
                        int index = name.indexOf(delimiter,
                                Strings.nullToEmpty(prefix).length());
                        if (index != -1) {
                            name = name.substring(0, index + 1);
                        }
                        name += delimiter;
                    }
                    commonPrefixes.add(name);
                    continue;
                default:
                    break;
                }

                xml.writeStartElement("Contents");

                xml.writeStartElement("Key");
                xml.writeCharacters(metadata.getName());
                xml.writeEndElement();

                Date lastModified = metadata.getLastModified();
                if (lastModified != null) {
                    xml.writeStartElement("LastModified");
                    xml.writeCharacters(blobStore.getContext().utils().date()
                            .iso8601DateFormat(lastModified));
                    xml.writeEndElement();
                }

                String eTag = metadata.getETag();
                if (eTag != null) {
                    xml.writeStartElement("ETag");
                    if (blobStoreType.equals("google-cloud-storage")) {
                        eTag = BaseEncoding.base16().lowerCase().encode(
                                BaseEncoding.base64().decode(eTag));
                    }
                    xml.writeCharacters("\"" + eTag + "\"");
                    xml.writeEndElement();
                }

                xml.writeStartElement("Size");
                xml.writeCharacters(String.valueOf(metadata.getSize()));
                xml.writeEndElement();

                xml.writeStartElement("StorageClass");
                xml.writeCharacters("STANDARD");
                xml.writeEndElement();

                writeOwnerStanza(xml);

                xml.writeEndElement();
            }

            for (String commonPrefix : commonPrefixes) {
                xml.writeStartElement("CommonPrefixes");

                xml.writeStartElement("Prefix");
                xml.writeCharacters(commonPrefix);
                xml.writeEndElement();

                xml.writeEndElement();
            }

            xml.writeEndElement();
            xml.flush();
        } catch (XMLStreamException xse) {
            throw new IOException(xse);
        }
    }

    private void handleBlobRemove(HttpServletResponse response,
            String containerName, String blobName)
            throws IOException, S3Exception {
        try {
            blobStore.removeBlob(containerName, blobName);
            response.sendError(HttpServletResponse.SC_NO_CONTENT);
        } catch (ContainerNotFoundException cnfe) {
            throw new S3Exception(S3ErrorCode.NO_SUCH_BUCKET, cnfe);
        }
    }

    private void handleMultiBlobRemove(HttpServletRequest request,
            HttpServletResponse response, String containerName)
            throws IOException {
        try (InputStream is = request.getInputStream();
             Writer writer = new OutputStreamWriter(response.getOutputStream(),
                    StandardCharsets.UTF_8)) {
            Collection<String> blobNames = parseSimpleXmlElements(is, "Key");
            blobStore.removeBlobs(containerName, blobNames);

            XMLStreamWriter xml = xmlOutputFactory.createXMLStreamWriter(
                    writer);
            xml.writeStartDocument();
            xml.writeStartElement("DeleteResult");
            xml.writeDefaultNamespace(AWS_XMLNS);
            for (String blobName : blobNames) {
                xml.writeStartElement("Deleted");
                xml.writeStartElement("Key");
                xml.writeCharacters(blobName);
                xml.writeEndElement();
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
            String containerName, String blobName)
            throws IOException, S3Exception {
        BlobMetadata metadata;
        try {
            metadata = blobStore.blobMetadata(containerName, blobName);
        } catch (ContainerNotFoundException cnfe) {
            throw new S3Exception(S3ErrorCode.NO_SUCH_BUCKET, cnfe);
        }
        if (metadata == null) {
            throw new S3Exception(S3ErrorCode.NO_SUCH_KEY);
        }

        response.setStatus(HttpServletResponse.SC_OK);
        addMetadataToResponse(response, metadata);
    }

    private void handleGetBlob(HttpServletRequest request,
            HttpServletResponse response, String containerName,
            String blobName) throws IOException, S3Exception {
        int status = HttpServletResponse.SC_OK;
        GetOptions options = new GetOptions();
        String range = request.getHeader(HttpHeaders.RANGE);
        if (range != null && range.startsWith("bytes=") &&
                // ignore multiple ranges
                range.indexOf(',') == -1) {
            range = range.substring("bytes=".length());
            String[] ranges = range.split("-", 2);
            if (ranges[0].isEmpty()) {
                options = options.tail(Long.parseLong(ranges[1]));
            } else if (ranges[1].isEmpty()) {
                options = options.startAt(Long.parseLong(ranges[0]));
            } else {
                options = options.range(Long.parseLong(ranges[0]),
                        Long.parseLong(ranges[1]));
            }
            status = HttpServletResponse.SC_PARTIAL_CONTENT;
        }

        Blob blob;
        try {
            blob = blobStore.getBlob(containerName, blobName, options);
        } catch (ContainerNotFoundException cnfe) {
            throw new S3Exception(S3ErrorCode.NO_SUCH_BUCKET, cnfe);
        }
        if (blob == null) {
            throw new S3Exception(S3ErrorCode.NO_SUCH_KEY);
        }

        response.setStatus(status);
        addMetadataToResponse(response, blob.getMetadata());
        try (InputStream is = blob.getPayload().openStream();
             OutputStream os = response.getOutputStream()) {
            ByteStreams.copy(is, os);
            os.flush();
        }
    }

    private void handleCopyBlob(HttpServletRequest request,
            HttpServletResponse response, String destContainerName,
            String destBlobName) throws IOException, S3Exception {
        String copySourceHeader = request.getHeader("x-amz-copy-source");
        if (copySourceHeader.startsWith("/")) {
            // Some clients like boto do not include the leading slash
            copySourceHeader = copySourceHeader.substring(1);
        }
        String[] path = copySourceHeader.split("/", 2);
        for (int i = 0; i < path.length; i++) {
            path[i] = URLDecoder.decode(path[i], "UTF-8");
        }
        String sourceContainerName = path[0];
        String sourceBlobName = path[1];
        boolean replaceMetadata = "REPLACE".equals(request.getHeader(
                "x-amz-metadata-directive"));

        if (sourceContainerName.equals(destContainerName) &&
                sourceBlobName.equals(destBlobName) &&
                !replaceMetadata) {
            throw new S3Exception(S3ErrorCode.INVALID_REQUEST);
        }

        Blob blob;
        try {
            blob = blobStore.getBlob(sourceContainerName, sourceBlobName);
        } catch (ContainerNotFoundException cnfe) {
            throw new S3Exception(S3ErrorCode.NO_SUCH_BUCKET, cnfe);
        }
        if (blob == null) {
            throw new S3Exception(S3ErrorCode.NO_SUCH_KEY);
        }

        try (InputStream is = blob.getPayload().openStream()) {
            ContentMetadata metadata = blob.getMetadata().getContentMetadata();
            BlobBuilder.PayloadBlobBuilder builder = blobStore
                    .blobBuilder(destBlobName)
                    .payload(is)
                    .contentLength(metadata.getContentLength());
            if (replaceMetadata) {
                addContentMetdataFromHttpRequest(builder, request);
            } else {
                builder.contentDisposition(metadata.getContentDisposition())
                        .contentEncoding(metadata.getContentEncoding())
                        .contentLanguage(metadata.getContentLanguage())
                        .contentType(metadata.getContentType())
                        .userMetadata(blob.getMetadata().getUserMetadata());
            }

            PutOptions options = new PutOptions()
                    .multipart(forceMultiPartUpload);
            String eTag = blobStore.putBlob(destContainerName,
                    builder.build(), options);
            Date lastModified = blob.getMetadata().getLastModified();
            try (Writer writer = response.getWriter()) {
                XMLStreamWriter xml = xmlOutputFactory.createXMLStreamWriter(
                        writer);
                xml.writeStartDocument();
                xml.writeStartElement("CopyObjectResult");
                xml.writeDefaultNamespace(AWS_XMLNS);

                xml.writeStartElement("LastModified");
                xml.writeCharacters(blobStore.getContext().utils().date()
                        .iso8601DateFormat(lastModified));
                xml.writeEndElement();

                xml.writeStartElement("ETag");
                xml.writeCharacters("\"" + eTag + "\"");
                xml.writeEndElement();

                xml.writeEndElement();
                xml.flush();
            } catch (XMLStreamException xse) {
                throw new IOException(xse);
            }
        }
    }

    private void handlePutBlob(HttpServletRequest request,
            HttpServletResponse response, String containerName,
            String blobName) throws IOException, S3Exception {
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

            PutOptions options = new PutOptions()
                    .multipart(forceMultiPartUpload);
            String eTag;
            try {
                eTag = blobStore.putBlob(containerName, builder.build(),
                        options);
            } catch (ContainerNotFoundException cnfe) {
                throw new S3Exception(S3ErrorCode.NO_SUCH_BUCKET, cnfe);
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

            // S3 quotes ETag while Swift does not
            if (!eTag.startsWith("\"") && !eTag.endsWith("\"")) {
                eTag = '"' + eTag + '"';
            }
            response.addHeader(HttpHeaders.ETAG, eTag);
        }
    }

    private void handleInitiateMultipartUpload(HttpServletRequest request,
            HttpServletResponse response, String containerName,
            String blobName) throws IOException {
        String uploadId = FAKE_UPLOAD_ID + UUID.randomUUID().toString();
        ByteSource payload = ByteSource.empty();
        BlobBuilder.PayloadBlobBuilder builder = blobStore
                .blobBuilder(uploadId)
                .payload(payload);
        addContentMetdataFromHttpRequest(builder, request);
        builder.contentLength(payload.size());
        blobStore.putBlob(containerName, builder.build());

        try (Writer writer = response.getWriter()) {
            XMLStreamWriter xml = xmlOutputFactory.createXMLStreamWriter(
                    writer);
            xml.writeStartDocument();
            xml.writeStartElement("InitiateMultipartUploadResult");
            xml.writeDefaultNamespace(AWS_XMLNS);

            xml.writeStartElement("Bucket");
            xml.writeCharacters(containerName);
            xml.writeEndElement();

            xml.writeStartElement("Key");
            xml.writeCharacters(blobName);
            xml.writeEndElement();

            xml.writeStartElement("UploadId");
            xml.writeCharacters(uploadId);
            xml.writeEndElement();

            xml.writeEndElement();
            xml.flush();
        } catch (XMLStreamException xse) {
            throw new IOException(xse);
        }
    }

    private void handleCompleteMultipartUpload(HttpServletRequest request,
            HttpServletResponse response, String containerName,
            String blobName, String uploadId) throws IOException, S3Exception {
        Collection<String> partNames = new ArrayList<>();
        long totalContentLength = 0;
        try (InputStream is = request.getInputStream()) {
            for (Iterator<String> it = parseSimpleXmlElements(is,
                    "PartNumber").iterator(); it.hasNext();) {
                String partName = uploadId + "." + it.next();
                partNames.add(partName);
                BlobMetadata metadata = blobStore.blobMetadata(containerName,
                        partName);
                long contentLength =
                        metadata.getContentMetadata().getContentLength();
                if (contentLength < MINIMUM_MULTIPART_PART_SIZE &&
                        it.hasNext()) {
                    throw new S3Exception(S3ErrorCode.ENTITY_TOO_SMALL);
                }
                totalContentLength += contentLength;
            }

            if (partNames.isEmpty()) {
                // Amazon requires at least one part
                throw new S3Exception(S3ErrorCode.MALFORMED_X_M_L);
            }
        }

        try (Writer writer = response.getWriter()) {
            BlobMetadata blobMetadata = blobStore.blobMetadata(
                    containerName, uploadId);
            ContentMetadata contentMetadata =
                    blobMetadata.getContentMetadata();
            BlobBuilder.PayloadBlobBuilder builder = blobStore
                    .blobBuilder(blobName)
                    .userMetadata(blobMetadata.getUserMetadata())
                    .payload(new MultiBlobByteSource(blobStore, containerName,
                            partNames))
                    .contentDisposition(
                            contentMetadata.getContentDisposition())
                    .contentEncoding(contentMetadata.getContentEncoding())
                    .contentLanguage(contentMetadata.getContentLanguage())
                    .contentLength(totalContentLength)
                    .expires(contentMetadata.getExpires());
            String contentType = contentMetadata.getContentType();
            if (contentType != null) {
                builder.contentType(contentType);
            }

            // TODO: will the client time out here?
            String eTag = blobStore.putBlob(containerName, builder.build(),
                    new PutOptions().multipart(true));

            blobStore.removeBlobs(containerName, partNames);

            XMLStreamWriter xml = xmlOutputFactory.createXMLStreamWriter(
                    writer);
            xml.writeStartDocument();
            xml.writeStartElement("CompleteMultipartUploadResult");
            xml.writeDefaultNamespace(AWS_XMLNS);

            xml.writeStartElement("Location");
            // TODO: bogus value
            xml.writeCharacters("http://Example-Bucket.s3.amazonaws.com/" +
                    blobName);
            xml.writeEndElement();

            xml.writeStartElement("Bucket");
            xml.writeCharacters(containerName);
            xml.writeEndElement();

            xml.writeStartElement("Key");
            xml.writeCharacters(blobName);
            xml.writeEndElement();

            if (eTag != null) {
                xml.writeStartElement("ETag");
                if (blobStoreType.equals("google-cloud-storage")) {
                    eTag = BaseEncoding.base16().lowerCase().encode(
                            BaseEncoding.base64().decode(eTag));
                }
                xml.writeCharacters("\"" + eTag + "\"");
                xml.writeEndElement();
            }

            xml.writeEndElement();
            xml.flush();
        } catch (XMLStreamException xse) {
            throw new IOException(xse);
        }
    }

    private void handleAbortMultipartUpload(HttpServletRequest request,
            HttpServletResponse response, String containerName,
            String blobName, String uploadId) throws IOException, S3Exception {
        if (!blobStore.blobExists(containerName, uploadId)) {
            throw new S3Exception(S3ErrorCode.NO_SUCH_UPLOAD);
        }
        PageSet<? extends StorageMetadata> pageSet = blobStore.list(
                containerName,
                new ListContainerOptions().afterMarker(uploadId));
        for (StorageMetadata sm : pageSet) {
            String partName = sm.getName();
            if (!partName.startsWith(uploadId + ".")) {
                break;
            }
            blobStore.removeBlob(containerName, partName);
        }
        blobStore.removeBlob(containerName, uploadId);
        response.sendError(HttpServletResponse.SC_NO_CONTENT);
    }

    private void handleListParts(HttpServletRequest request,
            HttpServletResponse response, String containerName,
            String blobName, String uploadId) throws IOException {
        try (Writer writer = response.getWriter()) {
            XMLStreamWriter xml = xmlOutputFactory.createXMLStreamWriter(
                    writer);
            xml.writeStartDocument();
            xml.writeStartElement("ListPartsResult");
            xml.writeDefaultNamespace(AWS_XMLNS);

            xml.writeStartElement("Bucket");
            xml.writeCharacters(containerName);
            xml.writeEndElement();

            xml.writeStartElement("Key");
            xml.writeCharacters(blobName);
            xml.writeEndElement();

            xml.writeStartElement("UploadId");
            xml.writeCharacters(uploadId);
            xml.writeEndElement();

            // TODO: bogus values
            xml.writeStartElement("Initiator");

            xml.writeStartElement("ID");
            xml.writeCharacters(FAKE_INITIATOR_ID);
            xml.writeEndElement();

            xml.writeStartElement("DisplayName");
            xml.writeCharacters(FAKE_INITIATOR_DISPLAY_NAME);
            xml.writeEndElement();

            xml.writeEndElement();

            writeOwnerStanza(xml);

            xml.writeStartElement("StorageClass");
            xml.writeCharacters("STANDARD");
            xml.writeEndElement();

            // TODO: pagination
/*
            xml.writeStartElement("PartNumberMarker");
            xml.writeCharacters("1");
            xml.writeEndElement();

            xml.writeStartElement("NextPartNumberMarker");
            xml.writeCharacters("3");
            xml.writeEndElement();

            xml.writeStartElement("MaxParts");
            xml.writeCharacters("2");
            xml.writeEndElement();

            xml.writeStartElement("IsTruncated");
            xml.writeCharacters("true");
            xml.writeEndElement();
*/

            PageSet<? extends StorageMetadata> pageSet = blobStore.list(
                    containerName,
                    new ListContainerOptions().afterMarker(uploadId));
            for (StorageMetadata sm : pageSet) {
                String partName = sm.getName();
                if (!partName.startsWith(uploadId + ".")) {
                    break;
                }

                BlobMetadata metadata = blobStore.blobMetadata(containerName,
                        partName);
                xml.writeStartElement("Part");

                xml.writeStartElement("PartNumber");
                xml.writeCharacters(partName.substring(
                        (uploadId + ".").length()));
                xml.writeEndElement();

                Date lastModified = sm.getLastModified();
                if (lastModified != null) {
                    xml.writeStartElement("LastModified");
                    xml.writeCharacters(blobStore.getContext().utils().date()
                            .iso8601DateFormat(lastModified));
                    xml.writeEndElement();
                }

                String eTag = sm.getETag();
                if (eTag != null) {
                    xml.writeStartElement("ETag");
                    if (blobStoreType.equals("google-cloud-storage")) {
                        eTag = BaseEncoding.base16().lowerCase().encode(
                                BaseEncoding.base64().decode(eTag));
                    }
                    xml.writeCharacters("\"" + eTag + "\"");
                    xml.writeEndElement();
                }

                xml.writeStartElement("Size");
                xml.writeCharacters(String.valueOf(
                        metadata.getContentMetadata().getContentLength()));
                xml.writeEndElement();

                xml.writeEndElement();
            }

            xml.writeEndElement();
            xml.flush();
        } catch (XMLStreamException xse) {
            throw new IOException(xse);
        }
    }

    private void handleUploadPart(HttpServletRequest request,
            HttpServletResponse response, String containerName,
            String blobName, String uploadId)
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

        String partNumber = request.getParameter("partNumber");
        // TODO: sanity checking

        try (HashingInputStream his = new HashingInputStream(Hashing.md5(),
                request.getInputStream())) {
            BlobBuilder.PayloadBlobBuilder builder = blobStore
                    .blobBuilder(uploadId + "." + partNumber)
                    .payload(his)
                    .contentLength(request.getContentLength());
            addContentMetdataFromHttpRequest(builder, request);
            if (contentMD5 != null) {
                builder = builder.contentMD5(contentMD5);
            }

            blobStore.putBlob(containerName, builder.build());

            // recalculate ETag since some object stores like Azure return
            // non-hash
            byte[] hashCode = his.hash().asBytes();
            response.addHeader(HttpHeaders.ETAG, "\"" +
                    BaseEncoding.base16().lowerCase().encode(hashCode) + "\"");
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
            response.addHeader(HttpHeaders.ETAG, "\"" +
                    BaseEncoding.base16().lowerCase().encode(contentMd5Bytes) +
                    "\"");
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

    private void sendSimpleErrorResponse(HttpServletResponse response,
            S3ErrorCode code) throws IOException {
        sendSimpleErrorResponse(response, code, code.getMessage(), null, null);
    }

    private void sendSimpleErrorResponse(HttpServletResponse response,
            S3ErrorCode code, String message, String element, String characters)
            throws IOException {
        checkArgument(!(element == null ^ characters == null),
                "Must specify neither or both element and characters");
        logger.debug("{} {} {}", code, element, characters);

        try (Writer writer = response.getWriter()) {
            XMLStreamWriter xml = xmlOutputFactory.createXMLStreamWriter(
                    writer);
            response.setStatus(code.getHttpStatusCode());
            xml.writeStartDocument();
            xml.writeStartElement("Error");

            xml.writeStartElement("Code");
            xml.writeCharacters(code.getErrorCode());
            xml.writeEndElement();

            xml.writeStartElement("Message");
            xml.writeCharacters(message);
            xml.writeEndElement();

            if (element != null) {
                xml.writeStartElement(element);
                xml.writeCharacters(characters);
                xml.writeEndElement();
            }

            xml.writeStartElement("RequestId");
            xml.writeCharacters(FAKE_REQUEST_ID);
            xml.writeEndElement();

            xml.writeEndElement();
            xml.flush();
        } catch (XMLStreamException xse) {
            throw new IOException(xse);
        }
    }

    static class S3Exception extends Exception {
        private final S3ErrorCode error;

        S3Exception(S3ErrorCode error) {
            this(error, null);
        }

        S3Exception(S3ErrorCode error, Throwable cause) {
            super(cause);
            this.error = checkNotNull(error);
        }

        S3ErrorCode getError() {
            return error;
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

        xml.writeStartElement("ID");
        xml.writeCharacters(FAKE_OWNER_ID);
        xml.writeEndElement();

        xml.writeStartElement("DisplayName");
        xml.writeCharacters(FAKE_OWNER_DISPLAY_NAME);
        xml.writeEndElement();

        xml.writeEndElement();
    }

    static final class MultiBlobByteSource extends ByteSource {
        private final BlobStore blobStore;
        private final String containerName;
        private final Collection<String> blobNames;

        MultiBlobByteSource(BlobStore blobStore, String containerName,
                Collection<String> blobNames) {
            this.blobStore = checkNotNull(blobStore);
            this.containerName = checkNotNull(containerName);
            this.blobNames = checkNotNull(blobNames);
        }

        @Override
        public InputStream openStream() throws IOException {
            return new MultiBlobInputStream(blobStore, containerName,
                    blobNames);
        }
    }

    static final class MultiBlobInputStream extends InputStream {
        private final BlobStore blobStore;
        private final String containerName;
        private final Iterator<String> blobNames;
        private InputStream is;

        MultiBlobInputStream(BlobStore blobStore, String containerName,
                Collection<String> blobNames) throws IOException {
            this.blobStore = checkNotNull(blobStore);
            this.containerName = checkNotNull(containerName);
            this.blobNames = blobNames.iterator();
            resetInputStream();
        }

        @Override
        public int read() throws IOException {
            int ch = is.read();
            if (ch != -1) {
                return ch;
            } else if (blobNames.hasNext()) {
                resetInputStream();
                return is.read();
            } else {
                return -1;
            }
        }

        @Override
        public int read(byte[] array, int offset, int length)
                throws IOException {
            int ch = is.read(array, offset, length);
            if (ch != -1) {
                return ch;
            } else if (blobNames.hasNext()) {
                resetInputStream();
                return is.read(array, offset, length);
            } else {
                return -1;
            }
        }

        private void resetInputStream() throws IOException {
            Blob blob = blobStore.getBlob(containerName, blobNames.next());
            is = blob.getPayload().openStream();
        }
    }
}
