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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.google.common.base.Optional;
import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.google.common.base.Throwables;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.SortedSetMultimap;
import com.google.common.collect.TreeMultimap;
import com.google.common.hash.HashCode;
import com.google.common.io.BaseEncoding;
import com.google.common.io.ByteStreams;
import com.google.common.net.HttpHeaders;

import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.jclouds.blobstore.BlobStore;
import org.jclouds.blobstore.ContainerNotFoundException;
import org.jclouds.blobstore.domain.Blob;
import org.jclouds.blobstore.domain.BlobBuilder;
import org.jclouds.blobstore.domain.BlobMetadata;
import org.jclouds.blobstore.domain.PageSet;
import org.jclouds.blobstore.domain.StorageMetadata;
import org.jclouds.blobstore.domain.StorageType;
import org.jclouds.blobstore.options.CreateContainerOptions;
import org.jclouds.blobstore.options.GetOptions;
import org.jclouds.blobstore.options.ListContainerOptions;
import org.jclouds.blobstore.options.PutOptions;
import org.jclouds.domain.Location;
import org.jclouds.http.HttpResponseException;
import org.jclouds.io.ContentMetadata;
import org.jclouds.rest.AuthorizationException;
import org.jclouds.util.Strings2;
import org.jclouds.util.Throwables2;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

final class S3ProxyHandler extends AbstractHandler {
    private static final Logger logger = LoggerFactory.getLogger(
            S3ProxyHandler.class);
    // Note that this excludes a trailing \r\n which the AWS SDK rejects.
    private static final String XML_PROLOG =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>";
    private static final String AWS_XMLNS =
            "xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"";
    // TODO: support configurable metadata prefix
    private static final String USER_METADATA_PREFIX = "x-amz-meta-";
    // TODO: fake owner
    private static final String FAKE_OWNER_ID =
            "75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a";
    private static final String FAKE_OWNER_DISPLAY_NAME =
            "CustomersName@amazon.com";
    private static final String FAKE_REQUEST_ID = "4442587FB7D0A2F9";
    private static final Pattern CREATE_BUCKET_LOCATION_PATTERN =
            Pattern.compile("<LocationConstraint>(.*?)</LocationConstraint>");
    private static final Pattern MULTI_DELETE_KEY_PATTERN =
            Pattern.compile("<Key>(.*?)</Key>");

    private final BlobStore blobStore;
    private final String identity;
    private final String credential;
    private final boolean forceMultiPartUpload;

    S3ProxyHandler(BlobStore blobStore, String identity, String credential,
            boolean forceMultiPartUpload) {
        this.blobStore = Preconditions.checkNotNull(blobStore);
        this.identity = identity;
        this.credential = credential;
        this.forceMultiPartUpload = forceMultiPartUpload;
    }

    @Override
    public void handle(String target, Request baseRequest,
            HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String method = request.getMethod();
        String uri = request.getRequestURI();
        String[] path = uri.split("/", 3);
        logger.debug("request: {}", request);
        for (String headerName : Collections.list(request.getHeaderNames())) {
            for (String headerValue : Collections.list(request.getHeaders(
                    headerName))) {
                logger.trace("header: {}: {}", headerName,
                        Strings.nullToEmpty(headerValue));
            }
        }

        long date;
        try {
            date = request.getDateHeader(HttpHeaders.DATE);
        } catch (IllegalArgumentException iae) {
            sendSimpleErrorResponse(response, S3ErrorCode.ACCESS_DENIED);
            baseRequest.setHandled(true);
            return;
        }
        if (date < 0) {
            sendSimpleErrorResponse(response, S3ErrorCode.ACCESS_DENIED);
            baseRequest.setHandled(true);
            return;
        }
        long now = System.currentTimeMillis();
        if (now + TimeUnit.DAYS.toMillis(1) < date ||
                now - TimeUnit.DAYS.toMillis(1) > date) {
            sendSimpleErrorResponse(response,
                    S3ErrorCode.REQUEST_TIME_TOO_SKEWED);
            baseRequest.setHandled(true);
            return;
        }

        if (identity != null) {
            String expectedAuthorization = createAuthorizationHeader(request,
                    identity, credential);
            String headerAuthorization = request.getHeader(
                    HttpHeaders.AUTHORIZATION);
            String queryStringAuthorization = "AWS " +
                    request.getParameter("AWSAccessKeyId") + ":" +
                    request.getParameter("Signature");
            if (!expectedAuthorization.equals(headerAuthorization) &&
                    !expectedAuthorization.equals(queryStringAuthorization)) {
                sendSimpleErrorResponse(response,
                        S3ErrorCode.SIGNATURE_DOES_NOT_MATCH);
                baseRequest.setHandled(true);
                return;
            }
        }

        switch (method) {
        case "DELETE":
            if (path.length <= 2 || path[2].isEmpty()) {
                handleContainerDelete(response, path[1]);
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
            } else if (uri.lastIndexOf("/") == 0 &&
                    "".equals(request.getParameter("acl"))) {
                handleContainerAcl(response, uri.substring(1));
                baseRequest.setHandled(true);
                return;
            } else if (path.length <= 2 || path[2].isEmpty()) {
                handleBlobList(request, response, path[1]);
                baseRequest.setHandled(true);
                return;
            } else {
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
            }
            break;
        case "PUT":
            if (path.length <= 2 || path[2].isEmpty()) {
                if ("".equals(request.getParameter("acl"))) {
                    response.sendError(HttpServletResponse.SC_NOT_IMPLEMENTED);
                    baseRequest.setHandled(true);
                    return;
                }
                handleContainerCreate(request, response, path[1]);
                baseRequest.setHandled(true);
                return;
            } else if (request.getHeader("x-amz-copy-source") != null) {
                handleCopyBlob(request, response, path[1], path[2]);
                baseRequest.setHandled(true);
                return;
            } else {
                handlePutBlob(request, response, path[1], path[2]);
                baseRequest.setHandled(true);
                return;
            }
        default:
            logger.error("Unknown method {} with URI {}",
                    method, request.getRequestURI());
            response.sendError(HttpServletResponse.SC_NOT_IMPLEMENTED);
            baseRequest.setHandled(true);
            return;
        }
    }

    private void handleContainerAcl(HttpServletResponse response,
            String containerName) throws IOException {
        try (Writer writer = response.getWriter()) {
            writer.write("<AccessControlPolicy>\r\n" +
                    "  <Owner>\r\n" +
                    "    <ID>" + FAKE_OWNER_ID + "</ID>\r\n" +
                    "    <DisplayName>" + FAKE_OWNER_DISPLAY_NAME + "</DisplayName>\r\n" +
                    "  </Owner>\r\n" +
                    "  <AccessControlList>\r\n" +
                    "    <Grant>\r\n" +
                    "      <Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\r\n" +
                    "            xsi:type=\"CanonicalUser\">\r\n" +
                    "        <ID>" + FAKE_OWNER_ID + "</ID>\r\n" +
                    "        <DisplayName>" + FAKE_OWNER_DISPLAY_NAME + "</DisplayName>\r\n" +
                    "      </Grantee>\r\n" +
                    "      <Permission>FULL_CONTROL</Permission>\r\n" +
                    "    </Grant>\r\n" +
                    "  </AccessControlList>\r\n" +
                    "</AccessControlPolicy>");
            writer.flush();
        }
    }

    private void handleContainerList(HttpServletResponse response)
            throws IOException {
        try (Writer writer = response.getWriter()) {
            writer.write(XML_PROLOG +
                    "<ListAllMyBucketsResult " + AWS_XMLNS + ">\r\n" +
                    "  <Owner>\r\n" +
                    "    <ID>" + FAKE_OWNER_ID + "</ID>\r\n" +
                    "    <DisplayName>" + FAKE_OWNER_DISPLAY_NAME + "</DisplayName>\r\n" +
                    "  </Owner>\r\n" +
                    "  <Buckets>\r\n");

            for (StorageMetadata metadata : blobStore.list()) {
                writer.write("    <Bucket>\r\n" +
                        "      <Name>");
                writer.write(metadata.getName());
                writer.write("</Name>\r\n");
                Date creationDate = metadata.getCreationDate();
                if (creationDate != null) {
                    writer.write("      <CreationDate>");
                    writer.write(blobStore.getContext().utils().date()
                            .iso8601DateFormat(creationDate).trim());
                    writer.write("</CreationDate>\r\n");
                }
                writer.write("    </Bucket>\r\n");
            }

            writer.write("  </Buckets>\r\n" +
                    "</ListAllMyBucketsResult>");
            writer.flush();
        }
    }

    private void handleContainerExists(HttpServletResponse response,
            String containerName) throws IOException {
        if (!blobStore.containerExists(containerName)) {
            sendSimpleErrorResponse(response, S3ErrorCode.NO_SUCH_BUCKET);
            return;
        }
    }

    private void handleContainerCreate(HttpServletRequest request,
            HttpServletResponse response, String containerName)
            throws IOException {
        if (containerName.isEmpty()) {
            sendSimpleErrorResponse(response, S3ErrorCode.METHOD_NOT_ALLOWED);
            return;
        }
        if (containerName.length() < 3 || containerName.length() > 255) {
            sendSimpleErrorResponse(response, S3ErrorCode.INVALID_BUCKET_NAME);
            return;
        }

        Location location = null;
        // TODO: more robust XML parsing
        Matcher matcher = CREATE_BUCKET_LOCATION_PATTERN.matcher(
                Strings2.toStringAndClose(request.getInputStream()));
        if (matcher.find()) {
            String locationString = matcher.group(1);
            for (Location loc : blobStore.listAssignableLocations()) {
                if (loc.getId().equalsIgnoreCase(locationString)) {
                    location = loc;
                    break;
                }
            }
            if (location == null) {
                sendSimpleErrorResponse(response,
                        S3ErrorCode.INVALID_LOCATION_CONSTRAINT);
                return;
            }
        }
        logger.debug("Creating bucket with location: {}", location);

        CreateContainerOptions options = new CreateContainerOptions();
        String acl = request.getHeader("x-amz-acl");
        if ("public-read".equals(acl)) {
            options.publicRead();
        }

        try {
            if (blobStore.createContainerInLocation(location, containerName,
                    options)) {
                return;
            }
            sendSimpleErrorResponse(response,
                    S3ErrorCode.BUCKET_ALREADY_OWNED_BY_YOU,
                    Optional.of("  <BucketName>" + containerName +
                            "</BucketName>\r\n"));
        } catch (AuthorizationException ae) {
            sendSimpleErrorResponse(response,
                    S3ErrorCode.BUCKET_ALREADY_EXISTS);
            return;
        }
    }

    private void handleContainerDelete(HttpServletResponse response,
            String containerName) throws IOException {
        if (!blobStore.containerExists(containerName)) {
            sendSimpleErrorResponse(response, S3ErrorCode.NO_SUCH_BUCKET);
            return;
        }
        if (!blobStore.deleteContainerIfEmpty(containerName)) {
            sendSimpleErrorResponse(response, S3ErrorCode.BUCKET_NOT_EMPTY);
            return;
        }
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }

    private void handleBlobList(HttpServletRequest request,
            HttpServletResponse response, String containerName)
            throws IOException {
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
                sendSimpleErrorResponse(response, S3ErrorCode.INVALID_ARGUMENT);
                return;
            }
        }
        options = options.maxResults(maxKeys);

        PageSet<? extends StorageMetadata> set;
        try {
            set = blobStore.list(containerName, options);
        } catch (ContainerNotFoundException cnfe) {
            sendSimpleErrorResponse(response, S3ErrorCode.NO_SUCH_BUCKET);
            return;
        }

        try (Writer writer = response.getWriter()) {
            response.setStatus(HttpServletResponse.SC_OK);
            writer.write(XML_PROLOG +
                    "<ListBucketResult " + AWS_XMLNS + ">\r\n" +
                    "  <Name>");
            writer.write(containerName);
            writer.write("</Name>\r\n");
            if (prefix == null) {
                writer.write("  <Prefix/>\r\n");
            } else {
                writer.write("  <Prefix>");
                writer.write(prefix);
                writer.write("</Prefix>\r\n");
            }
            writer.write("  <MaxKeys>");
            writer.write(String.valueOf(maxKeys));
            writer.write("</MaxKeys>\r\n");
            if (marker == null) {
                writer.write("  <Marker/>\r\n");
            } else {
                writer.write("  <Marker>");
                writer.write(marker);
                writer.write("</Marker>\r\n");
            }
            if (delimiter != null) {
                writer.write("  <Delimiter>");
                writer.write(delimiter);
                writer.write("</Delimiter>\r\n");
            }
            String nextMarker = set.getNextMarker();
            if (nextMarker != null) {
                writer.write("  <IsTruncated>true</IsTruncated>\r\n" +
                    "  <NextMarker>");
                writer.write(nextMarker);
                writer.write("</NextMarker>\r\n");
            } else {
                writer.write("  <IsTruncated>false</IsTruncated>\r\n");
            }

            Set<String> commonPrefixes = new HashSet<>();
            for (StorageMetadata metadata : set) {
                if (metadata.getType() != StorageType.BLOB) {
                    commonPrefixes.add(metadata.getName());
                    continue;
                }
                writer.write("  <Contents>\r\n" +
                    "    <Key>");
                writer.write(metadata.getName());
                writer.write("</Key>\r\n");
                Date lastModified = metadata.getLastModified();
                if (lastModified != null) {
                    writer.write("    <LastModified>");
                    writer.write(blobStore.getContext().utils().date()
                            .iso8601DateFormat(lastModified));
                    writer.write("</LastModified>\r\n");
                }
                String eTag = metadata.getETag();
                if (eTag != null) {
                    writer.write("    <ETag>&quot;");
                    if (eTag.startsWith("0x")) {
                        // Azure returns Etag as 0x8D1895E13DF8EF1 but S3
                        // expects "8d1895e13df8ef1" with zero-padding.
                        eTag = eTag.substring(2).toLowerCase();
                        if (eTag.length() < 16) {
                            writer.write(Strings.repeat("0", 16 -
                                    eTag.length()));
                        }
                    }
                    writer.write(eTag);
                    writer.write("&quot;</ETag>\r\n");
                }
                writer.write(
                    // TODO: StorageMetadata does not contain size
                    "    <Size>0</Size>\r\n" +
                    "    <StorageClass>STANDARD</StorageClass>\r\n" +
                    "    <Owner>\r\n" +
                    "      <ID>" + FAKE_OWNER_ID + "</ID>\r\n" +
                    "      <DisplayName>" + FAKE_OWNER_DISPLAY_NAME + "</DisplayName>\r\n" +
                    "    </Owner>\r\n" +
                    "  </Contents>\r\n");
            }

            for (String commonPrefix : commonPrefixes) {
                writer.write("  <CommonPrefixes>\r\n" +
                        "    <Prefix>");
                writer.write(commonPrefix);
                if (delimiter != null) {
                    writer.write(delimiter);
                }
                writer.write("</Prefix>\r\n" +
                        "  </CommonPrefixes>\r\n");
            }

            writer.write("</ListBucketResult>");
            writer.flush();
        }
    }

    private void handleBlobRemove(HttpServletResponse response,
            String containerName, String blobName) throws IOException {
        try {
            blobStore.removeBlob(containerName, blobName);
            response.sendError(HttpServletResponse.SC_NO_CONTENT);
        } catch (ContainerNotFoundException cnfe) {
            sendSimpleErrorResponse(response, S3ErrorCode.NO_SUCH_BUCKET);
            return;
        }
    }

    private void handleMultiBlobRemove(HttpServletRequest request,
            HttpServletResponse response, String containerName)
            throws IOException {
        try (Writer writer = response.getWriter()) {
            writer.write(XML_PROLOG);
            writer.write("<DeleteResult " + AWS_XMLNS + ">\r\n");
            // TODO: more robust XML parsing
            Matcher matcher = MULTI_DELETE_KEY_PATTERN.matcher(
                    Strings2.toStringAndClose(request.getInputStream()));
            while (matcher.find()) {
                String blobName = matcher.group(1);
                blobStore.removeBlob(containerName, blobName);

                writer.write("<Deleted><Key>");
                writer.write(blobName);
                writer.write("</Key></Deleted>\r\n");
            }
            // TODO: emit error stanza
            writer.write("</DeleteResult>");
        }
    }

    private void handleBlobMetadata(HttpServletResponse response,
            String containerName, String blobName) throws IOException {
        BlobMetadata metadata;
        try {
            metadata = blobStore.blobMetadata(containerName, blobName);
        } catch (ContainerNotFoundException cnfe) {
            sendSimpleErrorResponse(response, S3ErrorCode.NO_SUCH_BUCKET);
            return;
        }
        if (metadata == null) {
            sendSimpleErrorResponse(response, S3ErrorCode.NO_SUCH_KEY);
            return;
        }

        response.setStatus(HttpServletResponse.SC_OK);
        addMetadataToResponse(response, metadata);
    }

    private void handleGetBlob(HttpServletRequest request,
            HttpServletResponse response, String containerName,
            String blobName) throws IOException {
        int status = HttpServletResponse.SC_OK;
        GetOptions options = new GetOptions();
        String range = request.getHeader(HttpHeaders.RANGE);
        if (range != null && range.startsWith("bytes=")
                // ignore multiple ranges
                && range.indexOf(',') == -1) {
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
            sendSimpleErrorResponse(response, S3ErrorCode.NO_SUCH_BUCKET);
            return;
        }
        if (blob == null) {
            sendSimpleErrorResponse(response, S3ErrorCode.NO_SUCH_KEY);
            return;
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
            String destBlobName) throws IOException {
        String copySourceHeader = request.getHeader("x-amz-copy-source");
        if (copySourceHeader.startsWith("/")) {
            // Some clients like boto do not include the leading slash
            copySourceHeader = copySourceHeader.substring(1);
        }
        String[] path = copySourceHeader.split("/", 2);
        String sourceContainerName = path[0];
        String sourceBlobName = path[1];
        boolean replaceMetadata = "REPLACE".equals(request.getHeader(
                "x-amz-metadata-directive"));

        ImmutableMap.Builder<String, String> userMetadataBuilder =
                ImmutableMap.builder();
        for (String headerName : Collections.list(request.getHeaderNames())) {
            if (!headerName.startsWith(USER_METADATA_PREFIX)) {
                continue;
            }
            userMetadataBuilder.put(
                    headerName.substring(USER_METADATA_PREFIX.length()),
                    Strings.nullToEmpty(request.getHeader(headerName)));
        }
        Map<String, String> userMetadata = userMetadataBuilder.build();

        if (sourceContainerName.equals(destContainerName) &&
                sourceBlobName.equals(destBlobName) &&
                !replaceMetadata) {
            sendSimpleErrorResponse(response, S3ErrorCode.INVALID_REQUEST);
            return;
        }

        Blob blob = blobStore.getBlob(sourceContainerName, sourceBlobName);
        if (blob == null) {
            sendSimpleErrorResponse(response, S3ErrorCode.NO_SUCH_KEY);
            return;
        }

        try (InputStream is = blob.getPayload().openStream()) {
            ContentMetadata metadata = blob.getMetadata().getContentMetadata();
            BlobBuilder.PayloadBlobBuilder builder = blobStore
                    .blobBuilder(destBlobName)
                    .userMetadata(replaceMetadata ? userMetadata :
                            blob.getMetadata().getUserMetadata())
                    .payload(is)
                    .contentDisposition(metadata.getContentDisposition())
                    .contentEncoding(metadata.getContentEncoding())
                    .contentLanguage(metadata.getContentLanguage())
                    .contentLength(metadata.getContentLength())
                    .contentType(metadata.getContentType());

            String eTag = blobStore.putBlob(destContainerName,
                    builder.build());
            Date lastModified = blob.getMetadata().getLastModified();
            try (Writer writer = response.getWriter()) {
                writer.write(XML_PROLOG);
                writer.write("<CopyObjectResult>\r\n");
                writer.write("  <LastModified>");
                writer.write(blobStore.getContext().utils().date()
                        .iso8601DateFormat(lastModified));
                writer.write("</LastModified>\r\n");
                writer.write("  <ETag>&quot;");
                writer.write(eTag);
                writer.write("&quot;</ETag>\r\n");
                writer.write("</CopyObjectResult>");
            }
        }
    }

    private void handlePutBlob(HttpServletRequest request,
            HttpServletResponse response, String containerName,
            String blobName) throws IOException {
        // Flag headers present since HttpServletResponse.getHeader returns
        // null for empty headers.
        boolean hasContentLength = false;
        boolean hasContentMD5 = false;
        ImmutableMap.Builder<String, String> userMetadata =
                ImmutableMap.builder();
        Enumeration<String> enumeration = request.getHeaderNames();
        while (enumeration.hasMoreElements()) {
            String headerName = enumeration.nextElement();
            if (headerName.equals(HttpHeaders.CONTENT_LENGTH)) {
                hasContentLength = true;
            } else if (headerName.equals(HttpHeaders.CONTENT_MD5)) {
                hasContentMD5 = true;
            } else if (headerName.toLowerCase().startsWith(
                    USER_METADATA_PREFIX)) {
                userMetadata.put(
                        headerName.substring(USER_METADATA_PREFIX.length()),
                        Strings.nullToEmpty(request.getHeader(headerName)));
            }
        }

        HashCode contentMD5 = null;
        if (hasContentMD5) {
            boolean validDigest = true;
            String contentMD5String = request.getHeader(
                    HttpHeaders.CONTENT_MD5);
            if (contentMD5String == null) {
                validDigest = false;
            } else {
                try {
                    contentMD5 = HashCode.fromBytes(
                            BaseEncoding.base64().decode(contentMD5String));
                } catch (IllegalArgumentException iae) {
                    validDigest = false;
                }
            }
            if (!validDigest) {
                sendSimpleErrorResponse(response, S3ErrorCode.INVALID_DIGEST);
                return;
            }
        }

        if (!hasContentLength) {
            sendSimpleErrorResponse(response,
                    S3ErrorCode.MISSING_CONTENT_LENGTH);
            return;
        }
        long contentLength = 0;
        boolean validContentLength = true;
        String contentLengthString = request.getHeader(
                HttpHeaders.CONTENT_LENGTH);
        if (contentLengthString == null) {
            validContentLength = false;
        } else {
            try {
                contentLength = Long.parseLong(contentLengthString);
            } catch (NumberFormatException nfe) {
                validContentLength = false;
            }
        }
        if (!validContentLength || contentLength < 0) {
            sendSimpleErrorResponse(response, S3ErrorCode.INVALID_ARGUMENT);
            return;
        }

        try (InputStream is = request.getInputStream()) {
            BlobBuilder.PayloadBlobBuilder builder = blobStore
                    .blobBuilder(blobName)
                    .userMetadata(userMetadata.build())
                    .payload(is)
                    .contentDisposition(request.getHeader(
                            HttpHeaders.CONTENT_DISPOSITION))
                    .contentEncoding(request.getHeader(
                            HttpHeaders.CONTENT_ENCODING))
                    .contentLanguage(request.getHeader(
                            HttpHeaders.CONTENT_LANGUAGE))
                    .contentLength(request.getContentLength())
                    .contentType(request.getContentType());
            long expires = request.getDateHeader(HttpHeaders.EXPIRES);
            if (expires != -1) {
                builder = builder.expires(new Date(expires));
            }
            if (contentMD5 != null) {
                builder = builder.contentMD5(contentMD5);
            }
            PutOptions options = new PutOptions()
                .multipart(forceMultiPartUpload);
            try {
                String eTag = blobStore.putBlob(containerName, builder.build(),
                        options);
                response.addHeader(HttpHeaders.ETAG, "\"" + eTag + "\"");
            } catch (ContainerNotFoundException cnfe) {
                sendSimpleErrorResponse(response, S3ErrorCode.NO_SUCH_BUCKET);
                return;
            } catch (HttpResponseException hre) {
                int status = hre.getResponse().getStatusCode();
                switch (status) {
                case HttpServletResponse.SC_BAD_REQUEST:
                case 422:  // Swift returns 422 Unprocessable Entity
                    sendSimpleErrorResponse(response,
                            S3ErrorCode.INVALID_DIGEST);
                    break;
                default:
                    // TODO: emit hre.getContent() ?
                    response.sendError(status);
                    break;
                }
                return;
            } catch (RuntimeException re) {
                if (Throwables2.getFirstThrowableOfType(re,
                        TimeoutException.class) != null) {
                    sendSimpleErrorResponse(response,
                            S3ErrorCode.REQUEST_TIMEOUT);
                    return;
                } else {
                    throw re;
                }
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
            response.addHeader(HttpHeaders.CONTENT_MD5,
                    BaseEncoding.base64().encode(contentMd5.asBytes()));
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

    private static void sendSimpleErrorResponse(HttpServletResponse response,
            S3ErrorCode code) throws IOException {
        sendSimpleErrorResponse(response, code, Optional.<String>absent());
    }

    private static void sendSimpleErrorResponse(HttpServletResponse response,
            S3ErrorCode code, Optional<String> extra) throws IOException {
        logger.debug("{} {}", code, extra);
        try (Writer writer = response.getWriter()) {
            response.setStatus(code.getHttpStatusCode());
            writer.write(XML_PROLOG +
                    "<Error>\r\n" +
                    "  <Code>");
            writer.write(code.getErrorCode());
            writer.write("</Code>\r\n" +
                    "  <Message>");
            writer.write(code.getMessage());
            writer.write("</Message>\r\n");
            if (extra.isPresent()) {
                writer.write(extra.get());
            }
            writer.write("  <RequestId>" + FAKE_REQUEST_ID +
                    "</RequestId>\r\n" +
                    "</Error>");
            writer.flush();
        }
    }

    /**
     * Create Amazon V2 authorization header.  Reference:
     * http://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html
     */
    private static String createAuthorizationHeader(HttpServletRequest request,
            String identity, String credential) {
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
                .append(request.getMethod()).append('\n');
        String contentMD5 = request.getHeader(HttpHeaders.CONTENT_MD5);
        if (contentMD5 != null) {
            builder.append(contentMD5);
        }
        builder.append('\n');
        String contentType = request.getHeader(HttpHeaders.CONTENT_TYPE);
        if (contentType != null) {
            builder.append(contentType);
        }
        builder.append('\n');
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
        builder.append(request.getRequestURI());
        if ("".equals(request.getParameter("acl"))) {
            builder.append("?acl");
        } else if ("".equals(request.getParameter("delete"))) {
            builder.append("?delete");
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
        String signature = BaseEncoding.base64().encode(mac.doFinal(
                stringToSign.getBytes(StandardCharsets.UTF_8)));

        return "AWS" + " " + identity + ":" + signature;
    }
}
