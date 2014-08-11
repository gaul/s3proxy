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
import org.jclouds.blobstore.options.GetOptions;
import org.jclouds.blobstore.options.ListContainerOptions;
import org.jclouds.domain.Location;
import org.jclouds.http.HttpResponseException;
import org.jclouds.io.ContentMetadata;
import org.jclouds.util.Strings2;
import org.jclouds.util.Throwables2;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

final class S3ProxyHandler extends AbstractHandler {
    private static final Logger logger = LoggerFactory.getLogger(
            S3ProxyHandler.class);
    // TODO: support configurable metadata prefix
    private static final String USER_METADATA_PREFIX = "x-amz-meta-";
    // TODO: fake owner
    private static final String FAKE_OWNER_ID =
            "75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a";
    private static final String FAKE_OWNER_DISPLAY_NAME =
            "CustomersName@amazon.com";
    private static final String FAKE_REQUEST_ID = "4442587FB7D0A2F9";
    private static final Pattern CREATE_BUCKET_LOCATION_PATTERN =
            // TODO: non-greedy star .*?
            Pattern.compile("<LocationConstraint>([^<]*)</LocationConstraint>");

    private final BlobStore blobStore;
    private final String identity;
    private final String credential;

    S3ProxyHandler(BlobStore blobStore, String identity, String credential) {
        this.blobStore = Preconditions.checkNotNull(blobStore);
        this.identity = identity;
        this.credential = credential;
    }

    @Override
    public void handle(String target, Request baseRequest,
            HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String method = request.getMethod();
        String uri = request.getRequestURI();
        String[] path = uri.split("/", 3);
        logger.debug("request: {}", request);

        if (identity != null) {
            String expectedAuthorization = createAuthorizationHeader(request,
                    identity, credential);
            if (!expectedAuthorization.equals(request.getHeader(
                    HttpHeaders.AUTHORIZATION)) &&
                    !expectedAuthorization.equals("AWS " + request.getParameter("AWSAccessKeyId") + ":" + request.getParameter("Signature"))) {
                sendSimpleErrorResponse(response,
                        HttpServletResponse.SC_FORBIDDEN,
                        "SignatureDoesNotMatch", "Forbidden");
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
            String containerName) {
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
                    "</AccessControlPolicy>\r\n");
            writer.flush();
        } catch (IOException ioe) {
            logger.error("Error writing to client: {}", ioe.getMessage());
        }
    }

    private void handleContainerList(HttpServletResponse response) {
        try (Writer writer = response.getWriter()) {
            writer.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n" +
                    "<ListAllMyBucketsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\r\n" +
                    "  <Owner>\r\n" +
                    "    <ID>" + FAKE_OWNER_ID + "</ID>\r\n" +
                    "    <DisplayName>" + FAKE_OWNER_DISPLAY_NAME + "</DisplayName>\r\n" +
                    "  </Owner>\r\n" +
                    "  <Buckets>");

            for (StorageMetadata metadata : blobStore.list()) {
                writer.write("<Bucket>\r\n" +
                        "  <Name>");
                writer.write(metadata.getName());
                writer.write("</Name>\r\n");
                Date creationDate = metadata.getCreationDate();
                if (creationDate != null) {
                    writer.write("  <CreationDate>");
                    writer.write(blobStore.getContext().utils().date()
                            .iso8601DateFormat(creationDate));
                    writer.write("</CreationDate>\r\n");
                }
                writer.write("</Bucket>\r\n");
            }

            writer.write("  </Buckets>\r\n" +
                    "</ListAllMyBucketsResult>\r\n");
            writer.flush();
        } catch (IOException ioe) {
            logger.error("Error writing to client: {}", ioe.getMessage());
        }
    }

    private void handleContainerExists(HttpServletResponse response,
            String containerName) {
        if (!blobStore.containerExists(containerName)) {
            sendSimpleErrorResponse(response,
                    HttpServletResponse.SC_NOT_FOUND, "NoSuchBucket",
                    "Not Found");
            return;
        }
    }

    private void handleContainerCreate(HttpServletRequest request,
            HttpServletResponse response, String containerName)
            throws IOException {
        if (containerName.isEmpty()) {
            sendSimpleErrorResponse(response,
                    HttpServletResponse.SC_METHOD_NOT_ALLOWED,
                    "MethodNotAllowed", "Method Not Allowed");
            return;
        }
        if (containerName.length() < 3 || containerName.length() > 255) {
            sendSimpleErrorResponse(response,
                    HttpServletResponse.SC_BAD_REQUEST,
                    "InvalidBucketName", "Bad Request");
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
                        HttpServletResponse.SC_BAD_REQUEST,
                        "InvalidLocationConstraint",
                        "The specified location constraint is not valid. For" +
                        " more information about Regions, see How to Select" +
                        " a Region for Your Buckets.");
                return;
            }
        }
        logger.debug("Creating bucket with location: {}", location);

        try {
            if (blobStore.createContainerInLocation(location, containerName)) {
                return;
            }
            sendSimpleErrorResponse(response, HttpServletResponse.SC_CONFLICT,
                    "BucketAlreadyOwnedByYou",
                    "Your previous request to create the named bucket" +
                    " succeeded and you already own it.",
                    Optional.of("  <BucketName>" + containerName +
                            "</BucketName>\r\n"));
        } catch (RuntimeException re) {
            logger.error("Error creating container: {}", re.getMessage());
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        }
    }

    private void handleContainerDelete(HttpServletResponse response,
            String containerName) {
        if (!blobStore.containerExists(containerName)) {
            sendSimpleErrorResponse(response,
                    HttpServletResponse.SC_NOT_FOUND, "NoSuchBucket",
                    "Not Found");
            return;
        }
        if (!blobStore.deleteContainerIfEmpty(containerName)) {
            sendSimpleErrorResponse(response,
                    HttpServletResponse.SC_CONFLICT, "BucketNotEmpty",
                    "Conflict");
            return;
        }
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }

    private void handleBlobList(HttpServletRequest request,
            HttpServletResponse response, String containerName) {
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
                maxKeys = Integer.valueOf(maxKeysString);
            } catch (NumberFormatException nfe) {
                sendSimpleErrorResponse(response,
                        HttpServletResponse.SC_BAD_REQUEST, "InvalidArgument",
                        "Bad Request");
                return;
            }
        }
        options = options.maxResults(maxKeys);

        PageSet<? extends StorageMetadata> set;
        try {
            set = blobStore.list(containerName, options);
        } catch (ContainerNotFoundException cnfe) {
            response.setStatus(HttpServletResponse.SC_NOT_FOUND);
            return;
        }

        try (Writer writer = response.getWriter()) {
            response.setStatus(HttpServletResponse.SC_OK);
            writer.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n" +
                    "<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\r\n" +
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
                    writer.write(metadata.getETag());
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
        } catch (IOException ioe) {
            logger.error("Error writing to client: {}",
                    ioe.getMessage());
        }
    }

    private void handleBlobRemove(HttpServletResponse response,
            String containerName, String blobName) throws IOException {
        try {
            blobStore.removeBlob(containerName, blobName);
            response.sendError(HttpServletResponse.SC_NO_CONTENT);
        } catch (RuntimeException re) {
            logger.error("Error removing blob {} {}: {}", containerName,
                    blobName, re.getMessage());
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }

    private void handleBlobMetadata(HttpServletResponse response,
            String containerName, String blobName) {
        BlobMetadata metadata = blobStore.blobMetadata(containerName, blobName);
        if (metadata == null) {
            response.setStatus(HttpServletResponse.SC_NOT_FOUND);
            return;
        }

        response.setStatus(HttpServletResponse.SC_OK);
        addMetadataToResponse(response, metadata);
    }

    private void handleGetBlob(HttpServletRequest request,
            HttpServletResponse response, String containerName,
            String blobName) throws IOException {
        GetOptions options = new GetOptions();
        String range = request.getHeader(HttpHeaders.RANGE);
        if (range != null && range.startsWith("bytes=")
                // ignore multiple ranges
                && range.indexOf(',') == -1) {
            range = range.substring("bytes=".length());
            String[] ranges = range.split("-", 2);
            options = options.range(Long.parseLong(ranges[0]),
                    Long.parseLong(ranges[1]));
        }

        Blob blob = blobStore.getBlob(containerName, blobName, options);
        if (blob == null) {
            sendSimpleErrorResponse(response,
                    HttpServletResponse.SC_NOT_FOUND, "NoSuchKey",
                    "Not Found");
            return;
        }

        response.setStatus(HttpServletResponse.SC_OK);
        addMetadataToResponse(response, blob.getMetadata());
        try (InputStream is = blob.getPayload().openStream();
             OutputStream os = response.getOutputStream()) {
            ByteStreams.copy(is, os);
            os.flush();
        } catch (IOException ioe) {
            logger.error("Error writing to client: {}", ioe.getMessage());
            return;
        }
    }

    private void handleCopyBlob(HttpServletRequest request,
            HttpServletResponse response, String destContainerName,
            String destBlobName) throws IOException {
        String copySourceHeader = request.getHeader("x-amz-copy-source");
        if (copySourceHeader.startsWith("/")) {
            // Some clients like boto do not include the leading slash
            copySourceHeader.substring(1);
        }
        String[] path = request.getHeader("x-amz-copy-source").split("/", 2);
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
            sendSimpleErrorResponse(response,
                    HttpServletResponse.SC_BAD_REQUEST, "InvalidRequest",
                    "Bad Request");
            return;
        }

        Blob blob = blobStore.getBlob(sourceContainerName, sourceBlobName);
        if (blob == null) {
            sendSimpleErrorResponse(response,
                    HttpServletResponse.SC_NOT_FOUND, "NoSuchKey",
                    "Not Found");
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
                writer.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n");
                writer.write("<CopyObjectResult>\r\n");
                writer.write("  <LastModified>");
                writer.write(blobStore.getContext().utils().date()
                        .iso8601DateFormat(lastModified));
                writer.write("</LastModified>\r\n");
                writer.write("  <ETag>&quot;");
                writer.write(eTag);
                writer.write("&quot;</ETag>\r\n");
                writer.write("</CopyObjectResult>\r\n");
            }
        } catch (IOException ioe) {
            logger.error("Error writing to client: {}", ioe.getMessage());
            return;
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
                sendSimpleErrorResponse(response,
                        HttpServletResponse.SC_BAD_REQUEST, "InvalidDigest",
                        "Bad Request");
                return;
            }
        }

        if (!hasContentLength) {
            sendSimpleErrorResponse(response,
                    HttpServletResponse.SC_LENGTH_REQUIRED,
                    "MissingContentLength", "Length Required");
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
            sendSimpleErrorResponse(response,
                    HttpServletResponse.SC_BAD_REQUEST, "InvalidArgument",
                    "Invalid Argument");
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
            if (expires != 0) {
                builder = builder.expires(new Date(expires));
            }
            if (contentMD5 != null) {
                builder = builder.contentMD5(contentMD5);
            }
            try {
                String eTag = blobStore.putBlob(containerName, builder.build());
                response.addHeader(HttpHeaders.ETAG, "\"" + eTag + "\"");
            } catch (ContainerNotFoundException cnfe) {
                sendSimpleErrorResponse(response,
                        HttpServletResponse.SC_NOT_FOUND, "NoSuchBucket",
                        "Not Found");
                return;
            } catch (HttpResponseException hre) {
                int status = hre.getResponse().getStatusCode();
                if (status == HttpServletResponse.SC_BAD_REQUEST) {
                    sendSimpleErrorResponse(response, status, "InvalidDigest",
                            "Bad Request");
                } else {
                    // TODO: emit hre.getContent() ?
                    response.sendError(status);
                }
                return;
            } catch (RuntimeException re) {
                if (Throwables2.getFirstThrowableOfType(re,
                        TimeoutException.class) != null) {
                    sendSimpleErrorResponse(response,
                            HttpServletResponse.SC_BAD_REQUEST,
                            "RequestTimeout", "Bad Request");
                    return;
                } else {
                    throw re;
                }
            }
        } catch (IOException ioe) {
            logger.error("Error reading from client: {}", ioe.getMessage());
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            return;
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
        response.addHeader(HttpHeaders.CONTENT_MD5,
                BaseEncoding.base64().encode(
                        contentMetadata.getContentMD5AsHashCode().asBytes()));
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
            int status, String code, String message) {
        sendSimpleErrorResponse(response, status, code, message,
                Optional.<String>absent());
    }

    private static void sendSimpleErrorResponse(HttpServletResponse response,
            int status, String code, String message, Optional<String> extra) {
        logger.debug("{} {} {} {}", status, code, message, extra);
        try (Writer writer = response.getWriter()) {
            response.setStatus(status);
            writer.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n" +
                    "<Error>\r\n" +
                    "  <Code>");
            writer.write(code);
            writer.write("</Code>\r\n" +
                    "  <Message>");
            writer.write(message);
            writer.write("</Message>\r\n");
            if (extra.isPresent()) {
                writer.write(extra.get());
            }
            writer.write("  <RequestId>" + FAKE_REQUEST_ID +
                    "</RequestId>\r\n" +
                    "</Error>\r\n");
            writer.flush();
        } catch (IOException ioe) {
            logger.error("Error writing to client: {}",
                    ioe.getMessage());
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
