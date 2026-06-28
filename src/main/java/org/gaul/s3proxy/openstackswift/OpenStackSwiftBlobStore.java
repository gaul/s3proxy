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

package org.gaul.s3proxy.openstackswift;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Supplier;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.io.BaseEncoding;
import com.google.common.net.HttpHeaders;

import jakarta.inject.Inject;
import jakarta.inject.Named;
import jakarta.inject.Singleton;
import jakarta.ws.rs.core.Response.Status;

import org.jclouds.blobstore.BlobStoreContext;
import org.jclouds.blobstore.ContainerNotFoundException;
import org.jclouds.blobstore.KeyNotFoundException;
import org.jclouds.blobstore.domain.Blob;
import org.jclouds.blobstore.domain.BlobAccess;
import org.jclouds.blobstore.domain.BlobMetadata;
import org.jclouds.blobstore.domain.ContainerAccess;
import org.jclouds.blobstore.domain.MultipartPart;
import org.jclouds.blobstore.domain.MultipartUpload;
import org.jclouds.blobstore.domain.PageSet;
import org.jclouds.blobstore.domain.StorageMetadata;
import org.jclouds.blobstore.domain.StorageType;
import org.jclouds.blobstore.domain.Tier;
import org.jclouds.blobstore.domain.internal.BlobBuilderImpl;
import org.jclouds.blobstore.domain.internal.BlobMetadataImpl;
import org.jclouds.blobstore.domain.internal.PageSetImpl;
import org.jclouds.blobstore.domain.internal.StorageMetadataImpl;
import org.jclouds.blobstore.internal.BaseBlobStore;
import org.jclouds.blobstore.options.CopyOptions;
import org.jclouds.blobstore.options.CreateContainerOptions;
import org.jclouds.blobstore.options.GetOptions;
import org.jclouds.blobstore.options.ListContainerOptions;
import org.jclouds.blobstore.options.PutOptions;
import org.jclouds.blobstore.util.BlobUtils;
import org.jclouds.collect.Memoized;
import org.jclouds.domain.Credentials;
import org.jclouds.domain.Location;
import org.jclouds.http.HttpCommand;
import org.jclouds.http.HttpRequest;
import org.jclouds.http.HttpResponse;
import org.jclouds.http.HttpResponseException;
import org.jclouds.io.ContentMetadataBuilder;
import org.jclouds.io.Payload;
import org.jclouds.io.PayloadSlicer;
import org.jclouds.providers.ProviderMetadata;
import org.jclouds.rest.AuthorizationException;
import org.jspecify.annotations.Nullable;
import org.openstack4j.api.OSClient.OSClientV3;
import org.openstack4j.api.exceptions.ResponseException;
import org.openstack4j.api.storage.ObjectStorageService;
import org.openstack4j.model.common.ActionResponse;
import org.openstack4j.model.common.DLPayload;
import org.openstack4j.model.common.Identifier;
import org.openstack4j.model.common.Payloads;
import org.openstack4j.model.identity.v3.Token;
import org.openstack4j.model.storage.block.options.DownloadOptions;
import org.openstack4j.model.storage.object.SwiftHeaders;
import org.openstack4j.model.storage.object.SwiftObject;
import org.openstack4j.model.storage.object.options.CreateUpdateContainerOptions;
import org.openstack4j.model.storage.object.options.ObjectDeleteOptions;
import org.openstack4j.model.storage.object.options.ObjectListOptions;
import org.openstack4j.model.storage.object.options.ObjectLocation;
import org.openstack4j.model.storage.object.options.ObjectPutOptions;
import org.openstack4j.openstack.OSFactory;

/**
 * BlobStore backed by the OpenStack Swift object store via openstack4j.
 *
 * <p>Authenticates against Keystone v3 with a project-scoped token, which is
 * required to reach the object-store service in the catalog.  The provider
 * {@code endpoint} must be the Keystone auth URL (e.g.
 * {@code https://host:5000/v3}); the Swift endpoint itself is discovered from
 * the catalog.  The Keystone project and domains are supplied via the
 * {@link OpenStackSwiftApiMetadata} properties.
 */
@Singleton
public final class OpenStackSwiftBlobStore extends BaseBlobStore {
    private static final long EXPIRY_MARGIN_MILLIS = 60_000L;

    // Reserved key prefix for multipart-upload internals (segment objects and a
    // metadata marker) stored alongside user objects in the same container.
    // Keys under this prefix are hidden from list() so an in-progress or
    // completed multipart upload does not expose its segments.
    private static final String MPU_PREFIX = ".s3proxy-mpu/";
    private static final String MPU_META_SUFFIX = "/.meta";
    // User-metadata key on the marker object recording the target object name.
    private static final String MPU_KEY_METADATA = "s3proxy-mpu-key";
    // Serializes the Swift SLO manifest written by completeMultipartUpload.
    private static final ObjectMapper MANIFEST_MAPPER = new ObjectMapper();
    // Uppercase hex digits for percent-encoding object names.
    private static final char[] HEX = "0123456789ABCDEF".toCharArray();

    private final String endpoint;
    private final Supplier<Credentials> creds;
    private final String projectName;
    private final String projectDomainName;
    private final String userDomainName;
    private final String region;

    // Cached Keystone token; a fresh thread-bound client is derived from it
    // per request via OSFactory.clientFromToken().
    private volatile Token token;

    @Inject
    OpenStackSwiftBlobStore(BlobStoreContext context, BlobUtils blobUtils,
            Supplier<Location> defaultLocation,
            @Memoized Supplier<Set<? extends Location>> locations,
            PayloadSlicer slicer,
            @org.jclouds.location.Provider Supplier<Credentials> creds,
            ProviderMetadata provider,
            @Named(OpenStackSwiftApiMetadata.PROJECT_NAME) String projectName,
            @Named(OpenStackSwiftApiMetadata.PROJECT_DOMAIN_NAME)
                String projectDomainName,
            @Named(OpenStackSwiftApiMetadata.USER_DOMAIN_NAME)
                String userDomainName,
            @Named(OpenStackSwiftApiMetadata.REGION) String region) {
        super(context, blobUtils, defaultLocation, locations, slicer);
        this.endpoint = provider.getEndpoint();
        this.creds = creds;
        this.projectName = projectName;
        this.projectDomainName = projectDomainName;
        this.userDomainName = userDomainName;
        this.region = region;
    }

    private ObjectStorageService objectStorage() {
        Token current = token;
        if (current == null || isExpiringSoon(current)) {
            current = authenticate();
        }
        OSClientV3 client = OSFactory.clientFromToken(current);
        if (!region.isEmpty()) {
            client = client.useRegion(region);
        }
        return client.objectStorage();
    }

    private synchronized Token authenticate() {
        Token current = token;
        if (current != null && !isExpiringSoon(current)) {
            return current;
        }
        if (projectName.isEmpty()) {
            throw new IllegalArgumentException("Property " +
                    OpenStackSwiftApiMetadata.PROJECT_NAME +
                    " is required to access OpenStack Swift");
        }
        var cred = creds.get();
        OSClientV3 client = OSFactory.builderV3()
                .endpoint(endpoint)
                .credentials(cred.identity, cred.credential,
                        Identifier.byName(userDomainName))
                .scopeToProject(Identifier.byName(projectName),
                        Identifier.byName(projectDomainName))
                .authenticate();
        token = client.getToken();
        return token;
    }

    private static boolean isExpiringSoon(Token token) {
        Date expires = token.getExpires();
        return expires == null || expires.getTime() -
                System.currentTimeMillis() < EXPIRY_MARGIN_MILLIS;
    }

    @Override
    public PageSet<? extends StorageMetadata> list() {
        var swift = objectStorage();
        var set = ImmutableSet.<StorageMetadata>builder();
        for (var container : swift.containers().list()) {
            set.add(new StorageMetadataImpl(StorageType.CONTAINER,
                    /*id=*/ null, container.getName(), /*location=*/ null,
                    /*uri=*/ null, /*eTag=*/ null, /*creationDate=*/ null,
                    /*lastModified=*/ null, Map.of(), /*size=*/ null,
                    Tier.STANDARD));
        }
        return new PageSetImpl<StorageMetadata>(set.build(), null);
    }

    @Override
    public PageSet<? extends StorageMetadata> list(String container,
            ListContainerOptions options) {
        var swift = objectStorage();
        var swiftOptions = ObjectListOptions.create();
        if (options.getPrefix() != null) {
            swiftOptions.startsWith(options.getPrefix());
        }
        var delimiter = options.getDelimiter();
        if (delimiter != null && !delimiter.isEmpty()) {
            swiftOptions.delimiter(delimiter.charAt(0));
        }
        if (options.getMarker() != null) {
            swiftOptions.marker(options.getMarker());
        }
        Integer maxResults = options.getMaxResults();
        if (maxResults != null) {
            // Fetch one extra object so truncation can be detected precisely:
            // Swift's listing has no "truncated" flag, so a page filled exactly
            // to the limit is otherwise indistinguishable from the last page.
            swiftOptions.limit(maxResults + 1);
        }

        List<? extends SwiftObject> objects;
        try {
            objects = swift.objects().list(container, swiftOptions);
        } catch (ResponseException re) {
            throw translate(re, container, /*key=*/ null);
        }

        // Swift returns an empty body for both an empty and a missing
        // container; disambiguate so callers see ContainerNotFoundException.
        if (objects.isEmpty() && !containerExists(container)) {
            throw new ContainerNotFoundException(container, "");
        }

        boolean truncated = maxResults != null && objects.size() > maxResults;
        if (truncated) {
            objects = objects.subList(0, maxResults);
        }

        var set = ImmutableSet.<StorageMetadata>builder();
        String marker = null;
        for (var object : objects) {
            // openstack4j maps Swift "subdir" (common prefix) entries to
            // getDirectoryName(); its isDirectory() is unreliable (it returns
            // false for subdir entries), so key off getDirectoryName().
            var directoryName = object.getDirectoryName();
            if (directoryName != null && !directoryName.isEmpty()) {
                // Hide the multipart-upload segment pseudo-directory.
                if (directoryName.startsWith(MPU_PREFIX)) {
                    continue;
                }
                set.add(new StorageMetadataImpl(StorageType.RELATIVE_PATH,
                        /*id=*/ null, directoryName, /*location=*/ null,
                        /*uri=*/ null, /*eTag=*/ null, /*creationDate=*/ null,
                        /*lastModified=*/ null, Map.of(), /*size=*/ null,
                        Tier.STANDARD));
                marker = directoryName;
            } else {
                // Hide multipart-upload segments and metadata markers.
                if (object.getName() != null &&
                        object.getName().startsWith(MPU_PREFIX)) {
                    continue;
                }
                set.add(new StorageMetadataImpl(StorageType.BLOB,
                        /*id=*/ null, object.getName(), /*location=*/ null,
                        /*uri=*/ null, object.getETag(),
                        /*creationDate=*/ null, object.getLastModified(),
                        Map.of(), object.getSizeInBytes(), Tier.STANDARD));
                marker = object.getName();
            }
        }

        return new PageSetImpl<StorageMetadata>(set.build(),
                truncated ? marker : null);
    }

    @Override
    public boolean containerExists(String container) {
        var swift = objectStorage();
        // A container HEAD returns X-Container-Object-Count only when the
        // container exists; getMetadata() preserves x-* headers.
        for (var key : swift.containers().getMetadata(container).keySet()) {
            if (key.equalsIgnoreCase("X-Container-Object-Count")) {
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean createContainerInLocation(Location location,
            String container) {
        return createContainerInLocation(location, container,
                new CreateContainerOptions());
    }

    @Override
    public boolean createContainerInLocation(Location location,
            String container, CreateContainerOptions options) {
        var swift = objectStorage();
        CreateUpdateContainerOptions swiftOptions = null;
        if (options.isPublicRead()) {
            swiftOptions = CreateUpdateContainerOptions.create()
                    .accessAnybodyRead();
        }
        var response = swift.containers().create(container, swiftOptions);
        if (!response.isSuccess()) {
            throw translate(response, container, /*key=*/ null);
        }
        // Swift returns 201 Created for a new container and 202 Accepted when
        // the container already existed.
        return response.getCode() == Status.CREATED.getStatusCode();
    }

    @Override
    public void deleteContainer(String container) {
        clearContainer(container);
        // clearContainer lists via list(), which hides multipart-upload
        // segments, so purge those directly before the container delete (which
        // would otherwise fail because the container is not actually empty).
        purgeMultipartObjects(container);
        var response = deleteContainerResponse(container);
        if (!response.isSuccess() &&
                response.getCode() != Status.NOT_FOUND.getStatusCode()) {
            throw translate(response, container, /*key=*/ null);
        }
    }

    private void purgeMultipartObjects(String container) {
        var swift = objectStorage();
        List<? extends SwiftObject> objects;
        try {
            objects = swift.objects().list(container,
                    ObjectListOptions.create().startsWith(MPU_PREFIX));
        } catch (ResponseException re) {
            throw translate(re, container, /*key=*/ null);
        }
        for (var object : objects) {
            removeBlob(container, object.getName());
        }
    }

    @Override
    public boolean deleteContainerIfEmpty(String container) {
        var response = deleteContainerResponse(container);
        int code = response.getCode();
        if (response.isSuccess() ||
                code == Status.NOT_FOUND.getStatusCode()) {
            return true;
        }
        if (code == Status.CONFLICT.getStatusCode()) {
            // Container is not empty.
            return false;
        }
        throw translate(response, container, /*key=*/ null);
    }

    @Override
    protected boolean deleteAndVerifyContainerGone(String container) {
        deleteContainerResponse(container);
        return !containerExists(container);
    }

    /**
     * Delete a container, tolerating openstack4j's handling of error statuses.
     * For non-2xx delete responses openstack4j closes the HTTP response and
     * then reads its body, throwing a "closed" ClientResponseException instead
     * of returning an ActionResponse -- most commonly when deleting a
     * container that is already gone (404 Not Found).  Probe existence in that
     * case so callers can treat a now-missing container as already deleted.
     */
    private ActionResponse deleteContainerResponse(String container) {
        try {
            return objectStorage().containers().delete(container);
        } catch (ResponseException re) {
            if (!containerExists(container)) {
                return ActionResponse.actionFailed(
                        "", Status.NOT_FOUND.getStatusCode());
            }
            throw translate(re, container, /*key=*/ null);
        }
    }

    @Override
    public boolean blobExists(String container, String key) {
        var swift = objectStorage();
        try {
            return swift.objects().get(container, encodeName(key)) != null;
        } catch (ResponseException re) {
            if (re.getStatus() == Status.NOT_FOUND.getStatusCode()) {
                return false;
            }
            throw translate(re, container, key);
        }
    }

    @Override
    public Blob getBlob(String container, String key, GetOptions options) {
        if (hasPathTraversal(key)) {
            // okhttp normalizes ".." segments in the request URL, which would
            // turn an object GET into a request for a different resource (e.g.
            // a container listing).  Treat such keys as absent instead, like a
            // literal lookup that finds nothing.
            return null;
        }
        var swift = objectStorage();
        var downloadOptions = DownloadOptions.create();
        // Disable okhttp's transparent gzip so a stored Content-Encoding header
        // survives instead of being stripped (and the body gunzipped).
        downloadOptions.header(HttpHeaders.ACCEPT_ENCODING, "identity");
        boolean ranged = !options.getRanges().isEmpty();
        if (ranged) {
            downloadOptions.header(HttpHeaders.RANGE,
                    "bytes=" + options.getRanges().get(0));
        }
        if (options.getIfMatch() != null) {
            downloadOptions.header(HttpHeaders.IF_MATCH, options.getIfMatch());
        }
        if (options.getIfNoneMatch() != null) {
            downloadOptions.header(HttpHeaders.IF_NONE_MATCH,
                    options.getIfNoneMatch());
        }
        if (options.getIfModifiedSince() != null) {
            downloadOptions.header(HttpHeaders.IF_MODIFIED_SINCE,
                    toHttpDate(options.getIfModifiedSince()));
        }
        if (options.getIfUnmodifiedSince() != null) {
            downloadOptions.header(HttpHeaders.IF_UNMODIFIED_SINCE,
                    toHttpDate(options.getIfUnmodifiedSince()));
        }

        DLPayload payload;
        try {
            payload = swift.objects().download(container, encodeName(key),
                    downloadOptions);
        } catch (ResponseException re) {
            throw translate(re, container, key);
        }
        var response = payload.getHttpResponse();
        int status = response.getStatus();
        if (status == Status.NOT_FOUND.getStatusCode()) {
            return null;
        }
        if (status >= 300) {
            throw new HttpResponseException("unexpected status: " + status,
                    /*command=*/ null,
                    HttpResponse.builder().statusCode(status).build());
        }

        var userMetadata = ImmutableMap.<String, String>builder();
        for (var entry : response.headers().entrySet()) {
            String name = entry.getKey();
            if (name.regionMatches(true, 0,
                    SwiftHeaders.OBJECT_METADATA_PREFIX, 0,
                    SwiftHeaders.OBJECT_METADATA_PREFIX.length())) {
                // S3 metadata keys are case-insensitive and returned lowercase;
                // Swift's HTTP layer canonicalizes them (key1 -> Key1).
                userMetadata.put(name.substring(
                        SwiftHeaders.OBJECT_METADATA_PREFIX.length())
                        .toLowerCase(Locale.ROOT),
                        entry.getValue());
            }
        }

        long contentLength = resolveContentLength(swift, container, key,
                response.header(HttpHeaders.CONTENT_LENGTH),
                ranged ? response.header(HttpHeaders.CONTENT_RANGE) : null);
        var blob = new BlobBuilderImpl()
                .name(key)
                .payload(payload.getInputStream())
                .contentLength(contentLength)
                .contentType(response.getContentType())
                .contentDisposition(
                        response.header(HttpHeaders.CONTENT_DISPOSITION))
                .contentEncoding(response.header(HttpHeaders.CONTENT_ENCODING))
                .userMetadata(userMetadata.build())
                .build();
        if (ranged) {
            var contentRange = response.header(HttpHeaders.CONTENT_RANGE);
            if (contentRange != null) {
                blob.getAllHeaders().put(HttpHeaders.CONTENT_RANGE,
                        contentRange);
            }
        }
        var metadata = blob.getMetadata();
        metadata.setETag(response.header(SwiftHeaders.ETAG));
        metadata.setLastModified(
                parseHttpDate(response.header(SwiftHeaders.LAST_MODIFIED)));
        return blob;
    }

    @Override
    public String putBlob(String container, Blob blob) {
        return putBlob(container, blob, PutOptions.NONE);
    }

    @Override
    public String putBlob(String container, Blob blob, PutOptions options) {
        var swift = objectStorage();
        var metadata = blob.getMetadata();
        var contentMetadata = metadata.getContentMetadata();
        var swiftOptions = ObjectPutOptions.create();
        var contentType = contentMetadata.getContentType();
        if (contentType != null) {
            swiftOptions.contentType(contentType);
        }
        var contentDisposition = contentMetadata.getContentDisposition();
        if (contentDisposition != null) {
            swiftOptions.getOptions().put(HttpHeaders.CONTENT_DISPOSITION,
                    contentDisposition);
        }
        var contentEncoding = contentMetadata.getContentEncoding();
        if (contentEncoding != null) {
            swiftOptions.getOptions().put(HttpHeaders.CONTENT_ENCODING,
                    contentEncoding);
        }
        var userMetadata = metadata.getUserMetadata();
        if (userMetadata != null && !userMetadata.isEmpty()) {
            swiftOptions.metadata(userMetadata);
        }
        try (var is = blob.getPayload().openStream()) {
            return swift.objects().put(container,
                    encodeName(metadata.getName()), Payloads.create(is),
                    swiftOptions);
        } catch (ResponseException re) {
            throw translate(re, container, metadata.getName());
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }

    @Override
    public String copyBlob(String fromContainer, String fromName,
            String toContainer, String toName, CopyOptions options) {
        var contentMetadata = options.contentMetadata();
        var userMetadata = options.userMetadata();
        if (contentMetadata != null || userMetadata != null) {
            // S3 CopyObject with metadata directive REPLACE.  Swift's COPY
            // always preserves the source metadata, so download the source
            // object and re-upload it with the replacement metadata instead.
            var blob = getBlob(fromContainer, fromName, GetOptions.NONE);
            if (blob == null) {
                throw new KeyNotFoundException(fromContainer, fromName,
                        "while copying");
            }
            var blobMetadata = blob.getMetadata();
            if (contentMetadata != null) {
                var blobContentMetadata = blobMetadata.getContentMetadata();
                blobContentMetadata.setContentType(
                        contentMetadata.getContentType());
                blobContentMetadata.setContentDisposition(
                        contentMetadata.getContentDisposition());
                blobContentMetadata.setContentEncoding(
                        contentMetadata.getContentEncoding());
            }
            blobMetadata.setUserMetadata(userMetadata != null ? userMetadata :
                    ImmutableMap.of());
            blobMetadata.setName(toName);
            return putBlob(toContainer, blob);
        }
        var swift = objectStorage();
        String etag;
        try {
            etag = swift.objects().copy(
                    ObjectLocation.create(fromContainer,
                            encodeName(fromName)),
                    ObjectLocation.create(toContainer, encodeName(toName)));
        } catch (ResponseException re) {
            throw translate(re, fromContainer, fromName);
        }
        if (etag == null) {
            // openstack4j's copy() ignores the HTTP status and only returns the
            // ETag header, which Swift omits when the source does not exist.
            throw new KeyNotFoundException(fromContainer, fromName,
                    "while copying");
        }
        return etag;
    }

    @Override
    public void removeBlob(String container, String key) {
        var swift = objectStorage();
        String encoded = encodeName(key);
        var options = ObjectDeleteOptions.create();
        if (isStaticLargeObject(swift, container, encoded)) {
            // Delete the SLO manifest together with its segments.  Swift
            // returns 400 for this parameter on a regular object, so detect
            // the SLO first and send it only then -- as Swift's own s3api
            // does for DeleteObject.
            options.queryParam("multipart-manifest", "delete");
        }
        var response = swift.objects().delete(
                ObjectLocation.create(container, encoded), options);
        if (!response.isSuccess() &&
                response.getCode() != Status.NOT_FOUND.getStatusCode()) {
            throw translate(response, container, key);
        }
    }

    /**
     * HEADs the object to determine whether it is a static large object: an
     * SLO manifest carries {@code X-Static-Large-Object: True}.  Deleting an
     * SLO with {@code multipart-manifest=delete} removes its segments too, but
     * Swift rejects that parameter on a regular object with a 400, so it may
     * be sent only for an SLO.  s3proxy's own multipart internals are never
     * SLOs and skip the HEAD.
     */
    private boolean isStaticLargeObject(ObjectStorageService swift,
            String container, String encodedKey) {
        if (encodedKey.startsWith(MPU_PREFIX)) {
            return false;
        }
        Map<String, String> metadata;
        try {
            metadata = swift.objects().getMetadata(container, encodedKey);
        } catch (ResponseException re) {
            return false;
        }
        for (var entry : metadata.entrySet()) {
            if (entry.getKey().equalsIgnoreCase("X-Static-Large-Object")) {
                var value = entry.getValue();
                return value != null && (value.equalsIgnoreCase("true") ||
                        value.equals("1"));
            }
        }
        return false;
    }

    @Override
    public BlobMetadata blobMetadata(String container, String key) {
        var swift = objectStorage();
        SwiftObject object;
        try {
            object = swift.objects().get(container, encodeName(key));
        } catch (ResponseException re) {
            if (re.getStatus() == Status.NOT_FOUND.getStatusCode()) {
                return null;
            }
            throw translate(re, container, key);
        }
        if (object == null) {
            return null;
        }
        var contentMetadata = ContentMetadataBuilder.create()
                .contentLength(object.getSizeInBytes())
                .contentType(object.getMimeType())
                .build();
        return new BlobMetadataImpl(/*id=*/ null, key, /*location=*/ null,
                /*uri=*/ null, object.getETag(), /*creationDate=*/ null,
                object.getLastModified(), object.getMetadata(),
                /*publicUri=*/ null, container, contentMetadata,
                object.getSizeInBytes(), Tier.STANDARD);
    }

    @Override
    public ContainerAccess getContainerAccess(String container) {
        var swift = objectStorage();
        for (var entry : swift.containers().getMetadata(container).entrySet()) {
            if (entry.getKey().equalsIgnoreCase(SwiftHeaders.CONTAINER_READ)) {
                var read = entry.getValue();
                if (read != null && read.contains(".r:*")) {
                    return ContainerAccess.PUBLIC_READ;
                }
            }
        }
        return ContainerAccess.PRIVATE;
    }

    @Override
    public void setContainerAccess(String container, ContainerAccess access) {
        var options = CreateUpdateContainerOptions.create();
        if (access == ContainerAccess.PUBLIC_READ) {
            options.accessAnybodyRead();
        } else {
            // Clearing X-Container-Read removes anonymous read access.
            options.accessRead("");
        }
        var response = objectStorage().containers().update(container, options);
        if (!response.isSuccess()) {
            throw translate(response, container, /*key=*/ null);
        }
    }

    @Override
    public BlobAccess getBlobAccess(String container, String key) {
        return BlobAccess.PRIVATE;
    }

    @Override
    public void setBlobAccess(String container, String key,
            BlobAccess access) {
        throw new UnsupportedOperationException(
                "blob-level access unsupported in Swift");
    }

    // Multipart upload maps to Swift Static Large Objects: each part is stored
    // as a segment object under MPU_PREFIX in the same container, and
    // completion writes an SLO manifest at the target key referencing them.  A
    // metadata marker object holds the target content metadata between initiate
    // and complete, since S3ProxyHandler reconstructs the upload from only the
    // upload id.  All of this is hidden from list().
    @Override
    public MultipartUpload initiateMultipartUpload(String container,
            BlobMetadata blobMetadata, PutOptions options) {
        String uploadId = UUID.randomUUID().toString();

        var contentMetadata = blobMetadata.getContentMetadata();
        var userMetadata = new HashMap<String, String>();
        if (blobMetadata.getUserMetadata() != null) {
            userMetadata.putAll(blobMetadata.getUserMetadata());
        }
        // Record the target key so listMultipartUploads can recover it.
        userMetadata.put(MPU_KEY_METADATA, blobMetadata.getName());

        var marker = new BlobBuilderImpl()
                .name(mpuMetaKey(uploadId))
                .payload(new byte[0])
                .contentLength(0)
                .contentType(contentMetadata.getContentType())
                .contentDisposition(contentMetadata.getContentDisposition())
                .contentEncoding(contentMetadata.getContentEncoding())
                .userMetadata(userMetadata)
                .build();
        putBlob(container, marker);

        return MultipartUpload.create(container, blobMetadata.getName(),
                uploadId, blobMetadata, options);
    }

    @Override
    public MultipartPart uploadMultipartPart(MultipartUpload mpu,
            int partNumber, Payload payload) {
        Long contentLength = payload.getContentMetadata().getContentLength();
        long length = contentLength == null ? -1 : contentLength;
        var segment = new BlobBuilderImpl()
                .name(mpuSegmentKey(mpu.id(), partNumber))
                .payload(payload)
                .contentLength(length)
                .build();
        String eTag = putBlob(mpu.containerName(), segment);
        return MultipartPart.create(partNumber, length, eTag,
                /*lastModified=*/ null);
    }

    @Override
    public List<MultipartPart> listMultipartUpload(MultipartUpload mpu) {
        var swift = objectStorage();
        String prefix = mpuSegmentPrefix(mpu.id());
        String metaKey = mpuMetaKey(mpu.id());
        List<? extends SwiftObject> objects;
        try {
            objects = swift.objects().list(mpu.containerName(),
                    ObjectListOptions.create().startsWith(prefix));
        } catch (ResponseException re) {
            throw translate(re, mpu.containerName(), /*key=*/ null);
        }
        var parts = new ArrayList<MultipartPart>();
        for (var object : objects) {
            String name = object.getName();
            if (name == null || name.equals(metaKey)) {
                continue;
            }
            int partNumber;
            try {
                partNumber = Integer.parseInt(name.substring(prefix.length()));
            } catch (NumberFormatException nfe) {
                continue;
            }
            parts.add(MultipartPart.create(partNumber,
                    object.getSizeInBytes(), object.getETag(),
                    object.getLastModified()));
        }
        parts.sort(Comparator.comparingInt(MultipartPart::partNumber));
        return parts;
    }

    @Override
    public String completeMultipartUpload(MultipartUpload mpu,
            List<MultipartPart> parts) {
        var swift = objectStorage();
        String container = mpu.containerName();
        String uploadId = mpu.id();

        // Restore the target metadata saved by initiateMultipartUpload.
        var swiftOptions = ObjectPutOptions.create();
        var marker = getBlob(container, mpuMetaKey(uploadId), GetOptions.NONE);
        if (marker != null) {
            var contentMetadata = marker.getMetadata().getContentMetadata();
            if (contentMetadata.getContentType() != null) {
                swiftOptions.contentType(contentMetadata.getContentType());
            }
            if (contentMetadata.getContentDisposition() != null) {
                swiftOptions.getOptions().put(HttpHeaders.CONTENT_DISPOSITION,
                        contentMetadata.getContentDisposition());
            }
            if (contentMetadata.getContentEncoding() != null) {
                swiftOptions.getOptions().put(HttpHeaders.CONTENT_ENCODING,
                        contentMetadata.getContentEncoding());
            }
            var userMetadata = new HashMap<>(
                    marker.getMetadata().getUserMetadata());
            userMetadata.remove(MPU_KEY_METADATA);
            if (!userMetadata.isEmpty()) {
                swiftOptions.metadata(userMetadata);
            }
        }

        var sorted = new ArrayList<>(parts);
        sorted.sort(Comparator.comparingInt(MultipartPart::partNumber));

        // Build the Swift Static Large Object manifest -- a JSON array naming
        // each segment by its "<container>/<object>" path, MD5 etag, and exact
        // size -- and write it with the ?multipart-manifest=put query
        // parameter.  This issues the same request openstack4j's
        // createStaticLargeObject extension would, but through the stock put()
        // API so the provider builds against an unmodified openstack4j.  Swift
        // validates every segment's etag and size before creating the object.
        var manifest = new ArrayList<Map<String, Object>>(sorted.size());
        for (var part : sorted) {
            var entry = new LinkedHashMap<String, Object>();
            entry.put("path",
                    container + "/" + mpuSegmentKey(uploadId,
                            part.partNumber()));
            entry.put("etag", part.partETag());
            entry.put("size_bytes", part.partSize());
            manifest.add(entry);
        }
        byte[] manifestJson;
        try {
            manifestJson = MANIFEST_MAPPER.writeValueAsBytes(manifest);
        } catch (JsonProcessingException jpe) {
            throw new RuntimeException(jpe);
        }
        swiftOptions.queryParam("multipart-manifest", "put");

        String sloETag;
        try {
            sloETag = swift.objects().put(container,
                    encodeName(mpu.blobName()),
                    Payloads.create(new ByteArrayInputStream(manifestJson)),
                    swiftOptions);
        } catch (ResponseException re) {
            throw translate(re, container, mpu.blobName());
        }

        // The manifest now references the segments, which must persist; only
        // the metadata marker is no longer needed.
        removeBlob(container, mpuMetaKey(uploadId));

        String mpuETag = multipartETag(sorted);
        return mpuETag != null ? mpuETag : sloETag;
    }

    @Override
    public void abortMultipartUpload(MultipartUpload mpu) {
        var swift = objectStorage();
        String container = mpu.containerName();
        List<? extends SwiftObject> objects;
        try {
            objects = swift.objects().list(container, ObjectListOptions.create()
                    .startsWith(mpuSegmentPrefix(mpu.id())));
        } catch (ResponseException re) {
            throw translate(re, container, /*key=*/ null);
        }
        if (objects.isEmpty()) {
            throw new KeyNotFoundException(container, mpu.blobName(),
                    "no such multipart upload: " + mpu.id());
        }
        for (var object : objects) {
            removeBlob(container, object.getName());
        }
    }

    @Override
    public List<MultipartUpload> listMultipartUploads(String container) {
        var swift = objectStorage();
        List<? extends SwiftObject> objects;
        try {
            objects = swift.objects().list(container,
                    ObjectListOptions.create().startsWith(MPU_PREFIX));
        } catch (ResponseException re) {
            throw translate(re, container, /*key=*/ null);
        }
        var uploads = new ArrayList<MultipartUpload>();
        for (var object : objects) {
            String name = object.getName();
            if (name == null || !name.endsWith(MPU_META_SUFFIX)) {
                continue;
            }
            String uploadId = name.substring(MPU_PREFIX.length(),
                    name.length() - MPU_META_SUFFIX.length());
            var marker = getBlob(container, name, GetOptions.NONE);
            String blobName = null;
            if (marker != null) {
                blobName = marker.getMetadata().getUserMetadata()
                        .get(MPU_KEY_METADATA);
            }
            uploads.add(MultipartUpload.create(container, blobName, uploadId,
                    /*blobMetadata=*/ null, /*putOptions=*/ null));
        }
        return uploads;
    }

    @Override
    public long getMinimumMultipartPartSize() {
        return 1;
    }

    @Override
    public long getMaximumMultipartPartSize() {
        return 5L * 1024 * 1024 * 1024;
    }

    @Override
    public int getMaximumNumberOfParts() {
        return 1000;
    }

    @Override
    public java.io.InputStream streamBlob(String container, String name) {
        throw new UnsupportedOperationException("not yet implemented");
    }

    private static String mpuSegmentPrefix(String uploadId) {
        return MPU_PREFIX + uploadId + "/";
    }

    private static String mpuMetaKey(String uploadId) {
        return MPU_PREFIX + uploadId + MPU_META_SUFFIX;
    }

    private static String mpuSegmentKey(String uploadId, int partNumber) {
        return mpuSegmentPrefix(uploadId) +
                String.format(Locale.ROOT, "%05d", partNumber);
    }

    /**
     * Computes the canonical S3 multipart ETag: the hex MD5 of the
     * concatenated binary MD5s of each part, suffixed with "-{partCount}".
     * Returns null if a part ETag is not a plain MD5 hex digest, so the caller
     * can fall back to the manifest ETag.
     */
    @Nullable
    private static String multipartETag(List<MultipartPart> parts) {
        try {
            var md = MessageDigest.getInstance("MD5");
            for (var part : parts) {
                String eTag = part.partETag();
                if (eTag == null) {
                    return null;
                }
                eTag = eTag.trim();
                if (eTag.length() >= 2 && eTag.startsWith("\"") &&
                        eTag.endsWith("\"")) {
                    eTag = eTag.substring(1, eTag.length() - 1);
                }
                md.update(BaseEncoding.base16().lowerCase().decode(
                        eTag.toLowerCase(Locale.ROOT)));
            }
            return BaseEncoding.base16().lowerCase().encode(md.digest()) +
                    "-" + parts.size();
        } catch (NoSuchAlgorithmException | IllegalArgumentException e) {
            return null;
        }
    }

    /**
     * Determine the object size for a GET.  Some Swift servers omit
     * Content-Length on the download response (e.g., when the body is sent
     * with chunked transfer encoding), which would otherwise leave the blob
     * with a zero length and hang clients that trust it.  Fall back to the
     * Content-Range total for ranged reads, then to an authoritative HEAD.
     */
    private long resolveContentLength(ObjectStorageService swift,
            String container, String key, @Nullable String contentLength,
            @Nullable String contentRange) {
        if (contentLength != null) {
            try {
                return Long.parseLong(contentLength.trim());
            } catch (NumberFormatException nfe) {
                // fall through to the other sources
            }
        }
        if (contentRange != null) {
            // Format: "bytes <start>-<end>/<total>"
            int space = contentRange.indexOf(' ');
            int dash = contentRange.indexOf('-', space + 1);
            int slash = contentRange.indexOf('/', dash + 1);
            if (space >= 0 && dash > space && slash > dash) {
                try {
                    long start = Long.parseLong(
                            contentRange.substring(space + 1, dash).trim());
                    long end = Long.parseLong(
                            contentRange.substring(dash + 1, slash).trim());
                    return end - start + 1;
                } catch (NumberFormatException nfe) {
                    // fall through to the HEAD
                }
            }
        }
        var object = swift.objects().get(container, encodeName(key));
        return object != null ? object.getSizeInBytes() : 0L;
    }

    private static String toHttpDate(Date date) {
        return DateTimeFormatter.RFC_1123_DATE_TIME.format(
                date.toInstant().atOffset(ZoneOffset.UTC));
    }

    @Nullable
    private static Date parseHttpDate(@Nullable String value) {
        if (value == null) {
            return null;
        }
        try {
            return Date.from(DateTimeFormatter.RFC_1123_DATE_TIME.parse(
                    value, java.time.Instant::from));
        } catch (RuntimeException re) {
            return null;
        }
    }

    /**
     * Determine whether a key contains a {@code ".."} path segment, which the
     * HTTP client would normalize away and so could escape its container.
     */
    private static boolean hasPathTraversal(String key) {
        for (var segment : key.split("/", -1)) {
            if (segment.equals("..")) {
                return true;
            }
        }
        return false;
    }

    /**
     * Percent-encodes an object name for the Swift request path.  Stock
     * openstack4j places the raw name into the URL string the okhttp connector
     * hands to {@code Request.Builder.url(String)}, which parses it as a URL,
     * so a name containing {@code '%'}, {@code '#'}, or {@code '?'} is misread
     * (the openstack4j fork patches this internally).  Encoding the RFC 3986
     * unreserved set plus {@code '/'} here yields escapes that survive okhttp's
     * parse; Swift decodes them back to the original name, and listings already
     * return decoded names so the inbound path needs no change.
     */
    private static String encodeName(String name) {
        var encoded = new StringBuilder(name.length() + 16);
        for (byte rawByte : name.getBytes(StandardCharsets.UTF_8)) {
            int c = rawByte & 0xFF;
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                    (c >= '0' && c <= '9') || c == '-' || c == '.' ||
                    c == '_' || c == '~' || c == '/') {
                encoded.append((char) c);
            } else {
                encoded.append('%');
                encoded.append(HEX[(c >> 4) & 0xF]);
                encoded.append(HEX[c & 0xF]);
            }
        }
        return encoded.toString();
    }

    /**
     * Translate an openstack4j {@link ResponseException} into the jclouds
     * exception the s3proxy handler expects, or rethrow it unchanged.
     */
    private RuntimeException translate(ResponseException re, String container,
            @Nullable String key) {
        return translateStatus(re.getStatus(), container, key, re);
    }

    private RuntimeException translate(ActionResponse response,
            String container, @Nullable String key) {
        return translateStatus(response.getCode(), container, key,
                new RuntimeException(response.getFault()));
    }

    private RuntimeException translateStatus(int status, String container,
            @Nullable String key, Throwable cause) {
        if (status == Status.NOT_FOUND.getStatusCode()) {
            if (key != null) {
                var exception = new KeyNotFoundException(container, key, "");
                exception.initCause(cause);
                return exception;
            }
            var exception = new ContainerNotFoundException(container, "");
            exception.initCause(cause);
            return exception;
        } else if (status == Status.UNAUTHORIZED.getStatusCode() ||
                status == Status.FORBIDDEN.getStatusCode()) {
            return new AuthorizationException(cause);
        } else if (status == Status.PRECONDITION_FAILED.getStatusCode() ||
                status == Status.REQUESTED_RANGE_NOT_SATISFIABLE
                        .getStatusCode()) {
            var request = HttpRequest.builder()
                    .method("GET")
                    .endpoint(endpoint)
                    .build();
            var response = HttpResponse.builder()
                    .statusCode(status)
                    .build();
            return new HttpResponseException(new HttpCommand(request),
                    response, cause);
        }
        if (cause instanceof RuntimeException runtime) {
            return runtime;
        }
        return new RuntimeException(cause);
    }
}
