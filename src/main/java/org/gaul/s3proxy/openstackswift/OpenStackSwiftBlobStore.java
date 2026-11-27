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

import static java.util.Objects.requireNonNull;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Function;
import java.util.function.Predicate;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.google.common.base.CharMatcher;
import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.google.common.base.Supplier;
import com.google.common.collect.AbstractIterator;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.hash.HashCode;
import com.google.common.net.HttpHeaders;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.blobstore.Credentials;
import org.gaul.s3proxy.blobstore.MD5;
import org.gaul.s3proxy.blobstore.S3Exceptions;
import org.gaul.s3proxy.blobstore.SdkRequests;
import org.gaul.s3proxy.blobstore.SdkResponses;
import org.gaul.s3proxy.blobstore.UploadListings;
import org.gaul.s3proxy.blobstore.UploadNames;
import org.gaul.s3proxy.blobstore.domain.Blob;
import org.gaul.s3proxy.blobstore.domain.MultipartUpload;
import org.jspecify.annotations.Nullable;
import org.openstack4j.api.OSClient.OSClientV3;
import org.openstack4j.api.exceptions.AuthenticationException;
import org.openstack4j.api.exceptions.ResponseException;
import org.openstack4j.api.storage.ObjectStorageService;
import org.openstack4j.api.types.Facing;
import org.openstack4j.api.types.ServiceType;
import org.openstack4j.core.transport.ObjectMapperSingleton;
import org.openstack4j.model.common.ActionResponse;
import org.openstack4j.model.common.DLPayload;
import org.openstack4j.model.common.Identifier;
import org.openstack4j.model.common.Payloads;
import org.openstack4j.model.identity.v3.Token;
import org.openstack4j.model.storage.block.options.DownloadOptions;
import org.openstack4j.model.storage.object.SwiftHeaders;
import org.openstack4j.model.storage.object.SwiftObject;
import org.openstack4j.model.storage.object.options.ContainerListOptions;
import org.openstack4j.model.storage.object.options.CreateUpdateContainerOptions;
import org.openstack4j.model.storage.object.options.ObjectDeleteOptions;
import org.openstack4j.model.storage.object.options.ObjectListOptions;
import org.openstack4j.model.storage.object.options.ObjectLocation;
import org.openstack4j.model.storage.object.options.ObjectPutOptions;
import org.openstack4j.openstack.OSFactory;
import org.openstack4j.openstack.identity.v3.domain.KeystoneToken;

import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.services.s3.model.Bucket;
import software.amazon.awssdk.services.s3.model.BucketCannedACL;
import software.amazon.awssdk.services.s3.model.CommonPrefix;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.CompletedPart;
import software.amazon.awssdk.services.s3.model.CopyObjectRequest;
import software.amazon.awssdk.services.s3.model.CopyObjectResponse;
import software.amazon.awssdk.services.s3.model.CreateBucketRequest;
import software.amazon.awssdk.services.s3.model.CreateBucketResponse;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.DeleteObjectResponse;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.HeadBucketRequest;
import software.amazon.awssdk.services.s3.model.HeadBucketResponse;
import software.amazon.awssdk.services.s3.model.HeadObjectRequest;
import software.amazon.awssdk.services.s3.model.HeadObjectResponse;
import software.amazon.awssdk.services.s3.model.ListBucketsRequest;
import software.amazon.awssdk.services.s3.model.ListBucketsResponse;
import software.amazon.awssdk.services.s3.model.ListMultipartUploadsRequest;
import software.amazon.awssdk.services.s3.model.ListMultipartUploadsResponse;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Response;
import software.amazon.awssdk.services.s3.model.MetadataDirective;
import software.amazon.awssdk.services.s3.model.NoSuchBucketException;
import software.amazon.awssdk.services.s3.model.ObjectCannedACL;
import software.amazon.awssdk.services.s3.model.Part;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.services.s3.model.S3Object;
import software.amazon.awssdk.services.s3.model.StorageClass;
import software.amazon.awssdk.services.s3.model.UploadPartRequest;
import software.amazon.awssdk.services.s3.model.UploadPartResponse;

/**
 * BlobStore backed by the OpenStack Swift object store via openstack4j.
 *
 * <p>Authenticates in either of the two ways a Swift deployment offers, told
 * apart by the version in the {@code endpoint} path.
 *
 * <p>Against Keystone v3 ({@code https://host:5000/v3}) it takes a
 * project-scoped token, which is required to reach the object-store service in
 * the catalog, and the Swift endpoint itself is discovered from that catalog.
 * The project and domains come from the {@code openstack-swift-sdk.*}
 * properties.
 *
 * <p>Against Swift's own tempauth ({@code https://host:8080/auth/v1.0}) it
 * exchanges the credentials for a token and the URL of the one account they
 * reach.  tempauth names a user as {@code account:user}, so either give the
 * whole thing as the identity or name the account as the project.  Domains and
 * regions do not apply, Keystone being the thing that has them.
 */
public final class OpenStackSwiftBlobStore implements BlobStore {
    /**
     * Keystone project (tenant) name to scope the token to.  Required:
     * Swift object storage is only reachable through a project-scoped token.
     */
    public static final String PROPERTY_PROJECT_NAME =
            "openstack-swift-sdk.project-name";

    /** Keystone domain that owns the project.  Defaults to "Default". */
    public static final String PROPERTY_PROJECT_DOMAIN_NAME =
            "openstack-swift-sdk.project-domain-name";

    /** Keystone domain that owns the user.  Defaults to "Default". */
    public static final String PROPERTY_USER_DOMAIN_NAME =
            "openstack-swift-sdk.user-domain-name";

    /**
     * Region whose object-store endpoint should be selected from the service
     * catalog.  Empty selects the first/default region.
     */
    public static final String PROPERTY_REGION = "openstack-swift-sdk.region";

    // Names asked of Swift at a time by the listings of the multipart
    // namespace.  Swift's own page is 10,000 names, more than a listing
    // that keeps few of them should hold for each request.
    static final int LIST_PAGE_SIZE = 1000;

    private static final long EXPIRY_MARGIN_MILLIS = 60_000L;
    // How long a tempauth token is assumed good for when the response does
    // not say, short enough that a wrong guess costs one re-authentication.
    private static final long TEMPAUTH_DEFAULT_LIFETIME_SECONDS = 3600L;
    // Keystone spells expiry as an ISO-8601 instant, which is what the
    // Jackson mapping openstack4j parses a real response with expects.
    private static final DateTimeFormatter ISO_INSTANT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'")
                    .withZone(ZoneOffset.UTC);

    // HTTP status codes, spelled out to avoid a jakarta.ws.rs.core dependency
    // (the openstack4j okhttp connector deliberately avoids JAX-RS).
    // The most containers one Swift account listing returns.
    private static final int SWIFT_LIST_LIMIT = 10_000;
    // The most keys S3 lists in one page.
    private static final int S3_LIST_LIMIT = 1000;
    private static final int STATUS_OK = 200;
    private static final int STATUS_CREATED = 201;
    private static final int STATUS_UNAUTHORIZED = 401;
    private static final int STATUS_FORBIDDEN = 403;
    private static final int STATUS_NOT_FOUND = 404;
    private static final int STATUS_CONFLICT = 409;
    private static final int STATUS_PRECONDITION_FAILED = 412;
    private static final int STATUS_RANGE_NOT_SATISFIABLE = 416;
    private static final int DELETE_CONTAINER_MAX_ATTEMPTS = 6;
    private static final long DELETE_CONTAINER_RETRY_BASE_MILLIS = 100L;

    /**
     * Write an HTTP date, which RFC 7231 fixes the width of: the day of month
     * is always two digits.  RFC_1123_DATE_TIME writes one for the first nine
     * of each month, since RFC 1123 allows either, and a parser holding to the
     * HTTP grammar rejects that outright -- Go's net/http among them, which
     * treats an unparseable If-Modified-Since as absent and answers 200 where
     * it owed 304.  A conditional request therefore worked or did not by the
     * date it happened to be made on.  Locale.US pins the day and month names,
     * which the header spells in English whatever the server is set to.
     */
    private static final DateTimeFormatter HTTP_DATE =
            DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss 'GMT'",
                    Locale.US);

    // Reserved key prefix for multipart-upload internals (segment objects and a
    // metadata marker) stored alongside user objects in the same container.
    // Keys under this prefix are hidden from list() so an in-progress or
    // completed multipart upload does not expose its segments, and reserved
    // from client keys; see isReserved.
    /**
     * Where the store keeps its multipart bookkeeping, reserved from client
     * keys and hidden from listings.  An open upload's marker is named by
     * its key and upload ID under {@link #MPU_UPLOADS_PREFIX}, so that Swift
     * lists the uploads in S3's order and ListMultipartUploads reads one page
     * of them -- see {@link UploadNames}; a marker whose key is too long for
     * that name is kept under {@link #MPU_LONG_UPLOADS_PREFIX} by its upload
     * ID alone.  The segments lie apart under {@link #MPU_PARTS_PREFIX}, and
     * a finished object's manifest goes on naming them.  An upload begun
     * before this layout kept its segments and its ".meta" marker under
     * MPU_PREFIX + uploadId; finished objects still name such segments,
     * and the markers are those of uploads no request can find any more.
     */
    private static final String MPU_PREFIX = ".s3proxy-mpu/";
    private static final String MPU_UPLOADS_PREFIX = MPU_PREFIX + "u/";
    private static final String MPU_LONG_UPLOADS_PREFIX = MPU_PREFIX + "l/";
    private static final String MPU_PARTS_PREFIX = MPU_PREFIX + "p/";
    /** Swift's longest object name unless the operator raised it, in bytes. */
    private static final int MAX_OBJECT_NAME_BYTES = 1024;
    // User-metadata key on the marker object recording the target object name.
    private static final String MPU_KEY_METADATA = "s3proxy-mpu-key";
    // A completed multipart object's S3 composite ETag.  Swift cannot compute
    // it: an SLO manifest gets an ETag of Swift's own making, so the value
    // CompleteMultipartUpload returned would not survive to the next HEAD --
    // breaking clients that cache it and send it back as If-Match.  Recorded
    // here at completion and reported in its place, never as x-amz-meta-.
    private static final String MPU_ETAG_METADATA = "s3proxy-mpu-etag";
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
    @Nullable private volatile Token token;
    private final ReentrantLock authenticateLock = new ReentrantLock();

    public OpenStackSwiftBlobStore(Supplier<Credentials> creds, String endpoint,
            String projectName, String projectDomainName,
            String userDomainName, String region) {
        this.endpoint = endpoint;
        this.creds = creds;
        this.projectName = projectName;
        this.projectDomainName = projectDomainName;
        this.userDomainName = userDomainName;
        this.region = region;
        // Refused here, at startup, so that the operator hears of it.  The
        // same faults found while serving a request are a 500, not the 400
        // an IllegalArgumentException would answer there.
        if (isTempAuthEndpoint(endpoint)) {
            if (!Strings.isNullOrEmpty(creds.get().sessionToken())) {
                throw new IllegalArgumentException(
                        tempAuthSessionTokenMessage());
            }
        } else if (projectName.isEmpty()) {
            throw new IllegalArgumentException(projectRequiredMessage());
        }
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

    private Token authenticate() {
        // A lock rather than a monitor: authentication is a round trip,
        // and before Java 24 a virtual thread holding or awaiting a monitor
        // pins its carrier for all of it.
        authenticateLock.lock();
        try {
            Token current = token;
            if (current != null && !isExpiringSoon(current)) {
                return current;
            }
            var cred = creds.get();
            token = isTempAuthEndpoint(endpoint) ?
                    authenticateTempAuth(cred) : authenticateKeystone(cred);
            return token;
        } finally {
            authenticateLock.unlock();
        }
    }

    private static String projectRequiredMessage() {
        return "Property " + PROPERTY_PROJECT_NAME +
                " is required to access OpenStack Swift";
    }

    private String tempAuthSessionTokenMessage() {
        return "A session token names a Keystone token, which " + endpoint +
                " does not issue";
    }

    private Token authenticateKeystone(Credentials cred) {
        var builder = OSFactory.builderV3().endpoint(endpoint);
        String sessionToken = cred.sessionToken();
        if (Strings.isNullOrEmpty(sessionToken)) {
            builder.credentials(cred.identity(), cred.credential(),
                    Identifier.byName(userDomainName));
        } else {
            // Keystone re-scopes a token the caller already holds, so a
            // deployment that mints them hands one over instead of the
            // password behind it.  Its own expiry drives the next
            // authenticate, which reads the supplier again.
            builder.token(sessionToken);
        }
        OSClientV3 client = builder
                .scopeToProject(Identifier.byName(projectName),
                        Identifier.byName(projectDomainName))
                .authenticate();
        return client.getToken();
    }

    /**
     * Whether the endpoint names Swift's own authentication rather than
     * Keystone's, which the version in its path tells apart: tempauth answers
     * at {@code /auth/v1.0}, Keystone at {@code /v3}.  python-swiftclient and
     * the swift CLI read the URL the same way.
     */
    private static boolean isTempAuthEndpoint(String endpoint) {
        String path = endpoint;
        while (path.endsWith("/")) {
            path = path.substring(0, path.length() - 1);
        }
        return path.endsWith("/v1.0") || path.endsWith("/v1");
    }

    /**
     * Authenticates against Swift's built-in tempauth, which Keystone does not
     * front: a GET carrying the credentials returns a token and the URL of the
     * account it reaches, and nothing describes a catalog of other services.
     *
     * <p>The result is dressed as a Keystone token holding that one
     * object-store endpoint, so the rest of the provider -- which asks
     * openstack4j for a client and lets it resolve the object store -- cannot
     * tell which of the two answered.  The catalog carries whatever region was
     * configured so {@code useRegion} still matches; tempauth itself has no
     * notion of one.
     */
    private Token authenticateTempAuth(Credentials cred) {
        if (!Strings.isNullOrEmpty(cred.sessionToken())) {
            // The supplier has gained one since the store was built.
            throw S3Exceptions.misconfigured(tempAuthSessionTokenMessage());
        }
        // tempauth identifies a user as "account:user".  Accept either the
        // whole thing as the identity or the account named separately, since
        // the project is what a Keystone-configured store already calls it.
        String user = cred.identity().indexOf(':') >= 0 ? cred.identity() :
                projectName + ":" + cred.identity();
        HttpResponse<?> response;
        try {
            var request = HttpRequest.newBuilder(URI.create(endpoint))
                    .header("X-Auth-User", user)
                    .header("X-Auth-Key", cred.credential())
                    .GET()
                    .build();
            response = HttpClient.newHttpClient().send(request,
                    BodyHandlers.discarding());
        } catch (IOException ioe) {
            throw new AuthenticationException(
                    "Could not reach " + endpoint + ": " + ioe.getMessage(),
                    STATUS_UNAUTHORIZED, ioe);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            throw new AuthenticationException(
                    "Interrupted authenticating against " + endpoint,
                    STATUS_UNAUTHORIZED, ie);
        }
        if (response.statusCode() != STATUS_OK) {
            throw new AuthenticationException(
                    "tempauth rejected " + user + " at " + endpoint,
                    response.statusCode());
        }
        var headers = response.headers();
        String authToken = headers.firstValue("X-Auth-Token")
                .or(() -> headers.firstValue("X-Storage-Token"))
                .orElseThrow(() -> new AuthenticationException(
                        endpoint + " returned no X-Auth-Token",
                        STATUS_UNAUTHORIZED));
        String storageUrl = headers.firstValue("X-Storage-Url")
                .orElseThrow(() -> new AuthenticationException(
                        endpoint + " returned no X-Storage-Url",
                        STATUS_UNAUTHORIZED));
        // tempauth reports the lifetime in seconds and Keystone an instant.
        long lifetime = headers.firstValueAsLong("X-Auth-Token-Expires")
                .orElse(TEMPAUTH_DEFAULT_LIFETIME_SECONDS);
        return tempAuthToken(authToken, storageUrl, lifetime);
    }

    private Token tempAuthToken(String authToken, String storageUrl,
            long lifetimeSeconds) {
        var endpointNode = JsonNodeFactory.instance.objectNode()
                .put("id", "swift")
                .put("interface", Facing.PUBLIC.value())
                .put("region", tempAuthRegion())
                .put("region_id", tempAuthRegion())
                .put("url", storageUrl);
        var serviceNode = JsonNodeFactory.instance.objectNode()
                .put("id", "swift")
                .put("name", "swift")
                .put("type", ServiceType.OBJECT_STORAGE.getType());
        serviceNode.putArray("endpoints").add(endpointNode);
        var tokenNode = JsonNodeFactory.instance.objectNode()
                .put("expires_at", ISO_INSTANT.format(Instant.now()
                        .plusSeconds(lifetimeSeconds)))
                .put("issued_at", ISO_INSTANT.format(Instant.now()));
        tokenNode.putArray("catalog").add(serviceNode);
        var document = JsonNodeFactory.instance.objectNode();
        document.set("token", tokenNode);

        KeystoneToken parsed;
        try {
            parsed = ObjectMapperSingleton.getContext(KeystoneToken.class)
                    .treeToValue(document, KeystoneToken.class);
        } catch (JsonProcessingException jpe) {
            // The document is built just above, so a binding that fails is
            // a fault here or in openstack4j, a 500, and not the client's,
            // the 400 an IllegalStateException answered.
            throw new AssertionError(
                    "Could not build a token for " + storageUrl, jpe);
        }
        parsed.setId(authToken);
        // The session endpoint doubles as the identity a resolved URL is
        // cached under, so name the account rather than the auth URL every
        // account of one Swift would otherwise share.
        parsed.setEndpoint(storageUrl);
        return parsed;
    }

    private String tempAuthRegion() {
        return region.isEmpty() ? "RegionOne" : region;
    }

    private static boolean isExpiringSoon(Token token) {
        var expires = token.getExpires();
        return expires == null || expires.getTime() -
                System.currentTimeMillis() < EXPIRY_MARGIN_MILLIS;
    }

    @Override
    public ListBucketsResponse list() {
        var swift = objectStorage();
        var buckets = ImmutableList.<Bucket>builder();
        for (var container : swift.containers().list()) {
            buckets.add(SdkResponses.bucket(container.getName(),
                    /*creationDate=*/ null));
        }
        return ListBucketsResponse.builder()
                .buckets(buckets.build())
                .build();
    }

    @Override
    public ListBucketsResponse list(ListBucketsRequest request) {
        var swift = objectStorage();
        var options = ContainerListOptions.create();
        String prefix = request.prefix();
        if (prefix != null) {
            options.startsWith(prefix);
        }
        if (request.continuationToken() != null) {
            options.marker(request.continuationToken());
        }
        Integer maxBuckets = request.maxBuckets();
        if (maxBuckets != null) {
            // One past the page tells whether more remain: Swift's account
            // listing reports no truncation of its own, and a token on an
            // exactly-consumed account would send the caller one page too
            // many.
            options.limit(maxBuckets >= SWIFT_LIST_LIMIT ?
                    SWIFT_LIST_LIMIT : maxBuckets + 1);
        }
        var containers = swift.containers().list(options);
        int count = maxBuckets == null ? containers.size() :
                Math.min(containers.size(), maxBuckets);
        var buckets = ImmutableList.<Bucket>builder();
        for (int i = 0; i < count; ++i) {
            buckets.add(SdkResponses.bucket(containers.get(i).getName(),
                    /*creationDate=*/ null));
        }
        // More remain when the peek came back past the page, or when the
        // service cap ate the peek and the listing still filled to it.
        boolean more = maxBuckets != null &&
                (containers.size() > maxBuckets ||
                        containers.size() == SWIFT_LIST_LIMIT);
        return ListBucketsResponse.builder()
                .buckets(buckets.build())
                .continuationToken(more && count > 0 ?
                        containers.get(count - 1).getName() : null)
                .prefix(prefix)
                .build();
    }

    @Override
    public ListObjectsV2Response list(ListObjectsV2Request request) {
        String container = request.bucket();
        String marker0 = request.continuationToken() != null ?
                request.continuationToken() : request.startAfter();
        var swift = objectStorage();
        String prefix = request.prefix();
        var delimiter = request.delimiter();
        // The listing call takes a delimiter of one character.  A longer
        // one was cut to its first, which grouped keys at the wrong place
        // and still answered 200; it is applied here instead, to a flat
        // listing.
        boolean groupHere = delimiter != null && delimiter.length() > 1;
        Character delimiterChar = delimiter != null &&
                delimiter.length() == 1 ? delimiter.charAt(0) : null;
        String groupPrefix = Strings.nullToEmpty(prefix);
        // The group the previous page ended on: its keys all sort after the
        // token that named it, and were reported there.
        String skipGroup = groupHere && request.continuationToken() != null &&
                marker0 != null && marker0.equals(commonPrefixOf(marker0,
                        groupPrefix, requireNonNull(delimiter))) ?
                marker0 : null;
        String lastGroup = null;
        Integer maxResults = request.maxKeys();

        // Collect visible objects, hiding multipart-upload internals.  A whole
        // Swift page can consist entirely of hidden keys, so keep fetching
        // successive pages until enough visible objects are gathered or the
        // container is exhausted; otherwise the listing would truncate early
        // and the container could appear empty.  The continuation marker is a
        // real visible key so it round-trips through the S3 client.
        var contents = new ArrayList<S3Object>();
        var prefixes = new ArrayList<CommonPrefix>();
        int visibleCount = 0;
        String lastVisible = null;
        String swiftMarker = marker0;
        boolean firstRequest = true;
        boolean more = false;
        // Fetch one extra object so truncation can be detected precisely:
        // Swift's listing has no "truncated" flag, so a page filled exactly
        // to the limit is otherwise indistinguishable from the last page.
        Integer limit = maxResults == null ? null : maxResults + 1;

        while (true) {
            var swiftOptions = ObjectListOptions.create();
            if (prefix != null) {
                swiftOptions.startsWith(prefix);
            }
            if (delimiterChar != null) {
                swiftOptions.delimiter(delimiterChar);
            }
            if (swiftMarker != null) {
                swiftOptions.marker(swiftMarker);
            }
            if (limit != null) {
                swiftOptions.limit(limit);
            }

            List<? extends SwiftObject> objects;
            try {
                objects = swift.objects().list(container, swiftOptions);
            } catch (ResponseException re) {
                throw translate(re, container, /*key=*/ null);
            }

            if (objects.isEmpty()) {
                // Swift returns an empty body for both an empty and a missing
                // container; disambiguate so callers see NoSuchBucket.
                if (firstRequest && !containerExists(container)) {
                    throw S3Exceptions.noSuchBucket(container, "");
                }
                break;
            }
            firstRequest = false;

            int rawCount = objects.size();
            for (var object : objects) {
                // openstack4j maps Swift "subdir" (common prefix) entries to
                // getDirectoryName(); its isDirectory() is unreliable (it
                // returns false for subdir entries), so key off
                // getDirectoryName().
                var directoryName = object.getDirectoryName();
                boolean isDirectory =
                        directoryName != null && !directoryName.isEmpty();
                String name = isDirectory ? directoryName : object.getName();
                if (name == null) {
                    continue;
                }
                // Advance the Swift position past this key even when it is
                // hidden, so the next page continues correctly.
                swiftMarker = name;

                // Hide multipart-upload segments, metadata markers, and the
                // segment pseudo-directory.
                if (name.startsWith(MPU_PREFIX)) {
                    continue;
                }

                String group = groupHere ? commonPrefixOf(name, groupPrefix,
                        requireNonNull(delimiter)) : null;
                if (group != null && (group.equals(skipGroup) ||
                        group.equals(lastGroup))) {
                    continue;
                }

                if (maxResults != null && visibleCount == maxResults) {
                    // At least one more visible object exists beyond the page.
                    more = true;
                    break;
                }

                if (group != null) {
                    prefixes.add(SdkResponses.commonPrefix(group));
                    lastGroup = group;
                    visibleCount++;
                    lastVisible = group;
                    continue;
                }

                if (isDirectory) {
                    prefixes.add(SdkResponses.commonPrefix(name));
                } else {
                    contents.add(SdkResponses.objectEntry(name,
                            object.getETag(),
                            toInstant(object.getLastModified()),
                            object.getSizeInBytes(), StorageClass.STANDARD));
                }
                visibleCount++;
                lastVisible = name;
            }

            if (more) {
                break;
            }
            // A short page (fewer than requested) means Swift has no more
            // objects; an unbounded request is served in a single pass.
            if (limit == null || rawCount < limit) {
                break;
            }
            // Otherwise the page held only hidden keys or ran short of visible
            // objects; fetch the next page from the advanced marker.  Nothing
            // tells how many more hidden keys follow, so the pages after the
            // first are as long as the longest a client can ask for: at the
            // length this one asked for, max-keys=1 cost a request to Swift
            // for every two segments of an upload in progress.
            limit = Math.max(limit, S3_LIST_LIMIT + 1);
        }

        String nextMarker = more ? lastVisible : null;
        return SdkResponses.objectsPage(contents, prefixes, nextMarker);
    }

    /** The common prefix a key falls under, or null when it is listed. */
    private static @Nullable String commonPrefixOf(String key, String prefix,
            String delimiter) {
        if (!key.startsWith(prefix)) {
            return null;
        }
        int index = key.indexOf(delimiter, prefix.length());
        return index < 0 ? null :
                key.substring(0, index + delimiter.length());
    }

    @Override
    public HeadBucketResponse headBucket(HeadBucketRequest request) {
        var swift = objectStorage();
        // A container HEAD returns X-Container-Object-Count only when the
        // container exists; getMetadata() preserves x-* headers.
        for (var key : swift.containers().getMetadata(request.bucket())
                .keySet()) {
            if (key.equalsIgnoreCase("X-Container-Object-Count")) {
                return HeadBucketResponse.builder().build();
            }
        }
        throw S3Exceptions.noSuchBucket(request.bucket(), "");
    }

    @Override
    public CreateBucketResponse createContainer(CreateBucketRequest request) {
        if (request.acl() == BucketCannedACL.PUBLIC_READ_WRITE) {
            throw new UnsupportedOperationException(
                    "anonymous write access unsupported in Swift");
        }
        String container = request.bucket();
        var swift = objectStorage();
        CreateUpdateContainerOptions swiftOptions = null;
        if (request.acl() == BucketCannedACL.PUBLIC_READ) {
            swiftOptions = CreateUpdateContainerOptions.create()
                    .accessAnybodyRead();
        }
        var response = swift.containers().create(container, swiftOptions);
        if (!response.isSuccess()) {
            throw translate(response, container, /*key=*/ null);
        }
        // Swift returns 201 Created for a new container and 202 Accepted
        // when the container already existed.
        if (response.getCode() != STATUS_CREATED) {
            throw S3Exceptions.bucketAlreadyOwnedByYou(container);
        }
        return CreateBucketResponse.builder().build();
    }

    /**
     * Every object of a container whose name begins with {@code prefix}.
     * Swift answers a listing a page at a time -- 10,000 names unless the
     * operator set another limit -- so a single request sees only the first
     * page: an upload of 10,000 parts lost its last behind its marker, and
     * a bucket holding more segments than that listed no upload past them.
     */
    private List<SwiftObject> listAll(String container, String prefix) {
        return listAll(container, prefix, name -> true);
    }

    /**
     * As {@link #listAll(String, String)}, of the objects whose name
     * {@code keep} accepts.  The others are passed over a page at a time, so
     * a listing read for a few of its names holds those and one page.
     */
    private List<SwiftObject> listAll(String container, String prefix,
            Predicate<String> keep) {
        var swift = objectStorage();
        return allPages(marker -> {
            var options = ObjectListOptions.create().startsWith(prefix)
                    .limit(LIST_PAGE_SIZE);
            if (marker != null) {
                options.marker(marker);
            }
            return swift.objects().list(container, options);
        }, SwiftObject::getName, keep);
    }

    /**
     * Follows a listing by marker to its end.  A page's size says nothing
     * about whether another follows, the limit being the server's to set,
     * so the listing ends at an empty page.  Names come back strictly after
     * the marker; a backend that ignores markers answers the same page
     * again, which adds nothing and moves no marker, and ends it too.
     */
    static <T> List<T> allPages(
            Function<@Nullable String, List<? extends T>> fetch,
            Function<T, @Nullable String> nameOf) {
        return allPages(fetch, nameOf, name -> true);
    }

    /**
     * As {@link #allPages(Function, Function)}, keeping only the entries
     * whose name {@code keep} accepts.
     */
    static <T> List<T> allPages(
            Function<@Nullable String, List<? extends T>> fetch,
            Function<T, @Nullable String> nameOf, Predicate<String> keep) {
        var all = new ArrayList<T>();
        String marker = null;
        while (true) {
            String before = marker;
            for (T entry : fetch.apply(marker)) {
                String name = nameOf.apply(entry);
                if (name == null ||
                        (before != null && name.compareTo(before) <= 0)) {
                    continue;
                }
                if (keep.test(name)) {
                    all.add(entry);
                }
                marker = name;
            }
            if (Objects.equals(marker, before)) {
                return all;
            }
        }
    }

    private void purgeMultipartObjects(String container) {
        List<? extends SwiftObject> objects;
        try {
            objects = listAll(container, MPU_PREFIX);
        } catch (ResponseException re) {
            throw translate(re, container, /*key=*/ null);
        }
        for (var object : objects) {
            removeBlobInternal(container, object.getName());
        }
    }

    /**
     * Determines whether the container holds nothing but orphaned
     * multipart-upload segments: objects under {@link #MPU_PREFIX} that a
     * completed upload left behind, with no client-visible object and no
     * in-progress upload (which would carry a {@code .meta} marker).  Such
     * segments are hidden from S3 clients, so a container reduced to only
     * these is empty from the caller's point of view.
     */
    private boolean containsOnlyOrphanSegments(String container) {
        var swift = objectStorage();
        String marker = null;
        boolean sawSegment = false;
        while (true) {
            var options = ObjectListOptions.create();
            if (marker != null) {
                options.marker(marker);
            }
            List<? extends SwiftObject> objects;
            try {
                objects = swift.objects().list(container, options);
            } catch (ResponseException re) {
                throw translate(re, container, /*key=*/ null);
            }
            if (objects.isEmpty()) {
                return sawSegment;
            }
            String before = marker;
            for (var object : objects) {
                String name = object.getName();
                if (name == null) {
                    continue;
                }
                if (!name.startsWith(MPU_PREFIX) ||
                        name.startsWith(MPU_UPLOADS_PREFIX) ||
                        name.startsWith(MPU_LONG_UPLOADS_PREFIX)) {
                    // A client-visible object, or the marker of an upload in
                    // progress.  The ".meta" marker of an upload begun
                    // before the present layout is no such thing: no
                    // request can find that upload to complete or abort it.
                    return false;
                }
                sawSegment = true;
                marker = name;
            }
            // Names come back strictly after the marker, so a page that
            // leaves it unmoved is a backend ignoring markers, and asking
            // again would ask forever.  What it showed decides -- at worst
            // an unwarranted purge of orphans, which the delete retry
            // still answers with the container's true state.
            if (Objects.equals(marker, before)) {
                return sawSegment;
            }
        }
    }

    @Override
    public void deleteContainer(String container) {
        deleteContainerWithRetries(
                () -> BlobStore.super.deleteContainer(container));
    }

    static void deleteContainerWithRetries(Runnable deleteAttempt) {
        for (int attempt = 0; attempt < DELETE_CONTAINER_MAX_ATTEMPTS;
                attempt++) {
            try {
                deleteAttempt.run();
                return;
            } catch (S3Exception se) {
                if (!"BucketNotEmpty".equals(S3Exceptions.errorCode(se)) ||
                        attempt + 1 == DELETE_CONTAINER_MAX_ATTEMPTS) {
                    throw se;
                }
                // Swift acknowledges writes before every container listing
                // reflects them.  Re-running the full clear after a short,
                // bounded delay lets late entries become visible before the
                // next delete attempt.
                try {
                    Thread.sleep(DELETE_CONTAINER_RETRY_BASE_MILLIS <<
                            attempt);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    se.addSuppressed(ie);
                    throw se;
                }
            }
        }
    }

    @Override
    public void deleteBucket(String container) {
        var response = deleteContainerResponse(container);
        int code = response.getCode();
        if (response.isSuccess() || code == STATUS_NOT_FOUND) {
            return;
        }
        if (code != STATUS_CONFLICT) {
            throw translate(response, container, /*key=*/ null);
        }
        // Swift reports the container non-empty.  Overwriting or re-completing
        // a multipart object can orphan the previous upload's segments under
        // the reserved prefix, where no S3 client can see or remove them
        // (Swift's s3api isolates segments in a hidden container instead).
        // When those orphans are all that remain -- no visible object and no
        // in-progress upload, whose .meta marker must keep blocking the delete
        // -- purge them and retry, mirroring s3api's _delete_segments_bucket.
        // Otherwise the container is genuinely non-empty, so leave it intact.
        if (!containsOnlyOrphanSegments(container)) {
            throw S3Exceptions.bucketNotEmpty(container);
        }
        purgeMultipartObjects(container);
        response = deleteContainerResponse(container);
        code = response.getCode();
        if (response.isSuccess() || code == STATUS_NOT_FOUND) {
            return;
        }
        if (code == STATUS_CONFLICT) {
            throw S3Exceptions.bucketNotEmpty(container);
        }
        throw translate(response, container, /*key=*/ null);
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
                return ActionResponse.actionFailed("", STATUS_NOT_FOUND);
            }
            throw translate(re, container, /*key=*/ null);
        }
    }

    @Override
    public ResponseInputStream<GetObjectResponse> getBlob(
            GetObjectRequest request) {
        Blob blob = isReserved(request.key()) ? null :
                getBlobCarrier(request.bucket(), request.key(), request);
        if (blob == null) {
            throw S3Exceptions.noSuchKey(request.bucket(), request.key(),
                    "no such object");
        }
        return SdkResponses.getResponse(
                SdkResponses.toGetResponse(blob.getMetadata(),
                        blob.getContentRange()),
                requireNonNull(blob.getPayload()));
    }

    @Nullable
    private Blob getBlobCarrier(String container, String key,
            GetObjectRequest options) {
        if (options.versionId() != null) {
            throw new UnsupportedOperationException(
                    "versioning not supported");
        }
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
        boolean ranged = options.range() != null;
        // A suffix range of no bytes, bytes=-0, cannot be satisfied, and S3
        // says so; Swift ignores it and serves the whole object.  Any other
        // suffix of an empty object Swift answers with the whole of it, a
        // 200 with no Content-Range, as S3 does.
        boolean suffixRange = ranged &&
                requireNonNull(options.range()).startsWith("bytes=-");
        if (suffixRange && CharMatcher.is('0').matchesAllOf(
                requireNonNull(options.range()).substring(
                        "bytes=-".length()))) {
            throw S3Exceptions.fromStatusCode(STATUS_RANGE_NOT_SATISFIABLE);
        }
        if (ranged) {
            downloadOptions.header(HttpHeaders.RANGE, options.range());
        }
        // Swift judges an ETag condition against its own ETag, which for
        // an object assembled from parts is the hash of its manifest and
        // not the composite one this store reports for it.  A client
        // sending back the ETag it was given would be refused by If-Match
        // and served anew by If-None-Match, so for such an object the
        // conditions are judged here, against the ETag it knows.
        boolean eTagConditions = options.ifMatch() != null ||
                options.ifNoneMatch() != null;
        String multipartETag = eTagConditions ?
                reportedMultipartETag(swift, container, key) : null;
        if (multipartETag != null) {
            String eTag = maybeQuoteETag(multipartETag);
            String ifMatch = options.ifMatch();
            if (ifMatch != null && !ifMatch.equals("*") &&
                    !maybeQuoteETag(ifMatch).equals(eTag)) {
                throw S3Exceptions.fromStatusCode(
                        STATUS_PRECONDITION_FAILED);
            }
            String ifNoneMatch = options.ifNoneMatch();
            if (ifNoneMatch != null && (ifNoneMatch.equals("*") ||
                    maybeQuoteETag(ifNoneMatch).equals(eTag))) {
                throw S3Exceptions.fromStatusCode(304, eTag, Map.of(),
                        /*cause=*/ null);
            }
        } else {
            if (options.ifMatch() != null) {
                downloadOptions.header(HttpHeaders.IF_MATCH,
                        options.ifMatch());
            }
            if (options.ifNoneMatch() != null) {
                downloadOptions.header(HttpHeaders.IF_NONE_MATCH,
                        options.ifNoneMatch());
            }
        }
        if (options.ifModifiedSince() != null) {
            downloadOptions.header(HttpHeaders.IF_MODIFIED_SINCE,
                    toHttpDate(options.ifModifiedSince()));
        }
        // Only when If-Match is absent.  S3 answers a request carrying
        // both with 200 when the If-Match holds and the If-Unmodified-Since
        // does not; Swift, sent both, requires both.
        if (options.ifUnmodifiedSince() != null &&
                options.ifMatch() == null) {
            downloadOptions.header(HttpHeaders.IF_UNMODIFIED_SINCE,
                    toHttpDate(options.ifUnmodifiedSince()));
        }

        DLPayload payload;
        try {
            payload = swift.objects().download(container, encodeName(key),
                    downloadOptions);
        } catch (ResponseException re) {
            if (re.getStatus() == STATUS_NOT_FOUND &&
                    !containerExists(container)) {
                throw S3Exceptions.noSuchBucket(container, "");
            }
            throw translate(re, container, key);
        }
        var response = payload.getHttpResponse();
        int status = response.getStatus();
        if (status >= 300) {
            // A non-2xx response's body is never handed to the caller, so
            // capture the header we need and close the okhttp response to
            // release its connection rather than leaking it.
            String etag = response.header(SwiftHeaders.ETAG);
            try {
                response.close();
            } catch (IOException ioe) {
                // The connection is being abandoned; ignore close failures.
            }
            if (status == STATUS_NOT_FOUND) {
                // The object is gone; distinguish a gone container so the GET
                // reports NoSuchBucket rather than NoSuchKey.
                if (!containerExists(container)) {
                    throw S3Exceptions.noSuchBucket(container, "");
                }
                return null;
            }
            // Carry the ETag on the exception's response so S3ProxyHandler can
            // echo it: a 304 Not Modified from a conditional GET must return the
            // object's ETag, which the client relies on as the validator.  Swift
            // reports a bare MD5 digest, so quote it as S3 clients expect (the
            // raw header is copied through verbatim, matching how jclouds-native
            // backends surface the validator).
            throw S3Exceptions.fromStatusCode(status,
                    etag == null ? null : maybeQuoteETag(etag), Map.of(),
                    /*cause=*/ null);
        }

        var objectMetadata = ObjectMetadata.from(response.headers());

        long contentLength = resolveContentLength(swift, container, key,
                response.header(HttpHeaders.CONTENT_LENGTH),
                ranged ? response.header(HttpHeaders.CONTENT_RANGE) : null);
        var builder = Blob.builder(key)
                .payload(payload.getInputStream())
                .contentLength(contentLength)
                .contentType(response.getContentType())
                .contentDisposition(
                        response.header(HttpHeaders.CONTENT_DISPOSITION))
                .contentEncoding(response.header(HttpHeaders.CONTENT_ENCODING))
                .cacheControl(response.header(HttpHeaders.CACHE_CONTROL))
                .expires(parseHttpDate(response.header(HttpHeaders.EXPIRES)))
                .userMetadata(objectMetadata.userMetadata())
                .eTag(objectMetadata.eTagOr(
                        response.header(SwiftHeaders.ETAG)))
                .lastModified(
                        parseHttpDate(response.header(SwiftHeaders.LAST_MODIFIED)));
        if (ranged) {
            var contentRange = response.header(HttpHeaders.CONTENT_RANGE);
            if (contentRange != null) {
                builder.contentRange(contentRange);
            }
        }
        return builder.build();
    }

    /**
     * The composite ETag recorded for an object assembled from parts, or
     * null for any other object and for one that is not there.
     */
    private @Nullable String reportedMultipartETag(ObjectStorageService swift,
            String container, String key) {
        SwiftObject object;
        try {
            object = swift.objects().get(container, encodeName(key));
        } catch (ResponseException re) {
            if (re.getStatus() == STATUS_NOT_FOUND) {
                return null;
            }
            throw translate(re, container, key);
        }
        if (object == null || object.getMetadata() == null) {
            return null;
        }
        return ObjectMetadata.from(object.getMetadata()).mpuETag();
    }

    @Override
    public PutObjectResponse putBlob(PutObjectRequest request,
            InputStream payload) {
        checkNotReserved(request.key());
        var builder = Blob.builder(request.key())
                .payload(payload)
                .cacheControl(request.cacheControl())
                .contentDisposition(request.contentDisposition())
                .contentEncoding(request.contentEncoding())
                .contentType(request.contentType())
                .userMetadata(request.metadata());
        Long contentLength = request.contentLength();
        if (contentLength != null) {
            builder.contentLength(contentLength);
        }
        String contentMD5 = request.contentMD5();
        if (contentMD5 != null) {
            builder.contentMD5(HashCode.fromBytes(
                    Base64.getDecoder().decode(contentMD5)));
        }
        if (request.expires() != null) {
            builder.expires(request.expires());
        }
        return putBlobInternal(request.bucket(), builder.build(),
                request.ifNoneMatch());
    }

    private PutObjectResponse putBlobInternal(String container, Blob blob,
            @Nullable String ifNoneMatch) {
        var swift = objectStorage();
        var metadata = blob.getMetadata();
        var contentMetadata = metadata.contentMetadata();
        var swiftOptions = ObjectPutOptions.create();
        var contentType = contentMetadata.contentType();
        if (contentType != null) {
            swiftOptions.contentType(contentType);
        }
        var contentDisposition = contentMetadata.contentDisposition();
        if (contentDisposition != null) {
            swiftOptions.getOptions().put(HttpHeaders.CONTENT_DISPOSITION,
                    contentDisposition);
        }
        var contentEncoding = contentMetadata.contentEncoding();
        if (contentEncoding != null) {
            swiftOptions.getOptions().put(HttpHeaders.CONTENT_ENCODING,
                    contentEncoding);
        }
        var cacheControl = contentMetadata.cacheControl();
        if (cacheControl != null) {
            swiftOptions.getOptions().put(HttpHeaders.CACHE_CONTROL,
                    cacheControl);
        }
        var expires = contentMetadata.expires();
        if (expires != null) {
            swiftOptions.getOptions().put(HttpHeaders.EXPIRES,
                    toHttpDate(expires));
        }
        // Swift supports conditional PUT only via If-None-Match: *, replying
        // 412 Precondition Failed when the object already exists.
        boolean ifNoneMatchStar = "*".equals(ifNoneMatch);
        if (ifNoneMatchStar) {
            swiftOptions.getOptions().put(HttpHeaders.IF_NONE_MATCH, "*");
        }
        // Forward the client's Content-MD5 as the Swift ETag so the backend
        // verifies the object's integrity, replying 422 on a mismatch.
        var contentMD5 = contentMetadata.contentMD5();
        if (contentMD5 != null) {
            swiftOptions.getOptions().put(HttpHeaders.ETAG,
                    contentMD5.toString());
        }
        var userMetadata = metadata.userMetadata();
        if (!userMetadata.isEmpty()) {
            swiftOptions.metadata(encodeMetadata(userMetadata));
        }
        String etag;
        // The digest of what was sent, kept to tell a rejected Content-MD5
        // apart from every other way the write can fail.
        var sent = MD5.newDigest();
        try (var is = new DigestInputStream(
                requireNonNull(blob.getPayload()), sent)) {
            etag = swift.objects().put(container,
                    encodeName(metadata.name()), Payloads.create(is),
                    swiftOptions);
        } catch (ResponseException re) {
            throw translate(re, container, metadata.name());
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
        if (etag == null) {
            // openstack4j's put() ignores the response status, so a failed PUT
            // silently returns a null ETag instead of throwing.  Disambiguate:
            // a missing container is NoSuchBucket, an If-None-Match rejection
            // against an existing object (Swift replies 412) is
            // PreconditionFailed, and a rejected Content-MD5 (Swift replies
            // 422) is BadDigest.
            if (!containerExists(container)) {
                throw S3Exceptions.noSuchBucket(container, "");
            }
            if (ifNoneMatchStar &&
                    blobMetadataIfPresent(container, metadata.name()) !=
                    null) {
                throw S3Exceptions.fromStatusCode(STATUS_PRECONDITION_FAILED);
            }
            // Only when the bytes sent do not hash to it.  Every failure of
            // a write that carried a Content-MD5 was called BadDigest, which
            // a client does not retry, whatever had gone wrong.
            if (contentMD5 != null && !contentMD5.equals(
                    HashCode.fromBytes(sent.digest()))) {
                throw S3Exceptions.badDigest(/*cause=*/ null);
            }
            throw new RuntimeException(
                    "could not write object " + metadata.name());
        }
        return SdkResponses.putResponse(etag);
    }

    // Swift has no native copy-source conditionals, so emulate the
    // x-amz-copy-source-if-* preconditions against the source object's current
    // metadata and report a violation as 412 PreconditionFailed.
    private void enforceCopySourcePreconditions(String container, String name,
            CopyObjectRequest request) {
        String ifMatch = request.copySourceIfMatch();
        String ifNoneMatch = request.copySourceIfNoneMatch();
        Instant ifModifiedSince = request.copySourceIfModifiedSince();
        Instant ifUnmodifiedSince = request.copySourceIfUnmodifiedSince();
        if (ifMatch == null && ifNoneMatch == null &&
                ifModifiedSince == null && ifUnmodifiedSince == null) {
            return;
        }
        HeadObjectResponse metadata = blobMetadataIfPresent(container, name);
        if (metadata == null) {
            throw S3Exceptions.noSuchKey(container, name, "while copying");
        }
        String eTag = metadata.eTag();
        if (eTag != null) {
            String quoted = maybeQuoteETag(eTag);
            if (ifMatch != null && !maybeQuoteETag(ifMatch).equals(quoted)) {
                throw preconditionFailed();
            }
            if (ifNoneMatch != null &&
                    maybeQuoteETag(ifNoneMatch).equals(quoted)) {
                throw preconditionFailed();
            }
        }
        Instant lastModified = metadata.lastModified();
        if (lastModified != null) {
            if (ifModifiedSince != null &&
                    lastModified.compareTo(ifModifiedSince) <= 0) {
                throw preconditionFailed();
            }
            // only when the if-match is absent, as on a read
            if (ifUnmodifiedSince != null && ifMatch == null &&
                    lastModified.compareTo(ifUnmodifiedSince) > 0) {
                throw preconditionFailed();
            }
        }
    }

    private static S3Exception preconditionFailed() {
        return S3Exceptions.fromStatusCode(412);
    }

    @Override
    public CopyObjectResponse copyBlob(CopyObjectRequest request) {
        if (request.sourceVersionId() != null) {
            throw new UnsupportedOperationException(
                    "versioning not supported");
        }
        if (request.acl() == ObjectCannedACL.PUBLIC_READ) {
            // Matches setBlobAccess: Swift grants read at the container, so a
            // public copy is refused rather than silently made private.
            throw new UnsupportedOperationException(
                    "blob-level access unsupported in Swift");
        }
        String fromContainer = request.sourceBucket();
        String fromName = request.sourceKey();
        String toContainer = request.destinationBucket();
        String toName = request.destinationKey();
        checkNotReserved(toName);
        if (isReserved(fromName)) {
            throw S3Exceptions.noSuchKey(fromContainer, fromName,
                    "while copying");
        }
        enforceCopySourcePreconditions(fromContainer, fromName, request);
        if (request.metadataDirective() == MetadataDirective.REPLACE) {
            // S3 CopyObject with metadata directive REPLACE.  Swift's COPY
            // always preserves the source metadata, so download the source
            // object and re-upload it with the replacement metadata instead.
            var blob = getBlobCarrier(fromContainer, fromName,
                    GetObjectRequest.builder()
                            .bucket(fromContainer)
                            .key(fromName)
                            .build());
            if (blob == null) {
                throw S3Exceptions.noSuchKey(fromContainer, fromName,
                        "while copying");
            }
            var builder = blob.toBuilder().name(toName);
            builder.contentType(request.contentType())
                    .contentDisposition(request.contentDisposition())
                    .contentEncoding(request.contentEncoding());
            builder.userMetadata(request.metadata());
            return SdkResponses.copyResponse(putBlobInternal(toContainer,
                    builder.build(), /*ifNoneMatch=*/ null).eTag());
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
            throw S3Exceptions.noSuchKey(fromContainer, fromName,
                    "while copying");
        }
        return SdkResponses.copyResponse(etag);
    }

    @Override
    public DeleteObjectResponse removeBlob(DeleteObjectRequest request) {
        // The literal "null" names the null version, which on an
        // unversioned namespace is the object itself.
        if (request.versionId() != null &&
                !request.versionId().equals("null")) {
            throw new UnsupportedOperationException(
                    "versioning not supported");
        }
        if (request.ifMatch() != null || request.ifMatchSize() != null ||
                request.ifMatchLastModifiedTime() != null) {
            throw new UnsupportedOperationException(
                    "conditional delete not supported");
        }
        checkNotReserved(request.key());
        removeBlobInternal(request.bucket(), request.key());
        return DeleteObjectResponse.builder().build();
    }

    /**
     * Deletes without the reserved-name check, for the multipart bookkeeping
     * this store both writes and cleans up.
     */
    private void removeBlobInternal(String container, String key) {
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
                response.getCode() != STATUS_NOT_FOUND) {
            throw translate(response, container, key);
        }
        // Deleting an object that is not there succeeds, as on S3 -- but
        // not when the container is not there either, which Swift answers
        // with the same 404 and S3 answers NoSuchBucket for.
        if (response.getCode() == STATUS_NOT_FOUND &&
                !containerExists(container)) {
            throw S3Exceptions.noSuchBucket(container, "");
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

    /**
     * Whether the object is there, asked with a HEAD: existence needs none
     * of the headers {@link #headBlob} goes to a GET for, and is asked once
     * per part of an upload.
     */
    @Override
    public boolean blobExists(String container, String key) {
        return !isReserved(key) && blobExistsInternal(container, key);
    }

    /**
     * Asks without the reserved-name check, for the marker that says an
     * upload is still open.
     */
    private boolean blobExistsInternal(String container, String key) {
        if (hasPathTraversal(key)) {
            return false;
        }
        try {
            return objectStorage().objects().get(container,
                    encodeName(key)) != null;
        } catch (ResponseException re) {
            if (re.getStatus() == STATUS_NOT_FOUND) {
                return false;
            }
            throw translate(re, container, key);
        }
    }

    @Override
    public HeadObjectResponse blobMetadata(HeadObjectRequest request) {
        if (request.versionId() != null) {
            throw new UnsupportedOperationException(
                    "versioning not supported");
        }
        String container = request.bucket();
        String key = request.key();
        Blob blob;
        try {
            blob = isReserved(key) ? null : headBlob(container, key);
        } catch (NoSuchBucketException nsbe) {
            throw S3Exceptions.noSuchKey(container, key, "no such object",
                    nsbe);
        }
        if (blob == null) {
            throw S3Exceptions.noSuchKey(container, key, "no such object");
        }
        var metadata = blob.getMetadata();
        var content = metadata.contentMetadata();
        @SuppressWarnings("deprecation")
        HeadObjectResponse head = HeadObjectResponse.builder()
                .metadata(metadata.userMetadata())
                .eTag(metadata.eTag())
                .lastModified(metadata.lastModified())
                .storageClass(StorageClass.STANDARD.toString())
                .contentLength(totalLength(blob))
                .contentType(content.contentType())
                .contentDisposition(content.contentDisposition())
                .contentEncoding(content.contentEncoding())
                .cacheControl(content.cacheControl())
                .expires(content.expires())
                .build();
        return head;
    }

    /**
     * An object's headers, read with a GET of its first byte.  The client
     * library's own HEAD keeps only the headers whose names hold "x-", so
     * it reports no Content-Disposition, Content-Encoding, Cache-Control or
     * Expires, and offers no other way to send one; a GET returns them all,
     * and the range keeps it from costing the object.  An empty object has
     * no first byte, which Swift answers 416, and is read whole instead.
     */
    private @Nullable Blob headBlob(String container, String key) {
        var request = GetObjectRequest.builder().bucket(container).key(key);
        Blob blob;
        try {
            blob = getBlobCarrier(container, key,
                    request.range("bytes=0-0").build());
        } catch (S3Exception se) {
            if (se.statusCode() != STATUS_RANGE_NOT_SATISFIABLE) {
                throw se;
            }
            blob = getBlobCarrier(container, key,
                    request.range(null).build());
        }
        if (blob != null && blob.getPayload() != null) {
            try (var is = blob.getPayload()) {
                // the byte asked for, so the connection can be kept; never
                // more, should a server send the object regardless
                is.read();
            } catch (IOException ioe) {
                // only the headers were wanted
            }
        }
        return blob;
    }

    /** The size of the object a ranged read came from. */
    private static long totalLength(Blob blob) {
        String contentRange = blob.getContentRange();
        if (contentRange != null) {
            int slash = contentRange.lastIndexOf('/');
            try {
                return Long.parseLong(contentRange.substring(slash + 1)
                        .trim());
            } catch (NumberFormatException nfe) {
                // "*", or nothing after the slash: fall through
            }
        }
        Long length = blob.getMetadata().contentMetadata().contentLength();
        return length == null ? 0L : length;
    }

    /**
     * The X-Object-Meta- headers split into the user metadata S3 clients see
     * and the composite ETag s3proxy hides among them for multipart objects.
     * Swift returns raw response headers, so anything else -- X-Timestamp and
     * friends -- must not leak out as x-amz-meta-.
     */
    private record ObjectMetadata(Map<String, String> userMetadata,
            @Nullable String mpuETag) {
        static ObjectMetadata from(Map<String, String> headers) {
            var userMetadata = ImmutableMap.<String, String>builder();
            String mpuETag = null;
            for (var entry : headers.entrySet()) {
                String name = entry.getKey();
                if (!name.regionMatches(true, 0,
                        SwiftHeaders.OBJECT_METADATA_PREFIX, 0,
                        SwiftHeaders.OBJECT_METADATA_PREFIX.length())) {
                    continue;
                }
                // S3 metadata keys are case-insensitive and returned
                // lowercase; Swift's HTTP layer canonicalizes them
                // (key1 -> Key1).
                String key = decodeMetadataName(name.substring(
                        SwiftHeaders.OBJECT_METADATA_PREFIX.length())
                        .toLowerCase(Locale.ROOT));
                if (key.equals(MPU_ETAG_METADATA)) {
                    mpuETag = entry.getValue();
                } else {
                    userMetadata.put(key, entry.getValue());
                }
            }
            return new ObjectMetadata(userMetadata.build(), mpuETag);
        }

        /** The recorded composite ETag, or Swift's own when there is none. */
        @Nullable String eTagOr(@Nullable String swiftETag) {
            return mpuETag != null ? mpuETag : swiftETag;
        }
    }

    @Override
    public BucketCannedACL getContainerAccess(String container) {
        var swift = objectStorage();
        var metadata = swift.containers().getMetadata(container);
        // getMetadata returns an empty map for a missing container; the object
        // count is present only when it exists.  Signal a gone container so the
        // anonymous-access check reports NoSuchBucket instead of 403.
        boolean exists = false;
        var access = BucketCannedACL.PRIVATE;
        for (var entry : metadata.entrySet()) {
            if (entry.getKey().equalsIgnoreCase("X-Container-Object-Count")) {
                exists = true;
            } else if (entry.getKey().equalsIgnoreCase(
                    SwiftHeaders.CONTAINER_READ)) {
                if (isPublicRead(entry.getValue())) {
                    access = BucketCannedACL.PUBLIC_READ;
                }
            }
        }
        if (!exists) {
            throw S3Exceptions.noSuchBucket(container, "");
        }
        return access;
    }

    /**
     * Whether a container read ACL is S3's public-read: anyone may read the
     * objects and anyone may list them.  Swift grants the two apart, .r:* for
     * an object and .rlistings beside it for the listing, and .r:* alone
     * shares objects by name without telling anyone the names.  S3Proxy
     * lists a public-read bucket with its own token, so Swift never applies
     * the ACL to the anonymous client; only both together may be reported,
     * which is also what setContainerAccess writes.  Elements are compared
     * whole: the referrer .r:*.example.com is not everyone.
     */
    static boolean isPublicRead(@Nullable String readAcl) {
        if (readAcl == null) {
            return false;
        }
        var grants = Splitter.on(',').trimResults().splitToList(readAcl);
        return grants.contains(".r:*") && grants.contains(".rlistings");
    }

    @Override
    public void setContainerAccess(String container, BucketCannedACL access) {
        if (access == BucketCannedACL.PUBLIC_READ_WRITE) {
            // Swift write ACLs name users, not referrers; anonymous write is
            // not expressible, so refuse rather than grant only the read half.
            throw new UnsupportedOperationException(
                    "anonymous write access unsupported in Swift");
        }
        var options = CreateUpdateContainerOptions.create();
        if (access == BucketCannedACL.PUBLIC_READ) {
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
    public ObjectCannedACL getBlobAccess(String container, String key) {
        return ObjectCannedACL.PRIVATE;
    }

    @Override
    public void setBlobAccess(String container, String key,
            ObjectCannedACL access) {
        throw new UnsupportedOperationException(
                "blob-level access unsupported in Swift");
    }

    // Multipart upload maps to Swift Static Large Objects: each upload of a
    // part is stored as a segment object under MPU_PREFIX in the same
    // container, and completion writes an SLO manifest at the target key
    // referencing one segment for each of its parts.  A metadata marker
    // object holds the target content metadata between initiate and
    // complete, since S3ProxyHandler reconstructs the upload from only the
    // upload id.  All of this is hidden from list().
    @Override
    public MultipartUpload initiateMultipartUpload(
            CreateMultipartUploadRequest request) {
        // Completing this upload writes an object under the requested key,
        // which is the same write putBlob refuses.
        checkNotReserved(request.key());
        String uploadId = UploadNames.newUploadId(request.key());

        var userMetadata = new HashMap<String, String>(request.metadata());
        // Record the target key so listMultipartUploads can recover it,
        // spelled for a header rather than raw: a key is any UTF-8 and a
        // header is ASCII.
        userMetadata.put(MPU_KEY_METADATA,
                encodeMetadataValue(request.key()));

        var markerBuilder = Blob.builder(mpuMetaKey(request.key(), uploadId))
                .payload(new ByteArrayInputStream(new byte[0]))
                .contentLength(0)
                .userMetadata(userMetadata);
        if (request.contentType() != null) {
            markerBuilder.contentType(request.contentType());
        }
        if (request.contentDisposition() != null) {
            markerBuilder.contentDisposition(request.contentDisposition());
        }
        if (request.contentEncoding() != null) {
            markerBuilder.contentEncoding(request.contentEncoding());
        }
        putBlobInternal(request.bucket(), markerBuilder.build(),
                /*ifNoneMatch=*/ null);

        return new MultipartUpload(uploadId, request);
    }

    @Override
    public UploadPartResponse uploadMultipartPart(MultipartUpload mpu,
            UploadPartRequest request, InputStream is) {
        // The marker is there for as long as the upload is open.  Without
        // it this would write a segment for an upload never created or
        // already finished, where no completion will find it.  Nor is an
        // upload begun for another key open to this request.
        if (!isOpenUpload(mpu)) {
            throw S3Exceptions.noSuchUpload(mpu.id());
        }
        // The marker was looked for before the body is read, and the client
        // decides when the body ends: the upload may be complete by the time
        // the segment is written.  A finished object is its segments, which
        // its manifest names with the ETag and size they had, and Swift
        // refuses to serve it once one of them differs.  So no segment is
        // ever written over: each upload of a part writes one of its own,
        // and one that arrives late is a segment no manifest names rather
        // than other content under a name one does.
        var segment = Blob.builder(
                newSegmentKey(mpu.id(), request.partNumber()))
                .payload(is)
                .contentLength(request.contentLength())
                .contentMD5(SdkRequests.contentMD5(request))
                .build();
        String eTag = putBlobInternal(mpu.containerName(), segment,
                /*ifNoneMatch=*/ null).eTag();
        return SdkResponses.uploadedPart(eTag);
    }

    /**
     * The parts of an upload still open.  A finished upload keeps its
     * segments, which its object's manifest names, but they are parts no
     * longer: listing them had the frontend take a retried completion for a
     * first one and rewrite the manifest, by then without the metadata the
     * marker had carried.  So an upload whose marker is gone lists none,
     * which is how the frontend knows to look for the finished object.
     */
    @Override
    public List<Part> listMultipartUpload(MultipartUpload mpu) {
        // As in S3, a part uploaded again replaces the one before it.  The
        // segments come by part number and oldest first, so the last of
        // each number stays.
        var parts = new LinkedHashMap<Integer, Part>();
        for (var segment : listSegments(mpu, /*requireMarker=*/ true)) {
            parts.put(segment.part().partNumber(), segment.part());
        }
        return new ArrayList<>(parts.values());
    }

    /**
     * A segment of an upload: the name of its object, and the part it holds.
     */
    private record Segment(String name, Part part) {
        /**
         * By part number, and then oldest first.  That is by the time Swift
         * gives a segment, which is what decided between two uploads of a
         * part while they shared a name, and for segments of one time by
         * name, in which {@code newSegmentKey} puts this proxy's time
         * first.
         */
        static final Comparator<Segment> ORDER =
                Comparator.<Segment>comparingInt(
                        segment -> segment.part().partNumber())
                .thenComparing(segment -> segment.part().lastModified(),
                        Comparator.nullsFirst(Comparator.naturalOrder()))
                .thenComparing(Segment::name);
    }

    /**
     * Every segment of an upload, by part number and then oldest first.  A
     * part uploaded more than once has a segment for each time.
     */
    private List<Segment> listSegments(MultipartUpload mpu,
            boolean requireMarker) {
        // An upload ID names the key it was issued for, so one sent with
        // another key is no upload at all, as on S3.
        if (!UploadNames.namesKey(mpu.id(), mpu.blobName())) {
            throw S3Exceptions.noSuchUpload(mpu.id());
        }
        if (requireMarker && !isOpenUpload(mpu)) {
            return List.of();
        }
        String prefix = mpuSegmentPrefix(mpu.id());
        List<? extends SwiftObject> objects;
        try {
            objects = listAll(mpu.containerName(), prefix);
        } catch (ResponseException re) {
            throw translate(re, mpu.containerName(), /*key=*/ null);
        }
        var segments = new ArrayList<Segment>();
        for (var object : objects) {
            String name = object.getName();
            if (name == null) {
                continue;
            }
            int partNumber;
            try {
                partNumber = segmentPartNumber(
                        name.substring(prefix.length()));
            } catch (NumberFormatException nfe) {
                continue;
            }
            segments.add(new Segment(name, SdkResponses.part(partNumber,
                    object.getSizeInBytes(), object.getETag(),
                    toInstant(object.getLastModified()))));
        }
        segments.sort(Segment.ORDER);
        return segments;
    }

    /**
     * The segment of {@code candidates}, which are those of one part number
     * and oldest first, that a completion naming the part by {@code eTag}
     * means.  That is one with that ETag rather than the newest, which may
     * have arrived since the caller looked, and the oldest such, so that
     * nothing arriving later changes the choice.  A caller that states no
     * ETag, or one no segment has, means the newest.
     */
    private static Segment chooseSegment(List<Segment> candidates,
            @Nullable String eTag) {
        for (var candidate : candidates) {
            if (eTag != null && eTag.equals(candidate.part().eTag())) {
                return candidate;
            }
        }
        return candidates.get(candidates.size() - 1);
    }

    /**
     * Whether the upload is open, which is while its marker exists, and was
     * begun for the key the request names.  S3 answers NoSuchUpload to an
     * upload ID paired with another key; taken on the ID alone, a request
     * naming one key would add parts to, finish or abort the upload of
     * another.  A marker without its key predates the key being recorded
     * and answers to any.
     */
    private boolean isOpenUpload(MultipartUpload mpu) {
        if (!UploadNames.namesKey(mpu.id(), mpu.blobName())) {
            return false;
        }
        // Read past the reserved-name check, which the marker's name is
        // subject to as a client's key.
        Blob marker;
        try {
            marker = headBlob(mpu.containerName(),
                    mpuMetaKey(mpu.blobName(), mpu.id()));
        } catch (NoSuchBucketException nsbe) {
            return false;
        }
        if (marker == null) {
            return false;
        }
        String encoded = marker.getMetadata().userMetadata()
                .get(MPU_KEY_METADATA);
        return encoded == null ||
                decodeMetadataValue(encoded).equals(mpu.blobName());
    }

    @Override
    public CompleteMultipartUploadResponse completeMultipartUpload(MultipartUpload mpu,
            CompleteMultipartUploadRequest request) {
        // The key comes with this request, not from the marker, so it need
        // not be the one initiateMultipartUpload was asked about.
        checkNotReserved(mpu.blobName());
        List<CompletedPart> parts = request.multipartUpload() == null ?
                List.of() : request.multipartUpload().parts();
        var swift = objectStorage();
        String container = mpu.containerName();
        String uploadId = mpu.id();

        // Restore the target metadata saved by initiateMultipartUpload.
        var swiftOptions = ObjectPutOptions.create();
        var manifestMetadata = new HashMap<String, String>();
        String markerName = mpuMetaKey(mpu.blobName(), uploadId);
        var marker = !UploadNames.namesKey(uploadId, mpu.blobName()) ? null :
                getBlobCarrier(container, markerName,
                        GetObjectRequest.builder()
                                .bucket(container)
                                .key(markerName)
                                .build());
        if (marker == null) {
            // Already completed, aborted, or never created.  Carrying on
            // would write the manifest again without the metadata only the
            // marker held.
            throw S3Exceptions.noSuchUpload(uploadId);
        }
        String markerKey = marker.getMetadata().userMetadata()
                .get(MPU_KEY_METADATA);
        if (markerKey != null &&
                !decodeMetadataValue(markerKey).equals(mpu.blobName())) {
            // an upload of another key, which this request does not name
            throw S3Exceptions.noSuchUpload(uploadId);
        }
        var contentMetadata = marker.getMetadata().contentMetadata();
        if (contentMetadata.contentType() != null) {
            swiftOptions.contentType(contentMetadata.contentType());
        }
        if (contentMetadata.contentDisposition() != null) {
            swiftOptions.getOptions().put(HttpHeaders.CONTENT_DISPOSITION,
                    contentMetadata.contentDisposition());
        }
        if (contentMetadata.contentEncoding() != null) {
            swiftOptions.getOptions().put(HttpHeaders.CONTENT_ENCODING,
                    contentMetadata.contentEncoding());
        }
        manifestMetadata.putAll(marker.getMetadata().userMetadata());
        manifestMetadata.remove(MPU_KEY_METADATA);

        var sorted = new ArrayList<>(parts);
        sorted.sort(Comparator.comparingInt(CompletedPart::partNumber));

        // The caller's part values may not match the stored
        // segments: EncryptedBlobStore reports plaintext part sizes while
        // the segments hold padded ciphertext.  Swift validates every
        // manifest entry's etag and size against its segment, so resolve
        // each referenced part number against the stored segments, and
        // reject parts that were never uploaded (or whose upload was
        // aborted) like S3's InvalidPart.  A part uploaded more than once
        // has a segment for each time, and the one the caller means is the
        // one whose ETag it states.
        var segmentsByPartNumber = new HashMap<Integer, List<Segment>>();
        for (var segment : listSegments(mpu, /*requireMarker=*/ false)) {
            segmentsByPartNumber.computeIfAbsent(
                    segment.part().partNumber(), k -> new ArrayList<>())
                    .add(segment);
        }
        var resolved = new ArrayList<Segment>(sorted.size());
        for (var part : sorted) {
            var candidates = segmentsByPartNumber.get(part.partNumber());
            if (candidates == null) {
                throw S3Exceptions.invalidPart(part.partNumber());
            }
            resolved.add(chooseSegment(candidates, part.eTag()));
        }

        // Build the Swift Static Large Object manifest -- a JSON array naming
        // each segment by its "<container>/<object>" path, MD5 etag, and exact
        // size -- and write it with the ?multipart-manifest=put query
        // parameter.  This issues the same request openstack4j's
        // createStaticLargeObject extension would, but through the stock put()
        // API so the provider builds against an unmodified openstack4j.
        var manifest = new ArrayList<Map<String, Object>>(resolved.size());
        for (var segment : resolved) {
            var entry = new LinkedHashMap<String, Object>();
            entry.put("path", container + "/" + segment.name());
            entry.put("etag", segment.part().eTag());
            entry.put("size_bytes", segment.part().size());
            manifest.add(entry);
        }
        byte[] manifestJson;
        try {
            manifestJson = MANIFEST_MAPPER.writeValueAsBytes(manifest);
        } catch (JsonProcessingException jpe) {
            throw new RuntimeException(jpe);
        }
        swiftOptions.queryParam("multipart-manifest", "put");

        String mpuETag = multipartETag(
                resolved.stream().map(Segment::part).toList());
        if (mpuETag != null) {
            manifestMetadata.put(MPU_ETAG_METADATA, mpuETag);
        }
        if (!manifestMetadata.isEmpty()) {
            swiftOptions.metadata(encodeMetadata(manifestMetadata));
        }

        String sloETag;
        try {
            sloETag = swift.objects().put(container,
                    encodeName(mpu.blobName()),
                    Payloads.create(new ByteArrayInputStream(manifestJson)),
                    swiftOptions);
        } catch (ResponseException re) {
            throw translate(re, container, mpu.blobName());
        }
        if (sloETag == null) {
            // As in putBlobInternal: openstack4j's put() ignores the response
            // status, so a manifest Swift refused -- one naming more
            // segments than its max_manifest_segments, 1000 unless raised,
            // say -- comes back as a null ETag and no exception.  Nothing
            // was written, so say so and leave the marker: answering success
            // here told the caller an object existed that did not, and
            // removed the record that the upload was still open.
            throw new RuntimeException("Swift refused the manifest of " +
                    resolved.size() + " segments for " + mpu.blobName());
        }

        // The manifest now references the segments, which must persist; only
        // the metadata marker is no longer needed.  The segments it does
        // not name -- of a part left out, or uploaded again -- stay too,
        // until deleteBucket purges them: one of them may be what a
        // completion racing this one has named.
        removeBlobInternal(container, markerName);

        return SdkResponses.completeResponse(
                mpuETag != null ? mpuETag : sloETag);
    }

    @Override
    public void abortMultipartUpload(MultipartUpload mpu) {
        String container = mpu.containerName();

        // The .meta marker exists only while the upload is in progress:
        // completeMultipartUpload removes it but deliberately leaves the
        // segments, which the SLO manifest now references.  If the marker is
        // gone the upload has already completed (or never existed), so abort
        // must report no such upload rather than delete the segments that back
        // the live object.
        if (!isOpenUpload(mpu)) {
            throw S3Exceptions.noSuchKey(container, mpu.blobName(),
                    "no such multipart upload: " + mpu.id());
        }

        // the segments, and then the marker that says the upload is open
        List<? extends SwiftObject> objects;
        try {
            objects = listAll(container, mpuSegmentPrefix(mpu.id()));
        } catch (ResponseException re) {
            throw translate(re, container, /*key=*/ null);
        }
        for (var object : objects) {
            removeBlobInternal(container, object.getName());
        }
        removeBlobInternal(container, mpuMetaKey(mpu.blobName(), mpu.id()));
    }

    @Override
    public List<software.amazon.awssdk.services.s3.model.MultipartUpload>
            listMultipartUploads(String container) {
        // Only the markers: the segments, those of finished objects
        // included, lie apart, and the key is in a marker's name.
        List<? extends SwiftObject> objects;
        try {
            objects = listAll(container, MPU_UPLOADS_PREFIX);
        } catch (ResponseException re) {
            throw translate(re, container, /*key=*/ null);
        }
        var uploads = new ArrayList<
                software.amazon.awssdk.services.s3.model.MultipartUpload>();
        for (var object : objects) {
            var upload = keyedUpload(object);
            if (upload != null) {
                uploads.add(upload);
            }
        }
        uploads.addAll(longUploads(container));
        return uploads;
    }

    /**
     * One page of uploads, read from Swift a page at a time.  The markers
     * sort as S3 lists the uploads, so the listing starts where the request's
     * markers point and stops once it holds the page and the entry that
     * tells there is more; a slash delimiter is Swift's own, which folds a
     * group of keys into one entry however many uploads it holds.  The few
     * markers of keys too long to be named by them are read whole and
     * merged in.
     */
    @Override
    public ListMultipartUploadsResponse listMultipartUploads(
            ListMultipartUploadsRequest request) {
        String container = request.bucket();
        String prefix = Strings.nullToEmpty(request.prefix());
        String delimiter = Strings.emptyToNull(request.delimiter());
        String keyMarker = Strings.emptyToNull(request.keyMarker());
        String listPrefix = MPU_UPLOADS_PREFIX + UploadNames.escapeKey(prefix);
        int limit = Math.min(UploadListings.maxUploads(request) + 2,
                LIST_PAGE_SIZE);
        // Swift lists names strictly after its marker, and the page passes
        // over the one upload a start name can be.
        String start = UploadNames.startName(prefix, delimiter, keyMarker,
                keyMarker == null ? null :
                        Strings.emptyToNull(request.uploadIdMarker()));
        String first = start == null ? null : MPU_UPLOADS_PREFIX + start;
        var swift = objectStorage();
        Iterable<software.amazon.awssdk.services.s3.model.MultipartUpload>
                ordered = () -> new AbstractIterator<software.amazon.awssdk
                        .services.s3.model.MultipartUpload>() {
                    private @Nullable String marker = first;
                    private java.util.Iterator<? extends SwiftObject> page =
                            java.util.Collections.emptyIterator();
                    private boolean exhausted;

                    @Override
                    protected software.amazon.awssdk.services.s3.model
                            .@Nullable MultipartUpload computeNext() {
                        while (true) {
                            while (page.hasNext()) {
                                var object = page.next();
                                String name = listedName(object);
                                if (name == null) {
                                    continue;
                                }
                                marker = name;
                                var upload = listedUpload(object, name);
                                if (upload != null) {
                                    return upload;
                                }
                            }
                            if (exhausted) {
                                return endOfData();
                            }
                            var options = ObjectListOptions.create()
                                    .startsWith(listPrefix).limit(limit);
                            if ("/".equals(delimiter)) {
                                options.delimiter('/');
                            }
                            if (marker != null) {
                                options.marker(marker);
                            }
                            String before = marker;
                            var objects = swift.objects().list(container,
                                    options);
                            // an empty page ends the listing, and so does
                            // one a backend ignoring markers repeats
                            exhausted = objects.isEmpty();
                            page = objects.iterator();
                            if (!exhausted && before != null &&
                                    before.equals(listedName(objects.get(
                                            objects.size() - 1)))) {
                                return endOfData();
                            }
                        }
                    }
                };
        try {
            return UploadListings.pageFromOrdered(ordered,
                    longUploads(container), request);
        } catch (ResponseException re) {
            throw translate(re, container, /*key=*/ null);
        }
    }

    /** The name of a listed object, or of the subdir a delimiter made. */
    private static @Nullable String listedName(SwiftObject object) {
        // openstack4j maps a "subdir" to getDirectoryName(); see list()
        var directoryName = object.getDirectoryName();
        return directoryName != null && !directoryName.isEmpty() ?
                directoryName : object.getName();
    }

    /**
     * An entry of a listing of the uploads' markers: an upload, or a group
     * of keys Swift folded, which the page reports as the common prefix an
     * upload of that name folds into.
     */
    private static software.amazon.awssdk.services.s3.model.@Nullable
            MultipartUpload listedUpload(SwiftObject object, String name) {
        var directoryName = object.getDirectoryName();
        if (directoryName != null && !directoryName.isEmpty()) {
            return software.amazon.awssdk.services.s3.model.MultipartUpload
                    .builder()
                    .key(UploadNames.unescapeKey(name.substring(
                            MPU_UPLOADS_PREFIX.length())))
                    .uploadId("")
                    .build();
        }
        return keyedUpload(object);
    }

    /** The upload a marker named by its key records, or null for another. */
    private static software.amazon.awssdk.services.s3.model.@Nullable
            MultipartUpload keyedUpload(SwiftObject object) {
        String name = object.getName();
        if (name == null || !name.startsWith(MPU_UPLOADS_PREFIX)) {
            return null;
        }
        // The marker is written when the upload is created and never
        // again, so its time is the upload's.
        return UploadNames.parseStubName(
                name.substring(MPU_UPLOADS_PREFIX.length()),
                toInstant(object.getLastModified()));
    }

    /**
     * The uploads of keys too long for a marker to be named by them, whose
     * key each marker keeps in its metadata.
     */
    private List<software.amazon.awssdk.services.s3.model.MultipartUpload>
            longUploads(String container) {
        List<? extends SwiftObject> objects;
        try {
            objects = listAll(container, MPU_LONG_UPLOADS_PREFIX);
        } catch (ResponseException re) {
            throw translate(re, container, /*key=*/ null);
        }
        var uploads = new ArrayList<
                software.amazon.awssdk.services.s3.model.MultipartUpload>();
        for (var object : objects) {
            String name = object.getName();
            if (name == null) {
                continue;
            }
            String uploadId = name.substring(
                    MPU_LONG_UPLOADS_PREFIX.length());
            if (!UploadNames.isUploadId(uploadId)) {
                continue;
            }
            var marker = getBlobCarrier(container, name,
                    GetObjectRequest.builder()
                            .bucket(container)
                            .key(name)
                            .build());
            String encoded = marker == null ? null :
                    marker.getMetadata().userMetadata().get(MPU_KEY_METADATA);
            if (encoded != null) {
                uploads.add(SdkResponses.upload(decodeMetadataValue(encoded),
                        uploadId, toInstant(object.getLastModified())));
            }
        }
        return uploads;
    }

    @Override
    public long getMinimumMultipartPartSize() {
        return 1;
    }

    /**
     * Whether a client's key names the store's own multipart bookkeeping: an
     * upload's marker or one of its segments.  Hiding these from list() does
     * not keep them from a client that asks by name, and the name is the
     * upload ID, which ListMultipartUploads hands to anyone who may list the
     * container.  Nor do they have an access of their own: Swift grants read
     * by container, so a public-read one served anyone the parts and the
     * metadata of an upload not yet completed, and the segments an
     * overwritten object left behind.  So a read finds nothing at such a
     * key, and a write is refused by {@link #checkNotReserved}.  The store
     * reaches these names through getBlobCarrier, putBlobInternal,
     * blobExistsInternal and removeBlobInternal, which do not ask this.
     * A prefix comparison is enough: {@link #encodeName} refuses the dot
     * segments by which another spelling could reach the same name.
     */
    static boolean isReserved(String key) {
        return key.startsWith(MPU_PREFIX);
    }

    /**
     * Refuse a client key that {@link #isReserved}.  Writing or deleting one
     * replaces or discards a segment that a finished object's manifest names,
     * which Swift then refuses to serve, or the marker that holds the
     * metadata an open upload completes with.
     */
    private static void checkNotReserved(String key) {
        if (isReserved(key)) {
            throw S3Exceptions.invalidArgument("The key " + MPU_PREFIX +
                    "... is reserved for multipart uploads.");
        }
    }

    private static String mpuSegmentPrefix(String uploadId) {
        return MPU_PARTS_PREFIX + uploadId + "/";
    }

    /** The name of an open upload's marker, from its key and upload ID. */
    static String mpuMetaKey(String key, String uploadId) {
        String name = MPU_UPLOADS_PREFIX + UploadNames.escapeKey(key) +
                UploadNames.SEPARATOR + uploadId;
        if (name.getBytes(StandardCharsets.UTF_8).length <=
                MAX_OBJECT_NAME_BYTES) {
            return name;
        }
        return MPU_LONG_UPLOADS_PREFIX + uploadId;
    }

    /**
     * A name for a segment of a part that no other segment has, so that
     * writing it replaces nothing.  The time leads what follows the part
     * number, for {@code Segment.ORDER} to fall back on.
     */
    private static String newSegmentKey(String uploadId, int partNumber) {
        return mpuSegmentPrefix(uploadId) + String.format(Locale.ROOT,
                "%05d/%013d-%s", partNumber, System.currentTimeMillis(),
                UUID.randomUUID());
    }

    /**
     * The part number of the segment named {@code name} beneath its
     * upload's prefix, which is what precedes the slash.  A segment written
     * before each upload of a part had a name of its own is named by the
     * part number alone, and an upload begun then may still hold some.
     */
    private static int segmentPartNumber(String name) {
        int slash = name.indexOf('/');
        return Integer.parseInt(slash == -1 ? name : name.substring(0, slash));
    }

    /**
     * Computes the canonical S3 multipart ETag: the hex MD5 of the
     * concatenated binary MD5s of each part, suffixed with "-{partCount}".
     * Returns null if a part ETag is not a plain MD5 hex digest, so the caller
     * can fall back to the manifest ETag.
     */
    @Nullable
    private static String multipartETag(List<Part> parts) {
        try {
            var md = MessageDigest.getInstance("MD5");
            for (var part : parts) {
                String eTag = part.eTag();
                if (eTag == null) {
                    return null;
                }
                eTag = eTag.trim();
                if (eTag.length() >= 2 && eTag.startsWith("\"") &&
                        eTag.endsWith("\"")) {
                    eTag = eTag.substring(1, eTag.length() - 1);
                }
                md.update(HexFormat.of().parseHex(eTag));
            }
            return HexFormat.of().formatHex(md.digest()) +
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

    static String toHttpDate(Instant instant) {
        return HTTP_DATE.format(instant.atOffset(ZoneOffset.UTC));
    }

    /** openstack4j reports times in the legacy Date form. */
    @Nullable
    private static Instant toInstant(@Nullable Date date) {
        return date == null ? null : date.toInstant();
    }

    @Nullable
    private static Instant parseHttpDate(@Nullable String value) {
        if (value == null) {
            return null;
        }
        try {
            return DateTimeFormatter.RFC_1123_DATE_TIME.parse(
                    value, Instant::from);
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
     *
     * <p>A name whose path segments include {@code "."} or {@code ".."} is
     * refused rather than encoded, because this connector cannot express one.
     * {@code '.'} is unreserved and {@code '/'} is deliberately left alone, so
     * such a segment reaches okhttp as a dot segment, and okhttp resolves the
     * URL it parses -- removing the segment and, for {@code ".."}, the one
     * before it.  Escaping the dots does not help: okhttp reads {@code "%2E"}
     * as a dot for that resolution too, being hardened against exactly this
     * trick.  So the request left the container it addressed.  A key of
     * {@code "../evil.txt"} arrived at Swift as a container of the account to
     * create, and a key of {@code "../other/planted.txt"} wrote into a
     * container the request never named and the caller was never authorized
     * for -- answering the caller 200 while it did so.
     *
     * <p>The S3 API allows these keys, and the aws-s3, google-cloud-storage
     * and azureblob backends store them literally, so this refusal is a gap
     * in what this backend can hold rather than in what S3Proxy accepts.  It
     * is the same answer the nio2 stores give a key they cannot spell, and
     * the alternative is writing the object somewhere the caller did not ask
     * for.
     */
    private static String encodeName(String name) {
        var encoded = new StringBuilder(name.length() + 16);
        boolean firstSegment = true;
        for (String segment : Splitter.on('/').split(name)) {
            if (!firstSegment) {
                encoded.append('/');
            }
            firstSegment = false;
            if (segment.equals(".") || segment.equals("..")) {
                throw S3Exceptions.invalidArgument("The key must not contain" +
                        " a \"" + segment + "\" path segment, which this" +
                        " backend cannot address.");
            }
            encodeSegment(encoded, segment);
        }
        return encoded.toString();
    }

    /** Percent-encodes one path segment, which holds no {@code '/'}. */
    private static void encodeSegment(StringBuilder encoded, String segment) {
        for (byte rawByte : segment.getBytes(StandardCharsets.UTF_8)) {
            int c = rawByte & 0xFF;
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                    (c >= '0' && c <= '9') || c == '-' || c == '.' ||
                    c == '_' || c == '~') {
                encoded.append((char) c);
            } else {
                encoded.append('%');
                encoded.append(HEX[(c >> 4) & 0xF]);
                encoded.append(HEX[c & 0xF]);
            }
        }
    }

    /**
     * Escapes an underscore in a metadata name so Swift can store it.
     *
     * <p>S3 allows an underscore in a user-metadata name; Swift cannot see one.
     * WSGI, following CGI, folds both {@code '-'} and {@code '_'} in a header
     * name to {@code '_'} when it builds the environment key, leaving
     * {@code X-Object-Meta-a_b} and {@code X-Object-Meta-a-b} indistinguishable,
     * so Swift drops the ambiguous one outright -- silently, and along with
     * whatever it carried.  Percent-encoding the underscore gets it past that,
     * the same escape {@link #encodeName} already applies to object names.
     *
     * <p>Swift's own s3api middleware escapes it as {@code "=5F"} instead,
     * which this reads but deliberately does not write.  RFC 7230 builds a
     * header name out of tchar, which admits {@code '%'} and not {@code '='},
     * so {@code X-Object-Meta-a=5Fb} is not a well formed name at all: eventlet
     * takes it, which is how s3api gets away with the spelling, but nothing
     * obliges the next hop to -- a proxy, a load balancer, or Swift itself
     * under a stricter WSGI server may refuse the request outright.  Go's
     * parser does, with a 400, which is how this came to light.
     *
     * <p>What writing {@code "%5F"} costs is only that s3api shows a name
     * s3proxy wrote as {@code a%5Fb} rather than {@code a_b}.  Reading is
     * unaffected either way round, so an object s3api wrote still comes back
     * whole.  Do not trade a conformant request for that.
     */
    private static String encodeMetadataName(String name) {
        return name.replace("_", "%5F");
    }

    /**
     * Percent-encodes a value S3Proxy records for itself in a metadata
     * header.  A header carries ASCII and nothing else -- the HTTP client
     * refuses to write 0xE9 at all, and a stricter server would refuse the
     * request -- while an S3 key is any UTF-8 there is, so a key kept in a
     * header has to be spelled the way a URI spells one.
     *
     * <p>This is for S3Proxy's own values.  A caller's metadata rides
     * verbatim, as it does on S3, where encoding a value that needs it is
     * the caller's business.
     */
    private static String encodeMetadataValue(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    /**
     * Reverses {@link #encodeMetadataValue}, answering a value that was
     * never encoded unchanged: a marker written before this encoding existed
     * holds its key raw, and a raw key like {@code 50%-off.png} is not a
     * valid escape sequence.
     */
    private static String decodeMetadataValue(String value) {
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException iae) {
            return value;
        }
    }

    /**
     * Reverses {@link #encodeMetadataName} on an already-lowercased name, and
     * decodes s3api's spelling too so its objects read back correctly here.
     */
    private static String decodeMetadataName(String name) {
        return name.replace("%5f", "_").replace("=5f", "_");
    }

    /**
     * Applies {@link #encodeMetadataName} to every name in a metadata map.
     * Two names can encode alike -- "a_b" and a literal "a%5Fb" both become
     * "a%5Fb" -- so the map tolerates a collision and keeps the last, as Swift
     * would for two headers of one name, rather than failing the request.
     */
    private static Map<String, String> encodeMetadata(
            Map<String, String> metadata) {
        var encoded = new LinkedHashMap<String, String>(metadata.size());
        for (var entry : metadata.entrySet()) {
            encoded.put(encodeMetadataName(entry.getKey()), entry.getValue());
        }
        return encoded;
    }

    /**
     * Translate an openstack4j {@link ResponseException} into the exception the
     * s3proxy handler expects, or rethrow it unchanged.
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
        if (status == STATUS_NOT_FOUND) {
            if (key != null) {
                return S3Exceptions.noSuchKey(container, key, "", cause);
            }
            return S3Exceptions.noSuchBucket(container, "", cause);
        } else if (status == STATUS_UNAUTHORIZED || status == STATUS_FORBIDDEN) {
            // The fork has no AuthorizationException; a code-less 403 is
            // mapped to AccessDenied by the frontend.
            return S3Exceptions.fromStatusCode(STATUS_FORBIDDEN, cause);
        } else if (status == STATUS_PRECONDITION_FAILED ||
                status == STATUS_RANGE_NOT_SATISFIABLE) {
            return S3Exceptions.fromStatusCode(status, cause);
        } else if (status == 498) {
            // Swift's ratelimit middleware answers 498 unless configured
            // otherwise.  Passed on, it was a 500 InternalError; S3's
            // SlowDown tells the client to back off.
            return S3Exceptions.slowDown(cause);
        } else if (status == 422) {
            // Swift's answer to a body that does not hash to its ETag
            return S3Exceptions.badDigest(cause);
        }
        // The rest by status: a 400, say, for user metadata past Swift's
        // limits, which are narrower than S3's, was a 500 InternalError.
        RuntimeException translated = S3Exceptions.fromBackendStatus(status,
                cause);
        if (translated != null) {
            return translated;
        }
        if (cause instanceof RuntimeException runtime) {
            return runtime;
        }
        return new RuntimeException(cause);
    }

    private static String maybeQuoteETag(String eTag) {
        if (!eTag.startsWith("\"") && !eTag.endsWith("\"")) {
            eTag = "\"" + eTag + "\"";
        }
        return eTag;
    }
}
