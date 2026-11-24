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

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Properties;

import org.gaul.s3proxy.auth.AuthenticationType;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.middleware.Middlewares;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * A store that keeps the parts of an upload answers a completion with the
 * checksum of what was uploaded, whatever the request says the parts hash
 * to.  A middleware that renames the upload's key or encrypts what is stored
 * stands between the handler and those parts, so the handler has to read
 * them back through it.  Reading them by a name built from the client's key
 * instead found nothing there, and the request was taken at its word.
 */
public final class MultipartChecksumMiddlewareTest {
    private static final String CONTAINER = "container";
    /**
     * Not the first part: the encrypting middleware records the part number
     * beside the ciphertext, and a part read back on its own must decrypt
     * whichever number that is.
     */
    private static final int PART_NUMBER = 2;
    private static final byte[] UPLOADED =
            "what was uploaded".getBytes(StandardCharsets.UTF_8);
    private static final byte[] CLAIMED =
            "what the completion claims".getBytes(StandardCharsets.UTF_8);

    private @Nullable S3Proxy s3Proxy;
    private final HttpClient httpClient = HttpClient.newHttpClient();

    @AfterEach
    public void tearDown() throws Exception {
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
    }

    @Test
    public void testNoMiddleware() throws Exception {
        assertChecksumIsOfUploadedContent(new Properties(), "object");
    }

    @Test
    public void testAliasBlobStore() throws Exception {
        var properties = new Properties();
        properties.setProperty(S3ProxyConstants.PROPERTY_ALIAS_BLOBSTORE +
                "." + CONTAINER, "backend-container");
        assertChecksumIsOfUploadedContent(properties, "object");
    }

    @Test
    public void testPrefixBlobStore() throws Exception {
        assertChecksumIsOfUploadedContent(prefixProperties(), "object");
    }

    @Test
    public void testRegexBlobStore() throws Exception {
        var properties = new Properties();
        properties.setProperty(S3ProxyConstants.PROPERTY_REGEX_BLOBSTORE +
                "." + S3ProxyConstants.PROPERTY_REGEX_BLOBSTORE_MATCH +
                ".rule", "^from/(.*)$");
        properties.setProperty(S3ProxyConstants.PROPERTY_REGEX_BLOBSTORE +
                "." + S3ProxyConstants.PROPERTY_REGEX_BLOBSTORE_REPLACE +
                ".rule", "to/$1");
        assertChecksumIsOfUploadedContent(properties, "from/object");
    }

    @Test
    public void testEncryptedBlobStore() throws Exception {
        var properties = new Properties();
        properties.setProperty(
                S3ProxyConstants.PROPERTY_ENCRYPTED_BLOBSTORE, "true");
        properties.setProperty(
                S3ProxyConstants.PROPERTY_ENCRYPTED_BLOBSTORE_PASSWORD,
                "password");
        properties.setProperty(
                S3ProxyConstants.PROPERTY_ENCRYPTED_BLOBSTORE_SALT, "salt");
        assertChecksumIsOfUploadedContent(properties, "object");
    }

    /**
     * Behind a prefix the name a part is stored under at the root of the
     * bucket is, one prefix further in, a key like any other.  An object a
     * client writes there is not a part of the upload and must not be hashed
     * as one.
     */
    @Test
    public void testObjectNamedLikePartIsNotThePart() throws Exception {
        String bucketUri = startProxy(prefixProperties());
        String uri = bucketUri + "/object";
        String uploadId = initiate(uri);
        String eTag = uploadPart(uri, uploadId);

        send(HttpRequest.newBuilder(URI.create(bucketUri + "/.mpus-" +
                uploadId + "-object-" + PART_NUMBER))
                .header("Content-Type", "application/octet-stream")
                .PUT(HttpRequest.BodyPublishers.ofByteArray(CLAIMED)));

        HttpResponse<String> response = complete(uri, uploadId, eTag,
                digest(UPLOADED), composite(UPLOADED));
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).contains("<ChecksumSHA256>" +
                composite(UPLOADED) + "</ChecksumSHA256>");
    }

    private static Properties prefixProperties() {
        var properties = new Properties();
        properties.setProperty(S3ProxyConstants.PROPERTY_PREFIX_BLOBSTORE +
                "." + CONTAINER, "prefix/");
        return properties;
    }

    private void assertChecksumIsOfUploadedContent(Properties properties,
            String key) throws Exception {
        String uri = startProxy(properties) + "/" + key;

        // The truth is accepted, and is what the object then reports.
        HttpResponse<String> response = uploadAndComplete(uri,
                digest(UPLOADED), composite(UPLOADED));
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).contains("<ChecksumSHA256>" +
                composite(UPLOADED) + "</ChecksumSHA256>");

        // A claim about the part that is not the part's is refused, as a
        // wrong ETag is, rather than reported or ignored.
        response = uploadAndComplete(uri, digest(CLAIMED),
                /*objectChecksum=*/ null);
        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.body()).contains("InvalidPart");

        // So is one that comes with the object checksum to match it.
        response = uploadAndComplete(uri, digest(CLAIMED),
                composite(CLAIMED));
        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.body()).contains("InvalidPart");
    }

    /**
     * Starts a proxy over a transient store behind the middlewares that
     * {@code properties} configure, and answers the URI of its bucket.
     */
    private String startProxy(Properties properties) throws Exception {
        BlobStore blobStore = Middlewares.wrap(
                TestUtils.createTransientBlobStore(), properties,
                unused -> {
                    throw new AssertionError("no second backend");
                });
        blobStore.createContainer(CONTAINER);

        s3Proxy = S3Proxy.builder()
                .stopTimeout(0)
                .blobStore(blobStore)
                .awsAuthentication(AuthenticationType.NONE, "identity",
                        "credential")
                .endpoint(URI.create("http://127.0.0.1:0"))
                .build();
        s3Proxy.start();
        while (!s3Proxy.getState().equals("STARTED")) {
            Thread.sleep(10);
        }
        return "http://127.0.0.1:" + s3Proxy.getPort() + "/" + CONTAINER;
    }

    /**
     * Uploads {@link #UPLOADED} as the only part of an upload and completes
     * it, asserting {@code partChecksum} for the part and, when it is not
     * null, {@code objectChecksum} for the object.
     */
    private HttpResponse<String> uploadAndComplete(String uri,
            String partChecksum, @Nullable String objectChecksum)
            throws Exception {
        String uploadId = initiate(uri);
        return complete(uri, uploadId, uploadPart(uri, uploadId),
                partChecksum, objectChecksum);
    }

    /** Creates a SHA256 upload and answers its id. */
    private String initiate(String uri) throws Exception {
        var initiate = send(HttpRequest.newBuilder(URI.create(uri + "?uploads"))
                .header("Content-Type", "application/octet-stream")
                .header("x-amz-checksum-algorithm", "SHA256")
                .POST(HttpRequest.BodyPublishers.noBody()));
        assertThat(initiate.statusCode()).isEqualTo(200);
        String body = initiate.body();
        int start = body.indexOf("<UploadId>") + "<UploadId>".length();
        return body.substring(start, body.indexOf("</UploadId>", start));
    }

    /** Uploads {@link #UPLOADED} as the part and answers its ETag. */
    private String uploadPart(String uri, String uploadId) throws Exception {
        var part = send(HttpRequest.newBuilder(URI.create(uri +
                "?partNumber=" + PART_NUMBER + "&uploadId=" + uploadId))
                .header("Content-Type", "application/octet-stream")
                .PUT(HttpRequest.BodyPublishers.ofByteArray(UPLOADED)));
        assertThat(part.statusCode()).isEqualTo(200);
        return part.headers().firstValue("ETag").orElseThrow();
    }

    private HttpResponse<String> complete(String uri, String uploadId,
            String eTag, String partChecksum,
            @Nullable String objectChecksum) throws Exception {
        var builder = HttpRequest.newBuilder(URI.create(uri + "?uploadId=" +
                uploadId))
                .header("Content-Type", "application/xml")
                .POST(HttpRequest.BodyPublishers.ofString(
                        "<CompleteMultipartUpload><Part>" +
                        "<PartNumber>" + PART_NUMBER + "</PartNumber>" +
                        "<ETag>" + eTag + "</ETag>" +
                        "<ChecksumSHA256>" + partChecksum +
                        "</ChecksumSHA256></Part>" +
                        "</CompleteMultipartUpload>"));
        if (objectChecksum != null) {
            builder.header("x-amz-checksum-sha256", objectChecksum);
        }
        return send(builder);
    }

    /** The base64 SHA-256 of one part. */
    private static String digest(byte[] content) throws Exception {
        return Base64.getEncoder().encodeToString(sha256(content));
    }

    /** S3's composite checksum of an object made of that one part. */
    private static String composite(byte[] content) throws Exception {
        return Base64.getEncoder().encodeToString(sha256(sha256(content))) +
                "-1";
    }

    private static byte[] sha256(byte[] content) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(content);
    }

    private HttpResponse<String> send(HttpRequest.Builder builder)
            throws Exception {
        return httpClient.send(builder.build(),
                HttpResponse.BodyHandlers.ofString());
    }
}
