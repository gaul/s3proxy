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
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Random;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.google.common.io.ByteSource;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * A V2 signature covers only the query parameters named in the canonicalized
 * resource, so one left out rides along uncovered: the signature verifies
 * without it, yet the dispatcher still branches on it.  That is the V2 face
 * of the unsigned x-amz-* header flaw -- a signature good for one operation
 * made good for another -- and it reaches the parameters that select an
 * operation and postdate SigV2: "?attributes" and "?encryption", and the
 * object-lock and bucket access subresources.  Signing them turns the
 * injection into a signature mismatch while a URL that signed the parameter
 * still performs the operation it named.
 */
public final class V2SubresourceInjectionTest {
    private static final String CONTENT = "the-object-body";
    private static final String KEY = "object";

    private S3Proxy s3Proxy;
    private BlobStore blobStore;
    private String container;
    private String identity;
    private String credential;
    private String baseUri;
    private final HttpClient httpClient = HttpClient.newHttpClient();

    @BeforeEach
    public void setUp() throws Exception {
        TestUtils.S3ProxyLaunchInfo info = TestUtils.startS3Proxy(
                "s3proxy.conf");
        s3Proxy = info.getS3Proxy();
        blobStore = info.getBlobStore();
        identity = info.getS3Identity();
        credential = info.getS3Credential();
        baseUri = "http://" + info.getEndpoint().getHost() + ":" +
                s3Proxy.getPort();

        container = "container-" + new Random().nextInt(Integer.MAX_VALUE);
        blobStore.createContainer(container);
        TestUtils.putBlob(blobStore, container, KEY,
                ByteSource.wrap(CONTENT.getBytes(StandardCharsets.UTF_8)));
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
        if (blobStore != null && container != null) {
            blobStore.removeBlob(container, KEY);
            blobStore.deleteContainer(container);
        }
    }

    /** The control: a URL used as signed still fetches its one object. */
    @Test
    public void testSignedGetObjectSucceeds() throws Exception {
        HttpResponse<String> response = get(presign(
                "/" + container + "/" + KEY, /*subresource=*/ null));
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).isEqualTo(CONTENT);
    }

    /**
     * A URL signed to read an object, replayed with "?attributes" appended,
     * would answer GetObjectAttributes instead of the object it named.
     */
    @Test
    public void testAttributesInjectionRejected() throws Exception {
        HttpResponse<String> response = get(presign(
                "/" + container + "/" + KEY, /*subresource=*/ null) +
                "&attributes");
        System.err.println("attributes injection: " + response.statusCode() +
                " " + response.body());
        assertThat(response.statusCode()).isEqualTo(403);
        assertThat(response.body()).contains("SignatureDoesNotMatch");
    }

    /**
     * Signed rather than injected, the same subresource passes the signature
     * check and reaches GetObjectAttributes, which then answers on its own
     * terms -- a 400 here, since this request names no
     * x-amz-object-attributes.  That it is no longer refused as unsigned is
     * the whole of the claim.
     */
    @Test
    public void testSignedAttributesNotRefusedAsUnsigned() throws Exception {
        HttpResponse<String> response = get(presign(
                "/" + container + "/" + KEY, "attributes") + "&attributes");
        assertThat(response.body()).doesNotContain("SignatureDoesNotMatch");
    }

    /**
     * The same injection at the bucket level: a URL signed to list a bucket
     * would answer GetBucketEncryption instead.
     */
    @Test
    public void testEncryptionInjectionRejected() throws Exception {
        HttpResponse<String> response = get(presign(
                "/" + container, /*subresource=*/ null) + "&encryption");
        System.err.println("encryption injection: " + response.statusCode() +
                " " + response.body());
        assertThat(response.statusCode()).isEqualTo(403);
        assertThat(response.body()).contains("SignatureDoesNotMatch");
    }

    /**
     * Signed, the subresource passes the signature check.  Whether the
     * backing store has an encryption configuration to report is beside the
     * point; that it is no longer refused as unsigned is.
     */
    @Test
    public void testSignedEncryptionNotRefusedAsUnsigned() throws Exception {
        HttpResponse<String> response = get(presign(
                "/" + container, "encryption") + "&encryption");
        assertThat(response.body()).doesNotContain("SignatureDoesNotMatch");
    }

    /**
     * The subresources that select an object-lock or bucket access
     * operation, injected into URLs signed to upload an object or to write a
     * bucket.  Unsigned, they reached the store with a body of the holder's
     * choosing: a COMPLIANCE retention or a legal hold on the object, a
     * default retention for the bucket, its public access block lifted, its
     * object ownership changed.  Only the aws-s3-sdk backend implements
     * these, so the transient store here answers a signed one 501; what
     * matters is that an injected one is refused before it gets that far.
     */
    @Test
    public void testObjectLockAndAccessInjectionRejected() throws Exception {
        String object = "/" + container + "/" + KEY;
        String bucket = "/" + container;
        for (String[] target : new String[][] {
                {object, "retention"},
                {object, "legal-hold"},
                {bucket, "object-lock"},
                {bucket, "publicAccessBlock"},
                {bucket, "ownershipControls"}}) {
            String path = target[0];
            String subresource = target[1];
            HttpResponse<String> response = put(presign("PUT", path,
                    /*subresource=*/ null) + "&" + subresource);
            assertThat(response.statusCode()).as(subresource).isEqualTo(403);
            assertThat(response.body()).as(subresource)
                    .contains("SignatureDoesNotMatch");

            response = put(presign("PUT", path, subresource) + "&" +
                    subresource);
            assertThat(response.body()).as(subresource)
                    .doesNotContain("SignatureDoesNotMatch");
        }
        assertThat(get(presign(object, /*subresource=*/ null)).body())
                .isEqualTo(CONTENT);
    }

    /**
     * V2 signs subresource values decoded and unescaped, so a value may not
     * spell out another subresource: folding uploadId into partNumber drops
     * the parameter without changing the string to sign, and a URL signed to
     * upload one part would replace the finished object instead.
     */
    @Test
    public void testUploadPartUrlCannotPutObject() throws Exception {
        String path = "/" + container + "/" + KEY;
        HttpResponse<String> response = httpClient.send(
                HttpRequest.newBuilder(URI.create(
                        presign("POST", path, "uploads") + "&uploads"))
                        .POST(HttpRequest.BodyPublishers.noBody())
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(200);
        String body = response.body();
        String uploadId = body.substring(
                body.indexOf("<UploadId>") + "<UploadId>".length(),
                body.indexOf("</UploadId>"));

        String url = presign("PUT", path,
                "partNumber=1&uploadId=" + uploadId);
        response = put(url + "&partNumber=1&uploadId=" + uploadId);
        assertThat(response.statusCode()).isEqualTo(200);

        response = put(url + "&partNumber=1%26uploadId%3D" + uploadId);
        assertThat(response.statusCode()).isEqualTo(403);

        response = get(presign(path, /*subresource=*/ null));
        assertThat(response.body()).isEqualTo(CONTENT);

        response = httpClient.send(
                HttpRequest.newBuilder(URI.create(
                        presign("DELETE", path, "uploadId=" + uploadId) +
                        "&uploadId=" + uploadId))
                        .DELETE().build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(204);
    }

    /** The same folding between two subresources of a GetObject. */
    @Test
    public void testFoldedSubresourceRejected() throws Exception {
        String url = presign("/" + container + "/" + KEY,
                "response-content-language=en" +
                "&response-content-type=text/plain");
        HttpResponse<String> response = get(url +
                "&response-content-language=en" +
                "&response-content-type=text/plain");
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.headers().firstValue("Content-Type"))
                .hasValue("text/plain");

        response = get(url + "&response-content-language=" +
                "en%26response-content-type%3Dtext/plain");
        assertThat(response.statusCode()).isEqualTo(403);
    }

    /**
     * An ampersand that introduces no signed subresource has only one reading
     * and keeps working.
     */
    @Test
    public void testAmpersandInSubresourceValueAccepted() throws Exception {
        HttpResponse<String> response = get(presign(
                "/" + container + "/" + KEY,
                "response-content-disposition=attachment; filename=\"a&b\"") +
                "&response-content-disposition=" +
                "attachment%3B%20filename%3D%22a%26b%22");
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.headers().firstValue("Content-Disposition"))
                .hasValue("attachment; filename=\"a&b\"");
    }

    /**
     * A V2 presigned GET, signing the given path and, when named, the
     * subresources alongside it -- the canonicalized resource S3Proxy builds
     * for a query-authenticated request.
     */
    private String presign(String path, String subresource) throws Exception {
        return presign("GET", path, subresource);
    }

    private String presign(String method, String path, String subresource)
            throws Exception {
        long expires = System.currentTimeMillis() / 1000 + 3600;
        String resource = subresource == null ? path :
                path + "?" + subresource;
        String stringToSign = String.join("\n",
                method, "", "", Long.toString(expires), resource);
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(new SecretKeySpec(credential.getBytes(
                StandardCharsets.UTF_8), "HmacSHA1"));
        String signature = Base64.getEncoder().encodeToString(mac.doFinal(
                stringToSign.getBytes(StandardCharsets.UTF_8)));
        return baseUri + path +
                "?AWSAccessKeyId=" + URLEncoder.encode(identity,
                        StandardCharsets.UTF_8) +
                "&Expires=" + expires +
                "&Signature=" + URLEncoder.encode(signature,
                        StandardCharsets.UTF_8);
    }

    private HttpResponse<String> get(String url) throws Exception {
        return httpClient.send(
                HttpRequest.newBuilder(URI.create(url)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> put(String url) throws Exception {
        return httpClient.send(
                HttpRequest.newBuilder(URI.create(url))
                        .PUT(HttpRequest.BodyPublishers.ofString("replaced"))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
    }
}
