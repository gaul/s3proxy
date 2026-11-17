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
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Random;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.gaul.s3proxy.auth.AuthenticationType;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Signature Version 2 requests signed here by the specification, since no
 * current SDK signs them: the two places the string to sign was built
 * differently from what the specification's text describes.
 */
public final class SignatureV2CanonicalizationTest {
    private static final String IDENTITY = "identity";
    private static final String CREDENTIAL = "credential";

    private S3Proxy s3Proxy;
    private String bucket;
    private String baseUri;
    private final HttpClient httpClient = HttpClient.newHttpClient();

    @BeforeEach
    public void setUp() throws Exception {
        BlobStore blobStore = TestUtils.createTransientBlobStore();
        bucket = "bucket-" + new Random().nextInt(Integer.MAX_VALUE);
        blobStore.createContainer(bucket);

        s3Proxy = S3Proxy.builder()
                .stopTimeout(0)
                .blobStore(blobStore)
                .awsAuthentication(AuthenticationType.AWS_V2, IDENTITY,
                        CREDENTIAL)
                .endpoint(URI.create("http://127.0.0.1:0"))
                .build();
        s3Proxy.start();
        while (!s3Proxy.getState().equals("STARTED")) {
            Thread.sleep(10);
        }
        baseUri = "http://127.0.0.1:" + s3Proxy.getPort();
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
    }

    /**
     * With x-amz-date present the Date is signed as the empty string and
     * x-amz-date among the headers.
     */
    @Test
    public void testDateAndAmzDate() throws Exception {
        String date = now();
        String path = "/" + bucket + "/key";
        String stringToSign = "PUT\n\n\n\nx-amz-date:" + date + "\n" + path;
        assertThat(put(path, stringToSign, "Date", date, "x-amz-date", date)
                .statusCode()).isEqualTo(200);
    }

    /**
     * The form of the specification's DELETE example, which signs the
     * x-amz-date value in the Date's place, stays accepted.
     */
    @Test
    public void testDateAndAmzDateAsTheExampleSignsThem() throws Exception {
        String date = now();
        String path = "/" + bucket + "/key";
        String stringToSign = "PUT\n\n\n" + date + "\n" + path;
        assertThat(put(path, stringToSign, "Date", date, "x-amz-date", date)
                .statusCode()).isEqualTo(200);
    }

    /** A header sent twice is one line, its values in order of arrival. */
    @Test
    public void testRepeatedAmzHeader() throws Exception {
        String date = now();
        String path = "/" + bucket + "/key";
        String stringToSign = "PUT\n\n\n" + date + "\n" +
                "x-amz-meta-name:second,first\n" + path;
        assertThat(put(path, stringToSign, "Date", date,
                "x-amz-meta-name", "second", "x-amz-meta-name", "first")
                .statusCode()).isEqualTo(200);
    }

    @Test
    public void testWrongSignatureIsRefused() throws Exception {
        String date = now();
        String path = "/" + bucket + "/key";
        var response = put(path, "not what the request says", "Date", date);
        assertThat(response.statusCode()).isEqualTo(403);
        assertThat(response.body()).contains("SignatureDoesNotMatch");
    }

    private static String now() {
        return DateTimeFormatter.RFC_1123_DATE_TIME.format(
                ZonedDateTime.now(ZoneOffset.UTC));
    }

    private HttpResponse<String> put(String path, String stringToSign,
            String... headers) throws Exception {
        var mac = Mac.getInstance("HmacSHA1");
        mac.init(new SecretKeySpec(CREDENTIAL.getBytes(
                StandardCharsets.UTF_8), "HmacSHA1"));
        String signature = Base64.getEncoder().encodeToString(mac.doFinal(
                stringToSign.getBytes(StandardCharsets.UTF_8)));
        return httpClient.send(
                HttpRequest.newBuilder(URI.create(baseUri + path))
                        .headers(headers)
                        .header("Authorization",
                                "AWS " + IDENTITY + ":" + signature)
                        .PUT(HttpRequest.BodyPublishers.noBody())
                        .build(),
                HttpResponse.BodyHandlers.ofString());
    }
}
