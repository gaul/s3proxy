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
import java.util.Properties;

import org.gaul.s3proxy.auth.AuthenticationType;
import org.gaul.s3proxy.blobstore.BlobStore;
import org.gaul.s3proxy.middleware.EncryptedBlobStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.BucketCannedACL;

/**
 * A form POST is the one write whose key does not come from the URI, where
 * an empty key is the bucket, so it is the one write that can ask for an
 * empty key.  A store refuses that name, but the encrypting middleware appends
 * ".s3enc" first and the store is handed a name it accepts.  The object was
 * then listed under the empty key, which neither DeleteObject nor
 * DeleteObjects can name, so its bucket could never be emptied or deleted.
 */
public final class PostObjectEmptyKeyTest {
    private static final String BOUNDARY = "----------s3proxytest";

    private final HttpClient httpClient = HttpClient.newHttpClient();
    private S3Proxy s3Proxy;
    private BlobStore backing;
    private String containerName;
    private String bucketUri;

    @BeforeEach
    public void setUp() throws Exception {
        backing = TestUtils.createTransientBlobStore();
        containerName = TestUtils.createRandomContainerName();
        backing.createContainer(containerName);
        // Anyone may write, so nothing but the key stands in a form's way.
        backing.setContainerAccess(containerName,
                BucketCannedACL.PUBLIC_READ_WRITE);
        var properties = new Properties();
        properties.setProperty(
                S3ProxyConstants.PROPERTY_ENCRYPTED_BLOBSTORE_PASSWORD,
                "password");
        properties.setProperty(
                S3ProxyConstants.PROPERTY_ENCRYPTED_BLOBSTORE_SALT, "salt");

        s3Proxy = S3Proxy.builder()
                .stopTimeout(0)
                .blobStore(EncryptedBlobStore.newEncryptedBlobStore(backing,
                        properties))
                .awsAuthentication(AuthenticationType.AWS_V2_OR_V4,
                        "identity", "credential")
                .endpoint(URI.create("http://127.0.0.1:0"))
                .build();
        s3Proxy.start();
        while (!s3Proxy.getState().equals("STARTED")) {
            Thread.sleep(10);
        }
        bucketUri = "http://127.0.0.1:" + s3Proxy.getPort() + "/" +
                containerName;
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
    }

    /** The control: the same form with a key is stored. */
    @Test
    public void testNamedKeyIsStored() throws Exception {
        assertThat(post("note", "payload.txt").statusCode()).isEqualTo(204);
        assertThat(backing.list(containerName).contents()).hasSize(1);
    }

    @Test
    public void testEmptyKeyIsNotStored() throws Exception {
        HttpResponse<String> response = post("", "payload.txt");
        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.body()).contains("<Code>InvalidArgument</Code>");
        assertThat(backing.list(containerName).contents()).isEmpty();
    }

    /** The key is judged after ${filename} is replaced, not before. */
    @Test
    public void testEmptyFilenameSubstitutionIsNotStored() throws Exception {
        HttpResponse<String> response = post("${filename}", "");
        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.body()).contains("<Code>InvalidArgument</Code>");
        assertThat(backing.list(containerName).contents()).isEmpty();
    }

    /** An unsigned form with a key field and a file part, and nothing else. */
    private HttpResponse<String> post(String key, String fileName)
            throws Exception {
        String form = "--" + BOUNDARY + "\r\nContent-Disposition: form-data;" +
                " name=\"key\"\r\n\r\n" + key + "\r\n" +
                "--" + BOUNDARY + "\r\nContent-Disposition: form-data;" +
                " name=\"file\"; filename=\"" + fileName + "\"\r\n\r\n" +
                "bar\r\n" +
                "--" + BOUNDARY + "--\r\n";
        return httpClient.send(HttpRequest.newBuilder(URI.create(bucketUri))
                .header("Content-Type",
                        "multipart/form-data; boundary=" + BOUNDARY)
                .POST(HttpRequest.BodyPublishers.ofString(form))
                .build(), HttpResponse.BodyHandlers.ofString());
    }
}
