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
import static org.junit.Assume.assumeTrue;

import java.io.IOException;
import java.net.CookieManager;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.sshd.common.file.virtualfs.VirtualFileSystemFactory;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.sftp.server.SftpSubsystemFactory;
import org.gaul.s3proxy.sftp.SftpBlobStoreApiMetadata;
import org.jclouds.Constants;
import org.jclouds.ContextBuilder;
import org.jclouds.blobstore.BlobStoreContext;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.checksums.RequestChecksumCalculation;
import software.amazon.awssdk.core.checksums.ResponseChecksumValidation;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.S3Configuration;

public final class LocalS3BackupClientSmokeTest {
    private static final String SFTP_USER = "sftp-user";
    private static final String SFTP_PASSWORD = "sftp-password";
    private static final String S3_IDENTITY = "local-identity";
    private static final String S3_CREDENTIAL = "local-credential";
    private static final String BUCKET = "s3-backup-smoke";
    private static final String DEFAULT_APP_BASE_URL = "https://localhost:8443";
    private static final String DEFAULT_CSRF_PATH = "/api/public/csrf";
    private static final String DEFAULT_S3PROXY_BIND_HOST = "127.0.0.1";
    private static final String DEFAULT_S3PROXY_ADVERTISED_HOST =
            "127.0.0.1";
    private static final Pattern CSRF_TOKEN = Pattern.compile(
            "\"token\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern CSRF_PARAMETER = Pattern.compile(
            "\"parameterName\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern CSRF_HEADER = Pattern.compile(
            "\"headerName\"\\s*:\\s*\"([^\"]+)\"");

    private SshServer sshServer;
    private BlobStoreContext context;
    private S3Proxy s3Proxy;
    private S3AsyncClient s3Client;
    private URI s3Endpoint;
    private String s3Identity;
    private String s3Credential;
    private String bucketName;

    @Before
    public void setUp() throws Exception {
        assumeTrue("set S3PROXY_SMOKE_APP_USERNAME and " +
                "S3PROXY_SMOKE_APP_PASSWORD to run the local smoke test",
                requiredSetting("app.username").isPresent() &&
                requiredSetting("app.password").isPresent());

        s3Identity = setting("s3.identity", S3_IDENTITY);
        s3Credential = setting("s3.credential", S3_CREDENTIAL);
        bucketName = setting("s3.bucket", BUCKET);
        var externalEndpoint = requiredSetting("s3.externalEndpoint");
        if (externalEndpoint.isPresent()) {
            s3Endpoint = URI.create(externalEndpoint.orElseThrow());
            if (booleanSetting("s3.manageBucket", false)) {
                s3Client = buildS3Client(s3Endpoint, s3Identity, s3Credential);
                get(s3Client.createBucket(request -> request.bucket(bucketName)));
            }
            return;
        }

        var s3ProxyBindHost = setting("s3proxy.bindHost",
                DEFAULT_S3PROXY_BIND_HOST);
        var s3ProxyBindPort = intSetting("s3proxy.bindPort", 0);
        var s3ProxyAdvertisedHost = setting("s3proxy.advertisedHost",
                DEFAULT_S3PROXY_ADVERTISED_HOST);
        var s3ProxyAdvertisedPort = intSetting("s3proxy.advertisedPort",
                s3ProxyBindPort);

        var sftpRoot = Files.createTempDirectory("s3proxy-sftp-smoke-root");
        sshServer = SshServer.setUpDefaultServer();
        sshServer.setHost("127.0.0.1");
        sshServer.setPort(0);
        sshServer.setKeyPairProvider(new SimpleGeneratorHostKeyProvider(
                Files.createTempFile("s3proxy-sftp-smoke-hostkey", ".ser")));
        sshServer.setPasswordAuthenticator((username, password, session) ->
                SFTP_USER.equals(username) && SFTP_PASSWORD.equals(password));
        sshServer.setFileSystemFactory(new VirtualFileSystemFactory(sftpRoot));
        sshServer.setSubsystemFactories(List.of(
                new SftpSubsystemFactory.Builder().build()));
        sshServer.start();

        var properties = new Properties();
        properties.setProperty(Constants.PROPERTY_ENDPOINT,
                "sftp://127.0.0.1:" + sshServer.getPort() + "/");
        properties.setProperty(SftpBlobStoreApiMetadata.BASEDIR, "/");
        context = ContextBuilder.newBuilder("sftp")
                .credentials(SFTP_USER, SFTP_PASSWORD)
                .overrides(properties)
                .build(BlobStoreContext.class);

        s3Proxy = S3Proxy.builder()
                .endpoint(URI.create("http://" + s3ProxyBindHost + ":" +
                        s3ProxyBindPort))
                .awsAuthentication(AuthenticationType.AWS_V2_OR_V4,
                        S3_IDENTITY, S3_CREDENTIAL)
                .blobStore(context.getBlobStore())
                .ignoreUnknownHeaders(true)
                .build();
        s3Proxy.start();
        if (s3ProxyAdvertisedPort == 0) {
            s3ProxyAdvertisedPort = s3Proxy.getPort();
        }
        s3Endpoint = URI.create("http://" + s3ProxyAdvertisedHost + ":" +
                s3ProxyAdvertisedPort);

        s3Client = buildS3Client(s3Endpoint, s3Identity, s3Credential);
        get(s3Client.createBucket(request -> request.bucket(bucketName)));
    }

    @After
    public void tearDown() throws Exception {
        if (s3Client != null) {
            try {
                get(s3Client.deleteBucket(request -> request.bucket(bucketName)));
            } catch (Exception ignored) {
                // Best effort cleanup after a failed smoke.
            }
            s3Client.close();
        }
        if (s3Proxy != null) {
            s3Proxy.stop();
        }
        if (context != null) {
            context.close();
        }
        if (sshServer != null) {
            sshServer.stop();
        }
    }

    @Test
    public void testLocalApplicationS3BackupConnectivity() throws Exception {
        var client = appHttpClient();
        var baseUrl = setting("app.baseUrl", DEFAULT_APP_BASE_URL);
        var csrfPath = setting("app.csrfPath", DEFAULT_CSRF_PATH);
        var loginPath = setting("app.loginPath", "/login");
        var testPath = setting("app.s3TestPath",
                "/api/backup-settings?storageType=S3&action=test");
        var savePath = setting("app.s3SavePath",
                "/api/backup-settings/storage?storageType=S3");
        var saveMethod = setting("app.s3SaveMethod", "PATCH");
        var persistSettings = booleanSetting("app.persistSettings", false);

        var loginCsrf = fetchCsrf(client, baseUrl, csrfPath);
        login(client, baseUrl, loginPath, loginCsrf);
        var csrf = fetchCsrf(client, baseUrl, csrfPath);

        var body = """
                {
                  "accessKey": "%s",
                  "secretKey": "%s",
                  "bucketName": "%s",
                  "serviceEndpoint": "%s",
                  "disableChecksumValidation": true
                }
                """.formatted(s3Identity, s3Credential, bucketName, s3Endpoint);

        var response = client.send(HttpRequest.newBuilder(resolve(baseUrl,
                        testPath))
                .header("Content-Type", "application/json")
                .header(csrf.headerName(), csrf.token())
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build(), HttpResponse.BodyHandlers.ofString());

        assertThat(response.statusCode()).as(response.body()).isBetween(200, 299);
        assertThat(response.body()).doesNotContain("\"error\"");

        if (!persistSettings) {
            return;
        }

        var saveBody = """
                {
                  "serviceEndpoint": "%s",
                  "disableSslValidation": false,
                  "disableChecksumValidation": false,
                  "certificate": null,
                  "bucketName": "%s",
                  "accessKey": "%s",
                  "secretKey": "%s",
                  "writeOnly": false
                }
                """.formatted(s3Endpoint, bucketName, s3Identity, s3Credential);
        var saveRequest = HttpRequest.newBuilder(resolve(baseUrl, savePath))
                .header("Content-Type", "application/json")
                .header(csrf.headerName(), csrf.token())
                .method(saveMethod, HttpRequest.BodyPublishers.ofString(saveBody))
                .build();
        var saveResponse = client.send(saveRequest,
                HttpResponse.BodyHandlers.ofString());
        assertThat(saveResponse.statusCode()).as(saveResponse.body())
                .isBetween(200, 299);
    }

    private static SmokeCsrf fetchCsrf(HttpClient client, String baseUrl,
            String csrfPath) throws IOException, InterruptedException {
        var response = client.send(HttpRequest.newBuilder(resolve(baseUrl,
                        csrfPath))
                .GET()
                .build(), HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isBetween(200, 299);
        return new SmokeCsrf(
                match(response.body(), CSRF_PARAMETER),
                match(response.body(), CSRF_TOKEN),
                match(response.body(), CSRF_HEADER));
    }

    private static void login(HttpClient client, String baseUrl,
            String loginPath, SmokeCsrf csrf)
            throws IOException, InterruptedException {
        var username = requiredSetting("app.username").orElseThrow();
        var password = requiredSetting("app.password").orElseThrow();
        var form = csrf.parameterName() + "=" + encode(csrf.token()) +
                "&username=" + encode(username) +
                "&password=" + encode(password);
        var response = client.send(HttpRequest.newBuilder(resolve(baseUrl,
                        loginPath))
                .header(csrf.headerName(), csrf.token())
                .header("Content-Type",
                        "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form))
                .build(), HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isBetween(200, 399);
    }

    private static HttpClient appHttpClient()
            throws NoSuchAlgorithmException, KeyManagementException {
        var cookieManager = new CookieManager();
        return HttpClient.newBuilder()
                .cookieHandler(cookieManager)
                .followRedirects(HttpClient.Redirect.NORMAL)
                .sslContext(trustAllSslContext())
                .build();
    }

    private static SSLContext trustAllSslContext()
            throws NoSuchAlgorithmException, KeyManagementException {
        var trustManager = new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain,
                    String authType) {
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain,
                    String authType) {
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        };
        var context = SSLContext.getInstance("TLS");
        context.init(null, new TrustManager[] {trustManager},
                new SecureRandom());
        return context;
    }

    private static URI resolve(String baseUrl, String path) {
        return URI.create(baseUrl).resolve(path);
    }

    private static String match(String body, Pattern pattern) {
        var matcher = pattern.matcher(body);
        assertThat(matcher.find()).isTrue();
        return matcher.group(1);
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static String setting(String key, String defaultValue) {
        return requiredSetting(key).orElse(defaultValue);
    }

    private static int intSetting(String key, int defaultValue) {
        return requiredSetting(key).map(Integer::parseInt)
                .orElse(defaultValue);
    }

    private static boolean booleanSetting(String key, boolean defaultValue) {
        return requiredSetting(key).map(Boolean::parseBoolean)
                .orElse(defaultValue);
    }

    private static java.util.Optional<String> requiredSetting(String key) {
        var systemProperty = System.getProperty("s3proxy.smoke." + key);
        if (systemProperty != null && !systemProperty.isBlank()) {
            return java.util.Optional.of(systemProperty);
        }
        var envName = "S3PROXY_SMOKE_" + key.replace('.', '_')
                .toUpperCase(java.util.Locale.ROOT);
        var envValue = System.getenv(envName);
        if (envValue != null && !envValue.isBlank()) {
            return java.util.Optional.of(envValue);
        }
        return java.util.Optional.empty();
    }

    private static <T> T get(CompletableFuture<T> future) throws Exception {
        return future.get(30, TimeUnit.SECONDS);
    }

    private static S3AsyncClient buildS3Client(URI endpoint, String identity,
            String credential) {
        return S3AsyncClient.builder()
                .multipartEnabled(true)
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create(identity, credential)))
                .region(Region.US_EAST_1)
                .endpointOverride(endpoint)
                .requestChecksumCalculation(
                        RequestChecksumCalculation.WHEN_REQUIRED)
                .responseChecksumValidation(
                        ResponseChecksumValidation.WHEN_REQUIRED)
                .serviceConfiguration(S3Configuration.builder()
                        .pathStyleAccessEnabled(true)
                        .chunkedEncodingEnabled(false)
                        .build())
                .build();
    }

    private record SmokeCsrf(String parameterName, String token,
            String headerName) {
    }
}
