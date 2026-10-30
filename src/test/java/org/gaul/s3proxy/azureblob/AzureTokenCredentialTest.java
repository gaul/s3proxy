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

package org.gaul.s3proxy.azureblob;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;

import com.azure.core.credential.AccessToken;
import com.azure.core.credential.TokenCredential;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;

import org.gaul.s3proxy.blobstore.BlobStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;

import reactor.core.publisher.Mono;

/**
 * Checks what a store built with a {@link TokenCredential} presents to the
 * service, by reading the Authorization header off each request at a server
 * started here. The Azure SDK sends bearer tokens only over TLS, so the
 * server speaks it with the test keystore and the client is told to trust
 * that certificate for the duration of the test. The server refuses every
 * request, since only what was presented is in question.
 */
// SSLContext.setDefault reaches every TLS client built meanwhile.
@Isolated
public final class AzureTokenCredentialTest {
  private static final String KEYSTORE_PASSWORD = "password";

  private final List<String> authorizations = Collections.synchronizedList(new ArrayList<String>());

  private HttpsServer server;
  private SSLContext previousDefault;

  @BeforeEach
  public void setUp() throws IOException, GeneralSecurityException {
    var keyStore = KeyStore.getInstance("JKS");
    try (var in = getClass().getResourceAsStream("/keystore.jks")) {
      keyStore.load(in, KEYSTORE_PASSWORD.toCharArray());
    }
    var keyManagers = KeyManagerFactory.getInstance(
        KeyManagerFactory.getDefaultAlgorithm());
    keyManagers.init(keyStore, KEYSTORE_PASSWORD.toCharArray());
    var serverContext = SSLContext.getInstance("TLS");
    serverContext.init(keyManagers.getKeyManagers(), null, null);

    server = HttpsServer.create(new InetSocketAddress(
        InetAddress.getLoopbackAddress(), 0), 0);
    server.setHttpsConfigurator(new HttpsConfigurator(serverContext));
    server.createContext("/", this::handle);
    server.start();

    previousDefault = SSLContext.getDefault();
    var clientContext = SSLContext.getInstance("TLS");
    clientContext.init(null,
        new TrustManager[] { new TrustEverything() }, null);
    SSLContext.setDefault(clientContext);
  }

  @AfterEach
  public void tearDown() {
    SSLContext.setDefault(previousDefault);
    server.stop(0);
  }

  /** The token the credential returns is presented as a bearer token. */
  @Test
  public void testRequestCarriesTheBearerToken() {
    TokenCredential credential = request -> Mono.just(new AccessToken(
        "token", OffsetDateTime.now().plusHours(1)));

    try (BlobStore blobStore = store(credential)) {
      listRefusedByTheServer(blobStore);
    }

    assertThat(authorizations).containsExactly("Bearer token");
  }

  /** A token with time left is reused rather than asked for again. */
  @Test
  public void testTokenIsReusedWhileItLasts() {
    var asked = new AtomicInteger();
    TokenCredential credential = request -> Mono.just(new AccessToken(
        "token-" + asked.incrementAndGet(),
        OffsetDateTime.now().plusHours(1)));

    try (BlobStore blobStore = store(credential)) {
      listRefusedByTheServer(blobStore);
      listRefusedByTheServer(blobStore);
    }

    assertThat(asked.get()).isEqualTo(1);
    assertThat(authorizations).containsExactly(
        "Bearer token-1", "Bearer token-1");
  }

  /**
   * A token past its expiry gives way to its successor before the next
   * request, so a credential that renews keeps the store working.
   */
  @Test
  public void testExpiredTokenIsReplaced() {
    var asked = new AtomicInteger();
    TokenCredential credential = request -> Mono.just(new AccessToken(
        "token-" + asked.incrementAndGet(),
        OffsetDateTime.now().minusMinutes(1)));

    try (BlobStore blobStore = store(credential)) {
      listRefusedByTheServer(blobStore);
      listRefusedByTheServer(blobStore);
    }

    assertThat(authorizations).hasSize(2);
    assertThat(authorizations.get(1))
        .isNotEqualTo(authorizations.get(0));
  }

  /**
   * Lists once, expecting the refusal the handler answers with: the
   * request is made for the sake of the header it carries.
   */
  private static void listRefusedByTheServer(BlobStore blobStore) {
    assertThat(catchThrowable(blobStore::list)).isNotNull();
  }

  private BlobStore store(TokenCredential credential) {
    return new AzureBlobStore(credential, "https://127.0.0.1:" +
        server.getAddress().getPort() + "/devstoreaccount1");
  }

  private void handle(HttpExchange exchange) throws IOException {
    authorizations.add(exchange.getRequestHeaders().getFirst(
        "Authorization"));
    try (var in = exchange.getRequestBody()) {
      in.readAllBytes();
    }
    // Just sending the simplest error response as reply
    byte[] body = ("<?xml version=\"1.0\" encoding=\"utf-8\"?><Error>" +
        "<Code>AuthenticationFailed</Code><Message>token seen" +
        "</Message></Error>").getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().set("x-ms-error-code",
        "AuthenticationFailed");
    exchange.sendResponseHeaders(403, body.length);
    try (var out = exchange.getResponseBody()) {
      out.write(body);
    }
  }

  /** Trusts any certificate, for a server this test started itself. */
  private static final class TrustEverything
      extends X509ExtendedTrustManager {
    @Override
    public void checkClientTrusted(X509Certificate[] chain,
        String authType) {
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain,
        String authType, Socket socket) {
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain,
        String authType, SSLEngine engine) {
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain,
        String authType) {
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain,
        String authType, Socket socket) {
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain,
        String authType, SSLEngine engine) {
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
      return new X509Certificate[0];
    }
  }
}
