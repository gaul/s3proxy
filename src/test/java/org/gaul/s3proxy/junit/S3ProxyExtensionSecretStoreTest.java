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

package org.gaul.s3proxy.junit;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.SecureRandom;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

/** A secret store given to the extension serves HTTPS with it. */
public final class S3ProxyExtensionSecretStoreTest {
    @RegisterExtension
    static final S3ProxyExtension EXTENSION = S3ProxyExtension
            .builder()
            .withSecretStore(S3ProxyExtensionSecretStoreTest.class
                    .getResource("/keystore.jks").toString(), "password")
            .build();

    @Test
    public void testServesHttps() throws Exception {
        assertThat(EXTENSION.getUri().getScheme()).isEqualTo("http");
        var secureUri = EXTENSION.getSecureUri();
        assertThat(secureUri).isNotNull();
        assertThat(secureUri.getScheme()).isEqualTo("https");
        assertThat(secureUri.getPort()).isPositive();

        // the test key store's certificate is self-signed
        var sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, new TrustManager[] {new X509TrustManager() {
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
        } }, new SecureRandom());
        // a bare handshake: the certificate names no host to verify
        try (var socket = (SSLSocket) sslContext.getSocketFactory()
                .createSocket(secureUri.getHost(), secureUri.getPort())) {
            socket.startHandshake();
            assertThat(socket.getSession().isValid()).isTrue();
        }
    }
}
