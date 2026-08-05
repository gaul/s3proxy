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

package org.gaul.s3proxy.sftp;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Properties;

import com.google.common.io.MoreFiles;
import com.google.common.io.RecursiveDeleteOption;
import com.google.common.io.Resources;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.file.virtualfs.VirtualFileSystemFactory;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.sftp.server.SftpSubsystemFactory;
import org.jspecify.annotations.Nullable;
import org.junit.platform.launcher.LauncherSession;
import org.junit.platform.launcher.LauncherSessionListener;

/**
 * Starts one embedded SFTP server for the whole test JVM when the
 * s3proxy.test.conf system property selects the sftp provider.  The server
 * listens on the endpoint the configuration names and presents the
 * sftp-test-host-key resource, whose fingerprint the configuration pins,
 * so that a static configuration file can drive the AwsSdkTest lane the
 * same way the other backend lanes do.
 */
public final class SftpTestServerListener
        implements LauncherSessionListener {
    private static final String HOST_KEY_RESOURCE = "sftp-test-host-key";

    private @Nullable SshServer sshServer;
    private @Nullable Path sftpRoot;

    @Override
    public void launcherSessionOpened(LauncherSession session) {
        var properties = loadTestProperties();
        if (properties == null || !"sftp".equals(
                properties.getProperty("jclouds.provider"))) {
            return;
        }
        var endpoint = URI.create(properties.getProperty(
                "jclouds.endpoint", "sftp://127.0.0.1/"));
        var identity = properties.getProperty("jclouds.identity");
        var credential = properties.getProperty("jclouds.credential");
        try {
            sftpRoot = Files.createTempDirectory("s3proxy-sftp-test");
            var server = SshServer.setUpDefaultServer();
            server.setHost(endpoint.getHost());
            server.setPort(SftpBlobStore.endpointPort(endpoint));
            server.setKeyPairProvider(loadHostKey());
            server.setPasswordAuthenticator((username, password, sshSession)
                    -> username.equals(identity) &&
                            password.equals(credential));
            server.setFileSystemFactory(new VirtualFileSystemFactory(
                    sftpRoot));
            server.setSubsystemFactories(List.of(
                    new SftpSubsystemFactory.Builder().build()));
            server.start();
            sshServer = server;
        } catch (IOException ioe) {
            throw new UncheckedIOException(
                    "Failed to start embedded SFTP test server on " +
                    endpoint, ioe);
        }
    }

    @Override
    public void launcherSessionClosed(LauncherSession session) {
        try {
            if (sshServer != null) {
                sshServer.stop();
                sshServer = null;
            }
            if (sftpRoot != null) {
                MoreFiles.deleteRecursively(sftpRoot,
                        RecursiveDeleteOption.ALLOW_INSECURE);
                sftpRoot = null;
            }
        } catch (IOException ioe) {
            throw new UncheckedIOException(ioe);
        }
    }

    /**
     * Loads the configuration which the s3proxy.test.conf system property
     * names, or null when it is unset or does not resolve to a classpath
     * resource.
     */
    private static @Nullable Properties loadTestProperties() {
        String configFile = System.getProperty("s3proxy.test.conf");
        if (configFile == null) {
            return null;
        }
        URL url;
        try {
            url = Resources.getResource(configFile);
        } catch (IllegalArgumentException iae) {
            return null;
        }
        var properties = new Properties();
        try (InputStream is = Resources.asByteSource(url).openStream()) {
            properties.load(is);
        } catch (IOException ioe) {
            throw new UncheckedIOException(ioe);
        }
        return properties;
    }

    private static KeyPairProvider loadHostKey() throws IOException {
        var url = Resources.getResource(HOST_KEY_RESOURCE);
        try (InputStream is = Resources.asByteSource(url).openStream()) {
            return KeyPairProvider.wrap(SecurityUtils.loadKeyPairIdentities(
                    null, NamedResource.ofName(HOST_KEY_RESOURCE), is, null));
        } catch (GeneralSecurityException gse) {
            throw new IOException("Failed to load " + HOST_KEY_RESOURCE, gse);
        }
    }
}
