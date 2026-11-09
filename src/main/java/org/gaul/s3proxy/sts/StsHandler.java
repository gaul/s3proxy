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

package org.gaul.s3proxy.sts;

import java.io.IOException;
import java.io.Writer;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;

import jakarta.servlet.http.HttpServletResponse;

import org.gaul.s3proxy.S3ErrorCode;
import org.gaul.s3proxy.S3ProxyException;

/**
 * The one STS action S3Proxy answers: GetFederationToken, which lets a
 * configured identity mint temporary credentials narrowed by a session
 * policy.  Requests arrive as AWS query-protocol form bodies on POST /,
 * signed for the sts service, and are answered in the XML the AWS SDKs and
 * CLI expect, so stock clients work unchanged.
 */
public final class StsHandler {
    public static final String SERVICE = "sts";
    public static final String XMLNS =
            "https://sts.amazonaws.com/doc/2011-06-15/";
    public static final Duration MAX_DURATION = Duration.ofHours(36);

    private static final Duration MIN_DURATION = Duration.ofMinutes(15);
    private static final Duration DEFAULT_DURATION = Duration.ofHours(12);

    private static final String API_VERSION = "2011-06-15";
    /** S3Proxy has no accounts; ARNs name this one, as S3's owner id does. */
    private static final String ACCOUNT_ID = "000000000000";
    private static final Pattern NAME = Pattern.compile("[\\w+=,.@-]{2,32}");
    private static final Set<String> PARAMETERS = Set.of(
            "Action", "Version", "Name", "Policy", "DurationSeconds");
    /** The policy of a session minted without one: it may do nothing. */
    private static final String DENY_ALL = "{\"Version\":\"2012-10-17\"," +
            "\"Statement\":[{\"Effect\":\"Deny\",\"Action\":\"*\"," +
            "\"Resource\":\"*\"}]}";

    private final Duration maxDuration;
    private final SecureRandom random = new SecureRandom();
    private final XMLOutputFactory xmlOutputFactory =
            XMLOutputFactory.newInstance();

    /**
     * Answer GetFederationToken, issuing sessions of at most maxDuration; a
     * request for longer is shortened to it, as AWS shortens one past its
     * own limit.
     */
    public StsHandler(Duration maxDuration) {
        if (maxDuration.compareTo(MIN_DURATION) < 0 ||
                maxDuration.compareTo(MAX_DURATION) > 0) {
            throw new IllegalArgumentException(
                    "STS maximum duration must be between " +
                    MIN_DURATION.toSeconds() + " and " +
                    MAX_DURATION.toSeconds() + " seconds, was: " +
                    maxDuration.toSeconds());
        }
        this.maxDuration = maxDuration;
    }

    /**
     * Answer an STS request from a caller already authenticated as
     * parentIdentity with its long-term credential.
     */
    public void handle(byte[] body, HttpServletResponse response,
            String parentIdentity, String parentCredential, String requestId,
            Instant now) throws IOException {
        Map<String, String> params = parseForm(
                new String(body, StandardCharsets.UTF_8));
        String action = params.get("Action");
        if (action == null) {
            throw new S3ProxyException(S3ErrorCode.MISSING_ACTION,
                    "Missing Action");
        }
        if (!"GetFederationToken".equals(action)) {
            throw new S3ProxyException(S3ErrorCode.INVALID_ACTION,
                    "Could not find operation " + action + " for version " +
                    params.get("Version"));
        }
        if (!API_VERSION.equals(params.get("Version"))) {
            throw new S3ProxyException(S3ErrorCode.INVALID_ACTION,
                    "Unsupported Version: " + params.get("Version"));
        }
        for (String name : params.keySet()) {
            if (!PARAMETERS.contains(name)) {
                // PolicyArns.member.N and Tags.member.N among them: there
                // are no managed policies or tags here to honour, and
                // ignoring them would issue a session other than the one
                // asked for.
                throw new S3ProxyException(S3ErrorCode.VALIDATION_ERROR,
                        "Unsupported parameter: " + name);
            }
        }

        String name = params.get("Name");
        if (name == null || !NAME.matcher(name).matches()) {
            throw new S3ProxyException(S3ErrorCode.VALIDATION_ERROR,
                    "Name must be 2 to 32 characters from [\\w+=,.@-]");
        }

        Duration duration = DEFAULT_DURATION;
        String durationParam = params.get("DurationSeconds");
        if (durationParam != null) {
            long seconds;
            try {
                seconds = Long.parseLong(durationParam);
            } catch (NumberFormatException nfe) {
                throw new S3ProxyException(S3ErrorCode.VALIDATION_ERROR,
                        "DurationSeconds must be an integer");
            }
            if (seconds < MIN_DURATION.toSeconds() ||
                    seconds > MAX_DURATION.toSeconds()) {
                throw new S3ProxyException(S3ErrorCode.VALIDATION_ERROR,
                        "DurationSeconds must be between " +
                        MIN_DURATION.toSeconds() + " and " +
                        MAX_DURATION.toSeconds());
            }
            duration = Duration.ofSeconds(seconds);
        }
        if (duration.compareTo(maxDuration) > 0) {
            duration = maxDuration;
        }

        // Without a policy a federated user may do nothing, as in AWS.
        String policy = params.get("Policy");
        if (policy == null) {
            policy = DENY_ALL;
        } else if (SessionPolicy.utf8Length(policy) >
                SessionPolicy.MAX_LENGTH) {
            throw new S3ProxyException(S3ErrorCode.VALIDATION_ERROR,
                    "Policy must be at most " + SessionPolicy.MAX_LENGTH +
                    " bytes");
        } else {
            try {
                SessionPolicy.parse(policy);
            } catch (IllegalArgumentException iae) {
                throw new S3ProxyException(
                        S3ErrorCode.MALFORMED_POLICY_DOCUMENT,
                        String.valueOf(iae.getMessage()), iae);
            }
        }

        // The token keeps whole seconds; so does the expiry the client is
        // told, as in AWS, lest the token expire before the time it reads.
        Instant expiration = now.truncatedTo(ChronoUnit.SECONDS)
                .plus(duration);
        String accessKeyId = SessionToken.newAccessKeyId(random);
        String sessionToken = new SessionToken(parentIdentity, accessKeyId,
                expiration, name, policy).encode(parentCredential, random);
        String secretAccessKey = SessionToken.secretAccessKey(
                parentIdentity, accessKeyId, parentCredential);
        int packedPolicySize = params.get("Policy") == null ? 0 :
                (int) Math.ceil(100.0 * SessionPolicy.utf8Length(policy) /
                        SessionPolicy.MAX_LENGTH);

        response.setStatus(HttpServletResponse.SC_OK);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setContentType("text/xml");
        try (Writer writer = response.getWriter()) {
            XMLStreamWriter xml = xmlOutputFactory.createXMLStreamWriter(
                    writer);
            xml.writeStartDocument();
            xml.writeStartElement("GetFederationTokenResponse");
            xml.writeDefaultNamespace(XMLNS);
            xml.writeStartElement("GetFederationTokenResult");

            xml.writeStartElement("Credentials");
            writeSimpleElement(xml, "SessionToken", sessionToken);
            writeSimpleElement(xml, "SecretAccessKey", secretAccessKey);
            writeSimpleElement(xml, "Expiration",
                    DateTimeFormatter.ISO_INSTANT.format(expiration));
            writeSimpleElement(xml, "AccessKeyId", accessKeyId);
            xml.writeEndElement();

            xml.writeStartElement("FederatedUser");
            writeSimpleElement(xml, "Arn", "arn:aws:sts::" + ACCOUNT_ID +
                    ":federated-user/" + name);
            writeSimpleElement(xml, "FederatedUserId",
                    ACCOUNT_ID + ":" + name);
            xml.writeEndElement();

            writeSimpleElement(xml, "PackedPolicySize",
                    String.valueOf(packedPolicySize));
            xml.writeEndElement();

            xml.writeStartElement("ResponseMetadata");
            writeSimpleElement(xml, "RequestId", requestId);
            xml.writeEndElement();

            xml.writeEndElement();
            xml.flush();
        } catch (XMLStreamException xse) {
            throw new IOException(xse);
        }
    }

    /**
     * Parse an application/x-www-form-urlencoded body.  A parameter given
     * twice is refused rather than resolved one way or the other, since the
     * two readings would issue different sessions.
     */
    static Map<String, String> parseForm(String body) {
        var params = new HashMap<String, String>();
        if (body.isEmpty()) {
            return params;
        }
        for (String pair : body.split("&", -1)) {
            if (pair.isEmpty()) {
                continue;
            }
            int equals = pair.indexOf('=');
            String key;
            String value;
            try {
                key = URLDecoder.decode(equals < 0 ? pair :
                        pair.substring(0, equals), StandardCharsets.UTF_8);
                value = equals < 0 ? "" : URLDecoder.decode(
                        pair.substring(equals + 1), StandardCharsets.UTF_8);
            } catch (IllegalArgumentException iae) {
                throw new S3ProxyException(S3ErrorCode.VALIDATION_ERROR,
                        "Malformed form encoding", iae);
            }
            if (params.put(key, value) != null) {
                throw new S3ProxyException(S3ErrorCode.VALIDATION_ERROR,
                        "Duplicate parameter: " + key);
            }
        }
        return params;
    }

    private static void writeSimpleElement(XMLStreamWriter xml,
            String elementName, String characters) throws XMLStreamException {
        xml.writeStartElement(elementName);
        xml.writeCharacters(characters);
        xml.writeEndElement();
    }
}
